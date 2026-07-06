# 计划审批(Plan Approval)— 设计与实现记录

> 状态:已实现 · 配套:`docs/plans/approval-system.md`(单命令异步审批 v1.1)
>
> 起因:实测反馈「精确匹配审批太细碎——一次部署十几条命令批了 ~10 次」。
>
> 一句话:`agentssh plan submit <host> --session <id> -- 'cmd1' 'cmd2' …` 把一个任务的 N 条灰区命令打包成**一张审批单**,操作员整体审阅一次(TUI `[p]` 或 `plan grant`),等价于**批量铸造 N 个 exact 的 once/session grant**。执行仍然逐条走 `run` → `Authorize`,审计粒度与显式 deny 的不可逾越性**零变化**。

## 1. 设计原则:计划是审批的批处理,不是执行的批处理

刻意不做「approve 后自动执行 N 条命令」:

- **执行路径一行不改**。每条命令仍由 agent 逐条 `run`,逐条实时过 `Authorize`(分离引擎:显式 allow/deny 优先,grant 只在 default-deny 灰区参与)。计划里混进一条被 deny 的命令,批了也执行不了。
- **审计粒度不丢**。每条命令照旧有自己的 `started/completed/failed` 记录;审批生命周期事件(`approval_requested/granted/denied`)通过新增的 `plan_id` 字段(`,omitempty`,追加在 canonical 字段表末尾,旧链不回归)串起来。
- **grant 语义照旧**。批量批准 = 逐条 `ApplyDecision`,once/session 两档,exact matcher(`Generalize` 的解释器/特权/破坏性护栏逐条照跑);**批量档永不提供 host scope**——持久放宽必须回到单条命令的 deliberate 决定(`approval grant <id> --host`)。

## 2. 数据模型

- **成员请求**:复用现有 `PendingRequest`(pending/responses 存储、`req_digest`、O_EXCL、去重全部沿用),新增展示元数据 `plan_id / plan_seq / plan_total`(omitempty)。
- **计划清单**:`approvals/plans/<pl_id>.json`(0600,O_EXCL 一次写入):
  ```json
  { "version":1, "id":"pl_<96bit>", "session_id":"s_…", "host":"web-1",
    "ts":"…Z", "member_ids":["ap_…","ap_…"] }
  ```
  清单是**成员关系的权威来源**(`plan status/wait` 以它为准),避免重写 pending 文件;成员的裁决状态始终从 pending/responses 实时推导。清单同 resolution 一样**不是授权依据**——授权永远在 `run` → `Authorize` 处从 grant store 重新推导。
- **成员失效 = 拒绝**:成员 pending 文件被 TTL 清扫后,`PlanStatus` 计为 `expired` 并归入 denied(fail-closed,agent 重新提交而不是假设已批)。

## 3. 命面

**agent 面(无审批动词)**:
- `plan submit <host> --session <id> [--file <path>] [--json] -- '<cmd>' '<cmd>' …`
  - `--` 后**每个参数是一条完整命令**(不做 join;与 `run` 的 join 语义刻意不同,help 里写明);`--file` 每行一条,跳过空行与 `#`。
  - 单 host(组 → usage error;每 host 一张计划)。要求审批通道开启,否则 usage error 并指路 `policy test`。
  - 逐条 `PreflightAuthorize`(无副作用、不消费 grant):allow/allow_by_grant → `allowed`;显式 deny → `denied`(终态,不入计划);default-deny → 铸 pending(带 plan 标记)+ audit `approval_requested{plan_id, channel=plan}`。
  - 退出码沿用合并语义:任一 denied → 6 > 任一 pending → 7 > 全 allowed → 0。
- `plan status <plan_id> [--json]` / `plan wait <plan_id> [--timeout] [--json]`:聚合裁决状态,退出码对齐 approval:全批 0、任一拒/失效 6、仍有 pending 7、未知/畸形 2。

**操作员面(`requireOperator` 守门)**:
- `plan grant <plan_id> --once|--session` — 对全部仍 pending 的成员逐条 `ApplyDecision`(封装为 `ApplyPlanDecision`);`--host` 不存在。
- `plan deny <plan_id>` — 全部拒绝(不持久化,同单条 deny)。
- **TUI**:成员行在 Approvals 队列照常出现,详情行显示 `plan k/N` 与 `[p] decide whole plan`;按 `p` 打开整批 chooser(once/session/deny,无 host),单条 `o/s/h/d` 仍可逐行裁决(操作员可先 `d` 掉个别行,再 `p` 批余下的——这就是"逐行剔除")。

## 4. agent 工作流(SKILL.md 已写入)

```
1. policy test 逐条预检(免费,发现 deny 提前剔除)
2. plan submit → 拿到 plan_id + 每行 approval_id
3. 转告操作员 → plan wait <plan_id>
4. 全批后逐条 run(与计划同一 --session)→ grant 逐条命中
```

一次部署的操作员交互从 ~10 次降到 1-2 次(计划一次 + 可能的 stdin 写文件一次),审计里每条命令仍独立可回放。

## 5. 安全权衡

1. **整批批准的粗粒度风险**:操作员可能不逐行细看。缓解:TUI 逐行展示 + 单行可先 deny 再整批;批量档强制 exact matcher + 无 host scope;显式 deny 结构上不可被计划越过。
2. **计划与 session 绑定**:grant 绑 `(session_id, host)`,换 session 重跑不会搭车。
3. **成员被单独裁决**:`ApplyPlanDecision` 跳过已决成员(`ErrAlreadyResolved` 容忍),单条与整批两条路径可交错,幂等。
4. **plan_id 审计字段**:与 stdin 字段同批追加在 `Record`/`canonicalRecord` 末尾(`,omitempty`),升级前旧日志 `audit verify` 逐字节不变(已有 golden 链测试覆盖)。

## 6. 测试

`cmd/agentssh/plan_test.go`:submit(allowed/denied/pending 分流与退出码合并)、grant --session 后逐条 run 零额外审批、audit plan_id 生命周期 + verify、deny 全批、--file 解析、未开审批 usage error、grant 缺 scope usage error。`internal/tui` 既有测试回归通过。

## 7. 未来项

- 组 target 的多 host 计划(每 host preflight,与 run 的 group preflight 语义对齐)。
- 计划行内嵌 stdin(当前 `--stdin-file` 只在 `run` 上;计划行如需 stdin,先单独 run 走 stdin 审批)。
- TUI 折叠视图(同一计划聚合成一行,展开逐行)——当前逐行 + `[p]` 已可用,聚合视图等实测反馈。
