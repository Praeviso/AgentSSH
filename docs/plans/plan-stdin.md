# 计划行携带 stdin — 实现

> 状态:**已实现** · 配套:`docs/plans/plan-approval.md`(计划审批)、`docs/plans/run-stdin.md`(`run --stdin-file`)
>
> 起因:`plan-approval.md` §7 曾列出未来项「计划行内嵌 stdin」。旧版 `plan submit` 只接受命令文本,而 grant 绑定 `(命令, stdin 内容哈希)` —— 于是「写配置文件」这类最常见的部署动作**必然逃出计划**,操作员批了计划还要再批一次;本实现已补齐这条数据链路。
>
> 一句话:`plan submit` 通过**结构化计划文件**(`version: 1` + `commands: [{cmd, stdin_file}]`)声明每行 stdin;提交时计算哈希并写进审批单,批准后铸出的 grant 直接绑定该内容,后续 `run --stdin-file` 逐字节相同即可命中。

## 1. 缺口:不是"少个功能",是计划与 grant 的数据模型对不上

`Grant` 的匹配键是 `(host, 命令正则, stdin_sha256)` —— `session_store.go` 中 `grant.StdinSHA256 != stdinSHA256` 是无条件的。历史上的缺口是 `plan submit` 铸 pending 时**固定不带 stdin**:

- `PreflightAuthorize` 的最后一参 `stdinSHA256` 被写死为空串;
- `pendingStore.Create` 不设 `StdinSHA256` / `StdinBytes`。

现版在提交阶段读取并哈希每个 `stdin_file`,同时传入 preflight 和 pending store,所以计划批准铸出的 grant 会绑定真实哈希;带 `--stdin-file` 的 run 只有在内容逐字节相同的时候才会命中。

下面是修复前在真实二进制上的复现(临时探针,已删除):同一 host、同一 session,计划 `tee /etc/nginx/nginx.conf` 整批 `--session` 批准后 ——

| 后续动作 | 退出码 | 说明 |
|---|---|---|
| `run --stdin-file nginx.conf -- tee /etc/nginx/nginx.conf` | **7** | 又生成一张审批单 `ap_…`,executor 零调用 |
| `run -- tee /etc/nginx/nginx.conf`(不带 stdin) | 0 | grant 命中 |

这不是一个可以靠"agent 用法更聪明"绕开的问题:计划的目的就是把一个任务的全部灰区命令收进一次审阅,而部署任务里写配置文件几乎必然存在。上述缺口已由结构化计划与哈希绑定实现消除。

### 1.1 还有一半是安全问题,不只是麻烦

`authorize.go:135-144` 对带 stdin 的请求强制收紧:候选 matcher 改 `Exact(command)`、`Promotable=false`;`:112` 让持久 host 规则对 stdin run 一律不生效。这套收紧的前提是 `Authorize` **知道**这次运行带 stdin。

修复前计划路径不传 stdin,于是同一行命令在计划里被当作**无输入流命令**审阅:

- `host_grant_mode: prefix` 下,`tee /etc/nginx/nginx.conf` 会被泛化成前缀 matcher,TUI 显示 `[h] host-allow frees tee * — won't ask again`;
- 而这条命令**实际要携带操作员从未见过的内容**。

计划档本身不提供 host scope(`ApplyPlanDecision` 限定 once/session),所以当时没有被利用的路径 —— 但**操作员看到的描述与命令的真实能力不符**,这是审阅界面的正确性问题。现版传入 stdin 哈希后,`authorize` 现有的收紧逻辑自动生效,展示与实质重新对齐。

## 2. 界面:结构化计划文件

`plan submit` 现在支持三种组合输入:位置参数仍是纯字符串,传统 `--file` 仍是一行一条命令,而声明 `version:` 的 `--file` 使用结构化格式表达 per-line stdin:

```yaml
version: 1
commands:
  - cmd: systemctl status nginx
  - cmd: tee /etc/nginx/nginx.conf
    stdin_file: ./nginx.conf
  - cmd: systemctl reload nginx
```

```
agentssh plan submit web-1 --session s_1a2b3c4d --json --file deploy.yaml
```

### 2.1 两种文件格式的分派规则(刻意做成机械规则,不做内容猜测)

**跳过空行与 `#` 注释后的第一行是 `---`、或以 `version:` / `commands:` 开头 → 结构化;否则 → 现有的一行一条命令。**

- 两种格式都跳过 `#` 注释,而 YAML 的注释也是 `#`,规则在两边都自洽。
- 三个触发词都要认:**只认 `version:` 是不够的**。开头写一行 `---` 是最常见的 YAML 写法,把 `commands:` 写在 `version:` 前面也完全合法 —— 两者都会 decode 成正确的结构化计划,却会被窄规则判成行模式,于是 `---` / `version: 1` / `commands:` / `- cmd: …` / `stdin_file: …` 每行各自变成一条"命令"送审,真命令被打散,**所有 stdin 绑定被静默丢弃**。这恰是本规则要防的事,窄一格就等于没防。
- 一旦判定为结构化,YAML 语法错误就是**硬 usage error,绝不回落到行模式**。回落会把一个手滑的结构化文件按行拆成一堆"命令"提交审批 —— 虽然 fail-closed(每条都是 default-deny),但会给操作员一屏垃圾。
- 单文档校验只拒**有实际内容**的第二个文档:结尾多一行 `---`、或尾部是纯注释文档,decode 出来是 nil,按结束处理。
- `version` 非 1 → usage error 并写明支持的版本。
- 反向误判(行模式文件恰好首行以这三者之一开头)要求存在一条名为 `---` / `version:` / `commands:` 的命令,不是现实场景;真发生了,submit 的逐行输出立刻可见。

不引第二个 flag(`--plan-file` 之类):一个 flag 一件事,格式由文件自己声明,和 `policy.yaml` / `inventory.yaml` 都写 `version: 1` 的既有约定一致。

### 2.2 字段语义

| 字段 | 必填 | 语义 |
|---|---|---|
| `version` | 是 | 固定 `1` |
| `commands[].cmd` | 是 | 一条完整远端命令(等价 `--` 后的一个位置参数),不做 join、不过 shell;**与行模式一样 trim,且必须是单行** |
| `commands[].stdin_file` | 否 | 本地文件路径,**相对当前工作目录**解析 |

`cmd` 必须 trim 且单行,和行模式对齐:YAML 块标量(`cmd: |`)会带一个尾随换行,而 `run` 送出的命令没有。不 trim 的话铸出的 matcher 是 `\Asystemctl restart nginx\n\z`,操作员批了也永远匹配不上 —— 一个操作员无法打破的审批循环。

`stdin_file` 相对 **cwd** 而非计划文件所在目录:与 `run --stdin-file` 同一个参照系,全流程只有一个坐标系。要做可迁移的"计划 + 载荷"包就用绝对路径。

位置参数与 `--file` 仍可同时给(现有行为:位置参数在前,文件内容追加在后);位置参数天然没有 stdin。

## 3. 实现落点

**核心结论:`internal/approval/` 一行不改。** 收紧逻辑(强制 exact、禁 promotable、跳过 host 规则)、grant 绑定、pending 去重键、`req_digest` 纳入 stdin —— 全部已经在 `authorize.go` / `session_store.go` / `request.go` 里就位且被 `run` 路径覆盖。本实现只在 `cmd/agentssh/plan.go` 接通结构化解析、预加载和字段传递,并保留审批内核不变。

### 3.1 `cmd/agentssh/plan.go`

- 新增 `planSpec` / `planCommand` 两个结构体 + `readStructuredPlanFile`,与 `readPlanFile` 并列;`readPlanFile` **保持不变**。
- `runPlanSubmit` 内部把 `[]string` 换成 `[]planLine{cmd string; stdin stdinSpec}`;位置参数与行模式文件产出 `stdin` 为零值。
- **在进入 authorize/create 循环之前,先把所有 `stdin_file` 读完**(见 §3.2)。
- 循环内两处传参:
  - `PreflightAuthorize(…, command, line.stdin.sha256)`(原 `""`);
  - `pendingStore.Create(approval.PendingRequest{…, StdinSHA256: line.stdin.sha256, StdinBytes: line.stdin.bytes})`。
- 审计记录套一层现有的 `stampStdin(record, line.stdin)`。`Record` / `canonicalRecord` 的 `stdin_sha256` / `stdin_bytes` 早在 `run --stdin-file` 那一批就以 `,omitempty` 追加在字段表末尾(`run-stdin.md` §3.1),**没有新字段,hash 链零风险**,现有 golden 链测试继续覆盖。
- `planSubmitLine` 加 `StdinSHA256` / `StdinBytes`(`,omitempty`),与 `runResponse` 对齐,agent 能自行核对后续喂进去的内容。
- `printPlanSubmitHuman` 在带 stdin 的行加一段 `· stdin %d B` —— 与 TUI 的 `stdin %d B sha256=…` 用同一措辞,不再多写。

### 3.2 全部 stdin 必须在任何 pending 落盘之前读完

历史实现的 `runPlanSubmit` 是**边循环边写 pending**,循环中途返回 error 时:前面的 pending 已经落盘且带着 `plan_id`,而 manifest 还没写 —— 留下一批**没有清单的孤儿审批单**。它们会出现在 `approval ls` 和 TUI 里,`plan status` 却查不到。

stdin 引入了一整类新的读取失败(文件不存在、非常规文件、超 32 MiB、读错误),因此现实现**在写第一条 pending 之前全部读完**:所有 `stdin_file` 顺序预加载,任何一个失败就直接 usage error 返回,此时零副作用。

复用 `loadStdinSpec`(`main.go:974`),不另写哈希函数 —— 32 MiB 上限、常规文件校验、`LimitReader` 二次设防都在里面,平行实现迟早漂移。它返回完整 `data`,而计划只需要 `sha256` + `bytes`:预加载后**立即丢弃 `data`**,`stdinSpec` 在计划路径上只作为身份载体。峰值内存是单个文件而非 N 个之和,且 N 份内容全程不进审批存储、不进审计日志(与 `run --stdin-file` 同规格)。

不新增"计划总载荷上限":单文件 32 MiB 已是既定契约,顺序读取不叠加常驻内存,凭空发明一个新限制没有依据。

### 3.3 TUI:沿用既有分支,并修复空文件判据

`approvals_section.go` 的两个入口都已按 stdin 分支渲染,且只看 `PendingRequest` 的字段;本次仅将 stdin 存在性判据从字节数改为哈希是否非空:

- `kindLabel`(:534)—— KIND 列显示 `stdin`;
- `consequenceLine`(:555)—— `stdin %d B sha256=%s… — exact content only; no host-allow`。

`consequenceLine` 的 `plan k/N · [p] decide whole plan` 前缀在 stdin 分支**之前**拼进 `id`,stdin 分支返回时带着它 —— 所以带 stdin 的计划成员会同时显示计划位置和内容身份,无需再添加计划专用渲染逻辑。

## 4. 相邻缺陷(本次触及的代码里发现,与 stdin 无直接因果,均已修复)

两处都很小,单独列出以便独立复核或回滚。

### 4.1 TUI 曾用 `StdinBytes > 0` 判定 stdin,空文件被误标(已修复)

旧版 `kindLabel` 和 `consequenceLine` 都判 `req.StdinBytes > 0`。而**空文件**的 `loadStdinSpec` 返回 `sha256 = e3b0c442…`(空串哈希)、`bytes = 0` —— 授权侧一切正常(`stdinSHA256 != ""` 触发强制 exact,grant 也绑住了这个哈希),**只有展示错**:

- KIND 列落到 `!c.Promotable` 分支显示 `priv`;
- 详情行显示 `[h] unavailable — privileged command; use once or session`。

理由说错了(是 stdin,不是特权),方向是安全的(照样不给 host)。但"用空内容截断一个远端文件"是真实动作,操作员应当看到它带 stdin。

修:两处判据换成 `req.StdinSHA256 != ""`。这是 stdin 存在与否的权威判据 —— `loadStdinSpec` 只在路径为空时返回零值 spec,一旦读过文件哈希必非空。

### 4.2 计划里两条完全相同的命令会产生重复成员(已修复)

`PendingStore.Create` 的去重(`request.go:94` → `findUnresolved`)按 `(session, host, cmd_sha256, stdin_sha256)` 命中未裁决的旧单并**返回同一个 `ap_` id**。`runPlanSubmit` 无条件 `memberIDs = append(…)`,于是同一 id 进清单两次。实测 `plan submit web-1 -- 'ls -la /var' 'ls -la /var'` → `pending=2`,两个 id **完全相同**。

后果是 `plan status` 的 approved/denied/pending 计数虚高(同一成员数两次),不影响授权。现实现追加前跳过已在 `memberIDs` 里的 id。

顺带一提,stdin 让这里**变好**而非变坏:同命令不同内容因为 `stdin_sha256` 参与去重键,会正确地拿到两个不同的审批单。

## 5. 安全性质核对

1. **内容仍然不可见、不留存**:计划路径与 `run` 路径共用 `loadStdinSpec`,操作员看到的仍是 `sha256 + 字节数`;内容不进 pending 文件、不进 manifest、不进审计日志。
2. **绑定在提交时刻**:哈希在 `plan submit` 时算定。提交后编辑了本地文件,后续 `run` 的哈希就不同 → grant 不命中 → exit 7。这是**正确且必要**的:操作员批准的是那一份内容。文档与 SKILL 必须把"提交后别再动文件,改了要重新 submit"写成硬规则。
3. **计划不放宽 stdin 的收紧档**:传入哈希后 `authorize` 强制 `Exact` + `Promotable=false`;计划档本就不提供 host scope。两道限制叠加,stdin 行只能拿到 once/session 的逐字节 grant。
4. **显式 deny 照旧不可逾越**:`PreflightAuthorize` 走的仍是分离引擎,stdin 不改变 allow/deny/灰区三态的判定 —— 引擎只看命令文本。
5. **stdin 读取失败的原子性**:§3.2 的预加载保证 `stdin_file` 不存在、不是普通文件或超限时"零 pending、零 manifest"。这不是对后续审批/审计存储 I/O 的全流程事务承诺。
6. **审计链不回归**:不新增字段,只是让计划路径也填已有的两个 `,omitempty` 字段。

## 6. agent 工作流

```
1. 写 deploy.yaml:灰区命令逐条列出,要写文件的行标 stdin_file
2. plan submit web-1 --session s_… --file deploy.yaml   → plan_id + 每行 approval_id
3. 转告操作员 → plan wait <plan_id>
4. 全批后逐条 run(同一 --session;带 stdin 的行用同一个 --stdin-file 且内容未改动)
```

如将这套流程同步到 agent 的 SKILL.md,需要写进去的三点是:结构化文件格式;`stdin_file` 相对 cwd;**提交后到执行前不得修改载荷文件,改了必须重新 submit**。

## 7. 测试要点

- **头号回归**:结构化文件提交 `tee /etc/nginx/nginx.conf` + `stdin_file` → `plan grant --session` → `run --stdin-file` 同内容 → **exit 0 且 executor 收到内容**。
- 绑定成立的另一半:换内容 → exit 7;去掉 `--stdin-file` → exit 7;两者都不得触发 executor。
- `host_grant_mode: prefix` 下,带 stdin 的计划行候选 matcher 仍是 exact 且 `proposed_scope` 无 host。
- 格式分派:行模式文件逐字节同今(back-compat);`---` / `commands:` 开头也判为结构化;结构化文件 YAML 语法错 → usage error 且**不回落行模式**;结尾多一个 `---` 仍合法;`version: 2` → usage error;块标量多行命令 → usage error。
- `stdin_file` 出错时的报错指名 `commands[i].stdin_file`,不提 `plan submit` 根本没有的 `--stdin-file` flag。
- `submit` 报的 `pending` 数与 `plan status` 一致:两条相同的行共享一个审批单,只算一个。
- 原子性:任一行 `stdin_file` 不存在 / 是目录 / 超 32 MiB → usage error,且 `approvals/pending/` **为空**、无 manifest。
- 审计:计划的 `approval_requested` 记录带 `stdin_sha256` / `stdin_bytes`,内容不出现在日志里,`audit verify` 通过(含升级前 fixture 的 golden 链)。
- TUI:带 stdin 的计划成员同时显示 `plan k/N` 与 `stdin N B sha256=…`;**空 stdin 文件**标为 `stdin` 而非 `priv`(§4.1)。
- 重复行:同一命令写两遍 → 清单一个成员,`plan status` 计数为 1(§4.2)。

## 8. 非目标

- **`plan execute`**(批准后自动逐条执行):`plan-approval.md` §1 已定为刻意不做 —— 执行路径逐条实时过 `Authorize` 是审计粒度与显式 deny 不可逾越的根据。本设计不触碰。
- **多 host 计划**、**TUI 计划折叠视图**:仍是 `plan-approval.md` §7 的独立未来项。
- **计划总载荷上限**、**stdin 内容进审阅界面**(操作员看内容而非哈希):前者无依据,后者会把内容拖进审批存储,与 `run-stdin.md` §3 的立论相反。
