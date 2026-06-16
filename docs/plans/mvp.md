# 实施计划 — AgentSSH MVP

> 状态:草案 v1 · 更新于 2026-06-16 · 配套:`docs/prds/agentssh.md`、`docs/architecture/overview.md`、`docs/DESIGN.md`

## 0. 技术选型

| 关注点 | 选择 | 理由 |
|---|---|---|
| 语言/分发 | Go,单静态二进制 | 易分发、远端零依赖、SSH/TUI 生态成熟 |
| CLI 框架 | `spf13/cobra` | 动词式子命令、自带 help/补全 |
| 配置 | `gopkg.in/yaml.v3` | inventory/policy 用 YAML |
| SSH | MVP:shell-out 系统 `ssh` | 复用 ssh-agent/`~/.ssh/config`/known_hosts/ProxyJump |
| TUI | `charmbracelet/bubbletea` + `lipgloss` + `bubbles` | 终端审计查看界面事实标准 |
| 审计/policy/hash | 标准库(`crypto/sha256`、`regexp`、`encoding/json`) | 少依赖、可控 |

## 1. 里程碑

- **M0 脚手架**:仓库结构、cobra 骨架、config 载入、CI(build+test+lint)。
- **M1 直通执行(无 policy)**:`inventory` + `run`(全部直接执行)+ `hosts`。能在真实主机上跑命令。
- **M2 Policy + 审计**:allow/deny 判定(含 prod allowlist override)、hash 链审计 + `audit verify`。
- **M3 TUI 审计查看器**:`tui` 单视图(审计流 + 详情 + 过滤 + 校验链)。
- **M4 输出控制 + 手册**:Output Filter(脱敏/截断)、`--skill` 关联、1~2 个示例 SKILL.md、文档收尾。
- **M5 加固/打磨**:退出码全覆盖、错误信息、`policy test`、`NO_COLOR`、非 TTY 降级、E2E 验收。

## 2. 阶段任务

### M0 脚手架
- [ ] `go mod init`,落地 `cmd/`、`internal/` 包结构(见架构文档 §10)。
- [ ] cobra 根命令 + `--help`;空实现的子命令骨架。
- [ ] `internal/config`:解析 `~/.agentssh/`、`$AGENTSSH_HOME`;不存在时给清晰引导。
- [ ] 定义核心类型骨架:audit 记录(含 `session_id`/`session_label`)、policy 判定结果 —— 供后续阶段填充。
- [ ] CI:`go build` / `go test` / `golangci-lint`。

### M1 直通执行
- [ ] `internal/inventory`:解析 inventory.yaml,host/group → 连接信息;`hosts [--json]`。
- [ ] `internal/executor`:构造受控 argv shell-out `ssh`,捕获 stdout/stderr/exit/耗时。
- [ ] `run <host> -- <cmd>`(此阶段全部直接执行),`--json` 输出。
- [ ] 单测:inventory 解析、argv 构造(防注入)、退出码映射。

### M2 Policy + 审计
- [ ] `internal/policy`:规则匹配、`allow|deny`、`defaults.policy`、`host_overrides`(支持切 allowlist)。
- [ ] `policy show` / `policy test <cmd>`(打印命中规则 + allow|deny 判定)。
- [ ] `internal/audit`:JSONL 追加、hash 链、`audit ls|show|verify`;记录含 `session_id`/`session_label`。
- [ ] 会话:解析 `--session` / `$AGENTSSH_SESSION` / `~/.agentssh/session`(空闲 30m 新建)→ 贯穿审计;`session ls`。
- [ ] `run` 接入 policy:`allow` 执行、`deny` 拒绝(exit 6,记 denied)。
- [ ] 单测:规则顺序/override/allowlist、链构造、篡改检测、`deny` 路径、会话解析顺序与空闲窗口。

### M3 TUI 审计查看器
- [ ] `internal/tui`:单一审计视图 —— **按会话分组/折叠** + run 详情面板 + 会话过滤 + 校验链(见 DESIGN §B)。
- [ ] `tui` 与 `audit`/`session` 子命令共用同一查询/校验逻辑。
- [ ] 非 TTY 降级到 `audit`/`session` 子命令;`NO_COLOR` 支持。

### M4 输出控制 + 手册
- [ ] `internal/output`:按 policy 脱敏 + 截断;审计记 redactions/truncated。
- [ ] `run --skill <name>` 关联手册,贯穿审计与 TUI 展示。
- [ ] `skills/restart-service/SKILL.md`、`skills/investigate-cpu/SKILL.md` 示例。
- [ ] README + 文档串联。

### M5 加固/打磨
- [ ] 退出码全覆盖与一致性测试;错误信息「what/why/next」化。
- [ ] `NO_COLOR`、非 TTY 降级到 `audit` 子命令。
- [ ] E2E 验收:跑通 PRD §10 的 S1–S5(尤其 S5 注入命令被 deny + 留痕)。

## 3. 仓库脚手架(M0 产出)

```
agentssh/
  go.mod
  cmd/agentssh/main.go
  internal/{config,inventory,policy,executor,audit,output,tui}/   # approval 预留(MVP 空)
  skills/                # 示例手册(M4 填充)
  docs/                  # 已就位:prds/ architecture/ plans/ DESIGN.md
  .github/workflows/ci.yml
  README.md
```

## 4. 验收(对齐 PRD 成功标准)

逐条映射 PRD §10:S1(U1 全流程零凭据)、S2(高危未批不执行)、S3(审计可校验/篡改可检)、S4(远端零安装纳管)、S5(注入命令被拦且留痕)。M5 末做一次完整走查。

## 5. 风险 / 开放问题

- **R1 policy 匹配是启发式**:基于字符串正则,复合命令(`sh -c '…'`、管道)可能绕过 deny 模式。缓解:检测到管道/`sh -c` 时按更严规则;依赖 prod allowlist 收口;harness 在交互式补位。
- **R2 shell-out ssh 的可移植性**:依赖系统 `ssh` 与用户既有配置。缓解:启动自检 ssh 可用性;未来切 native。
- **R3 灰区依赖 harness**:default=allow,非 deny 的灰区命令在交互式靠 harness 把关;headless 下无人把关(只剩 deny + 审计)。缓解:把真正危险的都进 deny、prod 切 allowlist;无人值守需更强 gate 时再引入未来的 out-of-band 审批。
- **R4 审计输出只存 hash**:无法事后看原始输出。缓解:默认如此(防二次落盘),提供可选完整归档开关。
- **(已定)** 引入轻量 `session_id` 把一连串 run 归组(解析顺序见架构 §6.1);TUI 按会话折叠复盘。
- **(已定)** `deny` 不允许人类临场覆盖(防 Agent 诱导疲劳的人放行);需放宽只能改 policy。
