# PRD — AgentSSH

> 状态:草案 v1 · 更新于 2026-06-16

## 1. 一句话

AgentSSH 是一个本地运行的「最小权限 SSH 代理」:把服务器操作以**操作手册(skill)**的形式暴露给 AI Agent,Agent 只能表达意图、通过 `agentssh` CLI 执行;凭据与动作边界由人类掌控,每次操作分级审批、全量审计。**服务器侧零安装。**

## 2. 背景与问题

AI Agent 越来越多地需要在真实服务器上做运维(查日志、重启服务、部署、排障)。现状的三种做法都不够:

1. **直接给 Agent SSH 权限** —— 等于把钥匙交给一个会幻觉、会被 prompt-injection、可能泄漏凭据的主体。无边界、难审计。
2. **每个任务手写 MCP 工具** —— 工作量大、不灵活,跟不上运维场景的多样性。
3. **人类全程手动执行** —— 慢,失去用 Agent 的意义。

缺的是一个**中间层**:既让 Agent 有足够自主性去干活,又把「能干什么、用什么凭据、谁批准、留什么痕迹」牢牢攥在人类手里。

## 3. 目标用户与主体

本产品有两类「主体」,职责严格分离(这是产品的核心)。

| 主体 | 是谁 | 知道什么 | 能做什么 |
|---|---|---|---|
| **AI Agent**(不可信) | Claude Code 等能跑 shell 的 Agent | 想做什么(意图)、有哪些主机名、有哪些手册 | 读手册、调 `agentssh run` |
| **人类操作者**(可信) | 管服务器的工程师 | 凭据、policy、全部历史 | 配置 inventory/policy、策展手册、审批、审计 |

## 4. 核心概念(术语)

- **Skill(操作手册 / playbook)**:Anthropic Agent Skills 形式的 `SKILL.md` + 配套文件。人类编写的*程序性知识*,教 Agent「某类运维任务怎么做」。住在 Agent 的 skill 目录,版本化、可 review。**它是知识,不是可执行的 RPC。** 属于「软控制」—— 影响 Agent 会尝试什么,但不负责安全。
- **CLI(`agentssh`)**:Agent 实际调用的工具,也是**信任边界**。握凭据、跑 policy、做审批、写审计。属于「硬控制」—— 安全只依赖这一层。
- **Inventory**:人类维护的主机/分组清单(及其连接方式、凭据引用)。
- **Policy**:人类配置的规则,决定一条命令是自动放行 / 需审批 / 拒绝。
- **Audit log**:append-only、hash 链的全量操作记录。

关系:**手册告诉 Agent「怎么做」,CLI 是「拿来做」的那只受约束的手。再坏或被注入的手册也越不过 CLI 的 policy 和审计。**

## 5. 目标 / 非目标

### 目标
- G1 让 Agent 在**不持有任何凭据**的前提下,对人类批准的主机执行运维操作。
- G2 提供**硬边界 `deny`**:对资源侧危险命令做不可覆盖的拦截(headless 下亦生效);交互式「确认」委托给 agent harness,AgentSSH 自身不做同步审批。
- G3 提供**不可篡改的全量审计**,人类可事后还原每一次「意图 + 命令 + 结果」。
- G4 让 Agent 能**自发现能力**(列主机、读手册),减少瞎猜命令。
- G5 远端**零安装**,纯标准 SSH,复用用户既有的 SSH 配置/agent。
- G6 防御被 prompt-injection 的 Agent:动作受 policy 约束、危险操作需人批、回流输出做脱敏。

### 非目标(MVP)
- N0 不在 AgentSSH 内做同步审批/审批队列;交互式确认依赖 agent harness。无人值守下的硬审批留作未来可选。
- N1 不做 Web 界面(人类界面用终端 TUI,纯审计查看)。
- N2 不做多人/RBAC/团队协作(单操作者本地运行)。
- N3 不在远端装 agent / daemon。
- N4 不做凭据管理大而全(MVP 复用 ssh-agent / 系统 ssh,不自存私钥)。
- N5 不替代 CI/CD 或配置管理(Ansible 等);AgentSSH 管的是「Agent 临场操作」。

## 6. 威胁模型(产品视角)

把 Agent 当作**不可信的 confused deputy**。具体威胁与产品级对策:

| 威胁 | 对策 |
|---|---|
| Agent 被服务器内容(如恶意日志行)prompt-injection,转而执行破坏性命令 | 危险命令被 policy `deny` 硬拦截(谁都不能临场覆盖);灰区命令由 harness 交互确认;回流输出脱敏 + 截断 |
| Agent 幻觉出 `rm -rf` 等 | 危险命令模式 `deny` 拦死(headless 亦然);其余交 harness 确认,全程留审计 |
| Agent 泄漏凭据 | Agent 从不持有凭据,凭据只在 CLI 侧(ssh-agent) |
| 事后无法追责 | hash 链 append-only 审计,tamper-evident |
| 敏感输出进入模型 context 被外泄 | 输出回流前按规则脱敏、按上限截断 |

详见 `docs/architecture/overview.md` 的「威胁 → 缓解」映射。

## 7. 功能需求

- **FR1 Inventory**:人类可定义主机与分组及其 SSH 连接方式;Agent 可列出主机名(不含凭据)。
- **FR2 执行**:Agent 可 `agentssh run <host> -- <cmd>`;CLI 经 SSH 在目标主机执行并返回结果。
- **FR3 Policy(allow/deny)**:每条命令被判定为 `allow`(执行)或 `deny`(硬拦截、不可临场覆盖、headless 亦生效);未匹配默认 `allow`(deny-list 模型),可按主机组改为 allowlist(default deny)。
- **FR4 交互确认(委托)**:AgentSSH 不做同步审批、不阻塞等待人工裁决;灰区命令的交互式 allow/deny 由 agent harness(如 Claude Code 权限系统)负责。
- **FR5 审计**:每次请求(含意图、关联手册、命令、目标、决策、批准人、退出码、输出摘要/hash)写入 hash 链日志;提供查询与校验。
- **FR6 输出控制**:回流给 Agent 的输出按规则脱敏、按上限截断。
- **FR7 手册关联**:`run` 可带 `--skill <name>`,审计据此呈现「意图来自哪本手册」。
- **FR8 能力发现**:Agent 可 `agentssh hosts` 列主机;手册本身由 Agent 的 skill 机制发现。
- **FR9 请求查询**:Agent 可 `agentssh status <req>` 从审计中查询某次执行的结果(退出码/是否被 deny)。
- **FR10 会话分组**:相关的一连串 `run` 归入同一 `session_id`(显式 `--session` / `$AGENTSSH_SESSION` / 空闲 30m 的时间窗口自动);审计可按会话浏览与复盘,会话可带 `session_label`。

## 8. 关键用户故事

- **U1(排障)**:nginx 在 web-1 返 502。Agent 加载 `restart-service` 手册 → `run web-1 -- systemctl status nginx` → 发现挂了 → `run web-1 -- sudo systemctl restart nginx`;该命令未命中 `deny`,harness 弹权限确认、人类同意 → 执行成功 → 全程入审计。人类事后用 `agentssh tui` 复盘。
- **U2(审计回溯)**:人类周一早上 `agentssh tui` 按**会话**(每个任务一组)浏览周末 Agent 的全部操作,展开可疑会话细看,确认没有越界,并校验审计链完整。
- **U3(收紧策略)**:人类把一批明确危险的命令加入 `deny`,并把 `prod` 组切成 allowlist(default deny),只放行白名单内的命令。

## 9. MVP 范围

单一 Go 二进制 + `~/.agentssh/` 配置目录:
- inventory.yaml(主机/分组)、policy.yaml(allow/deny 规则 + 脱敏)、audit.log(JSONL hash 链)
- 凭据走 ssh-agent / 系统 ssh(不自存私钥)
- CLI 动词:`run` / `hosts` / `status`(Agent 面);`tui` / `inventory` / `policy` / `audit`(人类面)
- Policy 硬拦截(`deny`)+ 全量审计 —— **无同步审批**,交互确认交给 harness
- 终端 TUI:纯审计查看器(浏览 + 过滤 + 校验链)
- 随仓库附 1~2 个示例手册

## 10. 成功标准

- S1 Agent 在零凭据下完成 U1 全流程。
- S2 任意命中 `deny` 的命令**永不执行**(headless 下亦然,且不可临场覆盖)。
- S3 审计日志可校验、任何篡改可被检测。
- S4 远端主机无需任何安装即可被纳管。
- S5 一条注入式恶意命令(如日志里诱导的 `rm -rf /`)被 policy `deny` 拦下,且事件留痕。

## 11. 未来(Out of scope,先记着)

**无人值守下的可选 out-of-band 同步审批**、Web 仪表盘、多人与审批路由、MCP server 形态、native SSH(替代 shell-out)、凭据 vault、会话式多步操作的事务/回滚、远端可选 agent 以支持流式与更强隔离。
