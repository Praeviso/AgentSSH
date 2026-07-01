# 架构总览 — AgentSSH

> 状态:草案 v1 · 更新于 2026-06-16 · 配套:`docs/prds/agentssh.md`
>
> 审批模型:硬 `deny` 不可覆盖 + 全量审计始终是底线。在此之上提供**可选(默认关)的异步审批**——灰区(`default-deny`)命令可由 agent 申请,`run` 返回 exit 7 **不阻塞**,操作者在 TUI(或 `agentssh approval` CLI)裁决 once/session/host。**不做同步阻塞审批**。详见 §5 与 `docs/plans/approval-system.md`。

## 1. 组件总览

```
┌──────────────────────────────────────────────────────────────────┐
│  AI Agent (Claude Code 等)                                         │
│    读外部操作手册 → 调用 agentssh CLI                                │
│    [灰区命令的交互式 allow/deny 由 harness 在此层处理]              │
└───────────────────────────────┬──────────────────────────────────┘
                                 │  进程边界(argv + stdout/stderr + exit code)
┌────────────────────────────────▼─────────────────────────────────┐
│  agentssh (Go 单二进制) —— 信任边界                                 │
│                                                                    │
│   ┌──────────┐   ┌──────────┐   ┌──────────────┐                  │
│   │ CLI 解析  │──>│ Resolver │──>│ Policy Engine │                  │
│   │ (cobra)  │   │(inventory│   │ allow / deny  │                  │
│   └──────────┘   │ 主机解析) │   └──────┬───────┘                  │
│                  └──────────┘     deny  │ allow                    │
│                           拒绝(exit 6)◀─┤                          │
│        ┌─────────────────────────────────▼───────────────────┐   │
│        │ Executor (SSH)  ──>  Output Filter(脱敏+截断)        │   │
│        └──────────────────────────┬──────────────────────────┘   │
│                                    │ 全程写                        │
│        ┌───────────────────────────▼─────────────────────────┐  │
│        │ Audit (append-only JSONL, hash 链)                    │  │
│        └───────────────────────────────────────────────────--┘  │
│   ┌──────────┐                                                    │
│   │ TUI       │  人类面:**纯审计查看器**(读 Audit:浏览/过滤/校验) │
│   └──────────┘                                                    │
└───────────────────────────────┬──────────────────────────────────┘
                                 │ 标准 SSH(复用 ssh-agent / ~/.ssh/config)
                                 ▼
                          目标服务器(零安装)
```

各组件职责:
- **CLI 解析**:动词路由、参数校验。Agent 面与人类面共用一个二进制,不同子命令。
- **Resolver**:把 `<host>` / 分组名解析为 inventory 中的连接信息;**凭据引用永不回传 Agent**。
- **Policy Engine**:对「主机 + 命令」判定 `allow | deny`。`deny` 直接拒绝;`allow` 放行执行。
- **Executor**:经 SSH 执行,捕获 stdout/stderr/exit。
- **Output Filter**:回流给 Agent 前脱敏 + 截断。
- **Audit**:每次请求落 hash 链日志(allow 与 deny 都记)。
- **TUI**:人类的**审计查看 + 灰区审批裁决**界面(详见 `docs/DESIGN.md` 与 `docs/plans/approval-system.md`)。

> 注:同步审批(pending 队列、阻塞 run、人工裁决)**不在本架构内**。它属于 agent harness 的职责;AgentSSH 的安全底线是 resource-side 的 `deny` + 事后审计。理由见 §5。

## 2. 信任边界 / 双主体

- **进程边界即信任边界**:Agent 与 CLI 之间只有 argv / stdout / stderr / exit code。Agent 拿不到 CLI 的内存、配置、凭据。
- **凭据单向**:凭据只从 CLI → SSH → 服务器流动,**绝不**进入返回给 Agent 的任何字节。
- **两层控制**:手册(软,塑造行为)+ CLI policy `deny`(硬,强制底线)。安全只依赖硬控制。
- **harness 在 Agent 一侧**:harness 的交互审批是便利层,不是信任边界 —— headless / 自动批准 / allowlist 疲劳下会失效。因此**唯一不可委托给 harness 的就是 `deny` 硬拦截**。

## 3. 配置与数据模型

配置根:`~/.agentssh/`(可用 `$AGENTSSH_HOME` 覆盖)。

### 3.1 inventory.yaml

```yaml
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    port: 22
    ssh_config_alias: web-1     # 若设置,直接用 ~/.ssh/config 里的别名
    tags: [web, prod]
  db-1:
    addr: 10.0.0.21
    user: deploy
    tags: [db, prod]
groups:
  web:   { tags: [web] }
  prod:  { tags: [prod] }
```

设计要点:
- **不在此存私钥/口令**。认证走 ssh-agent 或 `~/.ssh/config`(`IdentityFile`、`ProxyJump` 等自然复用)。
- 分组用 tag 表达,便于 policy 按组施策。
- `groups.<name>.tags` 为 **AND** 语义:主机必须包含该 group 列出的全部 tag 才入组。

### 3.2 policy.yaml

```yaml
version: 1
rules:                     # 全局规则;priority 越大越先判定,同 priority 按文件顺序
  - name: catastrophic
    priority: 100
    match: { cmd_regex: '\b(rm\s+-rf|mkfs|dd|shutdown|reboot|init\s+0|userdel|:\(\)\s*\{)' }
    action: deny
  - name: readonly
    priority: 0
    match: { cmd_regex: '^(systemctl status|journalctl|tail|cat|df|ps)\b' }
    action: allow
host_overrides:
  prod:                    # 组规则;命中 prod tag 的 host 进入 host tier
    rules:
      - priority: 50
        match: { cmd_regex: '^sudo systemctl (restart|reload) [a-z0-9-]+$' }
        action: allow
  host:web-1:              # 单台 host 规则;由 `policy host rule ...` / TUI 管理
    rules:
      - priority: 10
        match: { cmd_regex: '^systemctl status\b' }
        action: allow
rule_groups:               # 可复用预设;仅用于编辑/复制,引擎不直接读取
  readonly:
    rules:
      - priority: 10
        match: { cmd_regex: '^(uptime|whoami)\b' }
        action: allow
output:
  max_bytes: 16384
  redact:                  # 命中即替换为 «REDACTED»
    - 'AKIA[0-9A-Z]{16}'                        # AWS access key
    - '-----BEGIN[^-]+PRIVATE KEY-----'         # PEM 私钥块
    - '(?i)(password|passwd|secret|token)\s*[=:]\s*\S+'
```

`host_overrides` 支持两类 key:`<group>` 按 inventory group/tag 匹配,`host:<name>` 只匹配该 host。`agentssh policy host rule ...` 和 TUI 的 Host detail Policy pane 只写 `host:<name>` host rules,不修改 inventory 的 tags/groups。

`rule_groups` 是**编排/编辑层**概念,不是执行层概念。Policy Engine 完全忽略 `rule_groups`,也忽略 `Rule.group` 字段;只有当人类执行 `agentssh policy host rule add <host> --from-group <name>` 或在 TUI Host detail Policy pane 里选择预设时,该组当前的 rules 会被**快照复制**到 `host_overrides["host:<name>"].rules`。复制出的每条 rule 带 `group: <name>` provenance,用于 UI/CLI 展示和 `policy host group rm <host> <name>` 批量移除。之后编辑 rule group 不会自动传播到已经 stamp 到 host 的副本。

判定规则(二层、首个命中生效):
1. 先取 host tier: `host_overrides["host:<name>"].rules` 加上该 host 按 tag 命中的所有 group 规则,合并后按 `priority` 降序判定;同 priority 按文件顺序。host tier 永远高于 global tier,所以 host 上 `priority: 0` 的 allow 也能覆盖 global 里 `priority: 100` 的 deny。
2. 再取 global tier:全局 `rules` 按 `priority` 降序判定;同 priority 按文件顺序。
3. 两层都未命中 → `deny`。这是不可配置的最终兜底,不再有 `defaults.policy`。
4. `deny` 一律拒绝,**不弹任何「是否允许」**(连人都不能临场覆盖,防 Agent 诱导疲劳的人放行)。需放宽只能添加/修改 allow 规则。

> 设计取舍:default=`deny` 把执行能力变成显式授权:开箱即拒绝所有命令,直到人类写入 allow 规则。硬安全底线不再只是 deny 黑名单,而是「无匹配即拒绝」;host tier 先于 global tier,便于给单台机器或某组机器写更具体的例外。
>
> 局限:基于命令字符串的匹配是启发式,不是沙箱;复合命令(`sh -c '…'`、管道)可能绕过模式。缓解见 `docs/plans/mvp.md` R1。

TUI 展示规则与引擎顺序保持一致:Host detail 的 Policy pane 是一张无边框统一列表,先列所有 host-tier 规则(`host:<name>` 与命中的 inventory group override,按 priority 降序),再列 global 规则。列包含 `scope / priority / action / command / group`;global 行在这里只读,用于让人类看到上下文而不在 host 详情里误改全局策略。

## 4. 命令生命周期(`run`)

```
run web-1 -- sudo systemctl restart nginx
  │
  1. 解析 host → inventory(web-1: deploy@10.0.0.11, 组=[web,prod])
  2. Policy 判定命令 → allow / deny
  3a. deny  → 写 audit(denied,未执行)→ 返回 exit 6,结束
  3b. allow → 写 audit(started)→ Executor 经 SSH 执行
  4. 捕获 stdout/stderr/exit → Output Filter 脱敏+截断
  5. 写 audit(completed:exit、输出 hash、截断标记、脱敏命中数)
  6. 把过滤后的输出 + exit 透传回 Agent
```

> 灰区命令的「是否允许」由 harness 在第 0 步(Agent 发起调用时)拦下并询问人类;AgentSSH 收到调用时只做 allow/deny + 执行 + 审计,不阻塞等待人工。

## 5. 为什么不在 AgentSSH 内做同步审批

把「审批」拆成两件事:
- **交互式确认**(人盯着 allow/deny):与 agent harness 的权限系统**重复**。harness 已拦截 Bash 调用、看得到完整 `agentssh run … -- <cmd>`。再造一套 TUI 审批 = 双重弹窗。→ **委托给 harness。**
- **硬边界 `deny`**(谁都不能临场放行):**不可委托**。harness 在 Agent 侧信任边界内,在 headless / 自动批准 / `agentssh run:*` 被加白名单时全部失效;且 harness 只看到命令字符串,不知道目标是 prod、不知道命中了哪条危险规则。→ **留在 CLI,做成不可覆盖的 deny。**

决策前提:**主要交互式、人盯着**(见 PRD)。灰区(`default-deny`)的可选人工裁决**已实现为异步、非阻塞模式**(默认关,`approval.enabled` / `AGENTSSH_APPROVAL` 开启):pending 请求落 `~/.agentssh/approvals/`,`run` **立即返回 exit 7 不阻塞**,操作者在 TUI 的 Approvals 标签(或 `agentssh approval` CLI)裁决 once/session/host,模型轮询 `approval status/wait` 或重跑后继续。硬 `deny` 仍不可覆盖,显式 deny 规则结构上进不了审批通道。详见 `docs/plans/approval-system.md`。

## 6. 审计日志

`~/.agentssh/audit.log`,**append-only JSONL**,每行一条记录,hash 链防篡改。

记录结构:

```json
{
  "seq": 42,
  "ts": "2026-06-16T08:32:11Z",
  "req_id": "a3f2c1",
  "session_id": "s_91be0c",
  "session_label": "fix 502 on web-1",
  "event": "completed",
  "host": "web-1",
  "cmd": "sudo systemctl restart nginx",
  "policy_action": "allow",
  "policy_rule": "prod/rules[0]",
  "error": "",
  "exit_code": 0,
  "output_sha256": "9f2b…",
  "output_truncated": false,
  "redactions": 0,
  "prev_hash": "00ab…",
  "hash": "7d41…"
}
```

- `event` ∈ `started | completed | failed | denied`。`deny` 记一条 `denied`(无 exit_code)。
- `error` 是可选的人类可读异常说明,主要用于本地管理操作的失败记录;常规 `run` 记录为空。
- harness 的交互审批不由 AgentSSH 记录(在 harness 自己的日志里);AgentSSH 只记自己看到与执行的事实。
- hash 链:`hash = SHA256(prev_hash || canonical_json(record_without_hash))`。第 0 条 `prev_hash` 全零。`agentssh audit verify` 从头重算,任一行被改/删/插都会断链。
- 修复只允许 `agentssh audit repair --truncate-broken`:从第一条断链记录开始截断到文件末尾,并先写 `audit.log.bak`。不支持任意删除单条审计记录。

设计取舍:
- 记录 `output_sha256` 而非全文,避免审计膨胀并防敏感输出二次落盘;需要时可单独开「完整输出归档」选项。
- 仅追加、不修改,符合「人类事后审计」的核心诉求。

### 6.1 会话(session)分组

目的:把 Agent 完成一个任务期间的一连串 `run` 归到同一会话,便于人类按「任务」复盘,而非看孤立命令。

会话 = `session_id`(+ 可空 `session_label`)。每条 audit 记录都带 `session_id`。

**会话由调用方显式声明,系统不猜任务边界。** AgentSSH 无法从命令或时间推断「一个任务从哪里开始、到哪里结束」,所以不做任何基于时间窗口的自动归并——否则同一主机上几分钟内的两个不相干任务会被并进同一个会话,破坏「按任务复盘」。

`session_id` 解析顺序(首个非空命中):
1. `agentssh run --session <id>` 显式指定 —— 单次 run 覆盖,优先级最高。
2. 环境变量 `$AGENTSSH_SESSION` —— harness/skill 在任务开始时设一次,该任务内所有 `run` 继承。
3. 两者都没有 → **报错(exit 2)**,提示声明一个会话。绝不新建或复用一个「猜」出来的 id。

约定:**一个任务一个会话**。skill/harness 在每个任务起始 mint 一个新 id 并导出:

```bash
export AGENTSSH_SESSION=$(agentssh session new)   # 形如 s_1a2b3c4d
```

`agentssh session new` 只是打印一个新随机 id(`internal/session.NewID`),不落任何状态。下一个任务再 mint 一个新的,天然区分。

`--session-label "fix 502 on web-1"` 可给会话一个人类可读标签(首次出现时记入会话元数据,贯穿后续记录)。

> 设计取舍:旧版有个「读 `~/.agentssh/session`、30 分钟空闲窗内复用」的回退,已移除——它在多任务/多 Agent 下会把不同任务串成一个会话,且那个指针文件并发下会写串。现在会话纯由调用方声明,无持久化状态,严格隔离是默认行为。

## 7. 凭据处理

- MVP 不自管私钥:Executor **shell-out 到系统 `ssh`**,自然复用 ssh-agent、`~/.ssh/config`、`known_hosts`、`ProxyJump`。
- CLI 进程内不缓存明文私钥;Agent 侧完全接触不到认证材料。
- 未来若需口令/Token,引入 OS keychain(`go-keyring`),仍不回传 Agent。

## 8. 输出脱敏与回流控制

回流是被忽视的攻击面:服务器输出会进入 Agent 的 context(既可能含密钥,也可能含注入文本)。Output Filter 在返回前:
1. 按 `policy.output.redact` 正则替换敏感片段为 `«REDACTED»`;
2. 超过 `max_bytes` 截断并标 `output_truncated`;
3. 在 audit 记录脱敏命中数与截断标记(可观测,不记原文)。

## 9. SSH 执行器

- MVP:构造受控 argv,`exec` 系统 `ssh`(命令由 CLI 生成,Agent 不能注入额外 argv —— 命令体经 SSH 在远端单条执行,参数不做本地 shell 二次拼接)。
- 注入防护:目标主机来自 inventory(枚举,不接受任意 host 字符串直连未知机);命令体作为单一参数传给远端,由 policy 判定其内容。
- 未来:可切到 `golang.org/x/crypto/ssh` 获得连接复用、流式输出、更细的会话控制。

## 10. 包结构(Go)

```
agentssh/
  cmd/agentssh/            # main:cobra 根命令,装配各子命令
  internal/
    config/                # ~/.agentssh 载入、$AGENTSSH_HOME
    inventory/             # 主机/分组解析
    policy/                # 规则匹配、allow/deny、override、脱敏
    executor/              # SSH shell-out、捕获 stdout/stderr/exit
    audit/                 # JSONL 写入、hash 链、verify
    session/               # 会话解析(--session / env,必须声明)、id 生成、聚合
    output/                # 脱敏 + 截断
    tui/                   # bubbletea:审计查看器
    approval/              # 灰区异步审批:Generalize/Authorize/grant store/裁决(默认关)
  skills/                  # AgentSSH 使用手册(SKILL.md):最佳实践,供 Agent 参考
  docs/
```

依赖(建议):`cobra`(CLI)、`gopkg.in/yaml.v3`(配置)、`charmbracelet/bubbletea`+`lipgloss`+`bubbles`(TUI)。审计/policy/executor 尽量用标准库。

## 11. 威胁 → 缓解 映射

| 威胁 | 组件 | 缓解 |
|---|---|---|
| 注入诱导破坏性命令 | Policy(deny) | 危险模式 `deny` 硬拦截,谁都不能临场覆盖;headless 亦生效 |
| 灰区命令的临场判断 | harness | 交互式 allow/deny 委托给 harness(人盯着时) |
| 凭据泄漏 | Executor + 边界 | 凭据只在 CLI/ssh-agent,不入回流字节 |
| 敏感输出进模型 | Output Filter | 脱敏 + 截断,审计只存 hash |
| 事后无法追责/抵赖 | Audit | hash 链 append-only,`verify` 可验完整性 |
| 越权访问未知主机 | Resolver | 仅允许 inventory 中枚举的主机/分组 |
| prod 上误操作 | Policy override | `prod` 组添加更具体的 allow/deny 规则;未匹配默认拒绝 |
