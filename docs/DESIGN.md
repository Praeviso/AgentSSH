# DESIGN — AgentSSH UI/UX 规范

> 状态:草案 v1 · 更新于 2026-06-16 · 范围:**仅** UI/UX —— CLI 交互 + 终端 TUI。架构见 `docs/architecture/overview.md`。
>
> 审批模型(已定):AgentSSH **不做同步审批**,交互确认交给 agent harness。故本规范无审批界面;TUI = **纯审计查看器**。`run` 命中 `deny` 即拒,不阻塞、不弹审批。

本项目有两种「界面」:
1. **CLI**:Agent 的「界面」(机器读者优先)。
2. **TUI**:人类的界面(审计查看)。

---

## A. CLI UX

### A.1 设计原则(面向 Agent 的人体工学)

- **自描述**:`agentssh hosts`、`--help` 输出结构清晰,Agent 不必猜。
- **机器友好**:所有读类命令支持 `--json`;默认输出对人也可读。
- **退出码即信号**:Agent 靠 exit code 判断结果,无需解析自然语言。
- **可预测、低惊喜**:同样输入同样输出;错误信息含「下一步怎么办」。
- **不阻塞**:`run` 要么立即执行返回,要么立即被 `deny` 拒绝。没有「等待人工审批」的挂起态。

### A.2 命令参考

#### Agent 面

```
agentssh hosts [--json]
    列出可达主机与分组(仅名字/tag,无凭据)。

agentssh run <host|group> [--session <id>] [--session-label <text>] [--json] -- <cmd…>
    在目标上执行命令。经 policy 判定:
      allow → 立即执行,返回输出与退出码
      deny  → 立即以 exit 6 返回,说明命中的规则
    <cmd…> 在 `--` 之后,原样作为远端单条命令。
    (灰区命令的「是否允许」由 agent harness 在调用前询问人类,与 AgentSSH 无关。)

agentssh status <req_id> [--json]
    从审计中查询某次执行的结果(exit / 是否被 deny)。
```

#### 人类面

```
agentssh tui                 打开审计查看器(主入口)
agentssh inventory ls|edit   查看/编辑主机清单
agentssh policy show|edit|test <cmd>   查看/编辑/试判某命令(allow|deny + 命中规则)
agentssh audit ls|show <req>|verify    浏览/查看/校验审计链
agentssh session ls          列出近期会话(id/label/起止/命令数)
```

### A.3 输出格式

**人类可读(默认)** —— `run` 成功:

```
✓ web-1 · exit 0 · 0.4s
nginx.service - A high performance web server
   Active: active (running) since Mon 2026-06-16 08:32:11 UTC
```

**`--json`** —— 稳定 schema,供 Agent 解析:

```json
{
  "req_id": "a3f2c1",
  "session_id": "s_91be0c",
  "host": "web-1",
  "status": "completed",
  "exit_code": 0,
  "duration_ms": 412,
  "stdout": "nginx.service - A high performance web server\n…",
  "stderr": "",
  "output_truncated": false,
  "redactions": 0
}
```

`run --json` 的顶层形状按用户给出的 target 类型决定:target 命中单个 host 时返回单个对象;target 命中 group 时恒返回数组(即使该 group 当前只匹配 1 台主机),避免输出形状随组内主机数量变化。

### A.4 被 policy 拒绝时 Agent 看到什么

`run` 命中 `deny` 时,**立即**返回(不阻塞),exit 6:

```
✗ denied by policy · web-1 · 命中规则 "catastrophic"
  rm -rf 属于不可执行的危险命令;此拦截无法临场放行。
  如确需放宽,请人类修改 ~/.agentssh/policy.yaml。
```

`--json` 模式返回:

```json
{ "req_id": "f1a0", "host": "web-1", "status": "denied",
  "policy_action": "deny", "policy_rule": "catastrophic", "exit_code": 6 }
```

> 没有「pending / 等待审批」态。Agent 不会被 AgentSSH 挂起;若 harness 在调用前要人工确认,那是 harness 的交互,AgentSSH 此时尚未被调用。

### A.5 退出码约定

| code | 含义 |
|---|---|
| 0 | 命令执行成功(remote exit 0);`audit verify` 链完整 |
| 1 | 命令执行了但 remote 非零退出(详见 stderr/json);`audit verify` 检出断链(非零=校验失败,符合 verify/check 惯例) |
| 2 | 用法错误(参数/未知主机/未知命令/未知 flag),以及**配置类 setup 问题**(`inventory.yaml`/`policy.yaml` 解析失败、policy/output 正则非法、配置目录缺失) |
| 6 | 被 policy `deny` 拒绝(未执行) |
| 9 | 连接/SSH 错误 |

> Agent 据此分流:`6` = 硬边界(别重试同命令,改走手册/换方案);`2` = 用法/配置问题(改输入或让人类修配置,别原样重试);`1/9` = 操作/环境问题(可诊断重试)。
> cobra/pflag 自身的校验错误(未知命令/flag、参数个数不符)也归 `2`。本地配置错误归 `2` 而非 `1`,因为那是 setup 问题不是远端失败。

`run <group>` 涉及多个目标时,整体退出码采用最保守优先级:`deny(6) > ssh_error(9) > remote_failed(1) > success(0)`。也就是说,任一目标被 policy `deny` 时整体返回 6;若无 deny 但有连接/SSH 错误则返回 9;若仅存在远端非零退出则返回 1。

### A.6 错误信息风格

每条错误 = 「发生了什么 + 为什么 + 下一步」。例:

```
✗ unknown host "web-9" (exit 2)
  inventory 中没有该主机。可用: web-1, db-1 或分组 web, prod
  查看全部: agentssh hosts
```

---

## B. TUI 设计(人类审计查看器)

> 注:本节是 TUI 的**原始**草案(Audit 为中心)。`agentssh tui` 现已是四 Tab 操作台(Hosts/Audit/Policy/Sessions),并完成了整体 UX 重构——统一 `internal/theme` 配色 + 字形降级、持久外壳 + `bubbles/help` 底栏、实测响应式布局、Hosts 主从面板、错误/确认卡片、Toast、分组加主机表单等。设计依据、各 Tab 原型与**已实现**的分阶段路线图见 [`docs/plans/tui-redesign.md`](plans/tui-redesign.md)(下文若与该文档冲突,以该文档为准)。

技术:`bubbletea` + `lipgloss` + `bubbles`。**单一视图:审计流,按会话分组**(无审批界面)。`agentssh tui` 即打开它,等价于交互式的 `agentssh audit`。

### B.1 全局布局(按会话折叠)

```
┌ AgentSSH · Audit ────────────────────────── human@local ─ 08:32 ┐
│  42 条 · 8 会话 · 链 ✓ 完整 (1..42)            / 过滤   v 校验     │  ← 顶部状态条
├───────────────────────────────────────────────────────────────────┤
│ ▾ s_91be0c  "fix 502 on web-1"   claude-code  08:31–08:32  4 cmd  │  ← 会话头(展开)
│   08:32:11 ✓ web-1  restart-service  sudo systemctl restart nginx │
│              allow:prod/allow_rules[1] · exit 0 · 412ms           │
│   08:32:05 ✓ web-1  restart-service  systemctl status nginx       │
│              allow · exit 0 · 88ms                                │
│ ▸ s_77a2d1  "disk cleanup db-1"   claude-code  08:20–08:25  6 cmd │  ← 会话头(折叠)
│ ▸ s_3c0f9a  (无标签)             claude-code  07:55–07:58  2 cmd  │
│              其中 1 条 ✗ deny:catastrophic                         │
└───────────────────────────────────────────────────────────────────┘
  enter 展开/折叠会话 · l 会话详情 · v 校验链 · / 过滤 · j/k 移动 · q 退出
```

- 顶层按**会话**倒序;会话头单行显示 `id · label · host(user@ip)`,有篡改时附一段异常提示。
- 展开后是该会话内的 run,时间倒序;状态图标:`✓` 成功 · `✗` 失败 · `⊘` 拒绝(policy deny)· `●` 执行中。
- 每行一眼看全:**时间 · 状态 · 主机(prod 加红角标) · 手册 · 真实命令 · policy 判定 · exit/耗时**。
- 危险/拒绝用红、prod 主机加红色 `prod` 角标、含异常的会话头标红;颜色仅作强调,信息不只靠颜色(同时有文字)。

### B.2 详情面板

选中行 `enter` 展开单条完整记录:

```
┌ Record seq 42 · req a3f2c1 ──────────────────────────────────────┐
│ 时间     2026-06-16 08:32:11Z                                     │
│ Session  s_91be0c "fix 502"    Host   web-1 (deploy@10.0.0.11)    │
│ Tags     web, prod                                                │
│ Command  sudo systemctl restart nginx                             │
│ Policy   allow ← prod/allow_rules[1]                              │
│ Exit     0 · 412ms · truncated false · redactions 0              │
│ Output   sha256 9f2b…(原文不入审计)                              │
│ Chain    prev 00ab…  hash 7d41…                                  │
└───────────────────────────────────────────────────────────────────┘
  esc 返回
```

- 给出 **policy 判定理由**(命中哪条规则),让人类信任分级。
- 只展示输出 `sha256`,不展示原文(架构 §6:原文不二次落盘)。
- M3 实现:Exit 行为 `exit · 时长(duration_ms)· truncated · redactions`,`Output sha256` 单独成行;输出体积(KB)尚未存储,留待 M4 输出处理。

### B.3 校验与过滤

- `v` 触发 `audit verify`:**顶部状态条**显示 `链 ✓ 完整 (0..N-1)`(seq 0 基)或 `链 ✗ 断于 seq=K · <原因>`。验证在任意焦点(列表/详情)下都可触发。
- `/` 进入过滤(顶部状态条显示当前 filter)。语法 = 自由文本 + 可选维度前缀,空格分隔、多条件 AND:
  - `host:<substr>`、`session:<substr>`(匹配 id 或 label)
  - `status:<allow|deny>`(匹配 policy_action)或 `status:<started|completed|failed|denied>`(匹配事件)
  - `date:<YYYY-MM-DD>`(按 ts 前缀做时间筛选)
  - 其余裸词为自由文本,在 host/session/cmd/状态/ts/policy/req 各字段做子串匹配
  - 实时生效;`enter` 提交并回列表(保留过滤),`esc` 取消并还原进入过滤前的查询。
- `l` 进/出会话焦点:只看选中会话的全部 run + 会话元数据(`(no session)` 合成组不可焦点)。

### B.4 键位总表

| 键 | 作用 |
|---|---|
| `j` `k` / ↑↓ | 上下移动 |
| `enter` / `space` | 会话头:展开/折叠;run 行:看记录详情 |
| `d` | 看选中 run 的记录详情(`enter` 的别名);详情面板内再按一次返回 |
| `l` | 进/出选中会话焦点 |
| `/` | 过滤(语法见 §B.3) |
| `v` | 校验审计链(任意焦点可用) |
| `esc` | 详情返回 / 取消过滤 / 退出会话焦点 |
| `q` · `ctrl+c` | 退出 |

### B.5 可访问性 / 降级

- 所有状态都有文字标签,不依赖颜色单独传达信息。
- `NO_COLOR` 环境变量 → 纯文本无色渲染。
- 非 TTY 环境下 `tui` 拒绝启动并提示改用 `agentssh audit ls|show|verify`(纯命令式审计,功能等价)。
