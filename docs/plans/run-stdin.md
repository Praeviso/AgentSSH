# `run --stdin-file` — 远端 stdin 输入 · 设计与实现记录

> 状态:已实现 · 起因:实测反馈「往主机写配置文件只能靠 printf 内联,长内容和引号转义都很痛苦;大参数还会撞 Linux `MAX_ARG_STRLEN`(单个 execve 参数 128KiB)」。
>
> 一句话:`agentssh run <host> --stdin-file <path> -- <cmd...>` 把本地文件喂给远端命令的 stdin。内容不进审批存储、不进审计日志——两处都只记 `sha256 + 字节数`;灰区审批强制 exact 匹配、禁止升 host 持久规则,grant 绑定「命令 + stdin 内容哈希」。

## 1. 为什么是 stdin 而不是先做 push/pull

- stdin 天然绕开 `MAX_ARG_STRLEN`:内容走管道,不占 execve 参数。
- 复用现有的一切:policy 引擎照旧只看命令文本;审批、审计、会话完全沿用,零新信任面。
- `--stdin-file nginx.conf -- tee /etc/nginx/nginx.conf` 直接覆盖「写配置文件」这个最高频场景,也顺带解决小文件上传(base64 分块 hack 从此不需要)。
- 真正的 `push/pull`(SFTP + 路径维度策略)仍值得做,但它引入新依赖和新策略形态,单独立项。

## 2. 行为定义

- `run` 新增 `--stdin-file <path>`。文件上限 **32 MiB**(`maxStdinBytes`,`cmd/agentssh/main.go`),超限 usage error(exit 2)。
- 不传该 flag 时行为逐字节同今(远端 stdin 是 /dev/null)。
- 两个传输后端都支持:shell-out(`exec.Cmd.Stdin`)与 native(`ssh.Session.Stdin`)。
- 组 run:同一份内容喂给每个目标 host。

## 3. 安全模型(核心)

stdin 是操作员在审批界面上**看不见的内容**,所以:

1. **审计**:`audit.Record` 新增 `stdin_sha256` / `stdin_bytes`(`,omitempty`,追加在 `canonicalRecord` 字段表**末尾**——旧记录的规范 JSON 逐字节不变,hash 链不回归)。内容本身永不入日志,日志不会被大 payload 灌满。
2. **灰区审批强制收紧**(`internal/approval/authorize.go`):
   - 候选 matcher 强制 `Exact(command)` 且 `Promotable=false`——即使 `host_grant_mode: prefix` 也不放宽,TUI 不提供 `[h]`。
   - **持久 host 审批规则对 stdin run 一律不生效**:host 规则只见过命令文本,不能为任意输入流背书。
3. **grant 绑定内容**:`Grant.StdinSHA256` 参与匹配(`session_store.go`)——同命令换内容、同命令去掉 stdin,都不命中 grant,重新走审批。pending 去重键与 `req_digest` 同步纳入 stdin 哈希(空值时不参与,升级前的旧审批单摘要不变)。
4. **显式 allow 规则对 stdin run 照常生效**:操作员写下 `^tee /etc/nginx/\b` 类 allow 时即视为接受其输入流(命令的参数本就可携带任意内容,这里不额外收紧);要更严可以只依赖审批通道。

## 4. 操作员可见性

- TUI Approvals:KIND 列显示 `stdin`;详情行显示 `stdin <N> bytes sha256=<12位>… — approval binds to this exact content; host-allow unavailable`。
- `run --json` 响应带 `stdin_sha256` / `stdin_bytes`,agent 可自行核对喂进去的内容。

## 5. 测试

- `internal/executor/stdin_test.go`:ExecRunner/streaming 喂 stdin;nil stdin 不阻塞(/dev/null 语义保留)。
- `cmd/agentssh/run_stdin_test.go`:
  - allow 规则 + stdin → 执行、响应/审计带哈希、audit verify 通过;
  - `prefix` 模式下 stdin 审批仍 exact、无 host scope、`approval grant --host` 被拒;
  - grant 绑定内容:换内容 / 去 stdin → exit 7,不搭车;
  - 超限文件 → usage error。

## 6. 已知边界

- 32 MiB 上限是常量,不是 policy 可调项;需要更大传输时应做 `push/pull` 原语而非调大 stdin。
- stdin 内容在本地进程内存中整体读入(为了先算哈希再授权);上限保证了内存可控。
- `policy test` 不感知 stdin(引擎判定只看命令文本,stdin 不改变 allow/deny/needs-approval 三态结论)。
