# 设计 — Native SSH 传输(替代 shell-out)

> 状态:设计稿 · 2026-06-17 · 关联:PRD §11(未来增强 #5)、架构 §7/§9(凭据/执行器)、`internal/executor`
>
> 目标:给 executor 增加一个**原生 Go SSH 后端**(`golang.org/x/crypto/ssh`),作为系统 `ssh` shell-out 的**可选替代**,去掉对外部 `ssh` 二进制的依赖,并为后续的流式输出 / 连接复用打基础。**严格保持现有安全语义**(host key 校验、输出脱敏、hash 链审计、退出码契约)。

## 1. 范围

**Phase 1(本次实现)**:
- 原生 SSH 后端:拨号 + ssh-agent/密钥认证 + **known_hosts 主机密钥校验** + 单命令缓冲执行 + ProxyJump。
- **可选传输切换**(默认仍走 shell-out `ssh`,native 显式开启)。
- `ssh_config` 别名解析(`ssh_config_alias` 设置时)。
- **drop-in**:实现 `executor.Executor`,返回相同的 `executor.Result`,使 policy/audit/output/tui/退出码**全部不变**。
- 进程内 SSH 测试服务器做真实 E2E 测试。

**Phase 2(本次不做,文档记录)**:
- **流式输出**:与输出脱敏冲突(脱敏需看到完整输出才能安全替换/截断),需要"脱敏感知的增量过滤器"才能边跑边回,留待专门设计。
- **跨调用连接复用**(类似 ssh ControlMaster):需要常驻控制套接字/daemon,超出本次。Phase 1 在单次 `run`(对 group 多目标时)每目标各拨号一次。

## 2. 传输选择

- 选择来源(优先级):环境变量 `AGENTSSH_TRANSPORT`(`ssh` | `native`)> inventory.yaml 顶层 `transport:` 字段 > 默认 `ssh`。
- **默认 `ssh`(shell-out)不变**,native 为显式 opt-in;待成熟后未来版本再考虑翻默认。
- 落点(见 seam):把 `cmd/agentssh/main.go` 的 `newExecutor` 改为接收 `*config.Config` 并据 transport 返回 `executor.NewSSHExecutor(nil)` 或 `executor.NewNativeExecutor(...)`。`runDirect` 的单一调用点(`ssh := newExecutor(cfg)`)不变;测试仍可整体替换 `newExecutor` 注入 fake(需同步更新 `main_test.go`/`m5_test.go` 的签名)。

## 3. 包结构

- 新增 `internal/executor/native.go`:`NativeExecutor`(实现 `executor.Executor`)+ 连接/认证/host key/exec/ProxyJump 逻辑。
- 新增 `internal/sshconf/`(或 `internal/executor` 内):用 `kevinburke/ssh_config` 把 inventory host 解析成 `resolvedTarget{hostname, port, user, identityFiles, proxyJump}`。
- shell-out 路径(`SSHExecutor`/`ExecRunner`/`BuildSSHArgv`)**保持不变**。

## 4. 连接建立

- **拨号超时**:`ClientConfig.Timeout` 只约束 TCP connect。需要对握手设硬上限时,用自带 `net.Dialer.DialContext` + `conn.SetDeadline`,再 `ssh.NewClientConn`,握手后 `conn.SetDeadline(time.Time{})` 清除。
- **认证**(顺序:agent 优先,再密钥文件):
  - ssh-agent:读 `SSH_AUTH_SOCK` → `net.Dial("unix", sock)` → `agent.NewClient(conn)` → `ssh.PublicKeysCallback(ag.Signers)`(惰性,认证时查询);agent 的 unix conn 在 Dial 完成后再关。
  - 密钥文件:`ssh.ParsePrivateKey`;遇 `*ssh.PassphraseMissingError` 用 `ParsePrivateKeyWithPassphrase`(用 `golang.org/x/term` 无回显读口令)。`~` 需自行展开。
  - Phase 1 以 **agent 为主**;无 agent 时回退标准 `~/.ssh/id_*` 与 ssh_config 的 IdentityFile(best-effort,缺失不致命)。
- **主机密钥校验(安全关键)**:`knownhosts.New(~/.ssh/known_hosts)` 作 `HostKeyCallback`。
  - 默认 **strict**:回调报错即拒。
  - 可选 **accept-new / TOFU**(配置 `host_key_policy: strict|accept-new`,默认 strict):`errors.As` 到 `*knownhosts.KeyError`,`len(Want)==0`(未知主机)→ `knownhosts.Line` 追加并接受;`len(Want)>0`(**密钥变更,疑似 MITM**)→ **拒绝**;`*knownhosts.RevokedError` → 拒绝。
  - 注意:无 `IsHostKeyChanged` 辅助函数;只能靠 `KeyError.Want` 长度区分。`known_hosts` 文件不存在时 `knownhosts.New` 会报错 → 首次运行前确保存在(建 0600 空文件,目录 0700)。追加要加锁(回调可能并发)。
  - **禁止** `ssh.InsecureIgnoreHostKey()` 进生产路径(仅限显式负向测试)。
- **ProxyJump**:拨 jump → `jumpClient.DialContext(ctx, "tcp", target)` 得隧道 `net.Conn` → `ssh.NewClientConn(tunnel, target.Addr, targetCfg)`(**用 target 自己的 HostKeyCallback 校验 target**,不是 jump 的)→ `ssh.NewClient`。支持逗号分隔多跳;`ProxyJump none` 表示直连。关闭顺序:target client → 隧道 → jump client。

## 5. ssh_config 解析

- 用 `github.com/kevinburke/ssh_config` v1.6.0(不要手写子集 —— Host 模式匹配/Include/默认值语义易错)。
- 当 `ssh_config_alias` **设置**:用 `*Strict` 变体解析 `HostName/User/Port`(标量)与 `IdentityFile`(`GetAllStrict`);`ProxyJump` 取原始串自行拨链。`HostName` 缺省时用 alias 本身作 hostname。**纯从 config 解析,不把 inventory 的 addr/user/port 叠加上去**(与 `ssh <alias>` 行为一致)。
- 当 `ssh_config_alias` **未设置**:直接用 inventory 的 `addr/user/port`(port 缺省 22,user 缺省本地 `$USER`)。
- 坑:库**不展开 `~`**(IdentityFile 路径要自己展开);`IdentityFile` 默认值不全(只回 `~/.ssh/identity`)→ 优先靠 agent;`SupportsMultiple` 有 bug 别用,直接 `GetAllStrict`;`Match exec` 之外的 Match 会报错 → 决定是 surface 还是 `IgnoreErrors`(建议 surface 以保证与 shell-out 的行为一致性,文档说明)。

## 6. 退出码 / 错误契约(**最关键 —— 决定 drop-in 是否正确**)

现有 `isSSHErrorResult`(main.go)判定:`Err != nil && !IsProcessExit(result)` **或** `Argv[0]=="ssh" && ExitCode==255`。`IsProcessExit` 为真 ⟺ `Err==nil` 或 `Err` 包了 `*exec.ExitError`。native 没有 `*exec.ExitError`,因此必须按下表设置 `Result`,否则远端非零退出会被误判成 exit 9:

| 情形 | ExitCode | Err | Argv[0] | 经现有逻辑得到 |
|---|---|---|---|---|
| 远端成功 | 0 | **nil** | 非 `"ssh"`(如 `"native-ssh"`) | exit 0 / completed |
| 远端非零退出(`*ssh.ExitError`) | `ExitStatus()` | **nil** | 非 `"ssh"` | exit 1 / failed |
| 远端被信号杀(`Signal()!=""`) | 非 0(如 128+sig 或 -1) | **nil** | 非 `"ssh"` | exit 1 / failed |
| 连接/认证/host key/隧道失败 | -1 | **非 nil(原始错误)** | 任意 | exit 9 / ssh_error |
| `*ssh.ExitMissingError`(远端没发 exit-status) | -1 | **非 nil** | 任意 | exit 9 / ssh_error |

要点:
- **远端确实跑了命令**(无论退出码)→ `Err=nil`,退出码放 `ExitCode`。这样 `IsProcessExit==true`,不会被当 ssh_error。
- **传输层失败** → `Err` 非 nil(任意 error 类型,只要不是 `*exec.ExitError`)→ `IsProcessExit==false` → ssh_error/exit 9。
- **`Argv[0]` 不能是 `"ssh"`**(用 `"native-ssh"` 之类),否则远端合法返回 255 会被 255 启发式误判成连接错。native 用 `Err` 而非 255 技巧来表达连接失败。
- `Result.Argv` 仅用于该启发式(其余只读 `Argv[0]`);填 `["native-ssh", user@host, cmd]` 便于审计可读且避开误判。
- `Stdout/Stderr/Duration` 语义与 shell-out 一致(原始输出交给 output.Filter 脱敏+截断;Duration 用 `time.Since(start)`)。

## 7. 安全不变量(不得破坏)

- 输出**仍先脱敏+截断再回流**(native 只产出原始 `Result.Stdout/Stderr`,过滤在 `runDirect` 不变)。
- 审计 hash 链、`output_sha256`(对过滤后字节)、session、policy 分级**完全不变**。
- 凭据**绝不回流 Agent**(agent/密钥只在 executor 内用)。
- host key 严格校验是 native 的硬要求(shell-out 靠系统 ssh + known_hosts;native 必须自己做到等价)。

## 8. 依赖

- `golang.org/x/crypto`(`ssh`、`ssh/agent`、`ssh/knownhosts`)—— `go get golang.org/x/crypto/ssh@latest`。
- `github.com/kevinburke/ssh_config` v1.6.0。
- `golang.org/x/term` 已在 go.mod(用于读口令)。
- 注意:x/crypto 升级可能上抬 `golang.org/x/text` → `go mod tidy`。

## 9. 测试计划

- **进程内 SSH 测试服务器**(`golang.org/x/crypto/ssh` + ed25519 临时 host key,监听 `127.0.0.1:0`):
  - exec 成功 + 退出码 0;远端非零(如 7)→ 断言映射到 `ExitCode==7`、`Err==nil`、`exitCodeForResult==1`。
  - **host key 拒绝**:known_hosts 写入"错误"的 key → Dial 失败 → 断言 `Result.Err!=nil`、`isSSHErrorResult==true`、exit 9。
  - 信任路径:`knownhosts.Line` 写正确 key → 成功。
  - 注意:exit-status payload 是裸 4 字节大端 uint32(`ssh.Marshal(struct{Status uint32}{code})`);必发 exit-status 再 `ch.Close()`;`go ssh.DiscardRequests`;`AddHostKey`;goroutine 用 WaitGroup 收(`ln.Close()` 在 `wg.Wait()` 前);`-race` 跑。
- **退出码契约测试**:构造各类 `Result`,断言经现有 `isSSHErrorResult`/`exitCodeForResult`/`statusForResult` 得到 0/1/9 与上表一致。
- **ssh_config 解析单测**:`UserSettings.ConfigFinder` 指向 fixture 配置,断言 alias → hostname/port/user/identityfile/proxyjump 解析正确;`~` 展开。
- **传输选择测试**:`AGENTSSH_TRANSPORT=native` 时 `newExecutor(cfg)` 返回 native 后端(可用一个不实际拨号的小断言,如类型断言)。
- 不破坏现有:M0–M5 全部测试仍过。

## 10. 不做(Phase 2 / 未来)

流式输出(需脱敏感知增量过滤)、跨调用连接池/ControlMaster、percent-token(`%h/%p/%r`)展开、完整 `Match` 块支持。
