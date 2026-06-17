# 设计 — 流式输出(native SSH Phase 2a)

> 状态:设计稿 · 2026-06-17 · 关联:PRD §11 #5(native SSH Phase 2)、`docs/architecture/native-ssh.md`、`internal/output`、`internal/executor`
>
> 目标:让 `run` 的输出**边跑边回显**(长命令实时可见),同时**严格保持脱敏/截断/审计语义**。核心是一个**行缓冲的脱敏感知 `StreamWriter`** —— 绝不吐出"半行",使任何 redact 匹配无法跨 chunk 边界泄漏。
>
> 不做:连接复用(ControlMaster,Phase 2b);见 §10。

## 1. 范围与适用条件

流式**仅**在以下条件同时满足时启用,否则**完全走现有缓冲路径(不变)**:
- `!flags.jsonOutput`(`--json` 必须缓冲 —— 它在最后序列化一个完整 runResponse 对象/数组)。
- `len(resolved.Targets) == 1`(单主机;`run <group>` 多主机交错会乱,保持缓冲、按主机分块,与今天一致)。
- executor 实现了流式接口(native + shell-out 都实现)。

两个后端(native `ssh.Session` 与 shell-out `os/exec`)都支持:把它们的 Stdout/Stderr 设成传入的 `io.Writer` 即可增量写出(已核对:两者都用 32KB 缓冲的 `io.Copy` 按 chunk 调用 `Write`,**stdout/stderr 各在独立 goroutine**)。

## 2. StreamWriter(核心:行缓冲脱敏过滤器)

`internal/output` 新增 `StreamWriter`(实现 `io.Writer`):每个流(stdout/stderr)**各一个独立实例**,每个实例只被一个 goroutine 写 → **无需内部锁**;**严禁**把一个实例同时当 stdout 和 stderr(会并发竞争)。

算法:
1. `Write(p)`:把 `p` 追加到 `partial` 行缓冲;循环找 `'\n'`,对每个**完整行**(含结尾 `\n`,`\r` 保留在行内)调用与缓冲路径**同一套** `redactString`(逐行 `FindAllIndex`+`ReplaceAll`),应用累计字节截断后写入内层 `dst`,推进;最后一个 `\n` 之后的尾巴留在 `partial` 等下一 chunk 或 `Flush`。
2. **截断**:维护本流累计 `emitted` 字节数;写某过滤后行前若 `emitted+len > maxBytes`,按 `truncateUTF8` 同样的 UTF-8 安全回退取前缀写出、置 `truncated=true`,之后**停止吐字但继续消费**(`Write` 永远返回 `len(p), nil`,绝不短写/报错 —— 否则会中止 ssh/exec 的 copy goroutine 甚至**背压挂住远端命令**)。
3. **`Flush()`**:在 `session.Wait()`/`cmd.Wait()` 返回**之后**(copy goroutine 已 join)吐出 `partial` 残行(同样脱敏+截断)。**忘记 Flush 会丢掉最后一行无换行的输出 —— 那可能正是一行 secret → 真实泄漏。**
4. 暴露 `Emitted() []byte`(已写出的过滤后字节)、`Redactions() int`、`Truncated() bool`。

### 为什么行缓冲是安全的(且与缓冲路径等价)
Go 正则 `.` 默认不匹配 `\n`、`^/$` 默认锚定整段两端,**对行式 pattern**(`password=\S+`、`AKIA[0-9A-Z]{16}`、单行 PEM `BEGIN` 标记),逐行脱敏与整段脱敏**逐字节、计数都一致**(已实测含 `^secret`、`secret$`、`(?m)$`、贪婪 `a.*b`)。secret 不会跨 `\n`,所以"行不完整就不吐"保证正则总能看到完整匹配窗口 → 不跨 chunk 泄漏。

### 红线:拒绝多行 / `(?s)` redact pattern
唯一会破的是**故意跨行**的 dotall pattern(如多行 PEM 块 `(?s)BEGIN.*END`):整段能脱、逐行脱不掉(实测 1 vs 0)→ **会漏**。处理:**在 `NewFilter` 加载 policy 时检测并拒绝**含 `(?s)` flag 或字面 `\n` 的 redact pattern(报清晰错误,exit 2),保证全局只有一种安全的行式脱敏语义。当前内置 pattern 全是行式,无回归。

### 边界
- **无换行的超长行**:`partial` 达到 `maxLineCap`(如 1MB)时强制当作一行脱敏吐出。**残留风险**(secret 正好骑在 cut 边界可能漏尾)→ 文档说明;cap 取远大于任何合理 secret 长度。
- **CRLF**:按 `\n` 切,`\r` 留在行内(与缓冲路径一致,输出逐字节相同)。
- **UTF-8 跨 chunk**:行缓冲天然解决(半个多字节字符在 `partial` 里拼回,字符必在行内 `\n` 前完整)。

## 3. 与审计哈希/计数保持一致(关键)

`audit.ComputeOutputSHA256(stdout, stderr)` = `sha256(stdout+stderr)` 拼接,顺序 stdout 先 stderr 后。流式下**不要**用两个独立 hasher 合并(`sha(A)`+`sha(B)` ≠ `sha(A+B)`)。做法:两个 `StreamWriter` 各自累积 `Emitted()`,命令结束后 `runDirect` 调 `ComputeOutputSHA256(swOut.Emitted(), swErr.Emitted())` —— **与缓冲路径逐字节相同**。
- 流式的收益是**延迟**(实时回显),不是内存;为算哈希额外留一份 emitted 副本是可接受的。
- 计数语义对齐:缓冲路径是"整段先 redact(连被截断的尾部也计数)再截断"。流式在截断后**仍继续逐行 redact 计数**(只是不吐字),以匹配 `Redactions`。`output_truncated = swOut||swErr`。

## 4. Executor 流式变体

- `internal/executor` 加可选接口:`type StreamingExecutor interface { RunStreaming(ctx, req Request, stdout, stderr io.Writer) Result }`。返回的 `Result` 带 `ExitCode/Duration/Err/Argv`,`Stdout/Stderr` 留空(已流式写出)。
- `NativeExecutor` 实现:`session.Stdout = stdout; session.Stderr = stderr; session.Run(cmd)`(退出码/错误契约与 buffered 完全一致 —— 见 native-ssh.md §6;远端跑了→`Err=nil`、传输失败→`Err≠nil`、`Argv[0]="native-ssh"`)。
- `SSHExecutor`(shell-out)实现:`cmd.Stdout = stdout; cmd.Stderr = stderr`。**必须传非 `*os.File` 的 writer**(StreamWriter 是)——否则 `os/exec` 把 fd 直连文件、跳过 copy goroutine、**绕过脱敏**。
- 现有 `Run`(buffered)**保持不变**,buffered 路径(--json/group)、`fakeExecutor` 照旧。`fakeExecutor` 另实现 `RunStreaming`(把预设输出写进 writer)以便测试流式路径。

## 5. runDirect 集成

信任边界不变:**脱敏仍在 run/output 层**(executor 只透传 writer)。流式分支(满足 §1 条件且 `ssh.(StreamingExecutor)` 成功):
```
swOut := output.NewStreamWriter(cmd.OutOrStdout(), redact, maxBytes, maxLineCap)
swErr := output.NewStreamWriter(cmd.ErrOrStderr(), redact, maxBytes, maxLineCap)
store.Append(started 记录)              // 同今天
result := streamExec.RunStreaming(ctx, req, swOut, swErr)
swOut.Flush(); swErr.Flush()           // Wait 已在 RunStreaming 内返回
outputHash := audit.ComputeOutputSHA256(string(swOut.Emitted()), string(swErr.Emitted()))
redactions := swOut.Redactions()+swErr.Redactions(); truncated := swOut.Truncated()||swErr.Truncated()
store.Append(completed/failed 记录: exit, outputHash, durationMS, {truncated, redactions})
printRunStreamFooter(cmd, host, result, skill)   // 输出已实时打过 → 末尾补 "✓ host · exit N · dur · skill="
mergeExitCode(...)
```
非流式分支:与今天**完全一致**(`outputFilter.Apply` + printRunHuman / json append)。`NewFilter` 既返回 buffered `Filter` 也提供编译好的 `redact`/`maxBytes` 供 StreamWriter 复用(共享同一套编译正则)。

## 6. 安全不变量(不得破坏)

- 跨 chunk / 半行**永不**吐出未脱敏字节(行缓冲保证)。
- 多行 `(?s)` redact pattern 在加载时被拒(不留"逐行脱不掉"的漏洞)。
- 截断后停止吐字但继续 drain(不背压远端、不中止 copy goroutine)。
- `Flush` 必在 `Wait` 之后,确保末行无换行也被脱敏吐出。
- `output_sha256`/`redactions`/`output_truncated` 与缓冲路径一致;policy/session/hash 链/退出码契约不变。
- 每流独立 writer/计数,无共享可变态(stdout/stderr 各自 goroutine)。

## 7. 测试计划

- **行缓冲脱敏等价性**:对一组输入 × 多种 chunk 切分(1/2/3/7/64 字节、跨 secret 边界、跨 UTF-8 字符、CRLF、无换行尾行),断言流式输出与 `Apply` 缓冲结果**逐字节相同**,且 `Redactions`/`Truncated` 相同。
- **跨 chunk 不泄漏**:`password=secret` 被切在 `=` 与 `secret` 之间,断言输出含 `«REDACTED»`、不含 `secret`。
- **截断**:累计 maxBytes(UTF-8 安全),断言前缀正确 + `truncated`,且超限后 Write 仍返回 `len(p),nil`(不阻断)。
- **末行无换行**:不带 `\n` 的尾行含 secret,断言 Flush 后被脱敏(防"忘记 Flush"回归)。
- **多行 pattern 拒绝**:`NewFilter` 给含 `(?s)` 的 redact → 返回错误(经 classifyConfig/usage → exit 2)。
- **审计一致**:流式与缓冲跑同一输出,断言 `output_sha256`/`redactions`/`output_truncated` 一致。
- **端到端**:用进程内 SSH 测试服务器(native)吐多行+含 secret 输出,`run`(单主机、非 json)走流式,断言实时写出 + 审计记录正确;`--json` 与 group 仍走缓冲(回归)。
- M0–M5 + native SSH 全部既有测试仍过;`go test -race`(流式有 goroutine,务必 -race)。

## 8. 不做(Phase 2b / 未来)

跨调用连接复用 / ControlMaster daemon(需常驻进程 + 控制套接字 + 信任边界进 daemon,单列项目);多行 dotall 脱敏(需 bounded 全缓冲回退,当前直接拒绝)。
