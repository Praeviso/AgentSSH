# 设计 — SSH 认证包装:服务发现 + 凭据登记

> 状态:**设计中**(未实现)· 2026-06-18 · 关联:`docs/architecture/native-ssh.md`、`internal/executor/native.go`、`internal/inventory`、`cmd/agentssh`、统一 TUI(`internal/tui`)
>
> 目标:在已经默认走 native SSH 的基础上,给"把一台服务接入 AgentSSH"做一层包装。两个能力:**(1) 识别本机已经能直连的服务**(从 `~/.ssh/config`/`known_hosts` 发现,可选真连探测),**(2) 登记未认证服务的连接凭据**(per-host 私钥文件 + 远端登录密码,密码加密落盘)。AgentSSH **只做客户端侧**——不碰远端 `authorized_keys`,远端由用户自己负责,连接失败时给可操作的提示。

## 0. 决策(已与用户确认)

| 维度 | 决策 |
| --- | --- |
| 凭据类型 | **私钥 + 远端密码都支持**(私钥首选,密码兜底) |
| 密码存储 | **加密存配置**(独立 `secrets.enc`,绝不进 `inventory.yaml`) |
| 发现方式 | **静态列举 + 可选 `--probe` 真连探测** |
| 入口 | **CLI + 统一 TUI 都做** |
| 远端管理 | **不做**。不 ssh-copy-id、不改远端;失败只提示 |

## 1. 范围

**做:**
- `inventory.Host` 增加 `identity_file`(指向私钥文件的路径,非秘密)。
- native 认证链补上:per-host 私钥 + 远端密码(`ssh.Password`)。
- 加密的密码库 `internal/secrets`(age 口令加密),`secret set/ls/rm` 管理(只暴露 host 名,永不回显密码)。
- `inventory discover [--probe]`:发现可直连/待认证服务,可导入。
- `inventory test <host>`:显式连通性自检 + 错误提示。
- 错误分类器:`run`/`discover --probe`/`test`/`add` 失败时给可操作建议。
- 统一 TUI:Hosts 区加 Discover / Import / Test 动作,add 表单加 identity_file + 密码字段。

**不做:**
- 远端侧任何操作(装公钥、改 sshd、建用户)。
- 凭据明文落盘;密码进 inventory;密码进审计/输出/日志。
- 反解 `known_hosts` 里的 hashed(`|1|…`)条目(不可逆,只能跳过并标注)。

## 2. 数据模型变更(`internal/inventory/inventory.go`)

```go
type Host struct {
	Addr           string   `yaml:"addr,omitempty"`
	User           string   `yaml:"user,omitempty"`
	Port           int      `yaml:"port,omitempty"`
	SSHConfigAlias string   `yaml:"ssh_config_alias,omitempty"`
	IdentityFile   string   `yaml:"identity_file,omitempty"` // 新增:私钥路径(非秘密)
	Tags           []string `yaml:"tags,omitempty"`
}
```

- `identity_file` 只是路径,放 operator 侧的 `inventory.yaml` 没问题。
- **`Public()` 不变**:agent 面的 `hosts` 仍只吐 name+tags,`identity_file` 属 operator-only,不外泄。
- **密码不进这里**。host 是否用密码认证由"`secrets.enc` 里有没有它的条目"隐式决定;无需 inventory 字段(可选未来加 `auth: [key,password]` 显式约束,本期不做)。

## 3. 加密密码库(新增 `internal/secrets`)

### 3.1 文件与格式
- 路径:`~/.agentssh/secrets.enc`(`config.Paths` 加 `SecretsFile`),mode **0600**,原子写(temp+rename,复用 inventory store 的写法)。
- 明文结构(加密前):`{"version":1,"passwords":{"web-1":"…"}}`。
- 落盘前**整体加密**;磁盘上只有密文。

### 3.2 加密方案(**推荐 age**)
- 用 [`filippo.io/age`](https://age-encryption.org) 的**口令(scrypt)加密**:经审计、专为此场景设计、自带 KDF+AEAD+版本头,免去手搓。
- 主口令来源(优先级):环境变量 **`AGENTSSH_MASTER_PASSWORD`** > TTY 交互提示(`term.ReadPassword`)。
- 备选(若不想引依赖):手搓 `scrypt(N=2^15,r=8,p=1)` 派生 key → `chacha20poly1305` AEAD,带版本/盐/nonce 头(`golang.org/x/crypto` 已有 scrypt 与 chacha20poly1305)。**倾向 age**,把密码学交给审计过的实现。

> ⚠️ 这是本设计唯一引入新依赖/密码学的点。实现前请确认 age vs 手搓的选择。

### 3.3 API(对 executor 解耦)
```go
type Store struct{ /* … */ }
func Open(path, master string) (*Store, error)     // 文件不存在→空 Store
func (s *Store) Password(host string) (string, bool)
func (s *Store) Set(host, password string) error
func (s *Store) Delete(host string) error
func (s *Store) Names() []string                   // 只名字,永不回值
func (s *Store) Save() error
```
- 错误:主口令错 → AEAD 解密失败 → 返回明确 `ErrWrongMaster`(不泄露任何明文)。

## 4. native 认证链改造(`internal/executor/native.go`)

当前 `authMethods(identityFiles)` = ssh-agent + 默认私钥。改成:

1. **ssh-agent**(`SSH_AUTH_SOCK`,不变,最优先)
2. **per-host `identity_file`**:`resolveTarget` 把 `host.IdentityFile` **prepend** 进 `identityFiles`,经既有 `signersFromFiles`(已支持加密私钥 passphrase)。
3. **默认私钥**(`~/.ssh/id_*`,不变)
4. **远端密码**:若该 host 有密码,**追加** `ssh.Password(pw)`(放最后,确保公钥优先)。

密码注入用**依赖注入**,executor 不直接依赖 `internal/secrets`:
```go
type NativeOptions struct {
	// …既有字段…
	PasswordSource func(host string) (string, bool) // main.go 用 secrets.Store 填充
}
```
- `nativeTarget` 已带 `Name`,`dial` 时用它查密码 → 命中才加 `ssh.Password`。
- `clientConfig` 的"无任何 auth 方法"错误信息更新,指向新提示(见 §5)。

## 5. 错误分类器(新增,`run`/`test`/`probe`/`add` 共用)

`func ConnectHint(err error) string`(放 executor 或新 `internal/sshdiag`),把底层错误映射成可操作建议:

| 现象 | 判定 | 提示 |
| --- | --- | --- |
| 无可用凭据 | `clientConfig` 的 no-auth 错 | 为该 host 设 `identity_file`,或 `ssh-add` 加载密钥,或 `agentssh secret set <host>` 登记密码 |
| 认证全失败 | `x/crypto/ssh` "unable to authenticate" | 同上 + 提醒远端 `authorized_keys`/账号是否就绪(**远端你自己处理**) |
| 未知主机指纹 | `knownhosts.KeyError` 且 `len(Want)==0` | 先 `ssh <host>` 信任,或 inventory 设 `host_key_policy: accept-new` |
| 主机密钥变更 | `knownhosts.KeyError` 且 `len(Want)>0` | **疑似 MITM**:核实指纹后再处理,勿盲目接受 |
| 连不上 | dial timeout / refused | 查 addr/port/网络/防火墙 |

- 接入点:`runDirect` 的传输失败分支(让 `agentssh run` 失败时直接给提示)、`discover --probe`、`inventory test`。**提示绝不含密码原文**。

## 6. 发现(`agentssh inventory discover`)

### 6.1 静态(默认,不联网)
- 源 A `~/.ssh/config`:`kevinburke/ssh_config` 的 `Decode` 列举 Host 块,取**具体**主机名(跳过 `*` 通配),解析 HostName/User/Port/IdentityFile。
- 源 B `~/.ssh/known_hosts`:解析非 hashed 主机名;hashed 跳过并标注"(hashed,无法列举)"。
- 源 C 可用密钥:ssh-agent 列表 + 存在的默认私钥文件。
- 对每个候选标注:`source`、`addr`、`has_key`(agent/idfile 命中)、`in_known_hosts`、`in_inventory`。
- 输出:文本表 + `--json`。

```
$ agentssh inventory discover
NAME    SOURCE         ADDR            KEY     KNOWN_HOSTS  STATUS
web-1   ssh_config     10.0.0.11       agent   yes          看起来可连(未导入)
db-2    known_hosts    10.0.0.20       -       yes          待认证
gw      ssh_config     gw.example:22   idfile  no           待认证
```

### 6.2 探测(`--probe`,真连)
- 对每个候选用 `NativeExecutor` 拨号+认证+开 session 跑空操作(或 `true`),短超时(默认 5s),**并发限速**。
- 分类:`可直连` / `认证失败` / `主机密钥问题` / `不可达`,失败附 §5 提示。
- **真实出网连接**——有副作用,故藏在 flag 后,文档明示。

### 6.3 导入
- `--import`:把"可直连且未导入"的候选写进 `inventory.yaml`(复用 `inventory.AddHost`,去重),带上其 addr/user/port/identity_file。
- 交互模式:列表多选导入(TUI / 简单 prompt)。

## 7. CLI 表面

```
agentssh inventory discover [--probe] [--json] [--import]
agentssh inventory add <name> --addr … [--identity-file PATH] [--password]
agentssh inventory test <name>          # 连通性自检 + 提示
agentssh secret set <host>              # TTY 录入密码 → 加密落盘
agentssh secret ls                      # 只列 host 名,永不回显密码
agentssh secret rm <host>
```
- `inventory add --password`:TTY(`term.ReadPassword`)录入 → `secrets.Set` → `Save`。非交互且无 `AGENTSSH_MASTER_PASSWORD` 时报错而非明文兜底。
- `--identity-file`:写入 `Host.IdentityFile`。

## 8. 统一 TUI(`internal/tui`)

- Hosts 区新增动作:
  - `d` Discover:进候选列表,多选 → 导入。
  - `t` Test:对选中 host 探测,弹出结果+提示。
  - add 表单(`internal/hostform`)加 `identity_file` 输入;可选密码字段(掩码),保存即写 `secrets`。
- 复用 §6/§5 的发现与提示逻辑,TUI 只是壳。

## 9. 安全分析(关键)

- **identity_file** 是路径非秘密 → 进 inventory 可接受。
- **密码**只在 `secrets.enc`(age,0600);绝不进 inventory / 审计 / 输出 / 日志。录入走无回显 TTY;`secret ls` 只名字。
- **主口令暴露面**:无人值守时主口令在 agent 进程的环境变量里 → **该进程能解密所有已存密码**,这削弱了"agent 看不到凭据"。
  - 建议:agent 驱动的 host **优先公钥**;密码+库主要用于 operator 手动会话,或确实无法用密钥的 host。
  - 可提供"仅 TTY 主口令"模式(不读 env)→ agent 无人值守时**用不了**密码 host(故意的安全降级)。
  - 文档明确写出这个权衡,默认行为保守。
- **`discover --probe`** 会真连用户的服务器 → 副作用,flag-gated,文档说明。
- **host key** 语义不变:strict 默认;变更密钥永远拒(MITM 防护)。
- **审计**:密码认证的 run 与公钥无差别记录(命令/退出码/输出哈希),凭据本身不入审计。

## 10. 分期(把密码学风险隔离)

- **Phase 1(无新密码学,先做):** `Host.IdentityFile` + native 接线;错误分类器接入 `run`;`inventory discover`(静态 + `--probe`);`inventory test`。CLI 优先。价值高、风险低。
- **Phase 2(密码学):** `internal/secrets`(age)+ native 密码认证(注入 `PasswordSource`)+ `secret set/ls/rm` + `inventory add --password`。
- **Phase 3(TUI):** Discover/Import/Test 动作 + 表单字段接入统一 TUI。

## 11. 测试计划

- **inventory**:`identity_file` round-trip(Save/Load、omitempty 干净);`Public()` 仍脱水成 name+tags。
- **native**:认证顺序(agent→idfile→默认→password);`PasswordSource` 命中才追加 `ssh.Password`;进程内 SSH server 跑密码认证 E2E。
- **secrets**:加解密 round-trip;错主口令→`ErrWrongMaster`;篡改密文→AEAD 失败;文件 0600;原子写。
- **discover**:`ssh_config`/`known_hosts` fixture 解析与分类;`--probe` 对进程内 server 验 可连/认证失败/主机密钥 三类。
- **hints**:错误→提示映射表。
- **回归**:既有传输选择/退出码契约/输出脱敏/审计 hash 链全不破;`go test -race` 全绿;gofmt/vet/golangci-lint v2 干净。

## 12. 实现说明(Phase 1-3,2026-06-18)

Phase 1 已实现并经对抗式审查 + 修复:`Host.identity_file`、native per-host 私钥接线、`ConnectHint`/`ProbeStatusForError`、`internal/discovery`、`inventory discover [--probe] [--json] [--import]`、`inventory test`。

审查发现并已修:
- **`run` 错误输出脱敏**:`run` 是 agent 面命令,其 stderr 之前会 `%v` 打印 `result.Err`(可能含 identity_file 路径、解析后的 addr),与 `hosts/Public()` 脱水边界矛盾。改为只打印**无凭据信息**的 `ConnectHint`;operator 要看原始错误用 `inventory test`。
- **`--import` 按端点去重**:之前只按 name/alias 去重,同一 `addr:port` 可被不同名导入两次 → group/tag 运行会重复执行同一机器。改为按 `addr:port` 端点去重(原有 + 增量)。
- **ssh_config 候选走别名探测/导入**:之前把 ssh_config 主机拍平成 addr/user/port 直连,丢了 ProxyJump/多 IdentityFile → 误报 + 导入后路由不可复现。改为 ssh_config 来源的候选**用 `ssh_config_alias` 探测与导入**,交给 native `resolveAlias` 复刻真实路由。
- **known_hosts 通配跳过**:`*.corp`、`!neg` 等 match-only 模式不再被当作可拨号候选枚举。

已知限制(留待后续/文档明示):
- IdentityFile 的 OpenSSH token(`%h/%p/%r/%u`)不展开;ssh_config 候选靠别名探测规避,但 `has_key` 展示对多 IdentityFile 仅尽力而为。
- known_hosts 通配条目不参与 `InKnownHosts` 匹配判定(保守地报 `no`,不会误报 `yes`)。
- 仅有 `ssh_config_alias`(无 addr)的既有 inventory 主机不参与端点去重(无法在此廉价解析别名→addr)。

Phase 2 已实现:`internal/secrets` 使用 `filippo.io/age` passphrase/scrypt 加密 `~/.agentssh/secrets.enc`,明文结构为 `{"version":1,"passwords":{...}}`,磁盘写入为 0600 + temp/rename 原子替换;`config.Paths` 增加 `SecretsFile`;native executor 增加 `NativeOptions.PasswordSource` 并把 `ssh.Password` 追加在 agent、per-host `identity_file`、默认私钥之后;`agentssh secret set|ls|rm` 与 `agentssh inventory add --password` 已接入。

Phase 2 安全约束:
- `secret ls` 文本/JSON 只输出 host 名称,不输出密码值。
- operator 命令的 master password 来源为 `AGENTSSH_MASTER_PASSWORD` 或无回显 TTY prompt;SSH password 录入也只走无回显 TTY prompt。
- `run` 路径只读取 `AGENTSSH_MASTER_PASSWORD`,不会 prompt;环境变量缺失、主口令错误、密文损坏或打开失败时只是不提供 password auth,继续按 key auth 尝试。
- 密码不写入 `inventory.yaml`,不进入 audit record,也不进入 run/secret 命令输出。

Phase 2 偏差/澄清:
- §3.3 早期草案里的 `Set/Delete` 返回 `error`、`Save()` 无参数已按 Phase 2 交付要求调整为 `Set/Delete` 无返回值、`Save(master string) error`。
- `inventory add --password` 不接受命令行明文密码;即使已有 `AGENTSSH_MASTER_PASSWORD`,SSH 登录密码本身仍必须通过无回显 TTY 录入。
- TUI 密码主口令只读 `AGENTSSH_MASTER_PASSWORD`,不会在 Bubble Tea 内 prompt(避免抢占 TTY);未设置时,带密码的 add 表单提交会拒绝并提示改用环境变量或 `agentssh secret set <host>`。

Phase 2 对抗式审查修复(2026-06-18):
- **shell-out 子进程剥离主口令**:`ExecRunner`(buffered + streaming)现在用 `scrubbedEnv()` 设置子进程环境,删除 `AGENTSSH_MASTER_PASSWORD`,避免在 `transport: ssh` 时把主口令泄漏给外部 `ssh` 及其 `ProxyCommand`/`LocalCommand`(shell 传输本就用不了加密库)。
- **secrets 目录信任边界**:`secrets.Save` 在 temp+rename 前 `ensureSafeDir` 校验目录归属当前用户且无 group/other 写位,否则 fail-closed(目录是原子写的信任根,仅文件 0600 不够;AEAD 能拒随机篡改但挡不住回滚替换)。
- **probe/test 使用已存密码**:`inventory discover --probe` 与 `inventory test` 现在注入 `passwordSourceForRun`(env-only master),使 password-only 主机能被正确探测/诊断/导入。
- **`add --password` 事务化**:先预检 master+密码录入(失败则不写 inventory),再写 host,最后存密码;存密码失败回滚 inventory 条目,保持两库一致。

已知限制(Phase 2):
- **ProxyJump 跳板的密码查找**按合成的 nativeTarget.Name(原始 ProxyJump token,如 `jump@bastion:2200`)作 key;若把跳板密码存在其自然主机名/别名下则查不到(静默回落 key auth)。password-only 跳板属边缘组合,留待后续做稳定 keying;当前需把跳板密码存在与 ProxyJump token 一致的 key 下。
- age scrypt KDF 故意慢,导致 secrets/cmd 测试较耗时(每次派生数百 ms)。

Phase 3 已实现:统一 TUI Hosts 区接入 `d` Discover overlay、候选多选/`p` async probe、`enter`/`i` 导入 connectable 且未入库的候选,导入复用 Phase 1 的 endpoint 去重与 ssh_config alias 规则;`t` 对当前 host async test 并显示 OK 或 `executor.ConnectHint`;add 表单新增 `identity_file` 与 masked password 字段。TUI probe/test 使用 `internal/secrets.EnvPasswordSource` 读取 env-only master,不阻塞 Update loop,不改变 secrets crypto、auth chain、exit code 或输出/audit 合约。

Phase 3 对抗式审查修复(2026-06-18):
- **async 结果按身份归并**:`mergeProbedCandidates` 改为按候选身份(source+name)归并 probe 结果,不再依赖可变的 selection 索引,避免探测进行中改选导致结果落到错误行。
- **stale overlay 防护**:`discoveryOverlay` 加单调 `runID`,`loadDiscoveryCmd`/`probeDiscoveryCmd` 携带该 ID;`discoveryLoadedMsg`/`discoveryProbedMsg` 处理时校验 `active && runID 匹配`,丢弃已关闭/被取代的 overlay 的迟到结果。
- **导入按重载库复检成员**:`importDiscoverySelected` 用 `discovery.InInventory(reloaded, name)` 复检(覆盖 alias-only 主机),不再信任发现时捕获的 `InInventory` 旧值,避免并发外部编辑导致重复导入。

## 13. 待确认

1. **加密库**:age(推荐)vs 手搓 scrypt+chacha20poly1305。
2. 主口令是否提供"仅 TTY、不读 env"的严格模式作为默认(更安全但无人值守用不了密码 host)。
3. 实现归属:我直接做 Phase 1,还是按惯例后台派发 Codex。
