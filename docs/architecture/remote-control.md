# 设计 — 远端管控:远程签名 + 配置下发

> **托管控制面适配**：新增显式 v2 HTTPS + 设备公钥请求签名协议，支持由
> config-center 等托管服务直接实现控制面。本文记录原 v1 mTLS 设计；v2 的
> 协议、路径前缀、注册 pin、防重放和迁移规则见
> [Hosted HTTPS control plane](https-control-plane.md)。Bundle 与 SSH 签名格式保持一致。

> 状态:**已实现**(三期一并完成,执行记录见 `docs/plans/remote-control.md`)· 2026-10-20 · 关联:`docs/architecture/native-ssh.md`、`docs/architecture/ssh-auth-onboarding.md`、`internal/executor/native.go`、`internal/config`、`docs/plans/approval-system.md`
>
> 目标:让一台 AgentSSH 客户端的**连接能力和配置都由远端控制面授予**。控制面能随时让它失效;客户端在任何时刻都拿不到 SSH 私钥原文。

## 0. 决策(已与用户确认)

| 维度 | 决策 |
| --- | --- |
| 凭据方案 | **远程签名**:SSH 私钥只存在控制面,客户端每条连接请求一次签名 |
| 控制面 | **自建 `agentssh-server`**(同仓库新二进制),签名后端抽接口,以后可换 KMS/Vault |
| 范围 | **签名 + 配置下发一起做**:inventory/policy 由控制面下发并签名,远端权威、本地只能收紧 |
| 离线 | **严格 fail-closed**:签不到名就连不上;配置过期就不能用 |
| 远端服务器 | **不改**。目标机只需把控制面持有的公钥放进 `authorized_keys`(与现状相同) |
| TOTP | **本期不做** |
| 密码主机 | 远端模式**不支持**(密码认证必须把明文交给客户端,和"看不到原始密钥"矛盾) |

## 1. 威胁模型

在原有对手(**agent**:同机、不可信 confused deputy)之外,新增对手 **客户端操作者/设备**(外包、离职、设备丢失)。对后者,客户端 CLI 本身不可信(可被改二进制)。

| 能力 | 强制方 | 防 agent | 防客户端操作者 |
| --- | --- | --- | --- |
| 私钥不落客户端 | 控制面 | ✓ | ✓ |
| 吊销后无法建立新连接 | 控制面(拒签) | ✓ | ✓ |
| 签名只能用于 SSH 用户认证、只能用指定 identity | 控制面(解析待签数据) | ✓ | ✓ |
| 每次签名留服务端审计 | 控制面 | ✓ | ✓ |
| policy deny / 审批 / 输出脱敏 | 客户端 CLI | ✓ | ✗ |
| 配置过期即不可用、吊销后中断进行中的命令 | 客户端 CLI | ✓ | ✗ |
| 签名只用于声明的那台主机 | **做不到**(见 §4.3) | — | ✗ |

结论:对客户端操作者,远端管控保证的是**拿不走、可收回、有记录**;在有效期内他能做的事,服务端只能靠 identity 粒度和 `authorized_keys` 的 `from=` 收窄。需要服务端强制命令级约束时,迁移到 SSH 证书 + `force-command`(签名接口已为此留口,见 §9)。

## 2. 总体结构

```
┌──────────────── 客户端 ────────────────┐         ┌────────── agentssh-server ──────────┐
│ agentssh CLI / TUI                      │  mTLS   │ devices   设备注册、吊销             │
│  config.Load ──▶ remote bundle(缓存+验签)│◀──────▶│ bundles   inventory/policy 按设备下发 │
│  native executor ──▶ remoteSigner       │         │ identities SSH 私钥(加密存储)       │
│  本地审计(hash 链,不变)                │         │ sign      校验 + 签名 + 服务端审计   │
└────────────────────┬───────────────────┘         └─────────────────────────────────────┘
                     │ SSH(公钥认证,签名来自控制面)
                     ▼
               目标服务器(authorized_keys 里是控制面 identity 的公钥)
```

## 3. 设备身份:注册与认证

### 3.1 注册(enroll)
1. 管理员在服务端:`agentssh-server device token create --name alice-laptop` → 输出一次性注册令牌(含 token id、secret、**服务端 CA 指纹**,10 分钟过期)。
2. 客户端:`agentssh remote enroll https://cp.example --token <token>`
   - 用令牌里的 CA 指纹校验服务端 TLS 证书(首次即 pin,不依赖系统 CA)。
   - 本地生成设备密钥(ed25519)+ CSR,连同令牌提交;服务端签发设备客户端证书(内部 CA)。
   - 落盘 `~/.agentssh/remote/`:`remote.yaml`(server URL、device id、CA 指纹、bundle 公钥)、`device.key`(0600)、`device.crt`。
3. 令牌一次性:用过即作废。

### 3.2 请求认证
- 所有 API 走 **mTLS**,服务端从客户端证书取 device id,**每个请求都查一次设备状态**(active / revoked)。
- 不另造 token/lease 协议:吊销 = 数据库里把设备标成 revoked,下一个请求就失败。
- 设备私钥可以被操作者拷走,这是可接受的:它只能在设备未吊销时调用控制面,本身不能登录任何服务器。

## 4. 远程签名

### 4.1 Identity
- 控制面持有命名的 SSH 密钥对(本期只支持 **ed25519**):`agentssh-server identity create web-prod` → 输出一行 `authorized_keys` 公钥,由管理员装到目标机(**这是唯一的远端动作,由人完成**)。
- 建议按主机组拆 identity,缩小单个签名能打开的范围;`authorized_keys` 可加 `from="客户端出口IP"`。
- 私钥加密落盘(age,服务端主口令来自 env/文件),经 `Signer` 后端接口访问,后续可换 KMS/HSM/Vault transit。

### 4.2 签名流程
```
客户端 native executor                              控制面
  密钥交换完成,x/crypto/ssh 调 Signer.Sign(data)
  POST /v1/sign {host, identity, data} ───────────▶ ① 设备 active?
                                                   ② host 在该设备的 bundle 里?identity 与 host 绑定一致?
                                                   ③ 解析 data(见 4.3),校验结构
                                                   ④ 用 identity 私钥签名
                                                   ⑤ 写签名审计(device, host, identity, user, 时间, 结果)
  ◀──────────────────────────── {signature, sign_id}
  USERAUTH_REQUEST 发给目标机
```

客户端实现 `ssh.Signer`:`PublicKey()` 返回 bundle 里该 identity 的公钥,`Sign()` 发一次 HTTPS 请求。每条连接一个签名,一次往返。

### 4.3 待签数据校验(防签名预言机被滥用)
控制面**只签 SSH 用户认证数据**,逐字段解析 RFC 4252 §7 结构:

```
string session_id | byte 50 (USERAUTH_REQUEST) | string user | string "ssh-connection"
| string "publickey" | bool TRUE | string 算法 | string 公钥
```
- 必须完整解析且无多余字节;`user` 等于 bundle 里该 host 的 user;公钥等于该 identity 的公钥;算法是 `ssh-ed25519`。
- 不符合就拒签。这样客户端无法拿这把密钥去签别的东西(比如其他协议的认证、任意数据)。

**做不到的**:`session_id` 是握手 hash,控制面无法知道这次连接的是哪台主机。持有效设备的客户端可以谎报 `host`,把签名用在任何信任该 identity 的机器上。缓解:identity 按组拆分、`from=` 限制来源。进阶:握手时服务器会用 host key 对 `session_id` 签名,客户端若把这份签名一起提交,控制面就能用登记的 host key 验证目标主机;但 `x/crypto/ssh` 不对外暴露该签名,需 fork,本期不做。

### 4.4 接入点
`internal/executor/native.go` 的 `authMethods`:**远端模式下只挂 remoteSigner**,不再挂 ssh-agent、默认私钥、identity_file、密码。避免远端托管的主机意外用本地凭据登录,也避免本地凭据被混进来。

```go
type NativeOptions struct {
	// …既有字段…
	// RemoteSigner, when set, replaces every local auth method.
	RemoteSigner func(host string) (ssh.Signer, error)
}
```
- 远端模式**强制 native transport**;`transport: ssh`(shell-out)在远端模式下报配置错误。
- **关闭连接池**:池化连接复用不走签名,会让吊销对后续命令失效。远端模式下每条命令新建连接、新签一次名("每条命令都过控制面")。代价是每条命令多一次握手 + 一次签名往返。

## 5. 配置下发

### 5.1 Bundle
```json
{
  "version": 42,
  "device_id": "dev_…",
  "issued_at": "…", "not_after": "…",   // 默认有效期 10 分钟
  "inventory": { …与 inventory.yaml 同结构,host 多一个 identity 字段… },
  "policy":    { …与 policy.yaml 同结构… },
  "identities": { "web-prod": "ssh-ed25519 AAAA…" }   // 只有公钥
}
```
- 服务端用 **bundle 签名密钥(ed25519)** 对整个 JSON 做分离签名;公钥在 enroll 时 pin 到 `remote.yaml`。TLS 之外再验一层,缓存文件被改也能发现。
- 客户端记录见过的最大 `version`,**拒绝回滚**到更旧的 bundle。
- `device_id` 必须等于本机,防止拿别的设备的 bundle 来用。

### 5.2 获取与缓存
- 缓存在 `~/.agentssh/remote/bundle.json` + `bundle.sig`。
- `config.Load()` 是唯一入口:远端模式下改为"取 bundle"。缓存在 60 秒内取过就直接用,否则向服务端拉取(带 `If-None-Match: version`)。
- 严格 fail-closed:拉取失败且缓存已过 `not_after` → 报错,不回退本地文件。拉取失败但缓存仍在有效期 → 继续用(最长滞后 = `not_after`,签名仍是每次在线)。

### 5.3 与本地文件的关系
- **inventory**:远端模式下完全来自 bundle,忽略本地 `inventory.yaml`。
- **policy**:以 bundle 为准;本地 `policy.yaml` **只合并 `deny` 规则**(收紧),本地 `allow` 忽略并在 `remote status` 里提示。
- 写操作(`inventory add/rm`、`policy … add`、TUI Hosts/Policy 编辑)在远端模式下拒绝,提示"由控制面管理"。
- **审批**:once / session 级 grant 照常(操作者本人在场裁决,只防 agent);**持久化 host grant 关闭**,因为它要写 policy 的 allow 规则。

## 6. 吊销语义

| 动作(服务端) | 生效范围 | 最坏延迟 |
| --- | --- | --- |
| `device revoke <id>` | 签名 + bundle 拉取全部拒绝 | 签名:下一条命令;bundle:≤ `not_after` |
| `identity disable <name>` | 该 identity 不再签名 | 下一条命令 |
| 从 bundle 移除 host / 改 policy | 新 bundle 生效 | ≤ 60 秒缓存刷新 |
| 停掉控制面 | 全部 | 下一条命令 |

**进行中的命令**:签名只在建连时发生,已建立的 SSH 连接不受影响。客户端在 `run` 期间每 30 秒检查一次设备状态,吊销即 cancel(复用 run 已有的 signal ctx)。这一层只防 agent。

## 7. 审计

- **服务端签名日志**(新):每次签名请求一条,含 device、host、identity、user、结果、`sign_id`。客户端无法篡改,是对客户端操作者唯一可信的记录。
- **客户端本地审计**:不变。audit Record 末尾新增 `remote_sign_id`(omitempty,保持旧链兼容),用于和服务端日志对账。
- 本期不做客户端审计上传。

## 8. 命令表面

客户端(`agentssh`):
```
agentssh remote enroll <url> --token <t>   # 注册设备
agentssh remote status                     # 设备状态、bundle 版本/过期时间、被忽略的本地规则
agentssh remote refresh                    # 立即拉取 bundle
agentssh remote leave                      # 删除本地设备凭据,退出远端模式
```

服务端(`agentssh-server`,本期只有 CLI,无 Web):
```
agentssh-server init                         # 生成内部 CA、bundle 签名密钥、数据目录
agentssh-server serve --listen :8443
agentssh-server tls renew [--san <host>]     # 用原 CA 换发 TLS 证书
agentssh-server device token create --name N
agentssh-server device ls | revoke <id>
agentssh-server identity create <name>       # 打印 authorized_keys 公钥
agentssh-server identity ls | disable <name>
agentssh-server config push --device <id> --inventory inventory.yaml --policy policy.yaml
agentssh-server log [--device] [--host]      # 签名审计
```

## 9. 包与依赖

- `cmd/agentssh-server`:服务端入口。
- `internal/remote`:请求/响应结构、注册令牌、bundle 信封签名/验签、userauth 解析、受管 inventory 校验(两端共用)。
- `internal/remoteclient`:enroll、mTLS client、bundle 拉取/验签/缓存、`remoteSigner`、run 期间吊销看门狗。
- `internal/remoteserver`:HTTP handler、SQLite 存储、密钥材料(本期:age 加密,见 §13)。
- `internal/managedmode`:远端模式标记判定,`inventory.Save`/`policy.Save` 据此拒写。
- 存储:单个 SQLite 文件(`modernc.org/sqlite`,纯 Go,保持静态构建)。
- 签名后端接口为证书方案留口:未来增加 `/v1/cert` 签发短期证书,客户端认证链换成证书即可,配置下发/设备/吊销全部复用。

## 10. 分期

- **Phase 1 — 签名链路**:server init/serve、设备 enroll + mTLS、identity、`/v1/sign`(含 §4.3 校验)、服务端签名日志、客户端 `remoteSigner` + 远端模式认证链 + 关池。此阶段 inventory 先用本地文件,host 加 `remote_identity` 字段。
- **Phase 2 — 配置下发**:bundle 签名/下发/缓存/回滚保护、`config.Load` 切换、本地只收紧的合并、写操作与持久化 grant 在远端模式下拒绝、TUI 只读提示、`remote status/refresh`。移除 Phase 1 的本地 `remote_identity` 过渡字段。
- **Phase 3 — 收尾**:run 期间吊销检查、`remote_sign_id` 进审计、`remote leave`、错误提示与退出码打磨、文档与 SKILL.md 更新。

## 11. 测试计划

- **userauth 解析**:合法数据通过;改 user/公钥/算法/服务名/多余字节/截断均拒;fuzz。
- **签名 E2E**:进程内 x/crypto/ssh 测试服务器 + 进程内控制面,验证:正常登录;设备吊销后下一次连接失败;identity disable 后失败;控制面不可达时失败(fail-closed)。
- **远端模式认证链**:设置了 `SSH_AUTH_SOCK`、默认私钥、密码时,远端模式下都不被使用。
- **bundle**:验签失败拒;`device_id` 不符拒;版本回滚拒;过期 + 拉取失败拒;有效期内拉取失败用缓存;本地 deny 合并生效、本地 allow 被忽略。
- **enroll**:CA 指纹不符拒;令牌重放拒;过期令牌拒。
- **回归**:非远端模式行为完全不变(认证链、连接池、本地配置读写、审批持久化 grant);审计旧链兼容;`go test -race`、gofmt/vet/golangci-lint 全过。

## 12. 已定(按默认值实施)

1. 设备认证用 **mTLS**;控制面前若有终止 TLS 的反向代理,需改为直连部署。
2. 远端模式**关闭连接池**,每条命令都过控制面。
3. bundle 有效期 10 分钟(`serve --bundle-ttl` 可调)/ 缓存刷新 60 秒 / run 期间检查 30 秒。
4. 存储用 SQLite。

## 13. 实现说明(与上文的差异与补充)

- **不需要过渡字段**:三期一起交付,inventory 直接用 `identity` 字段(`Host.Identity`),没有 Phase 1 的 `remote_identity`。
- **受管 inventory 约束**:每个 host 必须有 `addr`、`user`、`identity`;禁止 `ssh_config_alias`、`identity_file`;`transport` 只能空或 `native`。因此远端模式**不支持 ProxyJump**。`host_key_policy` 取自 bundle,known_hosts 仍在本机。
- **密钥材料**:服务端生成一个 age X25519 身份,只有它用主口令(scrypt)加密;CA 私钥、TLS 私钥、bundle 签名私钥、各 identity 私钥都加密给这个 X25519 收件人。所以 `identity create` 不需要主口令,只有 `init`/`serve` 需要。
- **注册令牌**:`agentssh-enroll.v1.<id>.<secret>.<CA 指纹>`;首次连接只信任令牌里指纹对应的 CA(服务端在证书链里附上 CA),并做正常的主机名校验。令牌一次性、默认 10 分钟过期;服务端只存 secret 的 SHA-256。
- **bundle 信封**:inventory/policy 以 YAML 原文放进 JSON,ed25519 签名带域分隔前缀 `agentssh-bundle-v1\x00`。客户端缓存为单个原子替换的 `bundle.cache.json`(bundle + 签名 + 拉取时间 + 回滚下限),不会读到"新 bundle 配旧签名"。
- **本地 deny 覆盖层**:`policy.Config.Overlay`(不序列化)在引擎里最先求值,只取显式 deny 规则(含 host_overrides 里的),命中时规则名带 `local:` 前缀;本地 allow 一律忽略。
- **写拦截**:`managedmode.CheckWritable` 挂在 `inventory.Save`/`policy.Save`,一处覆盖 CLI、TUI 和审批持久化 host grant。TUI 读取走生效配置(远端 bundle),状态栏显示 `managed vN`(离线时 `(offline)`)。
- **命令门槛**:`remote enroll` 要求 TTY(令牌本身是授权);`remote leave` 走 operator 门槛;`remote status/refresh` 不设门槛。
- **签名日志**:被吊销设备的签名请求在认证层就被拒,也会以 `device revoked` 记一条拒签。
- **退出码**:配置 bundle 不可用 → exit 2(配置类);控制面拒签/不可达 → exit 9,`ConnectHint` 给出对应提示。
- **离线可复盘**:只读本地状态的命令(audit / session / status / approval ls|status / plan status)用 `config.LoadPaths()`,不碰控制面;`agentssh tui` 在远端配置不可用时仍能打开并显示错误卡片。
- **host 级审批**:远端模式下在 `Resolve` 之前拒绝,请求仍可按 once / session 裁决,不会留下"已批准但无 grant"的死请求。
- **deny 提示**:远端模式下非本地覆盖层命中的 deny,提示改为联系控制面管理员,而不是编辑本地 `policy.yaml`。
- **主机发现**:`inventory discover` 和 TUI 的 `a`/`D` 在远端模式下直接拒绝。发现读本机 ssh_config 并用本地凭据探测,会绕过远程签名;主机只能由控制面下发。
- **失败登录也对账**:控制面已签名但目标机仍拒绝(或握手中断)时,`Result.RemoteSignID` 照样带上签名 id,审计记录能和签名日志对上。
- **证书有效期**:CA 10 年,服务端 TLS 证书与设备证书各 2 年。`agentssh-server tls renew` 用原 CA 换发 TLS 证书(默认沿用原 SAN),设备 pin 的是 CA,不需重新注册;`serve` 在证书 30 天内到期时告警。设备证书暂无在线续期,到期后需 `remote leave` + 重新 enroll。
