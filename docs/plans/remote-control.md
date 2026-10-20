# 执行计划 — 远端管控(远程签名 + 配置下发)

> 设计稿:`docs/architecture/remote-control.md`。§12 待确认项按默认值执行:mTLS、远端模式关连接池、bundle 10min / 缓存刷新 60s / run 期间检查 30s、SQLite。三期一次做完。

## 目标与验收

- 新二进制 `agentssh-server`:`init / serve / device token create|ls|revoke / identity create|ls|disable / config push / log`。
- 客户端 `agentssh remote enroll|status|refresh|leave`;注册后进入远端模式:
  - inventory 完全来自签名 bundle;policy = bundle + 本地 `policy.yaml` 的 deny 规则(本地 deny 永远先于远端规则生效)。
  - SSH 认证只用控制面远程签名;不使用 ssh-agent、本地私钥、identity_file、密码;强制 native transport;关连接池。
  - 本地 `inventory.yaml` / `policy.yaml` 写操作(CLI、TUI、审批持久化 host grant)报 "managed by remote control plane"。
- 控制面只签解析合格的 RFC 4252 publickey userauth 数据(user / 公钥 / 算法 / 服务 / 方法逐项核对),每次请求写签名日志(含拒签)。
- 吊销:设备 revoke 后下一次签名/拉取 bundle 失败;identity disable 后签名失败;run 期间每 30s 查设备状态,已吊销即取消命令。
- fail-closed:控制面不可达且 bundle 过期 → 报错;bundle 验签失败 / device_id 不符 / 版本回滚 → 报错。
- 审计 Record 末尾新增 `remote_sign_id`(omitempty),旧链兼容。
- 非远端模式行为完全不变。

### 远端模式 inventory 约束(服务端 push 时 + 客户端加载时都校验)
每个 host 必须有 `addr`、`user`、`identity`(且 identity 存在),不得有 `ssh_config_alias`、`identity_file`;`transport` 只能空或 `native`。

## 方案与包布局

| 路径 | 内容 |
| --- | --- |
| `internal/managedmode` | 叶子包:远端模式标记文件判定 + `ErrManaged`;`inventory.Save` / `policy.Save` 调用它拦写 |
| `internal/remote` | 两端共用:API 类型、注册令牌编解码、userauth 解析、bundle 信封签名/验签、受管 inventory 校验 |
| `internal/remoteserver` | SQLite 存储、密钥材料(age X25519 包裹,主口令只在 `init`/`serve` 用)、HTTP handler、管理操作 |
| `internal/remoteclient` | 状态文件、mTLS client、enroll、bundle 拉取/缓存/回滚保护、远程 Signer、执行器包装(吊销看门狗) |
| `cmd/agentssh-server` | 服务端 CLI |
| `internal/executor` | `NativeOptions.RemoteSigner`;`Result.RemoteSignID` |
| `internal/policy` | `Config.Overlay`(本地 deny 层,不序列化),引擎先评估 |
| `internal/config` | `Load()` 远端感知;`Config.Remote` |

关键决定:
- 服务端密钥材料全部用一个 age X25519 identity 加密,这个 identity 本身用主口令(scrypt)加密。`identity create` 只需公钥收件人,不需要主口令;`serve` 启动时解密一次进内存。
- 设备证书 / 服务端 TLS 证书用 ECDSA P-256,由内部 CA 签发;客户端 enroll 时凭令牌里的 CA 指纹 pin CA。
- bundle 内嵌 inventory/policy 的 YAML 原文,客户端复用现有 YAML 解析,避免 JSON/YAML 双份 schema。
- run 期间看门狗只在**确认吊销**(403)时取消命令;网络抖动不取消(签名和配置仍 fail-closed)。

## 进度

- [x] 设计稿、代码接缝测绘
- [x] Phase 1:managedmode / remote / remoteserver / agentssh-server / remoteclient 签名 / executor 接线
- [x] Phase 2:bundle 下发、config.Load 切换、本地 deny 合并、写拦截、TUI
- [x] Phase 3:吊销看门狗、审计 remote_sign_id、remote status/refresh/leave、提示与文档
- [x] 测试与最终验证

实现中追加的决定(已同步到设计稿 §13):
- 只读本地状态的命令(audit / session / status / approval ls|status / plan status)改用 `config.LoadPaths()`,控制面不可达时仍可复盘;`agentssh tui` 在远端配置不可用时也能打开(错误卡片)。
- host 级审批在远端模式下于 `Resolve` 之前拒绝,请求仍可改为 once/session 裁决,不会被"烧掉"。
- 被吊销设备的签名请求在认证层拒绝,同样写入签名日志(`device revoked`)。
- 远端模式下的 deny 提示改为"由控制面管理,请联系管理员"(命中本地覆盖层的 deny 除外)。
- release.yml 同时打包 `agentssh-server`。

## 验证

计划命令(与 CI 一致):`gofmt -l .`、`go vet ./...`、`go build ./...`、`go test -race -timeout=20m ./...`、`golangci-lint run`(v2)。

新增测试:
- `internal/remote`:userauth 解析正/负例(类型、服务、方法、非签名、空/超长 session id、空 user、尾随字节、截断、任意数据)、令牌编解码、bundle 验签(篡改/错钥/无域分隔)、受管 inventory 约束。
- `internal/policy/overlay_test.go`:本地 deny 优先于远端 host 级 allow;本地 allow 不能放松远端 deny 或灰区;host 级本地 deny 保持作用域。
- `internal/remoteserver`:Init 不覆盖 / 错主口令;令牌一次性、错 secret、过期;push 校验(未知 identity、alias、坏 YAML、坏正则、未知设备)、版本递增。
- `internal/remoteclient/e2e_test.go`(进程内控制面 + 进程内 SSH 服务器 + 真实 native 执行器):远程签名登录成功且每条命令新签名、签名日志对得上;吊销后登录失败且拒签入日志、刷新被拒;identity 停用;签名端点只签匹配的 userauth;控制面不可达 fail-closed(有效期内用缓存、过期拒绝);回滚与他设备 bundle 被拒;注册令牌一次性 / CA 不符 / 已注册;运行中吊销被取消;远端模式配置合并与本地写拦截、leave 后恢复本地。
- `internal/approval/managed_test.go`:远端模式 host 级审批被拒且请求仍可 once 裁决。
- `cmd/agentssh/remote_test.go`:控制面不可用时 `hosts`/`run` exit 2,`audit verify`/`session ls` 正常;未注册 `remote status` exit 2;无 TTY 拒绝 enroll。

真实 CLI 冒烟(构建出的 `agentssh` + `agentssh-server` + 临时 SSH 服务器):init → identity create → serve → token → `remote enroll`(伪 TTY)→ config push → `remote status` → `run`(exit 0,audit 记 `sign=sg_…`,与 `agentssh-server log` 一致)→ 灰区 exit 6 → 本地覆盖层 deny(`local:rules:no-whoami`)exit 6 → `audit verify` 链完整 → `device revoke` → 下一条 `run` exit 9 + 吊销提示 → `remote status` 显示 revoked、exit 1。

结果(2026-10-20,全部针对最终代码):
- `gofmt -l .` 无输出;`go vet ./...` 通过;`go build ./...` 通过。
- `go test -race -timeout=20m ./...` 全部通过(cmd/agentssh 458s,其余包秒级)。
- `golangci-lint run`:0 issues。注意本机是 v2.5.0,CI 固定 v2.12.2,版本差异留给 CI 兜底。
- 真实 CLI 冒烟如上,全部符合预期。

已知限制:远端模式不支持 ProxyJump / ssh_config 别名 / 密码主机;控制面无法验证签名用于哪台主机(见设计稿 §4.3);run 期间吊销检查和本地 policy 只防 agent,不防改了二进制的客户端。
