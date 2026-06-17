# 设计 — 统一 TUI 控制台(`agentssh tui` 升级为 app)

> 状态:设计稿 · 2026-06-17 · 关联:`internal/tui`(只读审计查看器)、`internal/hostform`、`internal/inventory`、`internal/policy`、`internal/session`、`internal/audit`
>
> 目标:把 `agentssh tui` 从「只读审计查看器」升级成**全屏统一控制台 app**,顶部分区栏在一个应用里切换、做所有人类侧操作。分区:**Hosts · Audit · Policy · Sessions**。
>
> 决策(已与用户确认):入口 = 升级现有 `agentssh tui`(不另起命令);现有的「standalone 审计 Run」被 app 取代,审计成为其中一个分区。

## 1. 范围

- **4 个分区**:
  - **Hosts**:列表(operator 全字段)+ 添加(嵌入 `hostform` 表单)+ 删除(确认),写回 `inventory.yaml`。
  - **Audit**:现有审计查看器 model 作为分区(按会话折叠、详情、过滤、校验链)。
  - **Policy**:展示 `policy.yaml` + 交互式 test 一条命令看 allow/deny + 命中规则。
  - **Sessions**:列出会话(id/label/起止/命令数),回车跳到 Audit 分区并按该 session 过滤。
- `agentssh inventory add/ls`、`agentssh audit/policy/session/hosts` 等 CLI 命令**保持不变**(app 是额外的统一界面,与命令共享底层)。
- 不做:run 命令(agent 侧操作,不进人类控制台)、多人/权限、policy 编辑(只读 + test)。

## 2. 使能重构(app 的前置)

### 2a. 抽出 inventory 读改写到 `internal/inventory/store.go`
当前读改写在 `cmd/agentssh/main.go`(`loadInventoryForWrite`/`addInventoryHost`/`writeInventoryAtomic`/`existingHostNames`,package main),`internal/tui` 无法 import。抽到已可被 tui import 的 `internal/inventory`(无 import 环:inventory 不依赖其它内部包):

```go
func Load(path string) (Inventory, error)              // 缺文件→零值 Inventory,nil(原 loadInventoryForWrite)
func Save(path string, inv Inventory) error            // 原子写:MkdirAll(dir,0700)、Marshal、CreateTemp(dir)、chmod600、Rename
func AddHost(inv Inventory, name string, host Host) (Inventory, error)   // 初始化 maps/version、DEDUP→ErrHostExists
func RemoveHost(inv Inventory, name string) (Inventory, error)           // 新增;不存在→ErrHostNotFound
func HostNames(inv Inventory) map[string]struct{}      // 原 existingHostNames
var ErrHostExists   = errors.New("inventory host already exists")
var ErrHostNotFound = errors.New("inventory host not found")
```
`AddHost`/`RemoveHost` 是**纯函数**(改副本返回,易测)。**非破坏性**:把 `cmd/agentssh` 的 4 个 helper 改成薄封装调用上面(保留原 `inventory add` 行为与现有测试,重名仍映射到 `newUsageError`/exit 2)。`Load` 返回原始 decode error,由命令层 `classifyConfigError` 分类(避免 inventory→config 反向依赖)。

### 2b. `internal/hostform` 变可嵌入(保留 `Run` 不变)
新增导出构造器与访问器,`Run` 内部继续用原私有构造:
```go
type Model = model                       // 导出(或把 struct 改名为 Model)
func New(opts Options, r *lipgloss.Renderer) Model     // 不启动 program,用 newStyles(r) 建样式
func (m Model) Init() tea.Cmd            // textinput.Blink
func (m Model) Update(tea.Msg) (Model, tea.Cmd)
func (m Model) View() string
func (m Model) Done() bool               // esc/ctrl+c 取消 或 提交成功 后为 true
func (m Model) Result() Result           // 取 m.result(Submitted 标识提交/取消)
```
关键:嵌入态下取消/提交**不要 `tea.Quit`**(否则杀掉整个 app)—— 改为把内部 `done` 置位,root 轮询 `Done()` 后回到 Hosts 列表。`Run`(standalone)仍可用 `tea.Quit`(它自己拥有 program)。建议:表单内部用一个 `quitting bool`,`Run` 包一层把 `Done()` 转成 `tea.Quit`,嵌入态 root 检查 `Done()`。

### 2c. 审计 model 变纯子 view(`internal/tui`,同包,root 可直接用)
- 加 `func (m model) capturing() bool { return m.focus == focusFilter }`(过滤输入时 root 要把按键全转给它)。
- **去掉自身 `tea.Quit`**:`q`/`ctrl+c` 不再由审计 model 直接 quit(改由 root 全局处理);审计 model 变成只负责审计区域的 Update/View。原 standalone `tui.run()` 被 root app 取代,故无回归。
- `newModel`/`newStyles` 留同包用;root 用 `newModel(records, hosts, styles, verifyFn)` 直接造审计子 view。
- 支持外部设置过滤(给 Sessions→Audit 跳转用):加 `func (m model) withSessionFilter(id string) model` 或一个消息,设 `filterQuery`/`sessionFocus` 并 rebuild。

## 3. 根 app(`internal/tui/app.go`)

```go
type section interface {
    tea.Model            // Init/Update/View(value-receiver,同 model.go 约定)
    title() string       // tab 名
    capturing() bool     // true=该区独占按键(文本输入态),root 不抢全局键
}
```
root model:
- `sections []section`(顺序 Hosts/Audit/Policy/Sessions)、`active int`、`styles`、`w,h`、`ready`。
- **全局按键(仅当 active section `!capturing()`)**:`tab`/`shift+tab` 或 `1`-`4` 切分区;`q`/`ctrl+c` 退出。`ctrl+c` **任何时候**都退出(硬退出)。capturing 时其余键全转给 active section。
- **委派**:非全局键 → `active.Update(msg)`,把返回的 section 存回 `sections[active]`、透传 Cmd。
- **WindowSizeMsg**:root 减去 tab 栏高度,**广播给所有 section**(每个都要尺寸;审计 model.View 在收到 size 前只显示 "loading…")。
- **跨区动作**:Sessions 回车 → 设 active=Audit 分区 + 给审计子 view 设 session 过滤(2c)。Hosts add/remove 提交后 → 调 `inventory.AddHost/RemoveHost`+`Save` → 重载 Hosts 列表(重新 `inventory.Load`)。
- root 拥有 `lipgloss.NewRenderer(os.Stdout)`(+ NO_COLOR)、TTY 守卫、`tea.NewProgram(root, tea.WithAltScreen())`。
- `tui.Runner.Run(Options)` 改为启动 root app;非 TTY → `ErrNotInteractive`(命令层 fallback,同今天)。

`tui.Options` 扩展(人类侧,带足 4 个分区所需):
```go
type Options struct { Paths config.Paths }   // app 自己按 Paths 加载 inventory/policy/audit,host 编辑后可重载
```
(`internal/tui` import `config` 不成环:config 依赖 inventory/policy,不依赖 tui。)`runTUI` 改为传 `cfg.Paths`。

## 4. 四个分区实现

- **Hosts**(新 `hostsSection`):`inventory.Load(Paths.InventoryFile)` → 列表(name/addr/user/port/alias/tags,排序);按键 `a`=add(切到内嵌 `hostform.New(...)`,`Done()` 后 `AddHost`+`Save`+重载)、`d`/`x`=remove(确认弹窗 → `RemoveHost`+`Save`+重载)、`j/k` 导航。capturing()=表单激活时 true。
- **Audit**(复用 2c 的审计 model):capturing()=过滤态。
- **Policy**(新 `policySection`):上半区渲染 `cfg.Policy`(defaults/rules/host_overrides/output);下半区一个 textinput 输 `host:cmd` 或 cmd,回车 `engine.Evaluate` 显示 `allow/deny · rule=…`。engine = `policy.NewEngine(cfg.Policy, cfg.Inventory)`。capturing()=test 输入聚焦时。
- **Sessions**(新 `sessionsSection`):`session.Summaries(audit.NewStore(Paths.AuditFile).ReadAll())` 列表;回车 → root 切 Audit + 过滤该 session。capturing()=false。

## 5. 非 TTY

复用现有守卫:`interactive()` 查 stdin&stdout(`golang.org/x/term`);非 TTY → `ErrNotInteractive`;`runTUI` 已有 fallback(打印提示 + `runSessionLS`),保持。

## 6. 测试

- **纯逻辑(可测)**:`internal/inventory` store —— `Load`(缺文件零值)、`AddHost`(初始化/dedup→ErrHostExists/保留已有)、`RemoveHost`(ErrHostNotFound/删除)、`Save`+`Load` round-trip、`HostNames`。
- **CLI 回归(非 TTY)**:`inventory add`(flag 路径)仍工作、重名 exit 2、首次建目录;新增 `inventory rm`(若也加 CLI 子命令)或至少 store 层 RemoveHost 测试。
- **section 纯逻辑**:`title()`/`capturing()`、policy test 渲染、sessions→audit 过滤设置、hosts 列表渲染、root 的分区切换/按键路由可抽成纯函数测(给定 active+capturing+key → 下一 active / 是否委派)。
- **交互层(bubbletea root + 各 section)**= 薄壳,靠 `go build` + 手测(同 M3/hostform 处理)。
- 既有测试全绿(审计 model 改动后 internal/tui 测试、hostform 测试、inventory 测试);`go build/vet/gofmt`、`go test -race`、**golangci-lint v2 = 0 issues**(本机已装,实现时自检)。

## 7. 不做(未来)

run/exec 进 TUI、policy 编辑、group 管理、多人、主题/配置持久化、鼠标。
