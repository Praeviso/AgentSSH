# 设计 — 交互式 inventory 管理(add 表单 + ls)

> 状态:设计稿 · 2026-06-17 · 关联:`internal/inventory`、`internal/config`、`cmd/agentssh`(`newInventoryCommand` 当前是占位桩)
>
> 目标:让人类**不必手写 YAML** 就能加主机 —— `agentssh inventory add` 在终端里弹出一个 bubbletea 表单填字段、写回 `~/.agentssh/inventory.yaml`;`agentssh inventory ls` 真实现(operator 全字段视图)。**这是人类侧配置管理,与只读审计 TUI(`agentssh tui`)分开**,放在 `inventory` 子命令下。

## 1. 范围与命令

- `agentssh inventory add [name] [--addr --user --port --alias --tags]`
  - **TTY**:弹 bubbletea **加主机表单**(用任何已给的 flag/positional 预填)→ 提交后写 `inventory.yaml`。
  - **非 TTY**(CI/管道):不弹表单,**用 flag 直接加**(可脚本化);字段不足(缺 name 且缺 addr/alias)→ `newUsageError`(exit 2)指引。
- `agentssh inventory ls [--json]`:真实现,展示 **operator 全字段**(name/addr/user/port/alias/tags + groups,可附 transport/host_key_policy 头);`--json` 输出完整 `Inventory` 结构。**区别于** agent 面的 `hosts`(只 Name+Tags、凭据无关,走 `Public()`)。
- `inventory edit`:保留为指向手改文件的占位(或删除)。本设计不做完整编辑器。

不做:删除/编辑主机的 TUI(可后续 `inventory rm` / 表单编辑)、group 管理、注释保留(见 §4 取舍)。

## 2. 加主机表单(`internal/hostform`,bubbletea v1)

新建独立包 `internal/hostform`(自包含,不污染只读审计 `internal/tui`)。

- 字段(tab 顺序):`name, addr, user, port, tags, ssh_config_alias`,各一个 `bubbles/textinput.Model`;并行 `errs []string`(空=合法)。
- 焦点导航(`bubbles/key`,沿用 internal/tui 约定):`tab`/`down` 下一个,`shift+tab`/`up` 上一个,`enter` 提交,`esc`/`ctrl+c` 取消。
  - `Init()` 返回 `textinput.Blink`(表单一开始就有焦点,必须启动光标闪烁)。
  - `Update`:KeyMsg 先处理取消/导航/提交;其余消息(输入字符、blink tick)**只转发给当前聚焦的 input**;切焦点时 `Blur()` 旧的、`Focus()` 新的并把返回的 Cmd 透传。
  - 移动焦点时校验离开的字段;提交时全量校验,有错则跳到第一个错误字段。
- 非 TTY 拒绝(照搬 `internal/tui/tui.go` 的写法):`ErrNotInteractive` 哨兵 + `IsNotInteractive`;`interactive()` 用 `golang.org/x/term` 检查 stdin&stdout 两个 fd;`Run(opts) (Result, error)` 在非 TTY 直接返回 `ErrNotInteractive`(命令层据此走 flag 路径)。
- `Run` 用 `lipgloss.NewRenderer(os.Stdout)` + `NO_COLOR` 处理(同 tui)。返回 `Result{ Name, Addr, User, Port, Tags, Alias; Submitted bool }`(取消则 Submitted=false)。

### 校验规则(TrimSpace 后)
- `name`:必填;不含空白;**唯一**(不在已有 hosts 里 —— 已有名字集合由命令层经 `Options.ExistingNames` 传入,表单不 import inventory)。
- `addr`:**除非设置了 `ssh_config_alias`** 否则必填(alias 提供连接目标)。
- `user`:可选,空则结果取 `$USER`(兜底 `root`)。
- `port`:可选;非空须是 1..65535 的数字;空则默认 22。
- `tags`:逗号分隔,各 trim、丢空 → `[]string`。
- `ssh_config_alias`:可选(其存在放宽 addr 必填)。

## 3. 写回 inventory.yaml

命令层(非表单)负责实际读改写,**TTY/非 TTY 两条路径汇到同一个 writer**:

1. **不要用 `config.Load()`**(它在 home 目录不存在时报 `MissingHomeError`,而 add 要支持首次运行)。改:`home, _ := config.ResolveHome()`;`paths := config.NewPaths(home)`;若 `paths.InventoryFile` 存在则 yaml 解码进 `inventory.Inventory`(**解析失败要报错、绝不覆盖**坏文件),不存在则零值 Inventory。
2. `if inv.Hosts == nil { inv.Hosts = map[string]inventory.Host{} }`;若 `inv.Version == 0 { inv.Version = 1 }`。
3. **拒绝重名**:`if _, ok := inv.Hosts[name]; ok` → `newUsageError`(exit 2)。
4. `inv.Hosts[name] = inventory.Host{Addr,User,Port,SSHConfigAlias,Tags}`。
5. `os.MkdirAll(home, 0o700)`;**原子写**:`os.CreateTemp(home, "inventory-*.yaml")` → chmod 0600 → 写 `yaml.Marshal(&inv)` → `os.Rename` 覆盖 `InventoryFile`(防半写损坏原文件)。

### Schema 改动:加 `omitempty`(必要)
当前 `Inventory`/`Host` 的 yaml tag **无 `omitempty`**,struct round-trip 会写出 `version: 0`、每个 host 的 `port: 0`、空 `user/ssh_config_alias/tags` —— 又脏又可能误导。**给 `inventory.go` 的可选字段加 `,omitempty`**:`Inventory.Transport/HostKeyPolicy`、`Host.User/Port/SSHConfigAlias/Tags`、`Groups`、`Version`(写前已置 1 故不会被省)。`Addr` 也可 omitempty(alias 场景为空)。**unmarshal 不受影响**(omitempty 只影响 marshal),仅 marshal 输出变干净。若 `inventory_test.go` 有 marshal golden 断言需同步;unmarshal 测试不受影响。

### 取舍(写文档说明)
struct round-trip 会:丢失 YAML 注释、丢失结构体未建模的未知字段、map key 按字母排序(host 顺序变化)。当前 schema 无注释驱动配置、无未知字段,可接受。将来若 inventory.yaml 需要保留注释,改用 `yaml.Node` 保留式写入(更重)。

## 4. inventory ls 渲染

- 走 `config.Load()` + `classifyConfigError`(ls 在无 home 时报 MissingHomeError→exit2 指引,正确)。
- 读 `cfg.Inventory.Hosts`(完整 map),本地 `sort.Strings` 排序 key(`sortedHostNames` 未导出,命令层自己排,别扩 inventory API)。
- 文本:每 host 一行 `  <name>  addr=<addr> user=<user> port=<port> alias=<alias> tags=<a,b>`,空字段省略;groups 同 `hosts` 风格;可加一行 `transport=.. host_key_policy=..` 头。空时打 `(none)`。
- `--json`:`writeJSON(cmd, cfg.Inventory)`(完整结构,含 addr/user)—— 与 `hosts --json`(脱敏 PublicInventory)区分。

## 5. 命令接线 + 复用

`newInventoryCommand` 把两个 `leafNoArgs` 桩换成:真 `ls`(`Args: noArgs`,`--json` flag)、新 `add`(positional `[name]` + flags `--addr/--user/--port/--alias/--tags`)。复用:`classifyConfigError`、`usageError`/`newUsageError`、`noArgs`、`writeJSON`、退出码常量与 `exitCodeForError`。`golang.org/x/term` 已是依赖(无新依赖)。

## 6. 测试

- **纯逻辑**(可测,不需 TTY):校验函数(name/addr/port/tags)、`splitTags`、**writer**(给定 Inventory + 新 host → marshal,断言重名拒绝、首次运行建 maps/version、omitempty 输出干净、已有 host 保留)、ls 渲染(全字段、--json 含 addr/user)。
- **E2E(非 TTY,走 flag 路径,无需驱动表单)**:`runCommandForTest(t,"inventory","add","web-1","--addr","10.0.0.11","--user","deploy","--tags","web,prod")` → 读回 `inventory.yaml` 断言;再 `inventory ls` 断言显示 addr/user;`inventory ls --json` 断言完整结构;重名 add → exit 2;首次运行(空 home 子目录)add 能建目录+文件。
- 表单交互层(bubbletea)= 薄壳,靠 build + 手测(同 M3 审计 TUI 的处理方式)。
- `go test -race` 全过;gofmt/vet 干净;M0–M5 + native/streaming 既有测试不破。

## 7. 不做(未来)

`inventory rm` / 表单内编辑已有 host / group 管理 / YAML 注释保留(`yaml.Node`)/ 把 add 折进审计 TUI(故意不做,保持审计只读)。
