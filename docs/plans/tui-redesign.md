# TUI 优化北极星 (North-star Optimization Plan)

> 状态:**已全部实现** v1 · 创建于 2026-06-22 · 实现于 2026-06-23 · 分支 `tui-redesign` · 范围:`agentssh tui` 操作台(人类界面)的整体 UX 重构。
>
> 由多智能体设计工作流综合产出:6 个 UX 视角审计(41 条问题,13 个 P0)→ 3 个独立设计方向 → 评审打分(Polished Modern 32 / Guided 31 / Cockpit 29)→ 综合 → 对抗式审查 → 定稿。配套规范见 [`docs/DESIGN.md`](../DESIGN.md);架构见 [`docs/architecture/unified-tui.md`](../architecture/unified-tui.md)。

> 一句话北极星:一个操作台,四个 Tab 终于看起来像同一个产品。Audit 这个 Tab 已经证明团队能做出一屏好界面——本方案把它的骨架(状态条 + 主从面板 + 实测布局)推广到全 app,合并重复的样式系统,并让异步/安全状态默认可见。

---

## 实施进度 (Implementation status)

全部 P0/P1/P2 项已在分支 `tui-redesign` 实现,每个提交均通过 `gofmt`/`go vet`/`go build`/`go test -race ./...`/`golangci-lint`(0 issues),零新增依赖;每个阶段后做了一轮 worktree 隔离的对抗式审查并修复全部发现。下表把路线图条目映射到提交。

| 项 | 内容 | 状态 | 提交 |
|---|---|---|---|
| P0#1 | 启动自动校验链 | ✅ | `846e7d7` |
| P0#2 | 类型化异步路由(切 Tab 不丢) | ✅ | `846e7d7` |
| P0#3 | 四 Tab `lipgloss/table` 对齐 | ✅ | `846e7d7` |
| P0#4 | probe/discover spinner | ✅ | `846e7d7` |
| P0#5 | 教学空状态 + 首跑欢迎 | ✅ | `846e7d7` |
| — | P0 对抗审查修复(spinner tick 路由 · `t` 重入 · 首跑 `q`)| ✅ | `4066edb` |
| P1#6 | 合并样式系统 → `internal/theme` | ✅ | `f568ffb` |
| P1#7 | 字形解析器(NO_COLOR 真降级)| ✅ | `f568ffb` |
| P1#8 | 持久外壳 + `bubbles/help` 底栏 | ✅ | `1d2152e` |
| P1#9 | 实测响应式布局(干掉魔法数)| ✅ | `dfc9971` |
| P1#11 | Hosts 焦点枚举 + 统一键义 | ✅ | `7699607` |
| P1#10 | Hosts 主从面板 | ✅ | `d0dfd6f` |
| P1#12 | 状态词汇 / 字形(随 #6/#7)| ✅ | `f568ffb` |
| P1#13 | 友好错误卡 + 删除确认卡 | ✅ | `9d50a8a` |
| — | P1 对抗审查修复(宽度溢出 · 焦点卡死 · 残留错误 · 裁剪)| ✅ | `0ace703` |
| P2#15 | Toast 通道 | ✅ | `d3cd914` |
| P2#14 | 分组加主机表单 | ✅ | `db47823` |
| P2#16 | Sessions DEN/FAIL 列 | ✅ | `123f5f9` |
| P2#17 | 按主机 probe 结果 + 密码指示 | ✅ | `ba8e72a` |
| P2#18 | Discover 流式 probe + 逐行指示 | ✅ | `72ef5ba` |
| — | P2 对抗审查修复(footer 省略号预算 · 密码指示生命周期)| ✅ | `682b81d` |

下文为定稿设计(保留为设计依据 / 后续参考)。

---

## 诊断 (Diagnosis)

八个最高影响的问题,从最严重排起,每条都带真实代码定位。

1. **三个扁平 Tab 用 `strings.Join` 拼 `key=value` 文本,毫无对齐,工具读起来像调试输出。** 这是 Hosts/Policy/Sessions/Discover "看着没做完"的头号原因;操作者没法纵向扫一列去对比各行的 addr/status/action,Discover 的表头列跟数据根本对不上。→ `app.go:renderHostLine`(1032,`return strings.Join(parts, " ")`)、`app.go:discoveryView`(886,表头字面量 `"SEL NAME SOURCE ADDR KEY KNOWN_HOSTS INVENTORY STATUS"`)、`app.go:renderPolicyConfig`(1186,伪 YAML `Fprintf`)、`app.go:sessionsSection.View`(1274,`Fprintf("...label=%q start=%s...")`)。

2. **三套重复的样式结构体硬编码同一批 ANSI 码,且已悄悄漂移**(提示说两套,实际是三套)。→ 没有单一真相源,四个 Tab 永远统一不了;计划中"给 Hosts 加详情面板"也没法复用 Audit 的面板外观。→ `app.go:newAppStyles`(65)、`model.go:newStyles`(91)、`hostform.go` 的 `newStyles`。颜色 `"63"`、`"196"`、`"42"`、`"212"` 在每处各自重打一遍。

3. **安全关键状态只靠颜色一个信号,而 `prod` 在 Audit 里是亮色、在 Hosts 里却是纯文本——偏偏 Hosts 就是你删主机的那一屏。** → `NO_COLOR` 下(`tui.go:55-56` 设 `termenv.Ascii`)denied/failed/deny/prod 全糊成无法区分的文本;亮色终端上紫底紫字不可读。两种红已经撞车:`196` 同时表示 error、failed 事件、deny 决策,而 `prod` 又是第二种红(`203`)。→ `model.go:renderRow`(531,`styles.prod.Render("[prod]")`)对比 `app.go:renderHostLine`(1049,纯文本 `tags=prod`);`app.go:1166` 把 `err`(196)复用给 `ActionDeny`。全代码零 `AdaptiveColor`。

4. **哈希链——这产品存在的全部理由——默认把完整性显示成"未知"。** → 被篡改的日志和未校验的日志第一眼一模一样;操作者必须**知道**要按 `v`。对一个防篡改工具这是错的默认值。→ `model.go:chainStatus`(430)在 `!verifyDone` 时返回 `"链 ? (press v)"`;`model.go:Init`(202)返回 `nil`,而不去触发已经存在的 `verifyCommand`(195)。

5. **多秒级的 probe/discover 零进度反馈;慢链路和卡死的 TUI 无法区分。** → probe 最多阻塞 `ProbeTimeout = 10s`(`executor/native.go:38`);discover 把 N 个候选一个接一个跑。唯一反馈是一行冻住的 `"testing X..."`。→ `app.go:probeHostCmd`(512)、`app.go:loadDiscoveryCmd`/`probeDiscoveryCmd`(478/492);状态布尔 `s.discover.loading/probing` 只用来拦输入,从不驱动可见指示器。

6. **没有持久化的应用框架:Tab 条不是满宽,每个 Tab 各自打印自己的帮助行。** → `renderTabs` 漂浮着,活动 Tab 背景右侧留空;六条手写帮助串(`app.go:882/946/1182/1300`、`model.go:446`,加 Tab 条那条 dim 串)在措辞和字形上漂移(Hosts 教 `j/k`、Audit 教 `↑/↓`,教错了),且垂直位置不一致。→ `app.go:renderTabs`(226)、`app.go:View`(214,只有 `JoinVertical(tabs, body)`)。

7. **最常按的两个键最不可预测:`enter` 有三种含义、`esc` 有五种,且异步结果在切 Tab 时被丢弃。** → `enter` = 展开 / 开详情 / 提交测试 / 导入;`esc` = 取消表单 / 关 Discover / 退出过滤 / 退出焦点 / 在 Hosts 列表上静默空操作。更糟:`appModel.Update`(147)把通用消息只投给 `m.active`(`updateActive`,188)——切 Tab 后到达的 `hostProbeMsg`/`verifyMsg` 被静默丢失。只有 `WindowSizeMsg`(157)广播给所有 section。→ `app.go:464`(Hosts `esc`==`n`)、`model.go:69`(`enter`/`space` 都绑到 Toggle)、`app.go:188`。

8. **空状态/错误态只说"没有",从不说"下一步";坏掉的 `inventory.yaml` 把整个 Hosts 的操作锁死在一行隐晦的原始报错后面。** → 首跑落在 dim 的 `(no hosts)`,没有行动号召(`EnsureHome` 打印的 "initialized ~/.agentssh" 那行会被 alt-screen 擦掉)。手改坏的 inventory 会原样 dump `s.err.Error()`,并静默禁用 `a/d/r/x`。→ `app.go:hostsSection.View`(853,`(no hosts)`)、`app.go:841`(原始 `s.err` 渲染)、`app.go:418/427/451`(静默禁用)、`config.go:86`(`ParseError`)。

---

## 北极星 (North-star vision)

**手感:** lazygit 级别的操作台——任一时刻恰好只有一个面板拥有高亮焦点边框,每个列表都是对齐的表格,框架永不抖动:顶部满宽状态条(品牌 · Tab pip · 实时计数 · 自动校验的链徽章 · spinner),中间是 section 主体,底部一条 footer 作为键位 + 瞬时 toast 的唯一真相源。操作者学**一套**状态词汇(字形 + 文字 + 颜色,所以 `NO_COLOR` 下也活)和**一套**跨四 Tab 的键位,永远不用猜链有没有被校验、probe 是不是卡住了。我们扩展 Audit 那套已被验证的骨架,而不是另发明一种隐喻。

### 统一设计系统

**把三套样式系统合并成一个 `internal/tui/theme` 包。** 定义 `theme.Theme` + `newTheme(r *lipgloss.Renderer) Theme`,在 `newAppModel` 里构造一次,贯穿 `app.go`、`model.go` 和 `hostform.go`。删除 `newAppStyles`(app.go:65)与两处 `newStyles`(model.go:91、hostform.go)。Audit 的 `prod`/`bad` 映射到新的 `Prod`/`Danger` token;`app.go` 的 `confirm` 映射到 `Warn`。

**配色 token** —— 全部用 `lipgloss.AdaptiveColor{Light, Dark}`,亮色终端也保持可读。失败只用一种红;deny 和 prod 用不同色相,这样一次例行 deny 不会读起来像告警:

| Token | Dark (256) | Light (256) | 用途 |
|---|---|---|---|
| `Accent` / `BorderFocus` | 63 | 61 | 焦点面板边框、活动 Tab pip、标题 |
| `AccentText` | 15 | 231 | 强调背景上的文字 |
| `Border`(未聚焦) | 240 | 250 | 暗的面板边框 |
| `Text` | 默认前景 | 默认前景 | 主单元格文本(永不硬编码) |
| `Dim` | 241 | 245 | 帮助、占位符、次要单元格、规则 |
| `Success`(✓ ok/allow) | 42 | 28 | OK probe、allow、可达、链完整 |
| `Warn`(▲ caution) | 220 | 130 | 删除确认、needs-auth、allow-默认横幅 |
| `Danger`(✖ fail) | 196 | 160 | 解析错误、failed 事件、**篡改**——唯一的红 |
| `Deny`(⊘ deny) | 208 | 166 | policy DENY 判决——独立的橙,deny ≠ 崩溃 |
| `Prod`(PROD chip) | 203 | 124 | prod 主机的唯一允许 token,凡出现主机处都用 |
| `SelBg`(当前行) | 237 | 254 | 选中行高亮带 |

**`NO_COLOR` 是两段式降级,而且第二段不是自动的。** `tui.go run()` 只在存在 `NO_COLOR` 时设 `termenv.Ascii`(`tui.go:55-56`)。`termenv.Ascii` 剥掉**颜色**——但它**不**剥 Unicode 字形(`●▲✖⊘⠹✓❰❱`),所以"字形 + 文字兜底 NO_COLOR"的保证是假的,除非我们自己用代码降级字形。因此加一个**带测试的字形解析器**,按渲染器 profile 取值(见 P1 第 7 项的 `Glyphs`/`glyphsFor`):当 `r.ColorProfile() == termenv.Ascii`(`NO_COLOR` 分支,以及任何真正无色的 TTY)时返回 ASCII 兜底——`●→*`、`▲→!`、`✖→x`、`⊘→D`、`⠹→.`、`✓→OK`、`❰ ❱→> <`,chip 渲染成 `[PROD]`/`[DENY]`/`[key]`/`[pwd]`(本就是带括号的词)。每个状态渲染器(StatusCell、Chip、Spinner、Panel 标记、链徽章)都从这一个解析器读符号,这样**颜色永远不是唯一信号**——一个无法显示的字形也不会成为唯一信号。

**间距:** 行单行高,列间 2 空格 gutter,表格内无空行分隔。面板用 `RoundedBorder` + `Padding(0,1)`。上下两条 rail 用 `Padding(0,1)` 并通过 `.Width(m.w)` 满宽。内容高度**实测、不用魔法数**:`contentH = innerH − lipgloss.Height(strip) − lipgloss.Height(footer)` —— 替换所有 `h-8`/`h-4`/`h-5`/`w/2-2` 字面量。

**可复用组件(定义一次,跨全 Tab 含 hostform 共享):**

- **`StatusBar(w, spinnerView)`** —— 顶部 rail。左:`AgentSSH` 品牌 + Tab pip `[1 Hosts][2 Audit][3 Policy][4 Sessions]`(活动 = `Accent` 反色,数字 = 热键)。右:实时计数、自动校验的链徽章、以及全局 spinner(**作为预渲染字符串传入**——appModel 持有 spinner,见 P0 第 2、4 项)。
- **`Footer(w, bindings)`** —— 底部 rail,由 `bubbles/help.Model` 喂以聚焦 section 的 `key.Map`;`?` 切换短/全;右对齐放衰减的 **Toast** 槽。
- **`Table(cols, rows)`** —— 对 `lipgloss/table` 的薄封装(纯格式化器,每帧喂可见行;保留既有 cursor 状态)。计算列宽,数字列右对齐(PORT/CMDS/exit),长路径/命令截断,表头行用 `Dim`,当前行用 `SelBg` 上色。Hosts/Discover/Policy-rules/Sessions 的核心原语。
- **`StatusCell(kind)`** —— 共享的 `字形+文字+颜色` 渲染器(`● ok` / `▲ warn` / `✖ fail` / `⊘ deny` / `⠹ probing`)。字形取自 profile 解析器,颜色取自 theme。每个 STATUS 列同一套词汇。
- **`Panel(title, focused)`** —— `RoundedBorder`;聚焦 → `BorderFocus` + 强调标题;未聚焦 → `Border` + dim 标题 + `❰ ❱` 标题标记(Ascii 下降级为 `> <`),使焦点在 `NO_COLOR` 下也活(边框粗细在 Ascii 下会塌缩)。
- **`Chip`** —— 带 padding 的内联徽章(`[PROD]` 用 `Prod`,`[key]`/`[pwd]` 认证 chip,`[DENY]`)。本就带词,所以 NO_COLOR 降级纯粹是剥颜色。
- **`Spinner`** —— appModel 持有的一个 `bubbles/spinner.Model`;它的 `View()` 每帧渲染一次,并**作为渲染参数传给** `StatusBar`(以及展示内联耗时的 section 视图),因为通用消息默认只到 `m.active`(见 P0 第 2 项的路由修复)。
- **`Toast{text, kind, expiresAt}`** —— 按严重度上色,`tea.Tick` 清除(~3s),渲染在 footer 右侧。与持久状态、与确认提示分开。
- **`EmptyState(title, hint)`** —— 居中(`lipgloss.Place`)的 dim 标题 + 更亮的可行动提示 + 键帽 chip,替换所有裸 `(no X)`。
- **`ConfirmCard(target)`** —— 居中的 `Warn` 边框模态,用于破坏性删除;在自己的通道上复述目标 + 凭据副作用;高亮被定位的行。

### ASCII 原型(~74 列)

**(a) 全局框架 —— 两条 rail,跨四 Tab 持久**

```
┌────────────────────────────────────────────────────────────────────┐
│ AgentSSH [1 HOSTS][2 Audit][3 Policy][4 Sessions]  12 hosts · 3 sess │
│                          链 ● 完整 (1,204 seq)    ⠹ probing 4s       │
├────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                       « active section body »                        │
│                                                                      │
├────────────────────────────────────────────────────────────────────┤
│ j/k move · / filter · a add · d discover · t test · enter inspect    │
└────────────────────────────────────────────────────────────────────┘
```

`NO_COLOR` 下同一框架降级(颜色剥掉,字形由解析器替换):

```
  AgentSSH [1 HOSTS][2 Audit][3 Policy][4 Sessions]  12 hosts · 3 sess
                           链 * 完整 (1,204 seq)    . probing 4s
  ------------------------------------------------------------------
  j/k move · / filter · a add · d discover · t test · enter inspect
```

顶部 `StatusBar` + 底部 `Footer` 持久;只有 body 变化。Tab pip 就是 Tab 条(活动 = 强调反色)。链徽章启动即自动校验(不用 `press v`),沿用既有 `链` 词汇。spinner + 耗时由 appModel 持有,在任何异步操作时渲染进状态条(其值传入,而非从活动 section 读)。Toast(如 `✓ host added`)在 footer 右侧自动消失。外框仅为示意——两条 rail 是满宽样式行,body 无边框。

**(b) Hosts —— 主从布局(`i`/Tab 切右侧面板)**

```
 Hosts you can reach. Pick one to test, inspect, or remove.
┏━ Hosts ━━━━━━━━━━━━━━━━━━━━━━━┓┌─ web-1 ───────────────────┐
┃ NAME            ADDR    PORT ┃│ addr     10.0.0.11        │
┃▌web-1 [PROD]    10.0.0.11 22 ┃│ user     deploy           │
┃ db-2            10.0.0.31 5432┃│ port     22              │
┃ greencloud-sg…  203.0.113.7 22┃│ alias    web-prod        │
┃ staging-7       10.0.2.7  22 ┃│ identity ~/.ssh/web-1 [key]│
┃ bastion         bastion… 2222┃│ password — (not stored)   │
┃                       1/6  ↑↓┃│ tags     web, PROD        │
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛│ probe    ● ok             │
                               └───────────────────────────┘
```

`lipgloss/table`:NAME/ADDR 左对齐,PORT 右对齐,长名中间截断。`[PROD]` chip 在行和详情卡里都用 `Prod` 上色(修第 3 条 P0:Hosts 里 prod 此前未上色)。AUTH 永不显示密钥——`identity_file` 是带 `[key]` 的路径;密码字面写 `— (not stored)` 或 `● stored (encrypted)`。详情面板可发现(footer 里可见 `i inspect`;Enter 自动打开,新手不会被困)。聚焦面板 = `BorderFocus` + `❰web-1❱` 式标题标记(Ascii 下 `>web-1<`)。`t` 触发 probe → STATUS 变 `⠹ probing` 并跑状态条 spinner。

**(c) 加主机表单 —— 分组,短字段并排**

```
 AgentSSH › Add host                       esc cancel · enter save
─────────────────────────────────────────────────────────────────
 ── Connection ─────────────────────────────────────────────────
   name [ web-3          ]  user [ root      ]  port [ 22 ]
   addr [ 203.0.113.42                                      ]
 ── Routing ────────────────────────────────────────────────────
   tags [ sg, PROD       ]  ssh_config_alias [ gc-sg        ]
 ── Auth ───────────────────────────────────────────────────────
   identity_file [ ~/.ssh/gc_sg_ed25519        ]  (path, stored)
   password      [ ••••••••                     ]  (encrypted)
   ▸ identity_file is a PATH saved in inventory; password is
     encrypted (age) and never shown.
   ⚠ AGENTSSH_MASTER_PASSWORD not set — password won't save
─────────────────────────────────────────────────────────────────
 tab/↓ next · shift-tab/↑ prev · enter save · esc cancel
```

三个带标题、用横线分隔的分组替换扁平的 8 输入框堆叠(`hostform.go:Model.View`)。短字段水平配对(`user|port`、`tags|alias`)。AUTH 注释在录入处就说明凭据规则;`AGENTSSH_MASTER_PASSWORD` 前置条件在密码字段非空时用 `Warn` 浮现——在**提交前**,这样填了密码也不会失败丢弃。提交失败时表单回填原值(不丢数据)。窄终端把堆叠塞进 viewport 滚动。

**(d) Discover 浮层 —— 对齐表格,字形布尔,多选**

```
┌─ Discover from ~/.ssh/config + known_hosts ──── ⠹ probing 3/6 ──┐
│ SEL NAME           SOURCE  ADDR         KEY KNW INV STATUS      │
│ [x]▌greencloud-2   config  203.0.113.51  ●   ·   ·  ⠹ probing   │
│ [x] web-3          config  10.0.0.13     ●   ●   ·  ● reachable │
│ [ ] old-jump       known   1.2.3.4       ·   ●   ·  ▲ needs-auth│
│ [ ] db-2           config  10.0.0.31     ●   ●   ●  · in invtry │
│ [ ] scratch        known   192.168.1.9   ·   ●   ·  ✖ unreach   │
│ note: db-2 already in inventory; skipped on import             │
├────────────────────────────────────────────────────────────────┤
│ space select · a all · p probe · enter import reachable · esc   │
└────────────────────────────────────────────────────────────────┘
```

替换那个跟谁都对不齐的空格拼接表头(`discoveryView` 886)。`lipgloss/table` 让表头与单元格对齐。KEY/KNW/INV 是字形单元格(`● 存在 / · 缺失`,降级为 `* / .`),不再是 `yesNo` 词(`app.go:990`)。STATUS 是 `StatusCell`。表头 spinner 串是 appModel 持有的 spinner 传入浮层视图。note 放在数据**上方**(今天埋在数据下面)。多选是唯一带选择的 Tab——`Space` 切换,`a` 全选,Enter 导入可达且已选的。

**(e) Policy —— 姿态横幅 + 上色动作表 + 判决**

```
 Your command policy. deny is a hard async boundary — no prompts.
┌──────────────────────────────────────────────────────────────┐
│ DEFAULT POSTURE:  ⊘ DENY — commands must match an allow rule  │
└──────────────────────────────────────────────────────────────┘
┏━ Rules (4) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ NAME           ACTION   CMD REGEX                            ┃
┃▌read-only      ● ALLOW  ^(ls|cat|tail|grep|systemctl status) ┃
┃ block-rm-rf    ⊘ DENY   rm\s+-rf\s+/                         ┃
┃ no-shutdown    ⊘ DENY   ^(shutdown|reboot|halt)              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
 overrides:  db-2 → ⊘ DENY (2 allow rules)
 test> web-1: rm -rf /tmp/cache    →  ⊘ DENY · rule=block-rm-rf
─────────────────────────────────────────────────────────────────
 j/k move · / focus test · enter evaluate · esc clear
```

替换 `renderPolicyConfig` 的伪 YAML 块。用一个按姿态上色的姿态横幅打头,亮出最重要的单一事实——默认 ALLOW 还是 DENY(DENY = `Deny` + ⊘;allow-默认 = `Warn`,因为默认放行更危险)。规则成表,ACTION 是上色的 `StatusCell`。host_overrides 显示**改了什么**(而非 `allow_rules=N`)。`/` 聚焦测试输入(到处保留给 filter/聚焦输入——永不重载);判决读起来像一个盖章的裁定。

**(f) Sessions —— 带异常列的仪表盘(DEN/FAIL 列见 P2,需补数据)**

```
 Recorded agent sessions. enter opens the session in Audit.
┏━ Sessions (3) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID       LABEL          AGENT     WINDOW       CMDS DEN FAIL ┃
┃▌s-3f9a   nightly-deploy claude    14:01–14:09   42   0   0  ┃
┃ s-77b1e  db-migrate     cron-bot  13:30–13:52   18   2   1  ┃
┃ s-0c4d   adhoc          operator  11:05–11:06    3   0   0  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
─────────────────────────────────────────────────────────────────
 j/k move · enter open in Audit · / filter · q quit
```

对齐表格替换 `Fprintf` 摘要行。WINDOW 用 `HH:MM–HH:MM`(Audit 的 `clockOf`),不再是两个溢出的 RFC3339 戳。CMDS 右对齐。**DEN/FAIL 列属 P2**(需要数据接管——见路线图);此前先上 ID/LABEL/AGENT/WINDOW/CMDS。`enter` 仍发 `sessionSelectedMsg` → Audit 会话过滤。

**Audit Tab —— 只改增量(保留其优点):** 保留双栏列表 + 边框详情 + 状态条——它们就是模板。① 从 `Init()` 触发 `verifyCommand`,徽章自动解析成 `链 ● 完整`/`链 ✖ 断于 seq N`;在途显示 `链 ⠼ 校验中…`。② 把 `newStyles` 换成共享 `theme`;`prod`→`Prod`、`bad`→`Danger`,新增独立的 `Deny` token,使 `renderRow` 不再用与篡改相同的 `196` 给一次例行 deny 上色。③ 渲染共享 `Footer` 代替 `helpLine`。④ 给详情 `hostLine`(model.go:785,当前纯文本)的 `[prod]` 上色。⑤ 让 `iconFor`(model.go:736)走新的字形解析器,使既有 Audit 字形也在 Ascii 下降级。

---

## 实施路线图 (Phased roadmap)

按尽快交付价值排序。工时:**S** ≤ 半天,**M** ≈ 1–2 天,**L** ≈ 3–5 天。

### P0 —— 快赢(高影响,低成本)

1. **启动时自动校验链。** *(S)* —— 每小时性价比最高,先做。把 `model.Init`(model.go:202)从 `return nil` 改成 `return m.verifyCommand()`(已存在,model.go:195)。更新 `chainStatus`(model.go:430)在途渲染 `链 ⠼ 校验中…` 并去掉 `(press v)` 哨兵;`v` 保留作手动重校验。**技术:** 从 `Init` 返回已有 `tea.Cmd`;把 `verifyMsg` 路由给 `sectionAudit`(见 P0 #2)。

2. **加类型化路由,异步结果切 Tab 时不丢。** *(S)* —— 今天只有 `WindowSizeMsg`(app.go:157)广播给每个 section,其他所有消息经 `updateActive`(188)只到 `m.active`,所以操作者切 Tab 后到达的 `verifyMsg`/`hostProbeMsg`/`discovery*Msg` 会丢失——这是净新增的路由代码,不是复用既有广播。在 `appModel.Update`(147)的 `updateActive` 兜底**之前**加一个 type-switch,把每个异步结果投给发起它的 section:`verifyMsg`→`sectionAudit`、`hostProbeMsg`/`discovery*Msg`→`sectionHosts`。**技术:** 既有的 `runID` 守卫(app.go:356/371)让向后台 section 的定向投递是安全的;只有 spinner tick(第 4 项)是真正需要广播给所有消费者的。

3. **三个扁平 Tab + Discover 换 `lipgloss/table`。** *(M)* —— 最大可见收益。把 `renderHostLine`(app.go:1032)、`discoveryView` 的表头+行(886)、`renderPolicyConfig` 规则(1186)、`sessionsSection.View`(1274)换成 `table.New().Headers(...).Rows(visibleRows...)`。**技术:** `lipgloss/table` 是纯格式化器——每帧喂既有的可见窗口切片,保留当前 cursor/选择状态,用 `StyleFunc` 给当前行涂 `SelBg`、数字列 `.Align(lipgloss.Right)`。布尔 → `● / ·` 字形单元格(经解析器),不是 `yesNo`(app.go:990)。

4. **probe/discover 加 spinner,由 `appModel` 持有。** *(S–M)* —— 给 `appModel` 加一个 `bubbles/spinner.Model`。在触发 `probeHostCmd`/`loadDiscoveryCmd`/`probeDiscoveryCmd`(app.go:512/478/492)时置 `busy` 标志并 `tea.Batch(theCmd, spinner.Tick)`。在 `appModel.Update` 加一个显式 `spinner.TickMsg` case,推进 appModel 持有的 spinner 并在 `busy` 时重发其 tick——这是唯一广播给所有视图的消息,所以放在 `updateActive` 之前处理(与第 2 项 type-switch 配套)。把 `spinner.View()+" testing X… 4s"` 渲染进状态条——通过**把 spinner 的 `View()` 作为渲染参数传下去**给 `StatusBar` 和 Discover 浮层,而非从活动 section 读。结果到达即停。**技术:** 标准 bubbletea 周期性 `Tick` 模式;配一个 1s `tea.Tick` 计耗时秒数。

5. **教学型空状态 + 首跑欢迎。** *(S)* —— 加 `EmptyState(title, hint)` 辅助;替换 `(no hosts)`(app.go:853)、`(no candidates)`(901)、`(no sessions)`(1283)、`(no records)`(model.go:481)。Hosts 首跑:居中 `lipgloss.Place` 卡片 `No hosts yet · [a] add  [d] discover`。**技术:** 把 `EnsureHome` 的 `created` 布尔穿进 `tui.Options`,让欢迎横幅替代被 alt-screen 擦掉的 stderr 行。

### P1 —— 结构性

6. **三套样式结构体合并成一个 `theme.Theme`。** *(M)* —— 不可妥协的清理,解锁后续一切。建 `internal/tui/theme`;删 `newAppStyles`(app.go:65)和两处 `newStyles`(model.go:91、hostform.go);在 `newAppModel` 里构造一次 `newTheme(r)` 并传下去。每个 token 用 `lipgloss.AdaptiveColor`。**技术:** 机械式查找替换;更新 `app_test.go`/`model_test.go` 构造器。Audit 的 `prod→Prod`、`bad→Danger`,新增独立 `Deny`。

7. **按 profile 取字形的解析器 —— 让 NO_COLOR 降级成真且有测试。** *(S–M,脊梁)* —— `termenv.Ascii` 剥颜色但**不**剥 Unicode 字形,所以今天的"字形+文字"安全保证未达成。在 `theme` 包加 `Glyphs` 集合和 `glyphsFor(r *lipgloss.Renderer) Glyphs`:当 `r.ColorProfile() == termenv.Ascii`(`tui.go:55-56` 在 `NO_COLOR` 时设的分支,以及任何无色 TTY)返回 ASCII 兜底集(`●→*`、`▲→!`、`✖→x`、`⊘→D`、`⠹→.`、`✓→OK`、`❰ ❱→> <`);否则用 Unicode 集。把解析出的 `Glyphs` 穿进 `StatusCell`、`Chip`、`Spinner` 帧、`Panel` 焦点标记、链徽章、`iconFor`(model.go:736)。**技术:** 一个解析器 = 一处维护正确性;加一个表驱动测试,构造一个 `SetColorProfile(termenv.Ascii)` 的渲染器,断言每个组件只渲染 ASCII(无 > 0x7F 的 rune)——这个测试就是保证,而非文档承诺。与第 6 项一起做,因为两者都在 `theme` 包、都为共享组件把关。

8. **持久三段式框架 + 一条 `bubbles/help` footer。** *(M)* —— 重写 `appModel.View`(app.go:214)为 `JoinVertical(statusBar, body, footer)`。`renderTabs`(226)变成满宽 `StatusBar`(`.Width(m.w)` + `BorderBottom`),把 appModel 持有的 spinner 视图作为参数接收。删除六条内联帮助串(app.go:882/946/1182/1300、model.go:446);渲染一个由各 section 的 `key.Map` 喂养的 `help.Model`。**技术:** 每个 section 暴露一个 `key.Map`(今天只有 Audit 有,model.go:55)——推广该模式;`?` 切换 `help.ShowAll`。

9. **实测的响应式布局 —— 干掉魔法数。** *(L)* —— 基础工程;在多面板框架"安全"前先做。一次算出 `contentH = innerH − lipgloss.Height(statusBar) − lipgloss.Height(footer)`;把余量交给每个 section 一个 `bubbles/viewport`。替换 `leftWidth`/`listHeight`(model.go:460/471)、`visibleNames` 的 `h-8`(app.go)、`h-4`/`h-5`。加:框架钳制 `MaxWidth(m.w).MaxHeight(m.h)`;~70 列以下把列表叠在详情之上,~40 列以下显示"终端太小"卡片。**技术:** 用 `lipgloss.Height` 量已渲染的框架,而非字面量;viewport 滚动可见性(`ScrollPercent` gutter + `row N/M`)。

10. **Hosts 主从 + 焦点面板强调。** *(M)* —— 镜像 Audit 的 `JoinHorizontal(left table, right Panel)`。右 `Panel` 显示选中主机的卡片(addr/user/port/alias、identity_file 路径、`[key]`/`[pwd]` chip、tags、prod chip)。焦点模型:`Tab`/`h`/`l` 循环面板;聚焦面板获 `BorderFocus` + `❰ ❱` 标题标记(由第 7 项降级)。Enter 自动开详情;`i` 切换。**技术:** 把 Audit 的焦点枚举(model.go:47)复制进 `hostsSection`;复用共享 `Panel`。

11. **统一键义 + 模态模型。** *(M)* —— 给 `hostsSection` 一个焦点枚举(`focusList/focusForm/focusConfirm/focusDiscover`)替换三个临时布尔(`capturing()`,app.go:317)。到处用稳定动词:`Enter`=主激活、`Space`=切换选择(仅在有选择处)、`Esc`=回退一层、`q`=仅顶层退出、`Ctrl+C`=永远退出、`/`=过滤/聚焦输入(永不作测试)。修 `esc`==`n` 空操作(app.go:464)和"移动光标会取消待确认"的坑(app.go:410/415 清 `s.confirm`)。**技术:** 单一按焦点 dispatch 的 switch;`key.Matches` 跨 section 统一。

12. **状态词汇 + 冗余编码(`StatusCell`/`Chip`)。** *(S–M)* —— 引入 `StatusCell`(`● ok / ▲ warn / ✖ fail / ⊘ deny / ⠹ probing`)和 `Chip`(`[PROD]`、`[key]`/`[pwd]`),两者字形取自第 7 项解析器、颜色取自第 6 项 theme。用在每个 STATUS 列并修 prod 那条 P0:在 Hosts 表和 `model.go:785` 检测 prod tag。Policy 判决 + 链徽章用同一个字形+文字渲染器。**技术:** 有第 7 项在,这步是把组件接到解析器,不是重新决定兜底。

13. **友好的错误/确认卡片。** *(M)* —— 坏 inventory 用 `ErrorCard`:`Danger` 边框标题、文件路径单独成行、可得时显示 yaml 行号、一个恢复键(`R` reload)。`s.err != nil` 时把 `a/d/r/x` 在 footer 里**变暗**显示,让人看到键为何不工作(app.go:418/427/451 今天静默吞掉)。删除用 `ConfirmCard`:居中 `lipgloss.Place` 的 `Warn` 边框框,复述目标 + 凭据副作用,走自己的通道(非被重载的 `s.status`,app.go:456),高亮被定位的行。

### P2 —— 打磨

14. **分组的加主机表单。** *(M)* —— 把 `hostform.Model.View`(320)重写成三个带标题的 `FieldGroup`(Connection/Routing/Auth),用 `JoinHorizontal` 配对短字段,加凭据规则注释和提交前的 `AGENTSSH_MASTER_PASSWORD` 内联告警。提交失败回填(不丢数据)。窄终端包进 `viewport`。**技术:** 分组既有 `[]textinput`;保留一个焦点索引但跳过非输入单元格。

15. **Toast 通道。** *(S)* —— `Toast{text, kind, expiresAt}` 由 `tea.Tick` 清除(~3s),渲染在 footer 右侧;把 "host added"/"imported 2"/"master password required" 走它,而非粘滞的 `s.status`(app.go:341/681)。

16. **Sessions DEN/FAIL 异常列。** *(M —— 推迟,需数据接管)* —— `session.Summary`(session.go:136)**没有** denied/failed 字段;那些计数只活在 Audit 模型的 `sessionGroup`(`makeGroup`,model.go:591)。通过扩展 `Summary` 或共享 group 构建器让两视图一致来上线;非零 DEN 用 `Deny`、FAIL 用 `Danger`。**在此之前,Sessions 不带这些列上线。**

17. **持久化最近 probe 判决 + Hosts 详情里的"密码已存"。** *(M —— 推迟,净新增状态)* —— `hostProbeMsg`(app.go:302)丢弃 `executor.Result.Duration`(executor.go:29);probe 判决是 section 级临时串,非按主机持久。"密码已存"需要按主机键查 age 密钥库(今天只在 add 时触碰,app.go:717)。加按主机 probe 状态 + 一个非密的 `secrets.Has(host)` 检查。P2——别堵脊梁。

18. **Discover 逐行 spinner + 流式 probe 结果。** *(S —— 推迟)* —— `Candidate`(discovery.go:29)没有在途标志。加按候选状态;让 `probeDiscoveryCmd` 发增量消息,经既有 `mergeProbedCandidates`(app.go:688)合并,使行随完成逐个解析。

---

## 风险与取舍 (Risks and tradeoffs)

- **工时诚实版:这是 2–3 周,不是"几天"。** 便宜的 P0(自动校验、类型路由修复、表格替换、spinner、空状态)是实打实的,几天内可上。但实测布局系统(第 9 项)是横切重写——今天每个 section 各算各的 viewport——且它必须先于多面板框架落地才安全。字形解析器(第 7 项)很小,但它是**脊梁,非点缀**:不做它 NO_COLOR 保证就是假的,所以它随 theme 合并一起上,不进 P2。别让推迟项(16–18,各需净新增状态)堵住 P0/P1 脊梁。

- **theme 合并爆炸半径可测。** 合并三个结构体会动 `app.go`、`model.go`、`hostform.go` 加 ~750 行测试(`app_test.go`、`model_test.go` 构造旧的构造器)。机械但面广——作为一个聚焦的 P1 commit(带测试)在叠新组件前做完。字形解析器落在同一个包、同一次评审。

- **路由是净新增,非复用。** "广播"的心智模型有误导:今天只有 `WindowSizeMsg` 广播。第 2、4 项加显式类型化 case——结果的定向投递(由 `runID` 守卫)和真正只为 appModel 持有的 spinner tick 做扇出,其 `View()` 随后**传下去**给展示它的视图。把这当作真实管线对待,为"切 Tab 后结果到达"路径配自己的测试。

- **密度 vs 引导。** lazygit 美学为常驻操作者优化;每月才用一次的操作者由教学标题、`EmptyState` chip 和常驻 footer 服务。缓解:让详情可发现(Enter 自动开、可见的 `i inspect`),每 Tab 标题保持一行。若日后惹恼日常用户,用首跑标志门控——但先上。

- **窄终端是弱点。** 两个边框面板 + header + footer 吃掉 ~6 列 / ~5 行框架。响应式兜底(< 70 列叠放、< 52 隐藏详情、< 40 守卫)是折进第 9 项的净新增工作——预留预算,别脚注带过。

- **`NO_COLOR` 与低色终端。** 两种不同的失败模式,都已处理:(1) 颜色被 `termenv.Ascii` 剥掉,所以每个状态**必须**还带字形+文字;(2) `termenv.Ascii` 不剥 Unicode,所以字形本身必须降级——由 profile 解析器(第 7 项)处理,配一个"Ascii 下禁止非 ASCII rune"的测试。边框粗细焦点也会塌缩,所以焦点带 `❰ ❱`/`> <` 标题标记。三种偏红色相(Danger/Deny/Prod)在 16 色终端塌缩,这没问题,**因为**字形/文字才是真信号。这种冗余花几列;是刻意的、强制的开销。

- **硬约束全程守住。** 全程不引入审批 UI——TUI 保持 VIEWER + manager;deny 仍是异步硬边界,渲染成判决而非提示。凭据永不显示:`identity_file` 是路径,密码在表单里遮蔽、只显示为 `— (not stored)`/`● stored (encrypted)`。不碰远端 `authorized_keys`。单一静态二进制、CGO 关闭——所有新引入(`lipgloss/table`、`bubbles/spinner`、`bubbles/help`、`bubbles/viewport`)都在锁定的模块版本里(`lipgloss v1.1.0`、`bubbles v0.21.0`),字形解析器复用已引入的 `muesli/termenv`,故零新依赖。既有的中英混排 `链 完整` 保留,不英语化。
