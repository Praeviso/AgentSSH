# 灰区命令异步审批系统 — 设计

> 状态:草案 v1.1 · 配套:`docs/architecture/overview.md`(§5 审批模型、§10 包结构)
>
> 一句话:在**不改动现有硬 `deny` 底线**的前提下,给「无规则覆盖的灰区命令」(`default-deny`)加一条**异步、非阻塞**的审批通道——`run` 立刻返回 `exit 7`,操作者事后在 `agentssh tui` 裁决,模型轮询/等待结果后干净重跑。审批结果可落为「本次 session 允许」或「该 host 始终允许」;`deny` 不持久化。
>
> **v1.1 修订(据 `approval-system-codex-review.md` 的对抗式评审 + 本地 Go 实测):** ① 泛化正则的空白由 `\s` 改为 `[ \t]`(`\s` 含换行,实测会被 `ls\nrm -rf /` 命中=注入);② 默认 `host_grant_mode` 由 `prefix` 改为 `safe-prefix`(prod 网关不默认放宽写类子命令);③ 删除不严谨的 deny 遮蔽探针,改纯靠分离引擎;④ host 规则来源标记由 `Group:"approval"` 改为保留名 `__agentssh_approval`(避免与用户规则组撞名);⑤ resolution 文件明确为**非授权依据**,只作通知;⑥ 审批 ID 规格化(≥96bit + `O_EXCL`)、`approval wait/status` 退出码与边界明确;⑦ 多 host 审批改为**先 preflight 再执行**。`\z`/`\A` 经实测 Go RE2 支持(评审转述误称不支持,以实测为准)。

## 1. 背景与定位

`overview.md` §5 的既定立场:AgentSSH 不做**同步**审批(不阻塞 `run`、不做人工实时裁决),只保留 `deny` 硬拦截 + 全量审计,灰区的交互确认委托给 harness。§10 为「可选的 out-of-band 异步审批」预留了 `internal/approval/` 空包。

本设计**落地那个预留项**,并明确它是既有架构的**扩展而非反转**:

- **没变**:explicit `deny` 规则仍是不可逾越的硬拦截,谁都不能临场放行;`default-deny`(无规则即拒)仍是兜底;凭据单向、审计 hash 链照旧。
- **新增**:灰区(`default-deny`)命令不再只能「被拒 exit 6」,而是可以走一条**异步审批**通道,由**操作者在 TUI**裁决,结果可持久化为 allow,从而「相似命令一次同意后不再问」。

定位上的诚实话(见 §11):**目标部署是单机、同一个 OS 用户、交互式**。在这个前提下,审批是**防误操作/注入的护栏 + 完整可验证留痕**,不是防恶意 agent 的沙箱;唯一能变成物理硬墙的办法是让 agent 跑在独立 OS 用户/容器里(见 §11,列为可选 hard 模式,单机默认不做)。这与产品既有信任假设一致(README/SKILL 已要求 agent 只调 `run`/`hosts`)。

## 2. 适用范围与不可逾越的边界

审批**仅对灰区生效**。判定入口 `Authorize` 在基础策略判定之后分流:

| 基础判定 | 含义 | 走向 |
|---|---|---|
| `allow` | 命中 allow 规则 | 照常执行(不变) |
| `deny` 且 `Rule != "default-deny"` | **命中显式 deny 规则** | **硬拦截**:audit `denied` + `exit 6`,**不进审批通道、TUI 里不出现**(结构上无法被审批) |
| `deny` 且 `Rule == "default-deny"` | 无任何规则覆盖(灰区) | 进入审批通道 |

落地要点:在 `internal/policy` 导出常量 `RuleDefaultDeny = "default-deny"`(`policy.go:316` 已经返回这个字面量),让「是否灰区」成为符号判断而非魔法字符串比较。

## 3. 端到端流程(异步 / 非阻塞)

```
1. agent:  agentssh run web-1 --session s_ab12 -- systemctl status nginx
2. Authorize → default-deny 灰区,且 session/host grant 均未命中
   → 写 pending 请求 + audit(approval_requested)
   → 立刻返回 exit 7 + JSON:
        {"status":"approval_pending","id":"ap_<96bit>","host":"web-1",
         "cmd":"systemctl status nginx","proposed_scope":["once","session","host"]}
     (人读 stderr:已提交审批 ap_…,等操作者在 agentssh tui 裁决,通过后重跑此命令)
3. agent:  agentssh approval wait ap_… --timeout 10m   # 见 §7,可被打断;run 本身早已返回
4. operator(已在 agentssh tui · Approvals):看到该行 → 按 [o]nce/[s]ession/[h]ost/[d]eny
   → 写 grant(或 host 规则)+ audit(approval_granted{scope})
5. agent:  agentssh approval wait 立刻返回 {"verdict":"approved","scope":"session"}
6. agent:  重跑 agentssh run web-1 --session s_ab12 -- systemctl status nginx
   → Authorize 实时重判:仍是 default-deny → 命中 session grant → 执行 → 审计 → 回输出
```

关键安全性质:

- **`run` 永不阻塞**,因此永不挂死;无人值守时请求一直挂 pending,模型每次重跑/`wait` 都拿到 pending,**没有任何静默放行**(fail-closed)。
- **执行发生在重跑这条 `run` 上**,会**实时重新走 `Authorize`**:grant 只在该命令**仍是 `default-deny`** 时生效;若期间操作者新增了一条显式 `deny`,grant 立即失效。grant **永远越不过显式 deny**(见 §4)。
- **resolution 文件只是通知提示,不是授权依据**(见 §7):授权永远在第 6 步的 `run`→`Authorize` 处从 grant store / host 规则**重新推导**;伪造一份 `responses/<id>` 只能骗 `approval wait` 显示 approved,重跑仍会被 `Authorize` 拦下。

## 4. 授权判定 `Authorize`(分离引擎,保证显式 deny 不被遮蔽)

`host_overrides` 正常情况下先于 global tier 判定,所以一条写进 `host_overrides` 的 approval allow 规则,**天然有遮蔽掉同 host 显式 deny 的风险**。为根除这一点,`Authorize` 采用「分离引擎 + 仅在灰区分支查 grant」:

1. 深拷贝 `policy.Config`,**剔除所有 `host:<name>` override 里来源标记为 `__agentssh_approval` 的规则**(只剔除 `host:<name>` 键下的;group override 键不产生 approval 规则,见 §12),用这份「干净」配置跑**原封不动的** `policy.NewEngine` / `Evaluate`。`policy.Evaluate` 一行不改。
2. 得到基础 `Decision`:
   - `allow` → `Allow`(照常执行);
   - `deny` 且非 `default-deny` → `HardDeny`(硬拦截);
   - `default-deny` → 进入第 3 步。
3. **只在灰区分支**按序查 grant:① session grant store(§6);② 被剔除出来的那批 host approval matcher。命中 → `AllowByGrant`;都不命中 → `NeedsApproval`。

因为 grant 是「**严格在 default-deny 之后**才参与」的兜底裁决,它**不可能遮蔽任何 tier 的显式 allow 或显式 deny**——即便 host_overrides 物理上排在前面。举例:操作者对 `systemctl restart prod-db` 写了显式 deny,且存在 host approval 前缀 `systemctl restart *`(若启用 prefix 档)。当命令是 `systemctl restart prod-db` 时,干净 base 引擎先命中那条 deny → `HardDeny`,grant 根本不被查;当命令是 `systemctl restart web` 时,base 引擎无 deny 命中 → default-deny → grant 命中 → allow(`web` 本就没被 deny,放行正确)。**逐条命令都给出正确答案,无需任何额外的「前缀 vs deny 重叠」探针**(v1.0 的 P0/P1 探针既不严谨又会过度拦,已删除)。

双保险(仅为「裸读 policy」时的可读性,不参与授权):host approval 规则仍以 `priority:0` 落盘,使 `policy show` 这类**原始视图**把 approval 行排在操作者 deny 之下。`run` 与 `agentssh policy test` **都走 `Authorize`**,保证「测出来的判定 == 运行时判定」;任何展示原始 policy 顺序的视图须明确标注「raw, 非运行时语义」。

## 5. 粒度 / 泛化算法(核心)

把「一条具体命令」变成「一条可复用的 `cmd_regex` allow 规则」,目标是**相似命令一次同意后不再问**,同时**绝不把复合/可逃逸命令泛化成一张大网**。

调研结论:Claude Code 与 Codex 都收敛到「**保留 程序名 + 前导子命令,通配其余参数,遇到 shell 元字符就拒绝放宽**」。本设计采用同样的骨架,但因为 AgentSSH 的 grant 是**静默 + 持久**(无同步重弹窗兜底)、且 AgentSSH 是 **prod SSH 网关**(非本地开发工具),把安全护栏做得更硬、默认更保守。

### 5.1 引擎匹配方式决定了必须全锚定

引擎用**非锚定**的 `regexp.MatchString` 对**整条命令字符串**匹配(`policy.go:305`)。所以一条 `git status` 的非锚定正则会被 `git status; rm -rf /` 子串命中。**因此所有产出的正则必须 `\A … \z` 全锚定**(实测 Go RE2 支持 `\A`/`\z`;`\Z` 不存在、`$` 在默认模式等价 `\z` 但 `(?m)` 下变行敏感,所以统一只用 `\A`/`\z`)。这是硬约束。

> 旁注:README 里操作者手写的 `^systemctl status\b` 这类规则其实也有同样的复合命令绕过弱点(只锚了头)。本审批自动生成的 grant **比手写规则更安全**,因为它全锚定、空白只用 `[ \t]`(不含换行)、且尾部字符类不含任何 shell 元字符。

### 5.2 `approval.Generalize(cmd) → Matcher`

`Matcher{ Kind: prefix|exact, Regex string, Prefix []string, Promotable bool, SourceCmd string }`,`Regex` 直接当作 `Rule.Match.CmdRegex` 落盘,走现有 `compileRegex`(`policy.go:418`),**不引入新匹配代码**。

- **STEP 0** — 含 NUL 字节 → **拒绝该审批申请**(NUL 不该出现在正常命令里,不进 once/session/host 任何档)。
- **STEP 1 词法安全扫描** — 命令含下列任一 → **不可放宽,直接 exact**:
  - shell 元字符:`; & | ( ) { } ` 反引号 ` $ < > ' " \ * ? [ ] ~ ! #`;
  - **任何 C0 控制字节**(`\t \n \r \f \v` 等)与**任何非 ASCII 空白**;
  - 开头形如 `^\s*\w+=\S`(环境变量前缀 `LD_PRELOAD=… cmd`)。
  *这一步保证后续「按单一 ASCII 空格切词 == shell 分词」,从而无需自己写 shell 词法器(规避 sudo Baron-Samedit 那类解析漏洞)。*
- **STEP 2 切词** — 用**字节级、仅 ASCII 空格 `0x20` 为分隔**的切词器(**不用 `strings.Fields`**,它按 Unicode 空白切,会与远端 shell 和生成的正则不一致),切成 `argv=[t0,t1,…]`。
- **STEP 3 选前缀** — 一组**硬护栏:任何模式下都强制 exact**,与下面的「激进度」无关:
  - `t0 ∈ 解释器/可逃逸类`(`sh bash dash zsh ksh env find xargs awk gawk sed perl python* ruby node php vi vim nano emacs less more man tar zip unzip ssh scp rsync nc socat tee watch flock setsid ionice nohup`)→ **exact**。
  - `t0 ∈ 特权类`(`sudo su doas`)→ **exact 且 `Promotable=false`**(不允许写成 host 持久规则;只能 once/session)。
  - `t0 ∈ 破坏性 leaf`(`rm rmdir dd mkfs* shred shutdown reboot halt poweroff kill pkill killall chmod chown mv truncate fdisk parted`)→ **exact**。
  - 否则按 `host_grant_mode`(§5.4 / §10)决定是否**放宽到前缀**。
- **STEP 4 产出 RE2**(注意空白用 `[ \t]`,**绝不用 `\s`**):
  - 放宽:`\A` + `strings.Join(map(QuoteMeta,P), "[ \\t]+")` + `(?:[ \t]+[A-Za-z0-9@%+=:,./_-]+)*[ \t]*\z`
  - exact:`\A` + `QuoteMeta(cmd)` + `\z`
  - **不变量(代码内自检,违则测试失败/panic)**:每条正则必以 `\A` 开头、`\z` 结尾;**正则体内不得出现 `\s`、字面换行、或 `.*`**;尾部只用允许表字符类 `[A-Za-z0-9@%+=:,./_-]`(`-` 置末尾为字面;实现时可写 `[A-Za-z0-9@%+=:,./_\-]` 更直观)。该字符类不含任何 shell 元字符与换行,故即便在 exact 档,`$(`、`|`、`>`、换行也只能逐字节命中。
  - **威胁模型边界声明**:尾类里 `% @ , : + =` 等并非 shell 命令分隔符,保留它们是为「防 shell 分隔符注入」,**不是**「防语义层的能力放宽」(如某命令把 `@host` 当作扩权参数);后者超出本算法范围,靠 host 档的子命令白名单与操作者裁决兜。

### 5.3 写 host 持久规则时的去重(不再做 deny 探针)

host 提升前,扫该 host 现有规则,`Name` 相同或 `CmdRegex` 相同则跳过(防堆积)。**不再**做 v1.0 的 P0/P1「deny 遮蔽探针」——它既不严谨(对 exact deny 检不出、对 family deny 又过度拦),也多余(§4 的分离引擎已逐条命令保证显式 deny 永远先命中)。

### 5.4 默认激进度(v1.1:`safe-prefix`)

`host_grant_mode` 三档:

- **`exact`** — 一切 exact,零放宽(最严;相似命令仍会再问)。
- **`safe-prefix`(v1.1 默认)** — **只**对「精选只读家族」放宽到前缀;**写类子命令、读任意文件的命令、未列入白名单的程序一律 exact**。即:`t0` 是多路命令且 `t1 ∈ 该命令的 read-mostly 白名单`(如 `systemctl:{status,is-active,is-enabled,show,cat,list-units}`、`git:{status,log,diff,show}`、`kubectl:{get,describe,logs}`、`journalctl`)→ `P=[t0,t1]`;或 `t0 ∈ 只读 leaf 白名单`(如 `ls df free uptime uname hostname ps`)→ `P=[t0]`;**其余 exact**。白名单内容见 §15 待定。
- **`prefix`(类 CC/Codex,需操作者显式开启)** — 护栏之外尽量放宽到 程序名(+任意子命令),包括写类(`systemctl restart *`、`git push *`)与读任意(`cat *`)。**问得最少,但会放宽写类、且 policy.yaml 会漂移**——仅建议在你充分理解风险时开启。

> 取舍:CC/Codex 默认前缀且有同步重弹窗兜底;AgentSSH 的 host grant 静默+持久、且面向 prod,所以默认收到 `safe-prefix`。想要 CC 式顺滑可切 `prefix`,或对单条写类命令每次手动选 `host`。

### 5.5 示例(`safe-prefix` 默认下)

| 输入命令 | STEP 结果 | 产出正则 | 范围 |
|---|---|---|---|
| `systemctl status nginx` | 多路 + read-mostly → `P=[systemctl,status]` | `\Asystemctl[ \t]+status(?:[ \t]+[A-Za-z0-9@%+=:,./_-]+)*[ \t]*\z` | prefix;之后 `systemctl status sshd` 不再问 |
| `systemctl restart nginx` | 多路但 `restart` 非 read-mostly | `\Asystemctl[ \t]+restart[ \t]+nginx\z`(exact) | **exact**(safe-prefix);仅 `prefix` 档才会放宽 |
| `ls -la /var` | 只读 leaf 白名单 → `P=[ls]` | `\Als(?:[ \t]+[A-Za-z0-9@%+=:,./_-]+)*[ \t]*\z` | prefix |
| `cat /etc/passwd` | 读任意文件,不在白名单 | `\Acat[ \t]+/etc/passwd\z`(exact) | **exact**(safe-prefix) |
| `git -c core.pager=… log` | 多路但 `t1=-c` | `\Agit[ \t]+-c[ \t]+core\.pager=…[ \t]+log\z`(exact) | exact(绝不 `git *`) |
| `sudo systemctl restart nginx` | `t0=sudo` 特权 | `\Asudo[ \t]+systemctl[ \t]+restart[ \t]+nginx\z`(exact) | once/session 限定,**host 档禁用** |
| `rm -rf /var/tmp/cache` | `t0=rm` 破坏性 | `\Arm[ \t]+-rf[ \t]+/var/tmp/cache\z`(exact) | exact,永不裸 `rm` |
| `cat /etc/passwd \| grep root` | STEP 1 命中 `\|` | `\Acat[ \t]+/etc/passwd[ \t]+\|[ \t]+grep[ \t]+root\z`(exact) | exact;`\| grep …` 永不搭便车 |
| `ls\nrm -rf /`(未来命令撞前缀) | — | 前缀正则用 `[ \t]` 不含 `\n` | **不命中**(实测:`\s` 版会命中=注入,故必须 `[ \t]`) |

## 6. 授权范围与持久化

三种裁决:

- **once** — 一次性,仅放行**这一条逐字节相同的命令**(绑 `approval_id` + exact cmd),被下一次匹配的 `Authorize` **在锁内消费一次**后即删,防两个并发重跑花同一张 once。不持久化为规则。
- **session** — **本次 session 允许**,写入 session grant store(下),绑 `(session_id, host)`,默认 exact(`Generalize` 在 once/session 档固定 exact;只有 host 档才按 `host_grant_mode` 放宽)。TTL 默认 12h(绝对,自 `updated` 起),`agentssh session end <id>` 可立即清。**绝不写进 policy.yaml**。
- **host** — **该 host 始终允许**,经现有 `policy.AddHostRule`(`store.go:237`)→ `saveValidatedPolicy` 写 `host_overrides["host:<name>"]`,规则形如:
  ```
  Rule{ Name:"approval/"+matcherSHA12, Priority:0,
        Match:{CmdRegex: matcher.Regex}, Action:ActionAllow, Group:"__agentssh_approval" }
  ```
  来源标记用**保留名** `__agentssh_approval`(在 `CreateGroup`/`StampGroupOntoHost` 里拒绝该名,避免与用户规则组撞名)。可用 `RemoveHostGroup(host,"__agentssh_approval")`(`store.go:386`)一键批量移除。
- **deny** — 一次性拒绝,**不持久化**(下次同命令仍会再次进入审批通道)。

### 6.1 数据模型(均在 `$AGENTSSH_HOME/approvals/` 下,0700/0600)

- **审批 ID**:`ap_` + **≥96bit 随机**(hex),用 `O_EXCL` 创建 pending,ID 碰撞当硬错。(不要复用只有 3 字节随机的 `audit.NewReqID`——那对审计标签够、对授权状态太弱。)
- **session grant store** — `approvals/sessions/<sha256(session_id)>.json`(文件名哈希化,兼容 `base@host` 这类 id;原始 id 存文件内校验):
  ```json
  { "version":1, "session_id":"s_ab12", "host":"web-1", "updated":"…Z",
    "grants":[ { "kind":"prefix", "regex":"\\Asystemctl[ \\t]+status(?:…)*\\z",
      "prefix":["systemctl","status"], "source_cmd":"systemctl status nginx",
      "host":"web-1", "granted_ts":"…", "expires_ts":"…",
      "approval_id":"ap_…", "req_id":"…", "channel":"tui" } ] }
  ```
  读时忽略过期项、写时惰性清理;每条 grant 带 `host`,匹配时要求 `host==target.Name`。读改写用 `syscall.Flock(LOCK_EX)`(对齐 `audit.Append`)+ `fileutil.WriteFileAtomic(…,0o600)`,按 `regex` 去重。**裁决方只写、`run` 只读**。
- **pending 请求** — `approvals/pending/<id>.json`:`{id, req_id, session_id, host, cmd, cmd_sha256, candidate_matcher, matcher_sha256, kind, promotable, ts}`,`run` 用 `O_EXCL` 原子写。
- **resolution(结果)** — `approvals/responses/<id>.json`:`{id, req_digest, verdict:approved|denied, scope:once|session|host, ts}`,其中 `req_digest = sha256(id||req_id||session_id||host||cmd_sha256||matcher_sha256||scope)`。`approval status`/`wait` 读它并**校验 `req_digest` 与对应 pending 一致**,防陈旧 resolution 被串到另一个同名请求。**resolution 是通知,不是授权**(§3/§7);无 HMAC,故同 uid 仍可伪造它(见 §11)——但伪造它不构成授权绕过,因为执行走重跑 `Authorize`。

## 7. 通知机制(模型怎么知道批了)

跨进程边界无法 push,落地为「模型来查」,三选一(`run` 都已立刻返回):

- **`agentssh approval status <id>`** — 秒回(读 resolution + 校验 req_digest)。**只读,agent 可调**。退出码:approved=0、denied=6、pending=7、未知/畸形 id=2。
- **`agentssh approval wait <id> [--timeout 10m]`** — 轮询 resolution 直到出结果或超时,操作者一按即返回。**只读、可超时打断,agent 可调**。退出码:approved=0、denied=6、**超时/无结果=7**(语义同「仍待审批」)、缺失/过期/畸形=2。轮询用退避;读到非最终临时文件名一律忽略。
- **直接重跑 `run`** — 没批再拿 `exit 7`,批了即执行。零额外命令的兜底。

边界处理须明确:pending 不存在、pending 已过期、resolution 畸形、resolution 的 `req_digest` 与 pending 不符 → 视为「未批」并提示重新发起,绝不当 approved。

SKILL.md 指南:拿到 `run` 的 `exit 7` → 把 `id` + 原命令 + 候选范围转告操作者 → `approval wait` → 通过后**干净重跑一次**;**绝不**自己调 `approval grant`/改 policy/换写法绕过。`exit 6` 仍是**终态,永不重试**。

## 8. 审计扩展

新增事件:`approval_requested` / `approval_granted` / `approval_denied`。在 `Record`(`audit/record.go:27-49`)**与** `canonicalRecord`(`audit/record.go:331-349`,两者是独立 struct)**末尾各追加**四个 `,omitempty` 字段:`ApprovalID`、`ApprovalScope`(once|session|host)、`ApprovalMatcher`、`ApprovalChannel`(tui|cli|wait|exit)。

**hash 链安全**:`ComputeHash`(`audit/record.go:320`)序列化 `canonicalRecord`(`:351-370` 手写字段表);旧记录这四个字段为空 → `omitempty` 省略 → 规范 JSON 逐字节不变 → 旧日志 `audit verify` 仍通过。**两处必须同步**:只加到 `Record` 而漏 `canonicalRecord`,审批元数据会写进 JSON 却**不被 hash 保护**;加到 `canonicalRecord` 却漏 `omitempty`、或插在已有字段之前,会让旧日志断链。用「升级前 fixture 的 golden 链回归」+「逐字段 tamper 测试(改任一新字段 → `Verify` 失败)」守住。不得在 canonical record 里放无序 map 值。

生命周期:`approval_requested →（granted{scope,matcher,channel}→ started → completed）` 或 `→ approval_denied / 超时(记 denied)`。

## 9. CLI / TUI 命面

**agent 面(不变 + 两个只读查询)**:`run`、`hosts`、`approval status <id>`、`approval wait <id>`。**没有** agent 可调的「批准」动词。

**操作者面(operator-only,与现有 `policy` 同级约定,经 `resolveOperatorMaster`/TTY 守门、非 TTY 硬失败)**:
- `agentssh approval ls [--json]` — 列待审批。
- `agentssh approval grant <id> --once|--session|--host` — 裁决(也可在 TUI 按键)。
- `agentssh approval deny <id>`。
- `agentssh session end <id>` — 立即清该 session 的 grant。

**TUI**:新增 `Approvals` 标签页(`entryApprovals`,注意修正 tab 轮转取模),`tea.Tick` 轮询 `pending/`,按键 `[o]nce/[s]ession/[h]ost/[d]eny` → `ApplyDecision`;裁决行展示 host · session · 原命令 · 候选 matcher · 可选范围。对**含 shell 元字符的 host-exact** 裁决给可见告警。无新增三方依赖。

## 10. 配置

- **默认关闭、显式开启**(向后兼容:关时灰区仍是今天的 `exit 6`,**逐字节同今**,不破坏现有脚本)。开关:`policy.Config.Approval.Enabled` 或环境变量 `AGENTSSH_APPROVAL`。开启后灰区 → `exit 7` 异步审批。
- `policy.Config` 增可选段(默认值):
  ```yaml
  approval:
    enabled: false                # 总开关
    host_grant_mode: safe-prefix  # safe-prefix(v1.1 默认) | exact | prefix(类 CC,需显式开)
    session_ttl: 12h              # session grant 绝对 TTL
    wait_timeout: 10m             # approval wait 默认超时
  ```
- `config.Paths` 增 `ApprovalsDir / SessionsDir / PendingDir / ResponsesDir`(惰性 0700)。`EnvApproval = "AGENTSSH_APPROVAL"`。
- 新增 `exit 7`:`const exitApprovalRequired = 7`(`main.go` 约 :30),`mergeExitCode` 优先级 `6 > 7 > 9 > 1 > 0`。

## 11. 自批准边界与部署形态(诚实声明)

**本项目目标部署 = 单机、同一个 OS 用户、交互式**(操作者与 agent 跑在同一账号下)。这个前提下要讲清审批保证什么、不保证什么:

- **能保证**:对一个**基本配合**的 agent(可能被 prompt-injection 带偏、幻觉出危险命令、或手滑),审批 + 显式 `deny` 硬拦 + default-deny + 可验证审计是一道**真实有效的护栏 + 完整留痕**。日常风险(误删 prod、被注入诱导跑破坏性命令)正属这一类——这正是 AgentSSH 的价值所在。
- **不保证**:它**不是**防一个**蓄意越权**的恶意 agent 的沙箱。同一个 OS 用户下,文件权限只挡别的用户、不挡同用户;一个蓄意的同 uid agent 可以绕开整套机制——直接改 `policy.yaml` 加 allow、直接写 `sessions/` grant、甚至不经 AgentSSH 而用本机 ssh-agent 直连目标机。这不是审批特有的洞,而是「同 uid ⇒ agent 拥有你的全部权限」的必然:AgentSSH 的凭据隔离与 policy 强制在同 uid 下同样只是约定 + 审计,不是物理墙。

**唯一能把它变成物理硬墙的办法,是让 agent 跑在独立、受限的 OS 用户(或容器)里**:它对 `~/.agentssh/` 无写权限、没有 ssh-agent,只能经操作者侧 broker 触达主机,内核替你挡住一切伪造与直连。红队验证这是**唯一**真正跨过同 uid 边界的方案(密码学签名方案被「改 policy.yaml」「直连 ssh」两扇侧门绕过,投入产出比差,已否)。它适合服务器 / CI / 专用 agent 主机——**运行时体验透明**(agent 命令、operator TUI 都不变),只是要一次性建账号 + 跑 broker;对单机交互式不划算。本设计因此把 broker 列为**可选「hard 模式」指引**(见 §15),不作默认实现。

同 uid 默认档的落地取舍:
- `approval grant`/`deny` 做成操作者专用、非 TTY 硬失败;`run` 只读不写 grant;resolution 仅作通知。这些**不改变同 uid 的真相**,但减少误触、保证一切留痕。
- **不**做密码学签名(理由见上)。
- `--help` 与文档如实标注:同 uid 下审批是「护栏 + 审计」,不是防恶意 agent 的边界。

## 12. 代码改动落点

- **`internal/policy/policy.go`**:导出 `RuleDefaultDeny="default-deny"`。引擎逻辑零改动。
- **`internal/policy/store.go`**:`CreateGroup` / `StampGroupOntoHost` 拒绝保留名 `__agentssh_approval`(以及任何 `__agentssh_` 前缀)。
- **`internal/approval/`**(现仅 `doc.go`):
  - `generalize.go`(`Generalize` + 字节级 ASCII-空格切词器 + 各 denylist/多路表/read-mostly 白名单 + 不变量自检)
  - `matcher.go`(`Matcher`、`Compile`、`SHA256`)
  - `session_store.go`(`Load/Grant/Match/GC/End`,flock + 原子写 + once 锁内消费)
  - `request.go`(`PendingStore`、resolution 读写 + `req_digest` 校验、`Status`/`Wait`、≥96bit ID)
  - `authorize.go`(`Authorize` + `splitPolicy` 深拷贝剔除 `host:<name>` 下 `__agentssh_approval` 规则 → `policy.NewEngine`)
  - `adjudicate.go`(`ApplyDecision`:session→Grant;host→去重 + `AddHostRule` + save;写审计;写 resolution)
- **`cmd/agentssh/main.go`**:`run` 流程把 `main.go:1694` 的 `if decision.Action==ActionDeny` 块换成 `switch approval.Authorize(...)`:`Allow`/`AllowByGrant`→原执行路径;`HardDeny`→原 deny+`exit 6`(不变);`NeedsApproval`→若审批关则今天的默认拒,否则写 pending + audit `approval_requested` + 返回 `exit 7`+JSON。**多 host/group:审批开启时先 preflight 全部目标的 `Authorize`,任一为 `NeedsApproval` 则不执行任何目标、整批返回 exit 7 + 每 host JSON**(避免半执行;见 §13)。`runResponse`(`main.go:808`)加 `Status/ApprovalID/ProposedMatcher/ScopesOffered`。新增 `approval`/`session end` 子命令(operator-only,`resolveOperatorMaster` 守门)。
- **`internal/config/config.go`**:`Paths` 增审批目录;`EnvApproval`;`policy.Config` 增 `Approval` 段。
- **`internal/audit/record.go`**:新增三个事件 + 四个 `,omitempty` 字段(`Record`(:27-49)与 `canonicalRecord`(:331-370)同步;`ComputeHash` :320)。
- **`internal/tui/app.go`**:`Approvals` 标签页 + 轮询 + 裁决按键 + 元字符告警。
- **`skills/agentssh-usage/SKILL.md`**:写明 `exit 7` 流程、`approval status/wait` 退出码、绝不自批;重申 `exit 6` 为终态。
- **`docs/architecture/overview.md`**:§5/§10 修订——把「未来 out-of-band **同步**审批」改为「可选、默认关的**异步**审批」,保留硬 deny 底线;TUI 从「纯审计查看器」更新为「审计 + 审批裁决」;迁移注:不开 `approval.enabled`/`AGENTSSH_APPROVAL` 则脚本仍见 `exit 6`。

## 13. 安全权衡与残留风险

1. **同 uid 自批准**(核心):见 §11。同 uid 下审批是「护栏 + 审计」,不是沙箱;唯一硬化办法 = 让 agent 跑独立 OS 用户/容器 + broker(可选 hard 模式)。密码学签名方案经红队否决(被改 `policy.yaml` / 直连 ssh 两扇侧门绕过)。
2. **非锚定 / `\s` 正则缺陷 = 立即注入**:`Generalize` 一旦漏锚或用 `\s`,`ls\nrm -rf /` 即可绕过(引擎子串匹配 + `\s` 吃换行,均已实测)。缓解:代码内不变量自检(缺锚、含 `\s`/换行、含 `.*` 即测试失败)+ 注入语料表驱动测试 + fuzz。**最高优先级正确性风险**。
3. **`prefix` 档(需显式开)的过度放宽**:会放宽写类多路子命令(`systemctl restart *`、`docker run *`、`git push *`)与读任意文件 leaf(`cat *`)。**默认 `safe-prefix` 不放宽这些**;开 `prefix` 即接受该取舍。边界仍由 解释器/特权/破坏性 denylist + 分离引擎兜。
4. **审计 hash 回归**:新字段必须 `,omitempty` 且 `Record`/`canonicalRecord` 同步;用 golden 链 + 逐字段 tamper 测试守住。
5. **resolution 重放 / 陈旧 pending**:`req_digest` 绑定 + `O_EXCL` + `id` 归属校验;pending/responses 按 TTL 清扫。无 HMAC,故不防同 uid **伪造**(同 §11),但防住**意外串号/重放**。
6. **多 host / group run 的部分审批**:已定为**审批开启时先 preflight 全部目标**——任一需审批则整批不执行、返回 exit 7 + 每 host JSON;非 JSON 输出在返回聚合 exit 前逐 host 打印 pending/denied/executed 状态,避免 harness 误读为整体成功。

## 14. 测试要点

- `Generalize`:护栏 denylist、元字符/控制字符/Unicode 空白拒绝、锚定 + 无 `\s`/`.*` 不变量、prefix/exact 分流、字节级切词器;表驱动 + 注入语料(`\n \r \t \f \v` / Unicode 空白 / `$()` / 管道 / 反斜杠续行 / 引号 / glob)+ fuzz;**专测 `ls\nrm -rf /` 不被任何前缀 grant 命中**。
- `Authorize`:**host_overrides 物理在前 + global 有显式 deny → 必返 HardDeny**;session/host grant 命中;实时重判(运行前新增 deny 使 grant 失效);once 在并发重跑下只被消费一次。
- session store:flock 并发、TTL 过期、`session end` 清除、`host` 绑定。
- request/resolution:`req_digest` 不符当未批;`O_EXCL` 防覆盖;`approval wait/status` 各退出码与缺失/过期/畸形分支。
- audit:golden 链回归(升级前 fixture 仍 verify 通过)+ 逐字段 tamper;三个新事件生命周期。
- e2e:`exit 7` → `approval wait` → TUI 裁决 → 重跑执行;`exit 6` 不进审批通道;group 部分审批走 preflight 不半执行。

## 15. 待定项

- **`safe-prefix` 白名单**(默认档依赖):各多路命令的 read-mostly 子命令表(`systemctl:{status,is-active,is-enabled,show,cat,list-units}`、`git:{status,log,diff,show}`、`kubectl:{get,describe,logs}`、`journalctl` …)+ 只读 leaf 表(`ls df free uptime uname hostname ps` …)。`exact`/`prefix` 不依赖它。
- **防自批「hard 模式」(可选,面向服务器/CI,单机默认不做)**:独立 OS 用户(或容器)+ 操作者侧 broker(PEERCRED 认证 socket,所有信任逻辑服务端以操作者身份跑;须校验 session-id `^s_[0-9a-f]+$` 防路径穿越、pending 创建即不可改、grant 消费串行化)。红队结论:这是同 uid 之外唯一的物理硬墙;密码学签名(master-HMAC / 非对称 / FIDO2)被「改 policy.yaml」「直连 ssh」两扇侧门绕过,已否。
- **session TTL 语义**:默认 12h 绝对;是否加 `--sliding` 续期留待反馈。
- **审批开启默认值**:本版默认 `false`(向后兼容);是否在某些发行默认开,待定。
