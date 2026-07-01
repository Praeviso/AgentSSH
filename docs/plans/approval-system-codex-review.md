# Approval System Design Review

Adversarial review of `docs/plans/approval-system.md` against the current source. The approval package is still only a placeholder, so all approval implementation behavior below is a design review unless explicitly tied to existing source (`internal/approval/doc.go:1-6`).

## Top Risk Ranking

1. Critical: the generated prefix regex uses Go `\s`, which matches newline, tab, form feed, carriage return, and space, so a persisted prefix grant can match a later multi-line command even though the design says newline forces exact matching. Evidence: the plan generates `\s+` and trailing `\s*` in `docs/plans/approval-system.md:96-99`, while Go defines `\s` as `[\t\n\f\r ]` in `/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:114-119`.
2. High: the `P0` / `P1` deny-shadow self-check is unsound. A global deny such as exact `systemctl restart nginx` is not detected by probes `systemctl restart` and `systemctl restart X`, while the prefix allow still overlaps it. This matters because the raw engine evaluates host tier before global tier (`internal/policy/policy.go:303-317`) and the architecture explicitly documents that host tier can override a higher-priority global deny (`docs/architecture/overview.md:130-134`).
3. High: `Group:"approval"` collides with existing rule-group provenance. Today `StampGroupOntoHost` writes the caller-supplied group name into `Rule.Group` (`internal/policy/store.go:354-381`), `RemoveHostGroup` deletes by that same field (`internal/policy/store.go:384-404`), and no code reserves the group name `approval` (`internal/policy/store.go:268-285`).
4. High: the same-UID boundary is honest but incomplete. The plan admits no HMAC and same-UID self-approval risk (`docs/plans/approval-system.md:197-204`), but should also explicitly call out direct forging of `responses/`, `sessions/` grants, and `policy.yaml` under the same normal user-owned config tree (`internal/config/config.go:127-139`, `internal/config/config.go:186-194`).
5. Medium: audit hash compatibility is correct only if the new fields are appended with `omitempty` to both `Record` and `canonicalRecord`. The current code uses a hand-written canonical field list (`internal/audit/record.go:331-370`), so a one-sided edit can make new approval data unauthenticated without breaking compilation.
6. Medium: multi-host approval can produce partial execution and ambiguous aggregate exit semantics. The current run loop authorizes and may execute each target before moving to the next (`cmd/agentssh/main.go:1673-1785`), and current aggregation has no exit 7 path (`cmd/agentssh/main.go:1938-1950`).
7. Medium: approval IDs and response files need stronger replay/collision guarantees than the plan currently specifies. Existing audit request IDs are only 3 random bytes (`internal/audit/record.go:63-70`), which is acceptable for audit labels but too small if copied for authorization state. The plan's `ap_7f3a` is an example, not a spec, so this is a HYPOTHESIS risk until the ID format is made explicit (`docs/plans/approval-system.md:37`).
8. Medium: `approval wait` and `status` are underspecified around missing pending files, timeout exit codes, stale responses, and atomic visibility. There is no current approval code beyond the empty package marker (`internal/approval/doc.go:1-6`).
9. Low: the plan overstates `^` / `$` in Go. `\A` / `\z` are the right generated anchors, but Go documents `$` as end-of-text like `\z` unless multiline mode is active (`/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:71-78`).

## A. Generalization Algorithm

Verdict: problem.

Evidence: the current policy engine compiles regexes with `regexp.Compile` and then uses `MatchString` directly (`internal/policy/policy.go:418-427`, `internal/policy/policy.go:303-317`). That means the plan is right that generated approval rules must be fully anchored, because the engine itself does not require full-string matches. The plan quote is: "引擎用非锚定的 `regexp.MatchString` ... 所以 ... 必须 `\A ... \z` 全锚定" (`docs/plans/approval-system.md:74-79`). The code confirms non-anchored matching at `internal/policy/policy.go:305` and default-deny fallback at `internal/policy/policy.go:316`.

Evidence: Go regexp supports `\A` and `\z`. The local Go 1.25.5 syntax documentation lists `\A` as beginning of text and `\z` as end of text (`/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:71-78`). It also says `$` is "like \z not \Z" unless multiline mode is active (`/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:73-78`). `\Z` is not listed as a Go empty-width anchor in that syntax block (`/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:71-78`). Concrete fix: keep generated approvals on `\A ... \z`, but revise the prose from "cannot use `^`/`$`" to "generated grants must use `\A`/`\z`; `$` is end-of-text in default Go mode but becomes line-sensitive under `(?m)`, and `\Z` is not the Go anchor to use."

Evidence: the tail character class `[A-Za-z0-9@%+=:,./_-]` places `-` immediately before `]` (`docs/plans/approval-system.md:96-99`). Go documents `A-Z` as the range form inside character classes (`/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:94-101`). A trailing hyphen is conventionally literal and is not between two range endpoints, so this is safe enough, but it is visually easy to misread. Concrete fix: spell the tail class as `[A-Za-z0-9@%+=:,./_\\-]` or put `-` first, and add a table test that the generated regex compiles and accepts a literal `-` argument.

Evidence: the whitespace story is internally inconsistent and is the highest-risk injection surface. The plan says STEP 1 sends commands containing newline to exact (`docs/plans/approval-system.md:84-87`), but STEP 4 emits prefix regexes with `\s+` separators and trailing `\s*` (`docs/plans/approval-system.md:96-99`). Go `\s` includes newline, tab, form feed, carriage return, and space (`/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:114-119`). Therefore a host prefix approval for a normal command can later match a command containing a newline separator. A concrete bad shape is a prefix grant for `ls` matching `ls\nid`, because `\s+` can consume the newline and the tail token class can consume `id`. Concrete fix: generated grant regexes must not use `\s`; use an ASCII space-only separator such as `[ ]+` and trailing `[ ]*`, or require one literal space layout. Also reject every C0 control byte and every non-ASCII whitespace rune for prefix generation, not only newline.

Evidence: vertical tab and Unicode whitespace are not consistently addressed. Go `\s` does not include vertical tab, while `[[:space:]]` does (`/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:114-119`, `/home/buyunfeng/.local/share/mise/installs/go/1.25.5/src/regexp/syntax/doc.go:123-136`). The plan does not specify the actual splitter implementation (`docs/plans/approval-system.md:84-99`). HYPOTHESIS: if implementation uses `strings.Fields`, Unicode whitespace may be treated as separators even though the generated regex and the remote shell do not share that model. Concrete fix: define a tiny byte-level tokenizer for the approval algorithm: only ASCII space separates tokens for prefix mode; `\t`, `\n`, `\r`, `\f`, `\v`, NUL, and all non-ASCII whitespace force exact or reject host promotion.

Evidence: the metacharacter blacklist includes backslash and most shell separators (`docs/plans/approval-system.md:84-87`), so backslash-newline line continuation is not directly generalizable from a source command. The problem is that generated `\s` later admits plain newlines even when the source command had none. `%`, `@`, `,`, and `:` are allowed in the tail class (`docs/plans/approval-system.md:96-99`); they are not shell command separators by themselves, but they may still be command-specific capability wideners. Concrete fix: keep them only if the threat model is "shell separator prevention", not "semantic write prevention", and state that distinction explicitly.

Evidence: the default `prefix` mode intentionally widens write-class subcommands: the plan says `systemctl restart nginx -> systemctl restart *`, `git push origin main -> git push *`, and `cat /etc/passwd -> cat *` are accepted tradeoffs (`docs/plans/approval-system.md:105-108`). That is a risky default for a least-privilege SSH gateway. The current architecture already warns that command-string matching is heuristic, not a sandbox (`docs/architecture/overview.md:136-138`). Concrete fix: change the default to `safe-prefix` or `exact`; require an explicit operator config or per-decision "promote to broad host prefix" action for write-class subcommands such as `systemctl restart`, `docker run`, `git push`, `kubectl apply`, `helm upgrade`, and package managers.

Evidence: the anchor invariant self-check cannot catch all dangerous outputs. It can catch missing `\A`, missing `\z`, and `.*`, but it will not catch the `\s` newline problem, an overbroad allowed character class, an unsafe prefix choice, or the unsound deny-shadow probes. The plan claims "不变量" around anchors and no `.*` (`docs/plans/approval-system.md:96-99`) and claims the two probes "绝不少拦" (`docs/plans/approval-system.md:101-104`). Concrete fix: parse generated regexes with `regexp/syntax` and assert a narrow AST shape, then run a mandatory negative corpus containing `\n`, `\r`, `\t`, `\f`, `\v`, `$()`, pipes, redirections, backslash-newline, quotes, glob characters, and Unicode whitespace. For deny overlap, either implement a conservative family-level rule that downgrades to exact when any explicit deny exists under the same command family, or remove the claim that two probes are sound.

## B. Authorize Split Engine

Verdict: agree with the split-engine direction, problem with the `Group=="approval"` marker.

Evidence: current `policy.NewEngine` compiles all top-level rules and all `host_overrides` rules without considering `Rule.Group` (`internal/policy/policy.go:90-130`). Current `Evaluate` checks host rules first, then global rules, then returns `default-deny` (`internal/policy/policy.go:303-317`). Current `hostRulesFor` includes both the concrete `host:<name>` override and inventory group overrides whose tags match the host (`internal/policy/policy.go:319-338`). Therefore a persisted approval allow inside `host_overrides` would shadow a global explicit deny in the raw engine.

Evidence: the plan recognizes this exact problem: "一条写进 `host_overrides` 的 approval allow 规则,天然有遮蔽掉同 host 显式 deny 的风险" (`docs/plans/approval-system.md:53-64`). Its proposed base-policy pass strips approval rules first, runs `policy.NewEngine` unchanged, and only checks grants after the base decision is `default-deny` (`docs/plans/approval-system.md:57-63`). If implemented everywhere, this does prevent grants from shadowing explicit allow or explicit deny rules, including the case where `host_overrides` is physically first and global has an explicit deny. In that case, the stripped base engine sees the global deny at `internal/policy/policy.go:310-313`, returns a non-default deny, and the grant lookup is never reached.

Evidence: this guarantee only holds if all decision paths stop using raw `policy.NewEngine` for approval-aware answers. Today `runDirect` creates the raw engine and evaluates it directly (`cmd/agentssh/main.go:1660-1694`), and `agentssh policy test` also creates the raw engine and evaluates it directly (`cmd/agentssh/main.go:2542-2559`). The plan says both should move to `Authorize` (`docs/plans/approval-system.md:66`). Concrete fix: make `Authorize` the only approval-aware decision API and update `run`, `policy test`, and any TUI/effective-policy preview that claims runtime semantics. Keep a separate raw `policy show` or debug command clearly labeled as raw policy order.

Evidence: `Group=="approval"` is not a safe marker in the current schema. `Rule.Group` already exists (`internal/policy/policy.go:53-60`). `StampGroupOntoHost` copies any named rule group onto a host and sets `copied.Group = groupName` (`internal/policy/store.go:354-381`). `RemoveHostGroup` removes host rules by comparing `rule.Group == groupName` (`internal/policy/store.go:384-404`). `CreateGroup` accepts any non-empty group name and does not reserve `approval` (`internal/policy/store.go:268-285`). The plan's host approval rule shape uses `Group:"approval"` and recommends `RemoveHostGroup(host,"approval")` for bulk removal (`docs/plans/approval-system.md:129-134`). A human-created reusable group named `approval` would collide with the generated approval marker. Concrete fix: reserve a generated-only marker such as `Group:"__agentssh_approval"` and reject that name in `CreateGroup` / `StampGroupOntoHost`, or use a stricter generated-rule predicate such as both `Group == "__agentssh_approval"` and `Name` prefixed by `approval/`. Document that inventory group override keys, rule-group names, and approval provenance are separate concepts.

Evidence: there is also a scope ambiguity. The plan says "剔除所有 `Group=="approval"` 的 host_override 规则" (`docs/plans/approval-system.md:57`). In current code, `host_overrides` includes both concrete `host:<name>` keys and inventory group override keys (`internal/policy/policy.go:319-338`, `docs/architecture/overview.md:126-128`). Concrete fix: generated persistent approval rules should be written only under `host:<name>` keys, and stripping should be documented as "strip generated approval rules from all host-tier overrides, but generated approvals are only produced under `host:<name>`." If group-level approval is ever added, it needs a separate design review.

## C. Audit Hash Chain Compatibility

Verdict: agree if implemented exactly, problem as a maintenance hazard.

Evidence: current `ComputeHash` clears `record.Hash`, marshals a hand-written `canonicalRecord`, and hashes `prev_hash || canonical_json` (`internal/audit/record.go:320-328`, `internal/audit/record.go:351-370`). The persisted `Record` and canonical projection are separate structs (`internal/audit/record.go:27-49`, `internal/audit/record.go:331-349`). The current optional fields `Error` and `ExitCode` use `omitempty` in both structs (`internal/audit/record.go:41-42`, `internal/audit/record.go:342-343`).

Evidence: the plan says to append four `omitempty` fields to both `Record` and `canonicalRecord`, and says old records remain byte-identical because empty fields are omitted (`docs/plans/approval-system.md:163-168`). That is correct only if the fields are appended to the end of the canonical struct, existing field tags and order remain unchanged, and the new fields are copied from `Record` into `canonicalRecord`. Old JSON lines that lack the new fields unmarshal to empty strings, and `omitempty` omits those strings during canonical marshaling.

Evidence: the main breakage risk is two-place sync. If `ApprovalID` or `ApprovalMatcher` is added to `Record` but not to `canonicalRecord`, the approval metadata will be written to audit JSON but will not be hash-protected, because `canonicalJSON` only marshals fields manually listed at `internal/audit/record.go:351-370`. If the fields are added to `canonicalRecord` without `omitempty`, old logs will fail verification because their canonical JSON changes. If the fields are inserted before existing canonical fields, old logs can also fail because Go marshals struct fields in declaration order.

Concrete fix: keep the plan's `omitempty` requirement, add a golden fixture generated by the current code before the approval change, and add a tamper test proving that changing each new approval field breaks `Verify`. Also add a test that `Record` and `canonicalRecord` stay in sync for every hash-protected approval field. Do not include map-valued approval fields in the canonical record unless deterministic ordering is guaranteed.

## D. Async Exit-7 Flow

Verdict: problem / uncertain because critical storage and concurrency details are not specified.

Evidence: current config paths contain only `Home`, `InventoryFile`, `PolicyFile`, `AuditFile`, and `SecretsFile` (`internal/config/config.go:71-78`), and `NewPaths` maps those to normal files under the resolved home (`internal/config/config.go:186-194`). The approval package has no implementation yet (`internal/approval/doc.go:1-6`). The plan adds `approvals/sessions`, `approvals/pending`, and `approvals/responses` (`docs/plans/approval-system.md:137-151`) but does not fully specify ID entropy, atomic create, stale-file semantics, or response binding.

Evidence: current audit append is the repository's strongest file-concurrency model: it opens the log, takes `syscall.Flock(LOCK_EX)`, reads records, computes the next hash, and appends while holding the lock (`internal/audit/record.go:72-118`). The plan says session grant read-modify-write should use flock and atomic writes (`docs/plans/approval-system.md:139-149`), which is directionally correct. Concrete fix: require the same discipline for pending and response creation: `O_EXCL` or equivalent no-overwrite creation, atomic write plus fsync where practical, exclusive lock for read-modify-write stores, and readers that tolerate incomplete temp files by ignoring non-final filenames.

Evidence: replay and binding are underspecified. The response shape in the plan is only `{id, verdict, scope, ts}` (`docs/plans/approval-system.md:148-151`). HYPOTHESIS: if `Authorize` or `wait` trusts only that response, a stale or copied response can be replayed across a different pending request with the same ID. Concrete fix: every response should include and verify a request digest covering `id`, `req_id`, `session_id`, `host`, exact command SHA-256, candidate matcher SHA-256, requested scope, and pending creation timestamp. The grant store should also persist those fields for auditability. Without HMAC this still does not stop same-UID forgery, but it prevents accidental stale replay and catches mismatched files.

Evidence: approval ID generation is not specified. The current audit request ID helper generates 3 random bytes (`internal/audit/record.go:63-70`); that is too collision-prone for authorization state if copied. The plan's `ap_7f3a` is shown as an example (`docs/plans/approval-system.md:37`), so this is a HYPOTHESIS risk rather than a confirmed design. Concrete fix: specify at least 96 bits of randomness for approval IDs, use collision-resistant create semantics, and treat ID collision as a hard error.

Evidence: approval wait polling is underspecified. The plan says `approval wait` polls resolution until result or timeout (`docs/plans/approval-system.md:153-161`). There is no current code for this (`internal/approval/doc.go:1-6`). Concrete fix: specify exact behavior for missing pending ID, expired pending ID, denied response, timeout, interrupted wait, malformed response, and stale response with no pending. Also specify exit codes for `approval wait`: for example approved = 0, denied = 6, timeout/no result = 7 or 1, malformed = 1, usage = 2. If `wait` returns JSON, keep the exit code contract equally explicit.

Evidence: real-time re-evaluate on rerun is the right security model. The current `runDirect` loads config and creates the engine at process start (`cmd/agentssh/main.go:1645-1664`), so a separate rerun after approval will reload policy from disk. The plan says execution happens on the rerun and must re-run `Authorize`, with grants effective only while base decision is still `default-deny` (`docs/plans/approval-system.md:48-52`). Concrete fix: make grant consumption part of a single `Authorize` call immediately before appending `started`, and consume once grants under lock so two concurrent reruns cannot spend the same once grant.

Evidence: multi-host/group behavior is currently per-target and can be partial. `runDirect` loops over `resolved.Targets`, resolves a host-specific session id, evaluates policy, and may execute that host before processing later hosts (`cmd/agentssh/main.go:1673-1785`). Current aggregation prefers deny over SSH error over remote failure over success (`cmd/agentssh/main.go:1938-1950`). The plan adds exit 7 with priority `6 > 7 > 9 > 1 > 0` (`docs/plans/approval-system.md:183-195`). Concrete fix: either preflight all target authorizations before executing any target in approval-enabled mode, or explicitly document that group runs can partially execute and require harnesses to inspect per-host JSON. For non-JSON output, print every host's pending/denied/executed state before returning the aggregate exit code.

## E. Self-Approval Boundary

Verdict: problem, although the document is more honest than most designs.

Evidence: the plan explicitly says resolution files are not HMAC-signed (`docs/plans/approval-system.md:151`) and says same-UID unrestricted agents can self-approve or edit policy (`docs/plans/approval-system.md:197-204`). That is honest. The hidden risk is broader than the CLI verbs. Since `AGENTSSH_HOME` resolves to a normal user-owned directory (`internal/config/config.go:127-139`) and all AgentSSH files live under normal paths (`internal/config/config.go:186-194`), a same-UID agent that can write the filesystem can forge response files, session grant files, host approval rules in `policy.yaml`, or remove/replace pending files. File mode `0600` / directory mode `0700` protects against other users, not against the same UID (`internal/config/config.go:141-180`).

Evidence: the current operator master-password guard is for existing secret-management operator flows, not a general filesystem boundary. `resolveOperatorMaster` reads `AGENTSSH_MASTER_PASSWORD` or prompts on a TTY (`cmd/agentssh/main.go:1319-1334`). That can gate a future `approval grant` command, but it does not stop a same-UID process from writing files directly under `$AGENTSSH_HOME`.

Concrete fix: amend §11 to state explicitly that, without OS-user separation or HMAC, `approval wait` seeing `approved` proves only that an approved-looking response file exists, not that a human operator wrote it. Also state that same-UID agents can forge `responses/`, `sessions/` grants, `pending/`, and `policy.yaml`. If the desired boundary is stronger than convenience plus audit, add HMAC over response/grant files using a secret not available to the agent, or require operator and agent to run under different OS users with filesystem ACLs.

## F. Consistency With Existing Architecture Overview §5

Verdict: uncertain / requires doc revision.

Evidence: the current overview states that TUI is a pure audit viewer and contains no approval (`docs/architecture/overview.md:41-50`). Its §5 says gray-area interactive approval is delegated to the harness, and that any future out-of-band approval would be a pending queue where `run` blocks waiting (`docs/architecture/overview.md:158-165`). The approval plan says it is asynchronous and non-blocking, returns exit 7 immediately, and adds an Approvals TUI tab (`docs/plans/approval-system.md:30-46`, `docs/plans/approval-system.md:171-181`). Those are material changes to the overview, not just implementation details.

Evidence: the plan can still extend rather than invert the hard-deny baseline if the split-engine rule is followed. Current code treats a deny decision as audit `denied`, response status `denied`, and aggregate exit 6 (`cmd/agentssh/main.go:1694-1713`). The plan preserves explicit deny as hard deny and only diverts `Rule == "default-deny"` into approval (`docs/plans/approval-system.md:18-29`, `docs/plans/approval-system.md:53-64`). That is consistent with the baseline if approval is default-off and explicit denies are structurally unreachable by grants.

Evidence: the current exit-code contract has no exit 7. Constants are `0`, `1`, `2`, `6`, and `9` (`cmd/agentssh/main.go:30-36`), top-level `commandExitError` controls process exit (`cmd/agentssh/main.go:81-92`), and merge aggregation knows only the existing four nonzero outcomes (`cmd/agentssh/main.go:1938-1950`). The plan adds exit 7 and says approval is default-off (`docs/plans/approval-system.md:183-195`). Default-off is sufficient for backward compatibility only if disabled behavior remains exactly today's default-deny exit 6 path.

Concrete fix: update `docs/architecture/overview.md` in the plan itself before implementation: replace "future out-of-band synchronous approval" with "optional default-off asynchronous approval", preserve the explicit deny baseline, and revise the TUI/package sections. Also add a migration note that existing scripts keep seeing exit 6 unless `approval.enabled` or `AGENTSSH_APPROVAL` is explicitly enabled.

## G. File:Line Discrepancies

Verdict: agree. I found no direct mismatches in the plan's explicit file:line citations.

Evidence:

| Plan citation | Current source check | Result |
|---|---|---|
| `policy.go:316` in `docs/plans/approval-system.md:28` | `internal/policy/policy.go:316` returns `Decision{Action: ActionDeny, Rule: "default-deny"}` | Accurate |
| `policy.go:305` in `docs/plans/approval-system.md:76` | `internal/policy/policy.go:305` calls `rule.regex.MatchString(command)` | Accurate |
| `policy.go:418` in `docs/plans/approval-system.md:82` | `internal/policy/policy.go:418` starts `compileRegex`; `regexp.Compile` is at `internal/policy/policy.go:422` | Accurate, but cite both lines if precision matters |
| `store.go:237` in `docs/plans/approval-system.md:129` | `internal/policy/store.go:237` starts `AddHostRule` | Accurate |
| `store.go:386` in `docs/plans/approval-system.md:134` | `internal/policy/store.go:386` starts `RemoveHostGroup` | Accurate |
| `main.go:1694` in `docs/plans/approval-system.md:216` | `cmd/agentssh/main.go:1694` is `if decision.Action == policy.ActionDeny` | Accurate |
| `main.go:808` in `docs/plans/approval-system.md:216` | `cmd/agentssh/main.go:808` starts `runResponse` | Accurate |
| `main.go` "约 :30" in `docs/plans/approval-system.md:195` | `cmd/agentssh/main.go:30-36` contains the exit-code constants | Accurate |

Evidence: non-line-specific references should be made more precise before implementation. The audit plan references `audit/record.go` without exact lines (`docs/plans/approval-system.md:165-168`, `docs/plans/approval-system.md:218`); the current relevant lines are `Record` at `internal/audit/record.go:27-49`, `ComputeHash` at `internal/audit/record.go:320-328`, and `canonicalRecord` / `canonicalJSON` at `internal/audit/record.go:331-370`.

Concrete fix: no file:line corrections are required for the explicit citations, but revise the plan to cite `internal/audit/record.go:27-49`, `internal/audit/record.go:320-328`, and `internal/audit/record.go:331-370` where it discusses audit hash compatibility.

## Checklist

### Must Fix

- Replace generated `\s+` and `\s*` with ASCII-space-only matching, and reject control/unicode whitespace for prefix-mode grants.
- Change the default host grant mode from broad `prefix` to `safe-prefix` or `exact`, or require an explicit operator opt-in for write-class prefix promotions.
- Remove the claim that the `P0` / `P1` deny-shadow probe is sound; either make it conservative by downgrading whole command families to exact when explicit denies exist, or rely solely on the split engine and document the raw-policy caveat.
- Stop using `Group:"approval"` as an unreserved marker; reserve a generated-only provenance value or use a stricter generated-rule predicate.
- Make `run`, `policy test`, and any runtime-semantics preview use `Authorize`; keep raw policy inspection clearly labeled as raw.
- Specify approval ID entropy, atomic create/no-overwrite behavior, response request binding, TTL, and GC rules.
- Explicitly document same-UID forging of `responses/`, session grants, pending files, and `policy.yaml`; add HMAC or OS-user separation if approval is meant to be a hard boundary.
- Add golden audit-chain compatibility tests and tamper tests for every new approval audit field.
- Define multi-host approval semantics before implementation: preflight all targets or explicitly document partial execution and per-host JSON interpretation.

### Should Fix

- Export and use `policy.RuleDefaultDeny` so gray-area checks do not compare the magic string directly.
- Specify `approval wait` / `approval status` exit codes for approved, denied, pending timeout, missing ID, expired ID, malformed response, and usage errors.
- Use flock/atomic-write discipline for all approval stores, not just the session grant store.
- Add a grant-consumption lock so one-time approvals cannot be consumed concurrently.
- Update `docs/architecture/overview.md` to describe optional default-off async approval instead of future blocking approval.
- Add table-driven and fuzz tests for `Generalize`, including newline, carriage return, tab, form feed, vertical tab, Unicode whitespace, backslash-newline, shell metacharacters, and broad write-class subcommands.
- Add an explicit test where `host_overrides["host:web-1"]` contains a generated approval allow and global rules contain an explicit deny; `Authorize` must return hard deny.

### Optional

- Reject NUL-containing commands for approval rather than treating them as exact; NUL is a poor fit for shell/executor boundaries.
- Include a visible operator warning when approving `host` scope for exact commands that contain shell metacharacters.
- Add a cleanup command for expired pending/responses files and stale session grant stores.
- Consider storing approval matcher digests in audit records rather than full regexes if audit log size or sensitive command disclosure becomes a concern.
