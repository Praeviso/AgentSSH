package tui

import (
	"io"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/charmbracelet/lipgloss"
)

// maxLineWidth returns the widest rendered line and the number of physical lines.
func maxLineWidth(s string) (int, int) {
	max := 0
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for _, ln := range lines {
		if w := lipgloss.Width(ln); w > max {
			max = w
		}
	}
	return max, len(lines)
}

func layoutRecords() []audit.Record {
	rs := []audit.Record{}
	add := func(seq uint64, ts, sid, label, host string, ev audit.Event, req, action, rule string) {
		rs = append(rs, audit.Record{Seq: seq, TS: ts, ReqID: req, SessionID: sid, SessionLabel: label,
			Event: ev, Host: host, Cmd: "sudo systemctl restart nginx", PolicyAction: action, PolicyRule: rule})
	}
	add(0, "2026-06-16T08:32:11Z", "s_91be0c", "fix 502 on web-1 production fleet", "web-1", audit.EventCompleted, "a3f2c1", "allow", "prod/allow_rules[1]")
	add(1, "2026-06-16T08:20:00Z", "s_77a2d1", "disk cleanup db-1 nightly batch", "db-1", audit.EventDenied, "f1a0bb", "deny", "catastrophic")
	add(2, "2026-06-16T07:55:00Z", "s_3c0f9a", "", "web-2", audit.EventFailed, "c0ffee", "allow", "default")
	return rs
}

func layoutHostMeta() map[string]HostMeta {
	return map[string]HostMeta{
		"web-1": {User: "deploy", Addr: "10.0.0.11", Tags: []string{"web", "prod"}},
		"db-1":  {User: "postgres", Addr: "10.0.0.31", Tags: []string{"db"}},
	}
}

// layoutViews returns each section's content renderer keyed by name, for the
// width-fit assertions and the diagnostic dump. The renderers return the raw
// (pre-frame-clamp) content so a regression that overflows the budget is caught
// before the shell's MaxWidth hides it by clipping.
func layoutViews() map[string]func(w int) string {
	r := lipgloss.NewRenderer(io.Discard)
	return map[string]func(w int) string{
		"audit-list": func(w int) string {
			m := newModel(layoutRecords(), layoutHostMeta(), newStyles(r), nil)
			m.w, m.h, m.ready = w, 24, true
			return m.renderList()
		},
		"audit-detail": func(w int) string {
			m := newModel(layoutRecords(), layoutHostMeta(), newStyles(r), nil)
			m.w, m.h, m.ready = w, 24, true
			m.openSessionDetail(0)
			return m.renderSessionDetail()
		},
		"hosts": func(w int) string {
			inv := inventory.Inventory{Hosts: map[string]inventory.Host{
				"web-production-primary": {Addr: "10.0.0.11", User: "deploy", Port: 22, IdentityFile: "~/.ssh/web", Tags: []string{"web", "prod"}},
				"db-1":                   {Addr: "10.0.0.31", User: "postgres", Port: 5432, Tags: []string{"db"}},
			}}
			s := newHostsSection(config.Paths{}, r, newAppStyles(r), inv, nil)
			s.w, s.h = w, 24
			return s.View()
		},
		"discover": func(w int) string {
			s := newHostsSection(config.Paths{}, r, newAppStyles(r), inventory.Inventory{}, nil)
			s.w, s.h = w, 24
			s.focus = hostFocusDiscover
			s.discover = discoveryOverlay{active: true, candidates: []discovery.Candidate{
				{Name: "web-production-primary", Source: discovery.SourceSSHConfig, Addr: "10.0.0.11", Port: 22, HasKey: true, InKnownHosts: true, ProbeStatus: executor.ProbeConnectable},
				{Name: "db-1", Source: discovery.SourceKnownHosts, Addr: "10.0.0.31", Port: 5432},
			}, selected: map[int]bool{0: true}}
			return s.discoveryView()
		},
		"policy": func(w int) string {
			cfg := policy.Config{
				Defaults: policy.Defaults{Policy: policy.ActionAllow},
				Rules: []policy.Rule{
					{Name: "catastrophic", Match: policy.Match{CmdRegex: `rm\s+-rf\s+/|mkfs|dd\s+if=`}, Action: policy.ActionDeny},
					{Name: "restart-allowed", Match: policy.Match{CmdRegex: `systemctl (restart|status) .*`}, Action: policy.ActionAllow},
				},
				// A long override name exercises the host_overrides line, which is not a
				// fitColumns table and so must bound itself to the frame.
				HostOverrides: map[string]policy.HostOverride{
					"web-production-primary-cluster-node-01": {Policy: policy.ActionDeny, AllowRules: []policy.Match{{}, {}}},
				},
			}
			s := newPolicySection("", inventory.Inventory{}, cfg, newAppStyles(r), nil)
			s.w, s.h = w, 24
			return s.View()
		},
		"sessions": func(w int) string {
			s := newSessionsSection(layoutRecords(), newAppStyles(r), nil)
			s.w, s.h = w, 24
			return s.View()
		},
	}
}

// TestLayoutNoOverflowAtUsableWidths is the core guard for the responsive layout:
// at the default terminal width (80) and wider, no view may render a line wider
// than the frame, which is what forces a wrap onto a second row. Below 72 we
// intentionally accept clipping (MaxWidth), not wrapping, so the floor is 72.
func TestLayoutNoOverflowAtUsableWidths(t *testing.T) {
	for name, fn := range layoutViews() {
		for _, w := range []int{72, 80, 96, 100, 120, 160, 200} {
			out := fn(w)
			if max, _ := maxLineWidth(out); max > w {
				t.Errorf("%s at w=%d overflows: widest line %d > %d\n%s", name, w, max, w, out)
			}
		}
	}
}

// TestLayoutNoOverflowWithWideRunes guards the wide-rune (CJK/emoji) path: column
// budgets are measured in display columns, so truncation must be too — a label of
// N CJK runes is 2N columns wide. A regression to rune-based truncation makes
// these rows render at ~2x budget and wrap.
func TestLayoutNoOverflowWithWideRunes(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	const cjkLabel = "修复生产环境web-1上的502网关错误并排查上游超时问题"
	const cjkHost = "生产环境数据库主节点机房一号"

	views := map[string]func(w int) string{
		"audit-list": func(w int) string {
			recs := layoutRecords()
			recs[0].SessionLabel = cjkLabel
			m := newModel(recs, layoutHostMeta(), newStyles(r), nil)
			m.w, m.h, m.ready = w, 24, true
			return m.renderList()
		},
		"audit-detail": func(w int) string {
			recs := layoutRecords()
			recs[0].SessionLabel = cjkLabel
			recs[0].Cmd = "sudo systemctl restart 生产环境的nginx网关服务进程"
			m := newModel(recs, layoutHostMeta(), newStyles(r), nil)
			m.w, m.h, m.ready = w, 24, true
			m.openSessionDetail(0)
			return m.renderSessionDetail()
		},
		"sessions": func(w int) string {
			recs := layoutRecords()
			recs[0].SessionLabel = cjkLabel
			s := newSessionsSection(recs, newAppStyles(r), nil)
			s.w, s.h = w, 24
			return s.View()
		},
		"hosts": func(w int) string {
			inv := inventory.Inventory{Hosts: map[string]inventory.Host{
				cjkHost: {Addr: "10.0.0.11", User: "deploy", Tags: []string{"web", "prod"}},
			}}
			s := newHostsSection(config.Paths{}, r, newAppStyles(r), inv, nil)
			s.w, s.h = w, 24
			return s.View()
		},
	}
	for name, fn := range views {
		for _, w := range []int{72, 80, 96, 120, 160} {
			if max, _ := maxLineWidth(fn(w)); max > w {
				t.Errorf("%s (CJK) at w=%d overflows: widest line %d > %d\n%s", name, w, max, w, fn(w))
			}
		}
	}
}

// TestLayoutFillsWideTerminals guards the grow-to-fill path: a wide terminal must
// use more columns than a narrow one (content spreads instead of hugging the left
// edge). Discover/policy are config displays with modest caps, so the elastic
// list views carry this assertion.
func TestLayoutFillsWideTerminals(t *testing.T) {
	views := layoutViews()
	for _, name := range []string{"audit-list", "hosts", "sessions", "discover"} {
		narrow, _ := maxLineWidth(views[name](80))
		wide, _ := maxLineWidth(views[name](160))
		if wide <= narrow {
			t.Errorf("%s should spread on a wide terminal: w80=%d w160=%d", name, narrow, wide)
		}
	}
}

// TestLayoutDump prints widths per view per width; run with -v to eyeball.
func TestLayoutDump(t *testing.T) {
	for name, fn := range layoutViews() {
		for _, w := range []int{70, 80, 100, 120, 160} {
			max, lines := maxLineWidth(fn(w))
			t.Logf("%-13s w=%-4d maxline=%-4d lines=%d", name, w, max, lines)
		}
	}
}
