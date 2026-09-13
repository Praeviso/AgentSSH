package approval

import (
	"fmt"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/commandline"
)

// TaskPermission is a versioned operation contract, never an arbitrary regex.
// Read requests propose diagnostic permissions; only a maintenance request can
// propose the wider maintenance profile. Context and resources stay pinned.
type TaskPermission struct {
	Version   int      `json:"version"`
	Profile   string   `json:"profile"`
	CWD       string   `json:"cwd,omitempty"`
	Launcher  []string `json:"launcher,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Compose   []string `json:"compose,omitempty"`
}

// TaskCandidate derives the exact permission the operator will review. Unknown
// syntax/options and stdin do not acquire a task candidate.
func TaskCandidate(command, stdinHash string) *TaskPermission {
	if stdinHash != "" {
		return nil
	}
	p, _, ok := taskOperation(command)
	if !ok {
		return nil
	}
	return &p
}

func (p TaskPermission) Summary() string {
	resource := strings.Join(p.Resources, ", ")
	if strings.HasPrefix(p.Profile, "compose-") {
		resource = strings.Join(p.Compose, " ")
		if len(p.Resources) > 0 {
			resource += " services=" + strings.Join(p.Resources, ",")
		}
	}
	actions := "status, show, is-active, is-enabled, bounded logs"
	switch p.Profile {
	case "service-maintenance":
		actions += ", restart, reload"
	case "compose-diagnostics":
		actions = "ps, bounded logs"
	case "compose-maintenance":
		actions = "ps, bounded logs, build, pull, up, restart"
	}
	if p.CWD != "" {
		resource += " cwd=" + p.CWD
	}
	if len(p.Launcher) > 0 {
		resource += " via " + strings.Join(p.Launcher, " ")
	}
	return p.Profile + " [" + resource + "]: " + actions
}

func (p TaskPermission) Match(command string) bool {
	q, _, ok := taskOperation(command)
	if !ok || p.Version != 1 || p.CWD != q.CWD || !slices.Equal(p.Launcher, q.Launcher) || !slices.Equal(p.Compose, q.Compose) {
		return false
	}
	profileMatches := p.Profile == q.Profile ||
		p.Profile == "service-maintenance" && q.Profile == "service-diagnostics" ||
		p.Profile == "compose-maintenance" && q.Profile == "compose-diagnostics"
	if !profileMatches {
		return false
	}
	if len(p.Resources) == 0 {
		return strings.HasPrefix(p.Profile, "compose-")
	}
	if len(q.Resources) == 0 {
		return false
	}
	for _, resource := range q.Resources {
		if !slices.Contains(p.Resources, resource) {
			return false
		}
	}
	return true
}

func taskMatcher(command string) (Matcher, error) {
	p := TaskCandidate(command, "")
	if p == nil {
		return Matcher{}, fmt.Errorf("this command has no bounded task profile; approve it exactly with --once or --session")
	}
	m, err := Exact(command)
	if err != nil {
		return Matcher{}, err
	}
	m.Kind, m.Promotable, m.Task = MatcherTask, false, p
	return m, nil
}

func validTaskMatcher(m Matcher) bool {
	p := TaskCandidate(m.SourceCmd, "")
	return m.Kind == MatcherTask && p != nil && m.Task != nil && reflect.DeepEqual(p, m.Task)
}

// taskOperation recognizes only literal, finite operations. Adding an option
// requires reviewing its effects; accepting a generic option tail is forbidden.
func taskOperation(command string) (TaskPermission, string, bool) {
	args, cwd, err := commandline.Parse(command)
	if err != nil {
		return TaskPermission{}, "", false
	}
	p := TaskPermission{Version: 1, CWD: cwd}
	if args[0] == "sudo" || args[0] == "/usr/bin/sudo" {
		p.Launcher = []string{args[0]}
		args = args[1:]
		if len(args) > 0 && (args[0] == "-n" || args[0] == "--non-interactive") {
			p.Launcher = append(p.Launcher, args[0])
			args = args[1:]
		}
	}
	if len(args) < 2 {
		return p, "", false
	}
	tool := args[0]
	if strings.HasPrefix(tool, "/usr/bin/") || strings.HasPrefix(tool, "/bin/") {
		tool = strings.TrimPrefix(strings.TrimPrefix(tool, "/usr/bin/"), "/bin/")
	}
	switch tool {
	case "systemctl":
		verb := args[1]
		p.Profile = "service-diagnostics"
		switch verb {
		case "status", "show", "is-active", "is-enabled":
		case "restart", "reload":
			p.Profile = "service-maintenance"
		default:
			return p, "", false
		}
		for _, arg := range args[2:] {
			if arg == "--no-pager" || arg == "--full" || arg == "-l" {
				if p.Profile != "service-diagnostics" {
					return p, "", false
				}
				continue
			}
			if !resourceName(arg) {
				return p, "", false
			}
			p.Resources = append(p.Resources, arg)
		}
		return p, verb, len(p.Resources) > 0
	case "journalctl":
		p.Profile = "service-diagnostics"
		bounded := false
		for i := 1; i < len(args); i++ {
			arg := args[i]
			switch arg {
			case "--no-pager", "--utc", "--reverse", "-r":
			case "-u", "--unit":
				i++
				if i >= len(args) || !resourceName(args[i]) {
					return p, "", false
				}
				p.Resources = append(p.Resources, args[i])
			case "-n", "--lines":
				i++
				if i >= len(args) || !boundedInt(args[i], 1000) {
					return p, "", false
				}
				bounded = true
			case "--since", "--until", "-S", "-U":
				i++
				if i >= len(args) || !timeValue(args[i]) {
					return p, "", false
				}
			case "-o", "--output":
				i++
				if i >= len(args) || !slices.Contains([]string{"short", "short-iso", "short-precise", "cat", "json", "json-pretty"}, args[i]) {
					return p, "", false
				}
			default:
				return p, "", false
			}
		}
		return p, "logs", len(p.Resources) > 0 && bounded
	case "docker":
		if args[1] != "compose" {
			return p, "", false
		}
		// Pin each file and global option, including executable spelling, so
		// alternate projects, daemons, env files and wrappers cannot ride along.
		p.Compose = []string{args[0], "compose"}
		i := 2
		files := 0
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			flag := args[i]
			i++
			if i >= len(args) {
				return p, "", false
			}
			value := args[i]
			i++
			switch flag {
			case "-f", "--file":
				if !path.IsAbs(value) || path.Clean(value) != value {
					return p, "", false
				}
				files++
			case "-p", "--project-name":
				if !resourceName(value) {
					return p, "", false
				}
			case "--project-directory":
				if !path.IsAbs(value) || path.Clean(value) != value {
					return p, "", false
				}
			default:
				return p, "", false
			}
			p.Compose = append(p.Compose, flag, value)
		}
		if files == 0 || i >= len(args) {
			return p, "", false
		}
		verb := args[i]
		i++
		p.Profile = "compose-maintenance"
		switch verb {
		case "ps", "logs":
			p.Profile = "compose-diagnostics"
		case "build", "pull", "up", "restart":
		default:
			return p, "", false
		}
		boundedLogs := verb != "logs"
		for ; i < len(args); i++ {
			arg := args[i]
			if !strings.HasPrefix(arg, "-") {
				if !resourceName(arg) {
					return p, "", false
				}
				p.Resources = append(p.Resources, arg)
				continue
			}
			flags := map[string][]string{
				"ps":    {"-a", "--all", "-q", "--quiet"},
				"logs":  {"-t", "--timestamps", "--no-color", "--no-log-prefix"},
				"build": {"--no-cache", "--pull", "-q", "--quiet"},
				"pull":  {"-q", "--quiet"},
				"up":    {"-d", "--detach", "--build", "--no-build", "--no-deps", "--force-recreate", "--wait"},
			}
			if slices.Contains(flags[verb], arg) {
				continue
			}
			if verb == "logs" && (arg == "--tail" || arg == "--since" || arg == "--until") {
				i++
				if i >= len(args) {
					return p, "", false
				}
				if arg == "--tail" {
					if !boundedInt(args[i], 1000) {
						return p, "", false
					}
					boundedLogs = true
				} else if !timeValue(args[i]) {
					return p, "", false
				}
				continue
			}
			if (verb == "restart" && (arg == "--timeout" || arg == "-t")) || (verb == "up" && arg == "--wait-timeout") {
				i++
				if i >= len(args) || !boundedInt(args[i], 600) {
					return p, "", false
				}
				continue
			}
			if verb == "ps" && arg == "--format" {
				i++
				if i >= len(args) || args[i] != "json" {
					return p, "", false
				}
				continue
			}
			return p, "", false
		}
		return p, verb, boundedLogs
	}
	return p, "", false
}

func resourceName(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && strings.IndexFunc(s, func(r rune) bool {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_@.:-", r)
		return !allowed
	}) < 0
}
func boundedInt(s string, max int) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= max
}
func timeValue(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && !strings.ContainsAny(s, "\x00\r\n")
}
