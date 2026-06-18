package discovery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	sshconfig "github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh/agent"
)

const (
	SourceSSHConfig  = "ssh_config"
	SourceKnownHosts = "known_hosts"
)

// Candidate is one host discovered from local SSH client state.
type Candidate struct {
	Name         string               `json:"name"`
	Source       string               `json:"source"`
	Addr         string               `json:"addr"`
	User         string               `json:"user,omitempty"`
	Port         int                  `json:"port,omitempty"`
	IdentityFile string               `json:"identity_file,omitempty"`
	HasKey       bool                 `json:"has_key"`
	InKnownHosts bool                 `json:"in_known_hosts"`
	InInventory  bool                 `json:"in_inventory"`
	ProbeStatus  executor.ProbeStatus `json:"probe_status,omitempty"`
	Hint         string               `json:"hint,omitempty"`
}

// ImportHost builds the inventory entry to persist for a discovered candidate.
// ssh_config-sourced hosts are stored by alias so the operator's real route
// (ProxyJump, multiple/tokenized IdentityFile) is preserved instead of a
// flattened addr/user/port that would drop those directives.
func ImportHost(c Candidate) inventory.Host {
	if c.Source == SourceSSHConfig {
		return inventory.Host{SSHConfigAlias: c.Name}
	}
	return inventory.Host{Addr: c.Addr, User: c.User, Port: c.Port, IdentityFile: c.IdentityFile}
}

// EndpointKey normalizes addr+port into a comparison key. It returns "" for
// hosts without a concrete addr (e.g. alias-only), which therefore cannot be
// endpoint-deduped cheaply.
func EndpointKey(addr string, port int) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return ""
	}
	if port == 0 {
		port = 22
	}
	return addr + ":" + strconv.Itoa(port)
}

// EndpointKeys returns normalized endpoint keys already present in inventory.
func EndpointKeys(inv inventory.Inventory) map[string]bool {
	keys := map[string]bool{}
	for _, h := range inv.Hosts {
		if k := EndpointKey(h.Addr, h.Port); k != "" {
			keys[k] = true
		}
	}
	return keys
}

// Result is the full static/probe discovery report.
type Result struct {
	Candidates []Candidate `json:"candidates"`
	Notes      []string    `json:"notes,omitempty"`
}

// Options configures static discovery.
type Options struct {
	ConfigPath     string
	KnownHostsPath string
	Home           string
	Inventory      inventory.Inventory
}

// ProbeOptions configures explicit network probing.
type ProbeOptions struct {
	Executor    executor.NativeExecutor
	Timeout     time.Duration
	Concurrency int
}

// Static enumerates SSH config and known_hosts without dialing the network.
func Static(opts Options) (Result, error) {
	home := opts.Home
	if home == "" {
		home = os.Getenv("HOME")
	}
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = filepath.Join(home, ".ssh", "config")
	}
	knownHostsPath := opts.KnownHostsPath
	if knownHostsPath == "" {
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	keyInfo := localKeys(home)
	known, hashed, err := knownHosts(knownHostsPath)
	if err != nil {
		return Result{}, err
	}

	entries := map[string]Candidate{}
	notes := []string{}
	if hashed > 0 {
		notes = append(notes, fmt.Sprintf("skipped %d hashed known_hosts entrie(s); hashed |1| hosts cannot be enumerated", hashed))
	}

	if err := addSSHConfigCandidates(entries, configPath, opts.Inventory, known, keyInfo, home); err != nil {
		return Result{}, err
	}
	addKnownHostCandidates(entries, opts.Inventory, known, keyInfo)

	result := Result{Candidates: sortedCandidates(entries), Notes: notes}
	return result, nil
}

// Probe dials each candidate and runs a no-op command.
func Probe(ctx context.Context, candidates []Candidate, opts ProbeOptions) []Candidate {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	out := make([]Candidate, len(candidates))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, candidate := range candidates {
		i, candidate := i, candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			result := opts.Executor.Probe(probeCtx, executorTarget(candidate))
			candidate.ProbeStatus = executor.ProbeConnectable
			if result.Err != nil {
				candidate.ProbeStatus = executor.ProbeStatusForError(result.Err)
				candidate.Hint = executor.ConnectHint(result.Err)
			} else if result.ExitCode != 0 {
				candidate.ProbeStatus = executor.ProbeUnreachable
				candidate.Hint = fmt.Sprintf("hint: probe command exited %d; verify the remote shell can run true.", result.ExitCode)
			}
			out[i] = candidate
		}()
	}
	wg.Wait()
	return out
}

func executorTarget(candidate Candidate) inventory.Target {
	// ssh_config-sourced candidates must probe through their alias so the native
	// executor reproduces the operator's real route (ProxyJump, multiple and
	// tokenized IdentityFile, etc.) via resolveAlias, instead of a flattened
	// direct dial that silently drops those directives. Other sources have a
	// concrete endpoint and probe it directly.
	if candidate.Source == SourceSSHConfig {
		return inventory.Target{Name: candidate.Name, Host: inventory.Host{SSHConfigAlias: candidate.Name}}
	}
	host := inventory.Host{
		Addr:         candidate.Addr,
		User:         candidate.User,
		Port:         candidate.Port,
		IdentityFile: candidate.IdentityFile,
	}
	return inventory.Target{Name: candidate.Name, Host: host}
}

func addSSHConfigCandidates(entries map[string]Candidate, configPath string, inv inventory.Inventory, known map[string]struct{}, keyInfo keySummary, home string) error {
	file, err := os.Open(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open ssh config %s: %w", configPath, err)
	}
	defer func() { _ = file.Close() }()

	cfg, err := sshconfig.Decode(file)
	if err != nil {
		return fmt.Errorf("decode ssh config %s: %w", configPath, err)
	}
	for _, block := range cfg.Hosts {
		for _, pattern := range block.Patterns {
			name := pattern.String()
			if !isConcreteHostPattern(name) {
				continue
			}
			hostName, err := cfg.Get(name, "HostName")
			if err != nil {
				return fmt.Errorf("ssh config %s HostName: %w", name, err)
			}
			if hostName == "" {
				hostName = name
			}
			userName, err := cfg.Get(name, "User")
			if err != nil {
				return fmt.Errorf("ssh config %s User: %w", name, err)
			}
			portValue, err := cfg.Get(name, "Port")
			if err != nil {
				return fmt.Errorf("ssh config %s Port: %w", name, err)
			}
			port := 22
			if portValue != "" {
				parsed, parseErr := strconv.Atoi(portValue)
				if parseErr != nil {
					return fmt.Errorf("ssh config %s invalid Port %q: %w", name, portValue, parseErr)
				}
				port = parsed
			}
			identityFiles, err := cfg.GetAll(name, "IdentityFile")
			if err != nil {
				return fmt.Errorf("ssh config %s IdentityFile: %w", name, err)
			}
			identityFile := ""
			if len(identityFiles) > 0 {
				identityFile = expandHome(identityFiles[0], home)
			}
			candidate := Candidate{
				Name:         name,
				Source:       SourceSSHConfig,
				Addr:         hostName,
				User:         userName,
				Port:         port,
				IdentityFile: identityFile,
				HasKey:       keyInfo.hasKey(identityFile),
				InKnownHosts: hasKnownHost(known, hostName, port),
				InInventory:  inInventory(inv, name),
			}
			entries[name] = candidate
		}
	}
	return nil
}

func addKnownHostCandidates(entries map[string]Candidate, inv inventory.Inventory, known map[string]struct{}, keyInfo keySummary) {
	for knownName := range known {
		name, addr, port := splitKnownHost(knownName)
		if name == "" {
			continue
		}
		if _, ok := entries[name]; ok {
			continue
		}
		if hasCandidateAddress(entries, addr, port) {
			continue
		}
		entries[name] = Candidate{
			Name:         name,
			Source:       SourceKnownHosts,
			Addr:         addr,
			Port:         port,
			HasKey:       keyInfo.hasAny,
			InKnownHosts: true,
			InInventory:  inInventory(inv, name),
		}
	}
}

func sortedCandidates(entries map[string]Candidate) []Candidate {
	candidates := make([]Candidate, 0, len(entries))
	for _, candidate := range entries {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Name == candidates[j].Name {
			return candidates[i].Source < candidates[j].Source
		}
		return candidates[i].Name < candidates[j].Name
	})
	return candidates
}

func knownHosts(path string) (map[string]struct{}, int, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]struct{}{}, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("open known_hosts %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	hosts := map[string]struct{}{}
	hashed := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		hostField := fields[0]
		if strings.HasPrefix(hostField, "@") {
			if len(fields) < 2 {
				continue
			}
			hostField = fields[1]
		}
		for _, value := range strings.Split(hostField, ",") {
			if strings.HasPrefix(value, "|1|") {
				hashed++
				continue
			}
			if value == "" {
				continue
			}
			// Wildcard / negated patterns (e.g. *.corp.example, !bad) are
			// match-only, not concrete endpoints; don't enumerate them as
			// dialable discovery candidates.
			if strings.ContainsAny(value, "*?!") {
				continue
			}
			hosts[value] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan known_hosts %s: %w", path, err)
	}
	return hosts, hashed, nil
}

type keySummary struct {
	home         string
	hasAny       bool
	existingFile map[string]struct{}
}

func (k keySummary) hasKey(identityFile string) bool {
	if identityFile != "" {
		path := expandHome(identityFile, k.home)
		if _, ok := k.existingFile[path]; ok {
			return true
		}
		if _, err := os.Stat(path); err == nil {
			return true
		}
		return false
	}
	return k.hasAny
}

func localKeys(home string) keySummary {
	files := map[string]struct{}{}
	for _, path := range defaultIdentityFiles(home) {
		if _, err := os.Stat(path); err == nil {
			files[path] = struct{}{}
		}
	}
	hasAgentKey := false
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			signers, signErr := agent.NewClient(conn).Signers()
			hasAgentKey = signErr == nil && len(signers) > 0
			_ = conn.Close()
		}
	}
	return keySummary{home: home, hasAny: hasAgentKey || len(files) > 0, existingFile: files}
}

func defaultIdentityFiles(home string) []string {
	return []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
}

func hasKnownHost(known map[string]struct{}, host string, port int) bool {
	if _, ok := known[host]; ok {
		return true
	}
	if port == 0 {
		port = 22
	}
	if _, ok := known[net.JoinHostPort(host, strconv.Itoa(port))]; ok {
		return true
	}
	if port != 22 {
		if _, ok := known[fmt.Sprintf("[%s]:%d", host, port)]; ok {
			return true
		}
	}
	return false
}

func splitKnownHost(value string) (name string, addr string, port int) {
	if strings.HasPrefix(value, "[") {
		host, portValue, err := net.SplitHostPort(value)
		if err == nil {
			parsed, parseErr := strconv.Atoi(portValue)
			if parseErr == nil {
				return host, host, parsed
			}
		}
	}
	if host, portValue, err := net.SplitHostPort(value); err == nil {
		parsed, parseErr := strconv.Atoi(portValue)
		if parseErr == nil {
			return host, host, parsed
		}
	}
	return value, value, 22
}

func isConcreteHostPattern(pattern string) bool {
	return pattern != "" && !strings.ContainsAny(pattern, "*?!")
}

// InInventory reports whether name already exists as an inventory host or as the
// ssh_config alias of some host. Callers re-checking import eligibility against a
// freshly reloaded inventory should use this (endpoint keys can't see alias-only
// hosts, and AddHost only rejects an exact name collision).
func InInventory(inv inventory.Inventory, name string) bool {
	return inInventory(inv, name)
}

func inInventory(inv inventory.Inventory, name string) bool {
	if _, ok := inv.Hosts[name]; ok {
		return true
	}
	for _, host := range inv.Hosts {
		if host.SSHConfigAlias == name {
			return true
		}
	}
	return false
}

func hasCandidateAddress(entries map[string]Candidate, addr string, port int) bool {
	if port == 0 {
		port = 22
	}
	for _, candidate := range entries {
		candidatePort := candidate.Port
		if candidatePort == 0 {
			candidatePort = 22
		}
		if candidate.Addr == addr && candidatePort == port {
			return true
		}
	}
	return false
}

func expandHome(path string, home string) string {
	if path == "~" {
		if home != "" {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home != "" {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
