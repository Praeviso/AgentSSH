package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/secrets"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// hostFocus is the mutually-exclusive interaction mode of the host grid: browsing
// the cards (default) or one of the modal overlays.
type hostFocus int

const (
	hostFocusList     hostFocus = iota // browsing the card grid (default)
	hostFocusForm                      // the add-host form owns the screen
	hostFocusConfirm                   // a destructive-delete confirmation is pending
	hostFocusDiscover                  // the discover overlay owns the screen
)

type hostsSection struct {
	paths       config.Paths
	renderer    *lipgloss.Renderer
	styles      appStyles
	inventory   inventory.Inventory
	names       []string
	cursor      int
	open        bool // set when the operator opened the selected host (enter); the shell consumes it
	status      string
	err         error // transient operation error (shown inline)
	loadErr     error // inventory load/parse error (blocking; shows the error card)
	form        hostform.Model
	focus       hostFocus
	testing     bool // a host connectivity probe is in flight
	discover    discoveryOverlay
	discoverSeq int
	spinner     spinner.Model
	probes      map[string]hostProbe // last probe verdict per host
	// secretHosts/secretsReadable are populated only when AGENTSSH_MASTER_PASSWORD
	// lets us read the encrypted store; otherwise the password indicator is "unknown".
	secretHosts     map[string]bool
	secretsReadable bool
	w, h            int
}

// busy reports whether any async Hosts operation is in flight, driving the
// spinner's tick loop and its visibility.
func (s hostsSection) busy() bool {
	return s.testing || s.discover.loading || s.discover.probing
}

type inventoryChangedMsg struct {
	inventory inventory.Inventory
}

type discoveryOverlay struct {
	active      bool
	loading     bool
	probing     bool
	runID       int
	candidates  []discovery.Candidate
	notes       []string
	selected    map[int]bool
	probingKeys map[string]bool
	cursor      int
	status      string
	err         error
}

type discoveryLoadedMsg struct {
	runID  int
	result discovery.Result
	err    error
}

type discoveryProbedMsg struct {
	runID      int
	candidates []discovery.Candidate
	err        error
}

type hostProbeMsg struct {
	name string
	hint string
	err  error
	ok   bool
	dur  time.Duration
}

// hostProbe is the remembered verdict of the last connectivity test for a host.
type hostProbe struct {
	ok     bool
	detail string
	dur    time.Duration
}

func newHostsSection(paths config.Paths, renderer *lipgloss.Renderer, st appStyles, inv inventory.Inventory, loadErr error) hostsSection {
	s := hostsSection{paths: paths, renderer: renderer, styles: st, inventory: inv, loadErr: loadErr}
	sp := spinner.New(spinner.WithSpinner(spinner.Line))
	if renderer != nil {
		sp.Style = renderer.NewStyle().Foreground(lipgloss.Color("212"))
	}
	s.spinner = sp
	s.probes = map[string]hostProbe{}
	if master := os.Getenv("AGENTSSH_MASTER_PASSWORD"); master != "" {
		if store, err := secrets.Open(paths.SecretsFile, master); err == nil {
			s.secretsReadable = true
			s.secretHosts = map[string]bool{}
			for _, n := range store.Names() {
				s.secretHosts[n] = true
			}
		}
	}
	s.rebuildNames()
	return s
}

func (s hostsSection) title() string { return "Hosts" }

// selectedHost returns the host name under the grid cursor, or "".
func (s hostsSection) selectedHost() string {
	if s.cursor < 0 || s.cursor >= len(s.names) {
		return ""
	}
	return s.names[s.cursor]
}

// capturing reports whether the grid owns the keyboard (a modal/text mode), so
// the shell must not steal q/?.
func (s hostsSection) capturing() bool {
	return s.focus == hostFocusForm || s.focus == hostFocusConfirm || s.focus == hostFocusDiscover
}

func (s hostsSection) helpKeyMap() help.KeyMap {
	if s.loadErr != nil {
		return helpMap{short: []key.Binding{hk("r", "reload inventory")}}
	}
	switch s.focus {
	case hostFocusForm:
		return helpMap{short: []key.Binding{hk("tab", "next"), hk("shift+tab", "prev"), hk("enter", "save"), hk("esc", "cancel")}}
	case hostFocusDiscover:
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("space", "select"), hk("p", "probe"), hk("enter", "import"), hk("esc", "close")}}
	case hostFocusConfirm:
		return helpMap{short: []key.Binding{hk("y", "confirm"), hk("n/esc", "cancel")}}
	default:
		return helpMap{short: []key.Binding{hk("↑↓←→/hjkl", "move"), hk("enter", "open"), hk("a", "add"), hk("d", "discover"), hk("t", "test"), hk("r/x", "remove")}}
	}
}

func (s hostsSection) Init() tea.Cmd { return nil }

func (s hostsSection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		s.w, s.h = ws.Width, ws.Height
	}

	switch msg := msg.(type) {
	case spinner.TickMsg:
		if s.busy() {
			var cmd tea.Cmd
			s.spinner, cmd = s.spinner.Update(msg)
			return s, cmd
		}
		return s, nil
	case discoveryLoadedMsg:
		if !s.discover.active || msg.runID != s.discover.runID {
			return s, nil
		}
		s.discover.loading = false
		if msg.err != nil {
			s.discover.err = msg.err
			s.discover.status = ""
			return s, nil
		}
		s.discover.candidates = msg.result.Candidates
		s.discover.notes = msg.result.Notes
		s.discover.selected = defaultDiscoverySelection(msg.result.Candidates)
		s.discover.status = fmt.Sprintf("discovered %d candidate(s)", len(msg.result.Candidates))
		return s, nil
	case discoveryProbedMsg:
		if !s.discover.active || msg.runID != s.discover.runID {
			return s, nil
		}
		if msg.err != nil {
			s.discover.err = msg.err
			s.discover.status = ""
			s.discover.probing = false
			s.discover.probingKeys = nil
			return s, nil
		}
		s.discover.candidates = mergeProbedCandidates(s.discover.candidates, msg.candidates)
		for _, c := range msg.candidates {
			delete(s.discover.probingKeys, candidateKey(c))
		}
		if len(s.discover.probingKeys) == 0 {
			s.discover.probing = false
			s.discover.status = "probe complete"
		} else {
			s.discover.status = fmt.Sprintf("probing %d candidate(s)…", len(s.discover.probingKeys))
		}
		return s, nil
	case hostProbeMsg:
		s.testing = false
		switch {
		case msg.ok:
			s.err = nil
			s.status = "OK " + msg.name
			s.probes[msg.name] = hostProbe{ok: true, detail: "ok", dur: msg.dur}
		case msg.hint != "":
			s.err = nil
			s.status = "FAILED " + msg.name + ": " + msg.hint
			s.probes[msg.name] = hostProbe{ok: false, detail: msg.hint, dur: msg.dur}
		case msg.err != nil:
			s.err = nil
			hint := executor.ConnectHint(msg.err)
			s.status = "FAILED " + msg.name + ": " + hint
			s.probes[msg.name] = hostProbe{ok: false, detail: hint, dur: msg.dur}
		}
		return s, nil
	}

	switch s.focus {
	case hostFocusForm:
		return s.updateForm(msg)
	case hostFocusDiscover:
		return s.updateDiscovery(msg)
	case hostFocusConfirm:
		return s.updateConfirm(msg)
	default:
		return s.updateList(msg)
	}
}

// startProbe begins a connectivity test for name (used by the Info pane in the
// detail screen). The result lands back via hostProbeMsg.
func (s hostsSection) startProbe(name string) (hostsSection, tea.Cmd) {
	if s.testing || name == "" {
		return s, nil
	}
	s.status = "testing " + name + "…"
	s.err = nil
	s.testing = true
	return s, tea.Batch(s.probeHostCmd(name), s.spinner.Tick)
}

func (s hostsSection) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := s.form.Update(msg)
	if form, ok := updated.(hostform.Model); ok {
		s.form = form
	}
	if !s.form.Done() {
		return s, cmd
	}
	result := s.form.Result()
	s.focus = hostFocusList
	s.form = hostform.Model{}
	if !result.Submitted {
		s.status = "add cancelled"
		return s, nil
	}
	if err := s.addHost(result); err != nil {
		s.err = err
		s.status = ""
		return s, nil
	}
	s.err = nil
	return s, tea.Batch(inventoryChangedCmd(s.inventory), toastCmd("host added: "+result.Name))
}

func (s hostsSection) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	switch keyMsg.String() {
	case "y":
		name := ""
		if len(s.names) > 0 {
			name = s.names[s.cursor]
		}
		removed := s.removeSelected()
		s.focus = hostFocusList
		if removed {
			return s, tea.Batch(inventoryChangedCmd(s.inventory), toastCmd("host removed: "+name))
		}
		return s, nil
	case "n", "esc":
		s.focus = hostFocusList
		s.status = ""
	}
	return s, nil
}

func (s hostsSection) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	if s.loadErr != nil {
		if keyMsg.String() == "r" {
			return s.reloadInventory()
		}
		return s, nil
	}
	cols := s.gridCols()
	last := len(s.names) - 1
	switch keyMsg.String() {
	case "left", "h":
		if s.cursor > 0 {
			s.cursor--
		}
	case "right", "l":
		if s.cursor < last {
			s.cursor++
		}
	case "up", "k":
		if s.cursor-cols >= 0 {
			s.cursor -= cols
		}
	case "down", "j":
		if s.cursor+cols <= last {
			s.cursor += cols
		} else if s.cursor != last && s.cursor/cols < last/cols {
			// Partial bottom row: snap to the last card so the bottom row is reachable.
			s.cursor = last
		}
	case "home", "g":
		s.cursor = 0
	case "end", "G":
		s.cursor = maxInt(last, 0)
	case "a":
		s.focus = hostFocusForm
		s.form = hostform.New(hostform.Options{ExistingNames: inventory.HostNames(s.inventory)}, s.renderer)
		s.form = s.form.SetSize(s.w, s.h)
		return s, s.form.Init()
	case "d":
		s.focus = hostFocusDiscover
		s.discoverSeq++
		s.discover = discoveryOverlay{
			active:   true,
			loading:  true,
			runID:    s.discoverSeq,
			selected: map[int]bool{},
			status:   "discovering from ssh config and known_hosts…",
		}
		return s, tea.Batch(s.loadDiscoveryCmd(), s.spinner.Tick)
	case "t":
		if s.testing {
			return s, nil
		}
		if len(s.names) == 0 {
			s.status = "no host selected"
			return s, nil
		}
		name := s.names[s.cursor]
		s.status = "testing " + name + "…"
		s.err = nil
		s.testing = true
		return s, tea.Batch(s.probeHostCmd(name), s.spinner.Tick)
	case "r", "x":
		if len(s.names) > 0 {
			s.focus = hostFocusConfirm
		}
	case "enter", "i":
		if len(s.names) > 0 {
			s.open = true
		}
	case "esc":
		s.status = ""
	}
	return s, nil
}

func (s hostsSection) reloadInventory() (tea.Model, tea.Cmd) {
	inv, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		s.loadErr = err
		return s, nil
	}
	s.inventory = inv
	s.loadErr = nil
	s.err = nil
	s.rebuildNames()
	return s, tea.Batch(inventoryChangedCmd(inv), toastCmd("inventory reloaded"))
}

func inventoryChangedCmd(inv inventory.Inventory) tea.Cmd {
	return func() tea.Msg {
		return inventoryChangedMsg{inventory: inv}
	}
}

func (s hostsSection) loadDiscoveryCmd() tea.Cmd {
	runID := s.discover.runID
	return func() tea.Msg {
		cfgPath, knownHostsPath, home := sshClientPaths()
		result, err := discovery.Static(discovery.Options{
			ConfigPath:     cfgPath,
			KnownHostsPath: knownHostsPath,
			Home:           home,
			Inventory:      s.inventory,
		})
		return discoveryLoadedMsg{runID: runID, result: result, err: err}
	}
}

func (s hostsSection) probeOneCmd(candidate discovery.Candidate) tea.Cmd {
	runID := s.discover.runID
	return func() tea.Msg {
		cfgPath, knownHostsPath, _ := sshClientPaths()
		exec := executor.NewNativeExecutor(executor.NativeOptions{
			ConfigPath:     cfgPath,
			KnownHostsPath: knownHostsPath,
			ConnectTimeout: executor.ProbeTimeout,
			HostKeyPolicy:  s.inventory.HostKeyPolicy,
			PasswordSource: secrets.EnvPasswordSource(s.paths.SecretsFile),
		})
		probed := discovery.Probe(context.Background(), []discovery.Candidate{candidate}, discovery.ProbeOptions{
			Executor:    exec,
			Timeout:     executor.ProbeTimeout,
			Concurrency: 1,
		})
		return discoveryProbedMsg{runID: runID, candidates: probed}
	}
}

func (s hostsSection) probeHostCmd(name string) tea.Cmd {
	host := s.inventory.Hosts[name]
	return func() tea.Msg {
		cfgPath, knownHostsPath, _ := sshClientPaths()
		exec := executor.NewNativeExecutor(executor.NativeOptions{
			ConfigPath:     cfgPath,
			KnownHostsPath: knownHostsPath,
			ConnectTimeout: executor.ProbeTimeout,
			HostKeyPolicy:  s.inventory.HostKeyPolicy,
			PasswordSource: secrets.EnvPasswordSource(s.paths.SecretsFile),
		})
		ctx, cancel := context.WithTimeout(context.Background(), executor.ProbeTimeout)
		defer cancel()
		result := exec.Probe(ctx, inventory.Target{Name: name, Host: host})
		if result.Err == nil && result.ExitCode == 0 {
			return hostProbeMsg{name: name, ok: true, dur: result.Duration}
		}
		if result.Err != nil {
			return hostProbeMsg{name: name, err: result.Err, hint: executor.ConnectHint(result.Err), dur: result.Duration}
		}
		return hostProbeMsg{name: name, hint: fmt.Sprintf("probe command exited %d", result.ExitCode), dur: result.Duration}
	}
}

func sshClientPaths() (configPath string, knownHostsPath string, home string) {
	home = os.Getenv("HOME")
	if home == "" {
		if resolved, err := os.UserHomeDir(); err == nil {
			home = resolved
		}
	}
	return filepath.Join(home, ".ssh", "config"), filepath.Join(home, ".ssh", "known_hosts"), home
}

func defaultDiscoverySelection(candidates []discovery.Candidate) map[int]bool {
	selected := map[int]bool{}
	for i, candidate := range candidates {
		if !candidate.InInventory {
			selected[i] = true
		}
	}
	return selected
}

func (s hostsSection) updateDiscovery(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	switch keyMsg.String() {
	case "j", "down":
		if s.discover.cursor < len(s.discover.candidates)-1 {
			s.discover.cursor++
		}
	case "k", "up":
		if s.discover.cursor > 0 {
			s.discover.cursor--
		}
	case " ":
		if len(s.discover.candidates) > 0 {
			if s.discover.selected == nil {
				s.discover.selected = map[int]bool{}
			}
			if s.discover.selected[s.discover.cursor] {
				delete(s.discover.selected, s.discover.cursor)
			} else {
				s.discover.selected[s.discover.cursor] = true
			}
		}
	case "p":
		if s.discover.loading || s.discover.probing {
			return s, nil
		}
		selected := s.selectedDiscoveryCandidates()
		if len(selected) == 0 {
			s.discover.status = "select candidates with space before probing"
			return s, nil
		}
		s.discover.probing = true
		s.discover.err = nil
		s.discover.probingKeys = make(map[string]bool, len(selected))
		cmds := []tea.Cmd{s.spinner.Tick}
		for _, c := range selected {
			s.discover.probingKeys[candidateKey(c)] = true
			cmds = append(cmds, s.probeOneCmd(c))
		}
		s.discover.status = fmt.Sprintf("probing %d candidate(s)…", len(selected))
		return s, tea.Batch(cmds...)
	case "enter", "i":
		if s.discover.loading || s.discover.probing {
			return s, nil
		}
		changed, err := s.importDiscoverySelected()
		if err != nil {
			s.discover.err = err
			s.discover.status = ""
			return s, nil
		}
		if changed {
			s.discover.active = false
			s.focus = hostFocusList
			imported := s.status
			s.status = ""
			return s, tea.Batch(inventoryChangedCmd(s.inventory), toastCmd(imported))
		}
	case "esc", "q":
		s.discover = discoveryOverlay{}
		s.focus = hostFocusList
		s.status = "discover cancelled"
	}
	return s, nil
}

func (s hostsSection) selectedDiscoveryCandidates() []discovery.Candidate {
	if len(s.discover.selected) == 0 {
		return nil
	}
	selected := make([]discovery.Candidate, 0, len(s.discover.selected))
	for i, candidate := range s.discover.candidates {
		if s.discover.selected[i] {
			selected = append(selected, candidate)
		}
	}
	return selected
}

func (s *hostsSection) importDiscoverySelected() (bool, error) {
	if len(s.discover.selected) == 0 {
		s.discover.status = "select connectable candidates before importing"
		return false, nil
	}
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return false, err
	}
	next := base
	seen := discovery.EndpointKeys(base)
	imported := 0
	for i, candidate := range s.discover.candidates {
		if !s.discover.selected[i] || candidate.ProbeStatus != executor.ProbeConnectable {
			continue
		}
		if discovery.InInventory(next, candidate.Name) {
			continue
		}
		key := discovery.EndpointKey(candidate.Addr, candidate.Port)
		if key != "" && seen[key] {
			continue
		}
		var addErr error
		next, addErr = inventory.AddHost(next, candidate.Name, discovery.ImportHost(candidate))
		if errors.Is(addErr, inventory.ErrHostExists) {
			continue
		}
		if addErr != nil {
			return false, addErr
		}
		if key != "" {
			seen[key] = true
		}
		imported++
	}
	if imported == 0 {
		s.discover.status = "no selected connectable candidates to import"
		return false, nil
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		return false, err
	}
	reloaded, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return false, err
	}
	s.inventory = reloaded
	s.rebuildNames()
	s.err = nil
	s.status = fmt.Sprintf("imported %d host(s)", imported)
	return true, nil
}

func mergeProbedCandidates(current []discovery.Candidate, probed []discovery.Candidate) []discovery.Candidate {
	byKey := make(map[string]discovery.Candidate, len(probed))
	for _, p := range probed {
		byKey[candidateKey(p)] = p
	}
	merged := append([]discovery.Candidate(nil), current...)
	for i := range merged {
		if p, ok := byKey[candidateKey(merged[i])]; ok {
			merged[i] = p
		}
	}
	return merged
}

func candidateKey(c discovery.Candidate) string {
	return c.Source + "\x00" + c.Name
}

func (s *hostsSection) addHost(result hostform.Result) error {
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return err
	}
	if result.Password != "" {
		master := os.Getenv("AGENTSSH_MASTER_PASSWORD")
		if master == "" {
			return fmt.Errorf("set AGENTSSH_MASTER_PASSWORD to store a password in the TUI, or use `agentssh secret set <host>`")
		}
		store, err := secrets.Open(s.paths.SecretsFile, master)
		if errors.Is(err, secrets.ErrWrongMaster) {
			return fmt.Errorf("cannot open secrets: wrong master password or corrupt secrets file")
		}
		if err != nil {
			return err
		}
		if err := s.addInventoryHost(base, result); err != nil {
			return err
		}
		store.Set(result.Name, result.Password)
		if err := store.Save(master); err != nil {
			if rbErr := s.removeHostByName(result.Name); rbErr != nil {
				return fmt.Errorf("failed to store password (%v) and to roll back inventory add: %w", err, rbErr)
			}
			return fmt.Errorf("failed to store password; rolled back inventory add: %w", err)
		}
		if s.secretHosts == nil {
			s.secretHosts = map[string]bool{}
		}
		s.secretHosts[result.Name] = true
		s.secretsReadable = true
		return nil
	}
	return s.addInventoryHost(base, result)
}

func (s *hostsSection) addInventoryHost(base inventory.Inventory, result hostform.Result) error {
	next, err := inventory.AddHost(base, result.Name, inventory.Host{
		Addr:           result.Addr,
		User:           result.User,
		Port:           result.Port,
		SSHConfigAlias: result.Alias,
		IdentityFile:   result.Identity,
		Tags:           result.Tags,
		OS:             result.OS,
	})
	if err != nil {
		return err
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		return err
	}
	s.inventory = next
	s.rebuildNames()
	return nil
}

func (s *hostsSection) removeHostByName(name string) error {
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return err
	}
	next, err := inventory.RemoveHost(base, name)
	if err != nil {
		return err
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		return err
	}
	s.inventory = next
	s.rebuildNames()
	return nil
}

func (s *hostsSection) removeSelected() bool {
	if len(s.names) == 0 {
		return false
	}
	name := s.names[s.cursor]
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		s.err = err
		s.status = ""
		return false
	}
	next, err := inventory.RemoveHost(base, name)
	if err != nil {
		s.err = err
		s.status = ""
		return false
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		s.err = err
		s.status = ""
		return false
	}
	s.inventory = next
	s.rebuildNames()
	delete(s.secretHosts, name)
	s.err = nil
	return true
}

func (s *hostsSection) rebuildNames() {
	s.names = sortedHostNames(s.inventory.Hosts)
	if s.cursor >= len(s.names) {
		s.cursor = len(s.names) - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

// ---- card grid layout ----

const (
	cardGap      = 2  // horizontal gap between cards
	cardRowGap   = 1  // blank line between card rows
	cardMinOuter = 26 // narrowest acceptable card (outer width incl. border + padding)
	cardInnerH   = 2  // content rows: label + tags (the icon spans both)
	cardOuterH   = cardInnerH + 2
	cardRowH     = cardOuterH + cardRowGap
	osIconW      = 3 // the OS badge is 3 columns wide, 2 rows tall
)

// gridCols is the number of equal-width cards that fit across the frame.
func (s hostsSection) gridCols() int {
	if s.w <= 0 {
		return 1
	}
	cols := (s.w + cardGap) / (cardMinOuter + cardGap)
	if cols < 1 {
		cols = 1
	}
	if cols > len(s.names) && len(s.names) > 0 {
		cols = len(s.names)
	}
	return cols
}

// cardOuterWidth is the equal outer width each card gets for cols columns.
func (s hostsSection) cardOuterWidth(cols int) int {
	if cols < 1 {
		cols = 1
	}
	avail := s.w - cardGap*(cols-1)
	w := avail / cols
	if w < cardMinOuter {
		w = cardMinOuter
	}
	return w
}

// listChromeHeight counts the non-grid lines the grid view renders above the
// cards (the error and status lines), so the grid windows to the rest.
func (s hostsSection) listChromeHeight() int {
	h := 0
	if s.err != nil {
		h++
	}
	if s.status != "" {
		h++
	}
	return h
}

func (s hostsSection) View() string {
	if s.focus == hostFocusForm {
		return s.form.View()
	}
	if s.focus == hostFocusDiscover {
		return s.discoveryView()
	}
	if s.loadErr != nil {
		return s.errorCardView()
	}
	if s.focus == hostFocusConfirm {
		return s.confirmCardView()
	}

	var b strings.Builder
	if s.err != nil {
		b.WriteString(truncate(s.styles.err.Render(s.err.Error()), s.w))
		b.WriteString("\n")
	}
	if s.status != "" {
		if s.testing {
			b.WriteString(s.spinner.View())
			b.WriteString(" ")
		}
		b.WriteString(truncate(s.styles.ok.Render(s.status), s.w))
		b.WriteString("\n")
	}
	if len(s.names) == 0 {
		b.WriteString(s.styles.dim.Render("No hosts yet."))
		b.WriteString("\n")
		b.WriteString(keyHint(s.styles, "a", "add a host"))
		b.WriteString("    ")
		b.WriteString(keyHint(s.styles, "d", "discover hosts you can already reach"))
		return b.String()
	}
	b.WriteString(s.gridView())
	return b.String()
}

// gridView renders the responsive, equal-sized card grid, windowed vertically so
// the selected card stays on screen.
func (s hostsSection) gridView() string {
	cols := s.gridCols()
	cardW := s.cardOuterWidth(cols)
	totalRows := (len(s.names) + cols - 1) / cols

	// How many card rows fit in the remaining body height. Reserve one line for
	// the "rows x–y of z" indicator when the grid can't show every row at once.
	avail := s.h - s.listChromeHeight()
	visRows := totalRows
	if s.h > 0 {
		fullGridH := totalRows*cardRowH - cardRowGap
		reserve := 0
		if fullGridH > avail {
			reserve = 1
		}
		visRows = (avail - reserve + cardRowGap) / cardRowH
		if visRows < 1 {
			visRows = 1
		}
	}
	cursorRow := 0
	if cols > 0 {
		cursorRow = s.cursor / cols
	}
	startRow, endRow := scrollWindow(cursorRow, totalRows, visRows)

	rows := make([]string, 0, endRow-startRow)
	for r := startRow; r < endRow; r++ {
		cards := make([]string, 0, cols*2)
		for c := 0; c < cols; c++ {
			idx := r*cols + c
			if idx >= len(s.names) {
				break
			}
			if c > 0 {
				cards = append(cards, strings.Repeat(" ", cardGap))
			}
			cards = append(cards, s.renderHostCard(s.names[idx], cardW, idx == s.cursor))
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, cards...))
	}
	grid := strings.Join(rows, strings.Repeat("\n", cardRowGap+1))
	if endRow < totalRows || startRow > 0 {
		grid += "\n" + s.styles.dim.Render(fmt.Sprintf("rows %d–%d of %d", startRow+1, endRow, totalRows))
	}
	return grid
}

// renderHostCard renders one equal-sized host card: the OS icon spanning two rows
// on the left, with the host label and its tags to the right.
func (s hostsSection) renderHostCard(name string, outerW int, selected bool) string {
	host := s.inventory.Hosts[name]
	// lipgloss Width is the box width INCLUDING padding; the border sits outside it.
	// So box = outer − border(2), and the text area = box − padding(2).
	box := outerW - 2
	if box < osIconW+4 {
		box = osIconW + 4
	}
	textW := box - 2 - osIconW - 1 // padding, icon, gutter
	if textW < 1 {
		textW = 1
	}

	label := name
	labelStyle := s.styles.background
	if selected {
		labelStyle = s.styles.header
	}
	line1 := fitCell(labelStyle.Render(truncate(label, textW)), textW, false)

	tags := strings.Join(host.Tags, " · ")
	if tags == "" {
		tags = "—"
	}
	line2 := fitCell(s.styles.dim.Render(truncate(tags, textW)), textW, false)

	icon := osBadge(s.renderer, host.OS)
	left := lipgloss.JoinVertical(lipgloss.Left, icon[0], icon[1])
	right := lipgloss.JoinVertical(lipgloss.Left, line1, line2)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)

	style := s.styles.card
	if selected {
		style = s.styles.cardSel
	}
	return style.Width(box).Render(body)
}

// osBadge returns the two-row, three-column OS icon, colored by OS family. The
// short code keeps the OS legible under NO_COLOR, where the color is stripped.
func osBadge(r *lipgloss.Renderer, osName string) [2]string {
	code, color := osMeta(osName)
	st := lipgloss.NewStyle()
	if r != nil {
		st = r.NewStyle()
	}
	st = st.Foreground(color).Bold(true)
	return [2]string{st.Render("███"), st.Render(code)}
}

func osMeta(osName string) (code string, color lipgloss.TerminalColor) {
	switch strings.ToLower(strings.TrimSpace(osName)) {
	case "linux":
		return "LNX", lipgloss.AdaptiveColor{Light: "28", Dark: "42"}
	case "macos", "darwin":
		return "MAC", lipgloss.AdaptiveColor{Light: "245", Dark: "251"}
	case "windows":
		return "WIN", lipgloss.AdaptiveColor{Light: "33", Dark: "39"}
	case "bsd":
		return "BSD", lipgloss.AdaptiveColor{Light: "160", Dark: "203"}
	default:
		return "SRV", theme.Dim
	}
}

// ---- info pane (host detail) ----

// infoView renders the selected host's facts as a bordered panel. box is the
// lipgloss box width (padding included; border sits outside it), clamped to
// height. focused accents the border (the active pane).
func (s hostsSection) infoView(name string, box, height int, focused bool) string {
	host, ok := s.inventory.Hosts[name]
	// Floor at 16 so the field layout (9-col label + space + a >=4-col value) fits
	// the text area (box-2) without overflowing, even if a caller passes a tiny box.
	if box < 16 {
		box = 16
	}
	textW := box - 2 // padding
	valW := textW - 10
	if valW < 4 {
		valW = 4
	}
	var b strings.Builder
	marker := " "
	if focused {
		marker = s.styles.glyphs.Marker
	}
	b.WriteString(s.styles.header.Render(truncate(marker+" "+name, textW)))
	b.WriteString("\n\n")
	if !ok {
		b.WriteString(s.styles.dim.Render("host not found"))
	} else {
		field := func(label, val string) {
			fmt.Fprintf(&b, "%s %s\n", s.styles.dim.Render(fmt.Sprintf("%-9s", label)), truncate(val, valW))
		}
		port := "22"
		if host.Port != 0 {
			port = strconv.Itoa(host.Port)
		}
		field("os", osLabel(host.OS))
		field("addr", orDash(host.Addr))
		field("user", orDash(host.User))
		field("port", port)
		field("alias", orDash(host.SSHConfigAlias))
		identity := orDash(host.IdentityFile)
		if host.IdentityFile != "" {
			identity += " " + s.styles.dim.Render("[key]")
		}
		field("identity", identity)
		field("password", s.passwordCell(name))
		field("tags", orDash(strings.Join(host.Tags, ", ")))
		b.WriteString("\n")
		if s.testing {
			fmt.Fprintf(&b, "%s %s%s\n", s.styles.dim.Render(fmt.Sprintf("%-9s", "probe")), s.spinner.View(), s.styles.dim.Render(" testing…"))
		} else {
			field("probe", s.probeCell(name))
		}
	}

	panel := s.styles.panel.Width(box)
	if height > 0 {
		panel = panel.MaxHeight(height)
	}
	if focused {
		panel = panel.BorderForeground(theme.Accent)
	} else {
		panel = panel.BorderForeground(theme.Border)
	}
	return panel.Render(b.String())
}

func osLabel(osName string) string {
	if strings.TrimSpace(osName) == "" {
		return "-"
	}
	return osName
}

func (s hostsSection) probeCell(name string) string {
	p, ok := s.probes[name]
	if !ok {
		return s.styles.dim.Render("not tested — press t")
	}
	if p.ok {
		return s.styles.ok.Render(s.styles.glyphs.OK + " ok · " + durStr(p.dur.Milliseconds()))
	}
	return s.styles.err.Render(s.styles.glyphs.Fail + " " + truncate(p.detail, 40))
}

func (s hostsSection) passwordCell(name string) string {
	if !s.secretsReadable {
		return s.styles.dim.Render("managed via `agentssh secret`")
	}
	if s.secretHosts[name] {
		return s.styles.ok.Render(s.styles.glyphs.OK + " stored (encrypted)")
	}
	return s.styles.dim.Render("— (not stored)")
}

// ---- modal overlays (centered cards + discovery) ----

func (s hostsSection) centeredCard(card string) string {
	if s.w > 0 && s.h > 0 {
		placed := lipgloss.Place(s.w, s.h, lipgloss.Center, lipgloss.Center, card)
		return lipgloss.NewStyle().MaxWidth(s.w).MaxHeight(s.h).Render(placed)
	}
	return card
}

func (s hostsSection) cardContentWidth() int {
	const natural = 60
	if s.w <= 0 {
		return natural
	}
	w := s.w - 4 - 4
	if w < 16 {
		w = 16
	}
	if w > natural {
		w = natural
	}
	return w
}

func (s hostsSection) errorCardView() string {
	cw := s.cardContentWidth()
	var b strings.Builder
	b.WriteString(s.styles.err.Render(s.styles.glyphs.Fail + " Inventory error"))
	b.WriteString("\n\n")
	msg := s.loadErr.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	b.WriteString(truncate(msg, cw))
	b.WriteString("\n\n")
	b.WriteString(s.styles.dim.Render("File: " + s.paths.InventoryFile))
	b.WriteString("\n")
	b.WriteString("Fix it in your editor, then " + keyHint(s.styles, "r", "reload"))
	card := s.styles.panel.BorderForeground(theme.Danger).Width(cw).Render(b.String())
	return s.centeredCard(card)
}

func (s hostsSection) confirmCardView() string {
	cw := s.cardContentWidth()
	name := ""
	if len(s.names) > 0 {
		name = s.names[s.cursor]
	}
	var b strings.Builder
	b.WriteString(s.styles.confirm.Render(s.styles.glyphs.Warn + " Remove host"))
	b.WriteString("\n\n")
	b.WriteString("Delete " + s.styles.header.Render(name) + " from inventory.yaml?")
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("A stored password (if any) stays in secrets.enc — remove with `agentssh secret rm`."))
	b.WriteString("\n\n")
	b.WriteString(keyHint(s.styles, "y", "confirm") + "    " + keyHint(s.styles, "n/esc", "cancel"))
	card := s.styles.panel.BorderForeground(theme.Warn).Width(cw).Render(b.String())
	return s.centeredCard(card)
}

func (s hostsSection) discoveryView() string {
	var b strings.Builder
	b.WriteString(s.styles.header.Render("Discover Hosts"))
	b.WriteString("\n")
	if s.discover.err != nil {
		b.WriteString(s.styles.err.Render(s.discover.err.Error()))
		b.WriteString("\n")
	}
	if s.discover.status != "" {
		if s.discover.loading || s.discover.probing {
			b.WriteString(s.spinner.View())
			b.WriteString(" ")
		}
		b.WriteString(s.styles.ok.Render(s.discover.status))
		b.WriteString("\n")
	}
	if s.discover.loading {
		b.WriteString(s.styles.dim.Render("scanning ssh config and known_hosts…"))
		b.WriteString("\n")
	} else if len(s.discover.candidates) == 0 {
		b.WriteString(s.styles.dim.Render("No hosts found in ~/.ssh/config or known_hosts."))
		b.WriteString("\n")
		b.WriteString(s.styles.dim.Render("Press esc to close, then a on the grid to add one by hand."))
		b.WriteString("\n")
	} else {
		window, start := s.discoverWindow()
		rows := make([][]string, 0, len(window))
		for i, candidate := range window {
			probing := s.discover.probingKeys[candidateKey(candidate)]
			rows = append(rows, discoverRow(s.styles.glyphs, candidate, s.discover.selected[start+i], probing))
		}
		b.WriteString(renderTable(s.styles, discoverColumns, rows, s.discover.cursor-start, s.w, true))
		b.WriteString("\n")
		if cur := s.discover.cursor; cur >= 0 && cur < len(s.discover.candidates) {
			if h := s.discover.candidates[cur].Hint; h != "" {
				b.WriteString(s.styles.dim.Render("  " + h))
				b.WriteString("\n")
			}
		}
	}
	for _, note := range s.discover.notes {
		b.WriteString(s.styles.dim.Render("note: " + note))
		b.WriteString("\n")
	}
	return b.String()
}

func (s hostsSection) discoverWindow() (candidates []discovery.Candidate, start int) {
	chrome := 3
	if s.discover.err != nil {
		chrome++
	}
	if s.discover.status != "" {
		chrome++
	}
	chrome += len(s.discover.notes)
	height := s.h - chrome
	if s.h <= 0 {
		height = len(s.discover.candidates)
	} else if height < 1 {
		height = 1
	}
	start, end := scrollWindow(s.discover.cursor, len(s.discover.candidates), height)
	return s.discover.candidates[start:end], start
}

var discoverColumns = []tableColumn{
	{header: "SEL", min: 3},
	{header: "NAME", min: 6, max: 30, weight: 2},
	{header: "SOURCE", min: 6, max: 12, weight: 1},
	{header: "ADDR", min: 8, max: 30, weight: 2},
	{header: "KEY", min: 3},
	{header: "KNW", min: 3},
	{header: "INV", min: 3},
	{header: "STATUS", min: 8, max: 20, weight: 1},
}

func discoverRow(g theme.Glyphs, candidate discovery.Candidate, selected, probing bool) []string {
	sel := "[ ]"
	if selected {
		sel = "[x]"
	}
	status := discoveryStatusCell(g, candidate)
	if probing {
		status = g.Maybe + " probing"
	}
	return []string{
		sel,
		candidate.Name,
		candidate.Source,
		formatDiscoveryAddr(candidate),
		glyphBool(g, candidate.HasKey),
		glyphBool(g, candidate.InKnownHosts),
		glyphBool(g, candidate.InInventory),
		status,
	}
}

func formatDiscoveryAddr(candidate discovery.Candidate) string {
	if candidate.Port == 0 || candidate.Port == 22 {
		return candidate.Addr
	}
	return fmt.Sprintf("%s:%d", candidate.Addr, candidate.Port)
}

func glyphBool(g theme.Glyphs, ok bool) string {
	if ok {
		return g.OK
	}
	return g.Absent
}

func discoveryStatusCell(g theme.Glyphs, candidate discovery.Candidate) string {
	switch candidate.ProbeStatus {
	case executor.ProbeConnectable:
		return g.OK + " reachable"
	case executor.ProbeAuthFailed:
		return g.Warn + " auth-failed"
	case executor.ProbeHostKeyIssue:
		return g.Warn + " host-key"
	case executor.ProbeUnreachable:
		return g.Fail + " unreachable"
	}
	switch {
	case candidate.InInventory:
		return g.Absent + " in inventory"
	case candidate.HasKey:
		return g.Maybe + " looks-connectable"
	default:
		return g.Absent + " needs-auth"
	}
}

func sortedHostNames(hosts map[string]inventory.Host) []string {
	names := make([]string, 0, len(hosts))
	for name := range hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedGroupNames(groups map[string]inventory.Group) []string {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
