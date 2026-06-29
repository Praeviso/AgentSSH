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

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/secrets"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
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

// statusLevel tags the transient grid status line so it renders in a color that
// matches its meaning. Without it every status — including "FAILED <host>" — was
// painted in the green success style, so a failed connectivity test read as a win.
type statusLevel int

const (
	statusInfo statusLevel = iota // neutral progress / cancellation (dim)
	statusOK                      // success (green)
	statusErr                     // failure (red)
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
	statusLevel statusLevel // severity of status, drives its color (see statusLevel)
	err         error       // transient operation error (shown inline)
	loadErr     error       // inventory load/parse error (blocking; shows the error card)
	form        hostform.Model
	focus       hostFocus
	filter      textinput.Model // the / search box that narrows the grid
	filtering   bool            // the filter box is focused and capturing keys
	query       string          // the live/committed filter query ("" = no filter)
	// Inline editing of the detail screen's Info pane: the same field list is both
	// the read view and the editor — a field cursor browses the editable rows, and
	// one row at a time turns into infoInput. No separate form, no staged save.
	infoFieldCursor int
	infoEditing     bool
	infoEditField   string
	infoEditErr     string
	infoInput       textinput.Model
	// The "auth" row is a two-stage edit: first pick a mode (key/password), then
	// enter its value. infoAuthChoosing is the mode-select stage; infoAuthMode is
	// the chosen mode. Key edits inventory's IdentityFile (empty = default ssh keys);
	// password writes the encrypted secrets store.
	infoAuthChoosing bool
	infoAuthMode     string
	testing          bool // a host connectivity probe is in flight
	discover         discoveryOverlay
	discoverSeq      int
	spinner          spinner.Model
	probes           map[string]hostProbe // last probe verdict per host
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

// setStatus sets the transient grid status line together with its severity so the
// two never drift — the level decides the color the status renders in (see View).
func (s *hostsSection) setStatus(level statusLevel, text string) {
	s.status = text
	s.statusLevel = level
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
	os   string
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
	ti := textinput.New()
	ti.Placeholder = "name, tag, addr, or user"
	ti.Prompt = "/ "
	s.filter = ti
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

// selectedHost returns the host name under the grid cursor, or "". The cursor
// indexes the visible (filtered) list, so this resolves against it.
func (s hostsSection) selectedHost() string {
	vis := s.visible()
	if s.cursor < 0 || s.cursor >= len(vis) {
		return ""
	}
	return vis[s.cursor]
}

// visible is the subset of hosts the grid shows: the full sorted list, narrowed
// to those matching the active filter query (by name, tag, addr, or user).
func (s hostsSection) visible() []string {
	q := strings.ToLower(strings.TrimSpace(s.query))
	if q == "" {
		return s.names
	}
	out := make([]string, 0, len(s.names))
	for _, name := range s.names {
		if hostMatchesQuery(s.inventory.Hosts[name], name, q) {
			out = append(out, name)
		}
	}
	return out
}

// hostMatchesQuery reports whether a host matches the (lowercased) filter query,
// matching its name, any tag, its address, or its user as a substring.
func hostMatchesQuery(h inventory.Host, name, q string) bool {
	if strings.Contains(strings.ToLower(name), q) ||
		strings.Contains(strings.ToLower(h.Addr), q) ||
		strings.Contains(strings.ToLower(h.User), q) {
		return true
	}
	for _, tag := range h.Tags {
		if strings.Contains(strings.ToLower(tag), q) {
			return true
		}
	}
	return false
}

// filterActive reports whether a filter query is currently narrowing the grid.
func (s hostsSection) filterActive() bool { return strings.TrimSpace(s.query) != "" }

// visibleCount is the number of hosts currently shown under the active filter.
func (s hostsSection) visibleCount() int { return len(s.visible()) }

// capturing reports whether the grid owns the keyboard (a modal/text mode), so
// the shell must not steal q/?.
func (s hostsSection) capturing() bool {
	return s.filtering || s.focus == hostFocusForm || s.focus == hostFocusConfirm || s.focus == hostFocusDiscover
}

func (s hostsSection) helpKeyMap() help.KeyMap {
	if s.loadErr != nil {
		return helpMap{short: []key.Binding{hk("r", "reload inventory")}}
	}
	if s.filtering {
		return helpMap{short: []key.Binding{hk("enter", "apply"), hk("esc", "clear")}}
	}
	switch s.focus {
	case hostFocusForm:
		return helpMap{short: []key.Binding{hk("tab", "next"), hk("shift+tab", "prev"), hk("enter", "save"), hk("esc", "cancel")}}
	case hostFocusDiscover:
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("space", "select"), hk("p", "probe"), hk("enter", "import"), hk("esc", "close")}}
	case hostFocusConfirm:
		return helpMap{short: []key.Binding{hk("y", "confirm"), hk("n/esc", "cancel")}}
	default:
		// Footer stays terse; ? expands to the grouped full help below.
		short := []key.Binding{hk("enter", "open"), hk("/", "filter"), hk("a", "add")}
		// Grouped full help (shown on ?): movement, finding, and actions as columns.
		full := [][]key.Binding{
			{hk("↑↓←→/hjkl", "move"), hk("g/G", "home/end"), hk("/", "filter")},
			{hk("enter/i", "open"), hk("a", "add")},
			{hk("D", "discover"), hk("t", "test"), hk("r", "reload")},
		}
		return helpMap{short: short, full: full}
	}
}

func (s hostsSection) Init() tea.Cmd { return nil }

func (s hostsSection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		s.w, s.h = ws.Width, ws.Height
		if s.w > 0 {
			fw := s.w - lipgloss.Width(s.filter.Prompt) - 1
			if fw < 8 {
				fw = 8
			}
			s.filter.Width = fw
		}
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
			s.setStatus(statusOK, "OK "+msg.name)
			s.probes[msg.name] = hostProbe{ok: true, detail: "ok", dur: msg.dur}
			if msg.os != "" {
				s.setHostOS(msg.name, msg.os)
			}
		case msg.hint != "":
			s.err = nil
			s.setStatus(statusErr, "FAILED "+msg.name+": "+msg.hint)
			s.probes[msg.name] = hostProbe{ok: false, detail: msg.hint, dur: msg.dur}
		case msg.err != nil:
			s.err = nil
			hint := executor.ConnectHint(msg.err)
			s.setStatus(statusErr, "FAILED "+msg.name+": "+hint)
			s.probes[msg.name] = hostProbe{ok: false, detail: hint, dur: msg.dur}
		}
		return s, nil
	}

	// The filter box overlays the grid (not a modal screen), so it intercepts keys
	// before the focus switch while it is open; non-key messages still flow to it so
	// its cursor keeps blinking.
	if s.filtering {
		if km, ok := msg.(tea.KeyMsg); ok {
			return s.updateFilter(km)
		}
		var cmd tea.Cmd
		s.filter, cmd = s.filter.Update(msg)
		return s, cmd
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

// updateFilter handles keys while the / filter box is focused: enter commits and
// returns to grid navigation (keeping the filter applied), esc clears it, and any
// other key edits the query with live, as-you-type filtering.
func (s hostsSection) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		s.filtering = false
		s.filter.Blur()
		s.query = strings.TrimSpace(s.filter.Value())
		s.clampCursor()
		return s, nil
	case "esc":
		s.filtering = false
		s.filter.Blur()
		s.filter.SetValue("")
		s.query = ""
		s.clampCursor()
		return s, nil
	}
	var cmd tea.Cmd
	s.filter, cmd = s.filter.Update(msg)
	s.query = s.filter.Value()
	s.cursor = 0 // jump to the first match as the query narrows
	s.clampCursor()
	return s, cmd
}

// startProbe begins a connectivity test for name (used by the Info pane in the
// detail screen). The result lands back via hostProbeMsg.
func (s hostsSection) startProbe(name string) (hostsSection, tea.Cmd) {
	if s.testing || name == "" {
		return s, nil
	}
	s.setStatus(statusInfo, "testing "+name+"…")
	s.err = nil
	s.testing = true
	return s, tea.Batch(s.probeHostCmd(name), s.spinner.Tick)
}

// editableInfoFields lists the Info-pane rows that can be edited in place, in the
// order they render. os is auto-detected by probing and password is held in the
// encrypted secrets store (`agentssh secret`), so neither is editable here.
func editableInfoFields() []string {
	return []string{"addr", "user", "port", "alias", "auth", "tags"}
}

// infoFieldRaw is the editable (unstyled) value of one field, as the inline input
// should prefill it. An unset port prefills empty so saving it keeps the default.
func infoFieldRaw(h inventory.Host, key string) string {
	switch key {
	case "addr":
		return h.Addr
	case "user":
		return h.User
	case "port":
		if h.Port == 0 {
			return ""
		}
		return strconv.Itoa(h.Port)
	case "alias":
		return h.SSHConfigAlias
	case "tags":
		return strings.Join(h.Tags, ", ")
	}
	return ""
}

// resetInfoEdit returns the Info pane to its browse state with the field cursor at
// the top — called when a host's detail screen is (re)opened.
func (s hostsSection) resetInfoEdit() hostsSection {
	s.infoFieldCursor = 0
	s.infoEditing = false
	s.infoEditField = ""
	s.infoEditErr = ""
	s.infoAuthChoosing = false
	s.infoAuthMode = ""
	return s
}

// cancelInfoEdit returns the pane to its browse state, keeping the field cursor.
func (s hostsSection) cancelInfoEdit() hostsSection {
	s.infoEditing = false
	s.infoAuthChoosing = false
	s.infoEditErr = ""
	s.infoInput.Blur()
	return s
}

func (s *hostsSection) infoFieldDown() {
	if s.infoFieldCursor < len(editableInfoFields())-1 {
		s.infoFieldCursor++
	}
}

func (s *hostsSection) infoFieldUp() {
	if s.infoFieldCursor > 0 {
		s.infoFieldCursor--
	}
}

// beginInfoEdit turns the focused field row into an editor prefilled with its
// current value — the pane layout is unchanged, only that one row becomes editable.
// The auth row opens in its mode-select stage instead of a text input.
func (s hostsSection) beginInfoEdit(name string) (hostsSection, tea.Cmd) {
	host, ok := s.inventory.Hosts[name]
	if !ok {
		return s, nil
	}
	fields := editableInfoFields()
	if s.infoFieldCursor < 0 || s.infoFieldCursor >= len(fields) {
		return s, nil
	}
	key := fields[s.infoFieldCursor]
	s.infoEditField = key
	s.infoEditErr = ""
	s.infoEditing = true
	if key == "auth" {
		// Open in the mode-select stage, defaulting to the mode already in effect.
		s.infoAuthChoosing = true
		if host.IdentityFile == "" && s.secretsReadable && s.secretHosts[name] {
			s.infoAuthMode = "password"
		} else {
			s.infoAuthMode = "key"
		}
		return s, nil
	}
	s.infoAuthChoosing = false
	s.infoInput = s.newInfoInput(infoFieldRaw(host, key), false, "")
	return s, s.infoInput.Focus()
}

// newInfoInput builds an inline value input sized to the value column, optionally
// masked (passwords), reserving room for the auth mode prefix when editing auth.
func (s hostsSection) newInfoInput(value string, masked bool, placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.Placeholder = placeholder
	if masked {
		ti.EchoMode = textinput.EchoPassword
	}
	ti.SetValue(value)
	ti.CursorEnd()
	reserve := 0
	if s.infoEditField == "auth" {
		reserve = len(s.infoAuthMode) + 2 // the "key  " / "password  " prefix
	}
	if w := s.w - infoValGutter - reserve; w > 6 {
		ti.Width = w
	} else {
		ti.Width = 6
	}
	return ti
}

// beginAuthValue advances the auth edit from mode-select to the value input: a path
// for key (empty = default ssh keys) or a masked password.
func (s hostsSection) beginAuthValue(name string) (hostsSection, tea.Cmd) {
	s.infoAuthChoosing = false
	if s.infoAuthMode == "password" {
		s.infoInput = s.newInfoInput("", true, "new password · empty keeps current")
	} else {
		s.infoInput = s.newInfoInput(s.inventory.Hosts[name].IdentityFile, false, "path · empty = default ssh keys")
	}
	return s, s.infoInput.Focus()
}

// updateInfoEdit drives the inline editor: the auth row first picks a mode, then any
// field takes a value — enter commits, esc discards, other keys edit.
func (s hostsSection) updateInfoEdit(msg tea.Msg, name string) (hostsSection, tea.Cmd) {
	km, isKey := msg.(tea.KeyMsg)
	if s.infoAuthChoosing {
		if !isKey {
			return s, nil
		}
		switch km.String() {
		case "left", "h", "right", "l", "tab", " ":
			if s.infoAuthMode == "password" {
				s.infoAuthMode = "key"
			} else {
				s.infoAuthMode = "password"
			}
		case "enter":
			return s.beginAuthValue(name)
		case "esc":
			return s.cancelInfoEdit(), nil
		}
		return s, nil
	}
	if isKey {
		switch km.String() {
		case "enter":
			return s.commitInfoEdit(name)
		case "esc":
			return s.cancelInfoEdit(), nil
		}
	}
	var cmd tea.Cmd
	s.infoInput, cmd = s.infoInput.Update(msg)
	return s, cmd
}

// commitInfoEdit writes the edited field. Plain fields and the auth key go to
// inventory.yaml; the auth password goes to the encrypted secrets store. On a
// validation error it keeps the input open and shows the message inline; on success
// it returns to browse and (for inventory edits) signals the change to the panes.
func (s hostsSection) commitInfoEdit(name string) (hostsSection, tea.Cmd) {
	val := s.infoInput.Value()
	if s.infoEditField == "auth" {
		if s.infoAuthMode == "password" {
			if val == "" {
				// Empty means "no change" — removing a stored password is a CLI action.
				return s.cancelInfoEdit(), toastCmd("password unchanged · " + name)
			}
			if err := s.setHostPassword(name, val); err != nil {
				s.infoEditErr = err.Error()
				return s, nil
			}
			return s.cancelInfoEdit(), toastCmd("password updated · " + name)
		}
		// key mode writes the identity path (empty clears it → default ssh keys).
		if err := s.setHostField(name, "identity", val); err != nil {
			s.infoEditErr = err.Error()
			return s, nil
		}
		return s.cancelInfoEdit(), tea.Batch(inventoryChangedCmd(s.inventory), toastCmd("key updated · "+name))
	}
	if err := s.setHostField(name, s.infoEditField, val); err != nil {
		s.infoEditErr = err.Error()
		return s, nil
	}
	return s.cancelInfoEdit(), tea.Batch(inventoryChangedCmd(s.inventory), toastCmd(s.infoEditField+" updated · "+name))
}

// setHostPassword stores the encrypted password for name. It needs
// AGENTSSH_MASTER_PASSWORD, mirroring the add form's password path.
func (s *hostsSection) setHostPassword(name, password string) error {
	master := os.Getenv("AGENTSSH_MASTER_PASSWORD")
	if master == "" {
		return fmt.Errorf("set AGENTSSH_MASTER_PASSWORD to edit passwords here, or use `agentssh secret set %s`", name)
	}
	store, err := secrets.Open(s.paths.SecretsFile, master)
	if errors.Is(err, secrets.ErrWrongMaster) {
		return fmt.Errorf("cannot open secrets: wrong master password or corrupt secrets file")
	}
	if err != nil {
		return err
	}
	store.Set(name, password)
	if err := store.Save(master); err != nil {
		return err
	}
	if s.secretHosts == nil {
		s.secretHosts = map[string]bool{}
	}
	s.secretHosts[name] = true
	s.secretsReadable = true
	return nil
}

// setHostField applies a single edited field to name in inventory.yaml, preserving
// every other field (including the probed OS).
func (s *hostsSection) setHostField(name, field, raw string) error {
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return err
	}
	host, ok := base.Hosts[name]
	if !ok {
		return inventory.ErrHostNotFound
	}
	switch field {
	case "addr":
		v := strings.TrimSpace(raw)
		if v == "" {
			return fmt.Errorf("addr cannot be empty")
		}
		host.Addr = v
	case "user":
		host.User = strings.TrimSpace(raw)
	case "port":
		v := strings.TrimSpace(raw)
		if v == "" {
			host.Port = 0
		} else {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("port must be a number 1–65535")
			}
			host.Port = n
		}
	case "alias":
		host.SSHConfigAlias = strings.TrimSpace(raw)
	case "identity":
		host.IdentityFile = strings.TrimSpace(raw)
	case "tags":
		host.Tags = hostform.SplitTags(raw)
	default:
		return fmt.Errorf("unknown field %q", field)
	}
	next, err := inventory.UpdateHost(base, name, host)
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

// startDelete opens the delete-confirm. Like inline edit it is driven from the Info
// pane; updateConfirm/removeSelected resolve the target via selectedHost, which
// equals the detail host because the grid cursor stays put while detail is open.
func (s hostsSection) startDelete(name string) hostsSection {
	if name == "" {
		return s
	}
	s.focus = hostFocusConfirm
	return s
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
	// The form only ever creates hosts now — editing an existing host happens inline
	// on the Info pane (see beginInfoEdit), so there is no update branch here.
	if !result.Submitted {
		s.setStatus(statusInfo, "add cancelled")
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
		name := s.selectedHost()
		removed, policyCmd := s.removeSelected()
		s.focus = hostFocusList
		if removed {
			return s, tea.Batch(inventoryChangedCmd(s.inventory), policyCmd, toastCmd("host removed: "+name))
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
	last := len(s.visible()) - 1
	switch keyMsg.String() {
	case "/":
		s.filtering = true
		s.filter.SetValue(s.query)
		s.filter.CursorEnd()
		return s, s.filter.Focus()
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
	case "D":
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
		if s.selectedHost() == "" {
			s.setStatus(statusInfo, "no host selected")
			return s, nil
		}
		name := s.selectedHost()
		s.setStatus(statusInfo, "testing "+name+"…")
		s.err = nil
		s.testing = true
		return s, tea.Batch(s.probeHostCmd(name), s.spinner.Tick)
	case "r":
		// Reload inventory.yaml from disk (e.g. after editing it externally); the
		// same key reloads from the parse-error card.
		return s.reloadInventory()
	case "enter", "i":
		if s.selectedHost() != "" {
			s.open = true
		}
	case "esc":
		// esc clears an active filter first; only when there is none does it drop the
		// transient status line.
		if s.filterActive() {
			s.query = ""
			s.filter.SetValue("")
			s.clampCursor()
		} else {
			s.status = ""
		}
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
			return hostProbeMsg{name: name, ok: true, dur: result.Duration, os: result.OS}
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
		s.setStatus(statusInfo, "discover cancelled")
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

func (s *hostsSection) setHostOS(name string, osName string) {
	osName = strings.TrimSpace(osName)
	if name == "" || osName == "" {
		return
	}
	host, ok := s.inventory.Hosts[name]
	if !ok || host.OS == osName {
		return
	}
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		s.err = err
		return
	}
	if host, ok = base.Hosts[name]; !ok || host.OS == osName {
		return
	}
	next, err := inventory.SetHostOS(base, name, osName)
	if err != nil {
		s.err = err
		return
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		s.err = err
		return
	}
	s.inventory = next
	s.rebuildNames()
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
	_, err = s.clearHostRulesForDeletedHost(name)
	return err
}

func (s hostsSection) appendDeleteAudit(name string, event audit.Event, errText string, exitCode int) error {
	reqID, err := audit.NewReqID()
	if err != nil {
		return err
	}
	exit := exitCode
	_, err = audit.NewStore(s.paths.AuditFile).Append(audit.Record{
		ReqID:    reqID,
		Event:    event,
		Host:     name,
		Cmd:      "inventory rm " + name,
		Error:    errText,
		ExitCode: &exit,
	})
	return err
}

func (s *hostsSection) removeSelected() (bool, tea.Cmd) {
	name := s.selectedHost()
	if name == "" {
		return false, nil
	}
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		if auditErr := s.appendDeleteAudit(name, audit.EventFailed, err.Error(), 1); auditErr != nil {
			err = fmt.Errorf("%v; audit failed: %w", err, auditErr)
		}
		s.err = err
		s.status = ""
		return false, nil
	}
	next, err := inventory.RemoveHost(base, name)
	if err != nil {
		if auditErr := s.appendDeleteAudit(name, audit.EventFailed, err.Error(), 2); auditErr != nil {
			err = fmt.Errorf("%v; audit failed: %w", err, auditErr)
		}
		s.err = err
		s.status = ""
		return false, nil
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		if auditErr := s.appendDeleteAudit(name, audit.EventFailed, err.Error(), 1); auditErr != nil {
			err = fmt.Errorf("%v; audit failed: %w", err, auditErr)
		}
		s.err = err
		s.status = ""
		return false, nil
	}
	s.inventory = next
	s.rebuildNames()
	delete(s.secretHosts, name)
	s.err = nil
	policyCmd, err := s.clearHostRulesForDeletedHost(name)
	if err != nil {
		if auditErr := s.appendDeleteAudit(name, audit.EventFailed, err.Error(), 1); auditErr != nil {
			err = fmt.Errorf("%v; audit failed: %w", err, auditErr)
		}
		s.err = err
		s.status = ""
		return true, inventoryChangedCmd(s.inventory)
	}
	if err := s.appendDeleteAudit(name, audit.EventCompleted, "", 0); err != nil {
		s.err = err
		s.setStatus(statusErr, "removed "+name+" but failed to audit deletion")
		return true, policyCmd
	}
	return true, policyCmd
}

func (s *hostsSection) clearHostRulesForDeletedHost(name string) (tea.Cmd, error) {
	cfg, err := policy.Load(s.paths.PolicyFile)
	if err != nil {
		return nil, err
	}
	next, err := policy.ClearHostRules(policy.Bundle{Policy: cfg}, name)
	if errors.Is(err, policy.ErrNoHostRules) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validatePolicyForTUI(next.Policy, s.inventory); err != nil {
		return nil, err
	}
	if err := policy.Save(s.paths.PolicyFile, next.Policy); err != nil {
		return nil, err
	}
	return policyChangedCmd(next.Policy, "host rules cleared: "+name), nil
}

func (s *hostsSection) rebuildNames() {
	s.names = sortedHostNames(s.inventory.Hosts)
	s.clampCursor()
}

// clampCursor keeps the grid cursor within the visible (filtered) list after the
// inventory or the filter query changes.
func (s *hostsSection) clampCursor() {
	n := len(s.visible())
	if s.cursor >= n {
		s.cursor = n - 1
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
	if n := len(s.visible()); cols > n && n > 0 {
		cols = n
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
	// The filter input (while editing) or the committed-filter chip costs one line.
	if s.filtering || s.filterActive() {
		h++
	}
	return h
}

// statusStyle maps the status severity to its color: green for success, red for
// failure, dim for neutral progress and cancellations.
func (s hostsSection) statusStyle() lipgloss.Style {
	switch s.statusLevel {
	case statusOK:
		return s.styles.ok
	case statusErr:
		return s.styles.err
	default:
		return s.styles.dim
	}
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
		b.WriteString(truncate(s.statusStyle().Render(s.status), s.w))
		b.WriteString("\n")
	}
	// Filter affordance: the live input while editing, or a static chip once a
	// committed filter is narrowing the grid.
	if s.filtering {
		b.WriteString(truncate(s.filter.View(), s.w))
		b.WriteString("\n")
	} else if s.filterActive() {
		chip := fmt.Sprintf("filter %q · esc clears", strings.TrimSpace(s.query))
		b.WriteString(truncate(s.styles.dim.Render(chip), s.w))
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
	if len(s.visible()) == 0 {
		b.WriteString(s.styles.dim.Render(fmt.Sprintf("No hosts match %q.", strings.TrimSpace(s.query))))
		return b.String()
	}
	b.WriteString(s.gridView())
	return b.String()
}

// gridView renders the responsive, equal-sized card grid, windowed vertically so
// the selected card stays on screen.
func (s hostsSection) gridView() string {
	vis := s.visible()
	cols := s.gridCols()
	cardW := s.cardOuterWidth(cols)
	totalRows := (len(vis) + cols - 1) / cols

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
			if idx >= len(vis) {
				break
			}
			if c > 0 {
				cards = append(cards, strings.Repeat(" ", cardGap))
			}
			cards = append(cards, s.renderHostCard(vis[idx], cardW, idx == s.cursor))
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

// infoValGutter is the chrome (border + padding + cursor gutter + label + space,
// on both sides) around the Info pane's value column, so the inline input width is
// s.w - infoValGutter — matching where the read-only value would sit.
const infoValGutter = 16

// infoView renders the selected host's facts as a bordered panel that doubles as
// the editor: a field cursor browses the editable rows and one row at a time turns
// into infoInput, all in the same layout. box is the lipgloss box width (padding
// included; border sits outside it), clamped to height. focused accents the border
// (the active pane) and enables the field cursor.
func (s hostsSection) infoView(name string, box, height int, focused bool) string {
	host, ok := s.inventory.Hosts[name]
	// Floor at 18 so the field layout (2-col cursor gutter + 9-col label + space + a
	// >=4-col value) fits the text area (box-2) without overflowing on a tiny box.
	if box < 18 {
		box = 18
	}
	textW := box - 2 // padding
	valW := textW - 12
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
		// Read-only row: a 2-col gutter keeps its label aligned with editable rows.
		roRow := func(label, val string) {
			fmt.Fprintf(&b, "  %s %s\n", s.styles.dim.Render(fmt.Sprintf("%-9s", label)), truncate(val, valW))
		}
		// Editable row idx: the field cursor (›) marks the focused row — while browsing
		// and while editing — and the inline input replaces its value during an edit.
		// The auth row (key "auth") has its own mode-select / value cells.
		editRow := func(idx int, key, val string) {
			gutter := "  "
			cell := truncate(val, valW)
			if focused && idx == s.infoFieldCursor {
				gutter = s.styles.cursor.Render("› ")
				switch {
				case key == "auth" && s.infoEditing && s.infoAuthChoosing:
					cell = s.authModeCell()
				case s.infoEditing && key == "auth":
					cell = s.styles.dim.Render(s.infoAuthMode+"  ") + s.infoInput.View()
				case s.infoEditing:
					cell = s.infoInput.View()
				}
			}
			fmt.Fprintf(&b, "%s%s %s\n", gutter, s.styles.dim.Render(fmt.Sprintf("%-9s", key)), cell)
		}
		port := "22"
		if host.Port != 0 {
			port = strconv.Itoa(host.Port)
		}
		roRow("os", osLabel(host.OS))
		editRow(0, "addr", orDash(host.Addr))
		editRow(1, "user", orDash(host.User))
		editRow(2, "port", port)
		editRow(3, "alias", orDash(host.SSHConfigAlias))
		editRow(4, "auth", s.authSummary(name, host))
		editRow(5, "tags", orDash(strings.Join(host.Tags, ", ")))
		b.WriteString("\n")
		if s.testing {
			fmt.Fprintf(&b, "  %s %s%s\n", s.styles.dim.Render(fmt.Sprintf("%-9s", "probe")), s.spinner.View(), s.styles.dim.Render(" testing…"))
		} else {
			roRow("probe", s.probeCell(name))
		}
		// Bridge the human viewer to the CLI that actually executes: show the run
		// template for this host (full width so the command isn't over-truncated).
		b.WriteString("\n")
		b.WriteString(truncate(s.styles.dim.Render("run · agentssh run "+name+" -- <cmd>"), textW))
		if focused && s.infoEditing && s.infoEditErr != "" {
			b.WriteString("\n")
			b.WriteString(truncate(s.styles.err.Render(s.styles.glyphs.Fail+" "+s.infoEditErr), textW))
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

// authSummary is the browse-mode value of the auth row: the configured key path,
// else a stored-password indicator, else the default-ssh-keys fallback.
func (s hostsSection) authSummary(name string, host inventory.Host) string {
	if host.IdentityFile != "" {
		return "key · " + host.IdentityFile
	}
	if s.secretsReadable && s.secretHosts[name] {
		return s.styles.ok.Render(s.styles.glyphs.OK + " password · stored (encrypted)")
	}
	if !s.secretsReadable {
		return s.styles.dim.Render("default ssh keys · password via `agentssh secret`")
	}
	return s.styles.dim.Render("default ssh keys")
}

// authModeCell renders the mode-select stage of an auth edit: the two modes with
// the chosen one highlighted.
func (s hostsSection) authModeCell() string {
	key, pw := "key", "password"
	if s.infoAuthMode == "password" {
		return s.styles.dim.Render(key) + "  " + s.styles.cursor.Render("["+pw+"]")
	}
	return s.styles.cursor.Render("["+key+"]") + "  " + s.styles.dim.Render(pw)
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
	name := s.selectedHost()
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
