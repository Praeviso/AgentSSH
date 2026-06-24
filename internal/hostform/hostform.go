package hostform

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	xterm "golang.org/x/term"
)

const defaultPort = 22

// ErrNotInteractive is returned when stdin or stdout is not a terminal.
var ErrNotInteractive = errors.New("hostform: stdin/stdout is not a terminal")

// IsNotInteractive reports whether err signals a non-interactive environment.
func IsNotInteractive(err error) bool { return errors.Is(err, ErrNotInteractive) }

// Options pre-populates the add-host form.
type Options struct {
	Name          string
	Addr          string
	User          string
	Port          int
	Tags          []string
	Alias         string
	IdentityFile  string
	ExistingNames map[string]struct{}
}

// Result is the normalized submitted form value.
type Result struct {
	Name      string
	Addr      string
	User      string
	Port      int
	Tags      []string
	Alias     string
	Identity  string
	Password  string
	Submitted bool
}

// Validate normalizes and validates host fields.
func Validate(opts Options) (Result, map[string]string) {
	values := formValues{
		name:     strings.TrimSpace(opts.Name),
		addr:     strings.TrimSpace(opts.Addr),
		user:     strings.TrimSpace(opts.User),
		port:     portString(opts.Port),
		tags:     strings.Join(opts.Tags, ","),
		alias:    strings.TrimSpace(opts.Alias),
		identity: strings.TrimSpace(opts.IdentityFile),
	}
	return validateValues(values, opts.ExistingNames)
}

// SplitTags parses comma-separated tags, trimming whitespace and dropping empty values.
func SplitTags(value string) []string {
	parts := strings.Split(value, ",")
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

// Run opens the interactive add-host form.
func Run(opts Options) (Result, error) {
	if !interactive() {
		return Result{}, ErrNotInteractive
	}
	renderer := lipgloss.NewRenderer(os.Stdout)
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		renderer.SetColorProfile(termenv.Ascii)
	}
	initial := runModel{model: New(opts, renderer)}
	final, err := tea.NewProgram(initial).Run()
	if err != nil {
		return Result{}, err
	}
	m, ok := final.(runModel)
	if !ok {
		return Result{}, fmt.Errorf("host form returned unexpected model %T", final)
	}
	return m.model.Result(), nil
}

type runModel struct {
	model Model
}

func (m runModel) Init() tea.Cmd { return m.model.Init() }

func (m runModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.model.Update(msg)
	if model, ok := next.(Model); ok {
		m.model = model
	}
	if m.model.Done() {
		return m, tea.Quit
	}
	return m, cmd
}

func (m runModel) View() string { return m.model.View() }

type formValues struct {
	name     string
	addr     string
	user     string
	port     string
	tags     string
	alias    string
	identity string
	password string
}

func validateValues(values formValues, existing map[string]struct{}) (Result, map[string]string) {
	errs := map[string]string{}

	name := strings.TrimSpace(values.name)
	if name == "" {
		errs["name"] = "name is required"
	} else if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		errs["name"] = "name must not contain whitespace"
	} else if _, ok := existing[name]; ok {
		errs["name"] = "host name already exists"
	}

	addr := strings.TrimSpace(values.addr)
	alias := strings.TrimSpace(values.alias)
	if addr == "" && alias == "" {
		errs["addr"] = "addr is required unless ssh_config_alias is set"
	}

	userName := strings.TrimSpace(values.user)
	if userName == "" {
		userName = os.Getenv("USER")
	}
	if userName == "" {
		userName = "root"
	}

	portValue := strings.TrimSpace(values.port)
	port := defaultPort
	if portValue != "" {
		parsed, err := strconv.Atoi(portValue)
		if err != nil || parsed < 1 || parsed > 65535 {
			errs["port"] = "port must be a number from 1 to 65535"
		} else {
			port = parsed
		}
	}

	result := Result{
		Name:      name,
		Addr:      addr,
		User:      userName,
		Port:      port,
		Tags:      SplitTags(values.tags),
		Alias:     alias,
		Identity:  strings.TrimSpace(values.identity),
		Password:  values.password,
		Submitted: len(errs) == 0,
	}
	if len(errs) > 0 {
		result.Submitted = false
	}
	return result, errs
}

func portString(port int) string {
	if port <= 0 {
		return ""
	}
	return strconv.Itoa(port)
}

func interactive() bool {
	return xterm.IsTerminal(int(os.Stdin.Fd())) && xterm.IsTerminal(int(os.Stdout.Fd()))
}

type field int

const (
	fieldName field = iota
	fieldAddr
	fieldUser
	fieldPort
	fieldTags
	fieldAlias
	fieldIdentity
	fieldPassword
	fieldCount
)

var fieldKeys = []string{"name", "addr", "user", "port", "tags", "alias", "identity", "password"}

type keyMap struct {
	Next      key.Binding
	Prev      key.Binding
	Submit    key.Binding
	Cancel    key.Binding
	ForceQuit key.Binding
}

func defaultKeys() keyMap {
	return keyMap{
		Next:      key.NewBinding(key.WithKeys("tab", "down")),
		Prev:      key.NewBinding(key.WithKeys("shift+tab", "up")),
		Submit:    key.NewBinding(key.WithKeys("enter")),
		Cancel:    key.NewBinding(key.WithKeys("esc")),
		ForceQuit: key.NewBinding(key.WithKeys("ctrl+c")),
	}
}

type styles struct {
	title  lipgloss.Style
	group  lipgloss.Style
	label  lipgloss.Style
	help   lipgloss.Style
	err    lipgloss.Style
	warn   lipgloss.Style
	glyphs theme.Glyphs
}

func newStyles(r *lipgloss.Renderer) styles {
	return styles{
		title:  r.NewStyle().Bold(true),
		group:  r.NewStyle().Foreground(theme.Accent).Bold(true),
		label:  r.NewStyle().Foreground(theme.Dim),
		help:   r.NewStyle().Foreground(theme.Dim),
		err:    r.NewStyle().Foreground(theme.Danger),
		warn:   r.NewStyle().Foreground(theme.Warn),
		glyphs: theme.GlyphsFor(r),
	}
}

// fieldLabels are the display labels indexed by field.
var fieldLabels = []string{"name", "addr", "user", "port", "tags", "ssh_config_alias", "identity_file", "password"}

// fieldWidths are the textinput widths indexed by field, sized for the grouped
// layout (short fields pair on one row).
var fieldWidths = []int{18, 44, 12, 5, 22, 20, 38, 24}

// Model is the embeddable add-host form model.
type Model struct {
	inputs   []textinput.Model
	focus    field
	errs     []string
	keys     keyMap
	styles   styles
	existing map[string]struct{}
	result   Result
	done     bool
	// w, h are the live render budget (the section body the shell allocates). They
	// drive responsive field widths and the height scroll window; 0 means "size
	// unknown" and the form falls back to its natural fixed widths (see
	// layoutWidths) so a direct, sizeless render keeps full content.
	w, h int
}

// SetSize records the render budget so the next View recomputes field widths and
// the scroll window. Returned by value (the form is an embeddable value model).
func (m Model) SetSize(w, h int) Model {
	m.w, m.h = w, h
	return m
}

// New constructs an add-host form without starting a Bubble Tea program.
func New(opts Options, r *lipgloss.Renderer) Model {
	if r == nil {
		r = lipgloss.NewRenderer(os.Stdout)
	}
	return newModel(opts, newStyles(r))
}

func newModel(opts Options, st styles) Model {
	inputs := make([]textinput.Model, fieldCount)
	placeholders := []string{"web-1", "10.0.0.11", "$USER", "22", "web,prod", "ssh-config-host", "~/.ssh/web-1", "optional"}
	values := []string{opts.Name, opts.Addr, opts.User, portString(opts.Port), strings.Join(opts.Tags, ","), opts.Alias, opts.IdentityFile, ""}
	for i := range inputs {
		ti := textinput.New()
		ti.Placeholder = placeholders[i]
		ti.SetValue(values[i])
		ti.Width = fieldWidths[i]
		if field(i) == fieldPassword {
			ti.EchoMode = textinput.EchoPassword
		}
		inputs[i] = ti
	}
	_ = inputs[fieldName].Focus()

	return Model{
		inputs:   inputs,
		keys:     defaultKeys(),
		styles:   st,
		errs:     make([]string, fieldCount),
		existing: opts.ExistingNames,
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Recompute layout from the live budget; the textinput needs no resize
		// message, so don't forward it.
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.ForceQuit):
			// Ctrl+C means quit, not just cancel the form: return tea.Quit so it
			// propagates up and exits the whole program (the standalone runner and
			// the embedded TUI both honor it).
			return m, tea.Quit
		case key.Matches(msg, m.keys.Cancel):
			m.result = Result{Submitted: false}
			m.done = true
			return m, nil
		case key.Matches(msg, m.keys.Next):
			return m.move(1)
		case key.Matches(msg, m.keys.Prev):
			return m.move(-1)
		case key.Matches(msg, m.keys.Submit):
			return m.submit()
		}
	}

	var cmd tea.Cmd
	m.inputs[m.focus], cmd = m.inputs[m.focus].Update(msg)
	return m, cmd
}

// Done reports whether the form has been submitted or cancelled.
func (m Model) Done() bool { return m.done }

// Result returns the normalized submitted value; Submitted is false on cancel.
func (m Model) Result() Result { return m.result }

func (m Model) View() string {
	widths := m.layoutWidths()
	// fieldBlock renders one labelled input (+ inline error) at its computed width,
	// as a block for horizontal joining.
	fieldBlock := func(f field) string {
		in := m.inputs[f]
		in.Width = widths[f]
		var b strings.Builder
		b.WriteString(m.styles.label.Render(fieldLabels[f]))
		b.WriteString("\n")
		b.WriteString(in.View())
		if m.errs[f] != "" {
			b.WriteString("\n")
			b.WriteString(m.styles.err.Render(m.errs[f]))
		}
		return b.String()
	}

	var lines []string
	focusLine := 0
	add := func(s string) { lines = append(lines, strings.Split(s, "\n")...) }
	// addRow appends a field block (whose input is its 2nd line) and records the
	// focus line when the focused field lives in this row, so the height window can
	// keep the active input on screen.
	addRow := func(block string, fs ...field) {
		for _, f := range fs {
			if f == m.focus {
				focusLine = len(lines) + 1
			}
		}
		lines = append(lines, strings.Split(block, "\n")...)
	}

	add(m.fit(m.styles.title, "Add inventory host"))
	add("")
	add(m.groupHeader("Connection"))
	addRow(joinFields(fieldBlock(fieldName), fieldBlock(fieldUser), fieldBlock(fieldPort)), fieldName, fieldUser, fieldPort)
	addRow(fieldBlock(fieldAddr), fieldAddr)
	add("")
	add(m.groupHeader("Routing"))
	addRow(joinFields(fieldBlock(fieldTags), fieldBlock(fieldAlias)), fieldTags, fieldAlias)
	add("")
	add(m.groupHeader("Auth"))
	addRow(fieldBlock(fieldIdentity), fieldIdentity)
	addRow(fieldBlock(fieldPassword), fieldPassword)
	add(m.fit(m.styles.help, "identity_file is a path saved in inventory; password is encrypted (age) and never shown."))
	if strings.TrimSpace(m.inputs[fieldPassword].Value()) != "" && os.Getenv("AGENTSSH_MASTER_PASSWORD") == "" {
		add(m.fit(m.styles.warn, m.styles.glyphs.Warn+" AGENTSSH_MASTER_PASSWORD not set — the password won't be saved."))
	}
	add("")
	add(m.fit(m.styles.help, "tab/down next · shift+tab/up prev · enter submit · esc cancel"))

	// Height window: when the form is taller than the budget, scroll it so the
	// focused field stays visible instead of letting the bottom clip off-screen
	// (mirrors the Sessions list's scrollWindow contract).
	if m.h > 0 && len(lines) > m.h {
		start, end := windowLines(focusLine, len(lines), m.h)
		lines = lines[start:end]
	}
	return strings.Join(lines, "\n")
}

// fit renders s in style, clipping it to the form width so a long line never
// wraps past the frame (mirrors the Sessions list's MaxWidth contract).
func (m Model) fit(style lipgloss.Style, s string) string {
	if m.w > 0 {
		return style.MaxWidth(m.w).Render(s)
	}
	return style.Render(s)
}

func (m Model) groupHeader(name string) string {
	prefix := "── " + name + " "
	fill := 24 - len(name)
	if m.w > 0 {
		fill = m.w - lipgloss.Width(prefix)
	}
	if fill < 0 {
		fill = 0
	}
	return m.fit(m.styles.group, prefix+strings.Repeat("─", fill))
}

// formGutter separates horizontally-joined field blocks.
const formGutter = "  "

// joinFields lays out field blocks side by side with a gutter between them.
func joinFields(blocks ...string) string {
	parts := make([]string, 0, len(blocks)*2-1)
	for i, blk := range blocks {
		if i > 0 {
			parts = append(parts, formGutter)
		}
		parts = append(parts, blk)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

// rowField is a flex spec for one input on a horizontally-joined form row:
// weight 0 is rigid (holds min); max 0 is uncapped.
type rowField struct {
	f      field
	weight int
	min    int
	max    int
}

type fittedField struct {
	f field
	w int
}

// layoutWidths returns the textinput content width for every field, derived from
// the live form width so the form fills a wide frame and shrinks on a narrow one
// instead of being hard-clipped by the shell. With an unknown size (w<=0) it
// returns the natural fixed widths so a sizeless render keeps the original layout.
func (m Model) layoutWidths() []int {
	widths := make([]int, fieldCount)
	if m.w <= 0 {
		copy(widths, fieldWidths)
		return widths
	}
	prompt := 2
	if len(m.inputs) > 0 {
		prompt = lipgloss.Width(m.inputs[0].Prompt)
	}
	// A textinput renders its prompt + content width + a trailing cursor cell, so
	// each field costs prompt+1 columns of chrome beyond its content width.
	chrome := prompt + 1
	avail := m.w - 1 // a column of slack so the widest input never touches the edge
	if avail < 12 {
		avail = 12
	}
	gut := lipgloss.Width(formGutter)
	// Row: name | user | port (two gutters + three fields of chrome).
	row1 := fitRow(avail-2*gut-3*chrome, []rowField{
		{f: fieldName, weight: 3, min: 8, max: 24},
		{f: fieldUser, weight: 2, min: 6, max: 16},
		{f: fieldPort, weight: 0, min: 5, max: 5},
	})
	// Row: addr stretches across the available width.
	rowAddr := fitRow(avail-chrome, []rowField{
		{f: fieldAddr, weight: 3, min: 12, max: 0},
	})
	// Row: tags | alias (one gutter + two fields of chrome).
	row2 := fitRow(avail-gut-2*chrome, []rowField{
		{f: fieldTags, weight: 1, min: 8, max: 40},
		{f: fieldAlias, weight: 1, min: 8, max: 40},
	})
	for _, r := range append(append(row1, rowAddr...), row2...) {
		widths[r.f] = r.w
	}
	// Single-field rows fill the row (minus their own chrome).
	widths[fieldIdentity] = clampW(avail-chrome, 12, 0)
	widths[fieldPassword] = clampW(avail-chrome, 8, 48)
	return widths
}

// fitRow assigns each field a width so the row (its widths plus the chrome the
// caller already subtracted) fills avail: start at min, grow weighted fields by
// weight up to max, then shrink toward 1 if avail is below the sum of mins.
func fitRow(avail int, fields []rowField) []fittedField {
	out := make([]fittedField, len(fields))
	used := 0
	for i, f := range fields {
		out[i] = fittedField{f: f.f, w: f.min}
		used += f.min
	}
	for {
		slack := avail - used
		if slack <= 0 {
			break
		}
		weight := 0
		for i := range fields {
			if fields[i].weight > 0 && (fields[i].max == 0 || out[i].w < fields[i].max) {
				weight += fields[i].weight
			}
		}
		if weight == 0 {
			break
		}
		grew := false
		for i := range fields {
			if slack <= 0 {
				break
			}
			if fields[i].weight == 0 || (fields[i].max != 0 && out[i].w >= fields[i].max) {
				continue
			}
			add := slack * fields[i].weight / weight
			if add < 1 {
				add = 1
			}
			if fields[i].max != 0 && out[i].w+add > fields[i].max {
				add = fields[i].max - out[i].w
			}
			if add <= 0 {
				continue
			}
			out[i].w += add
			used += add
			slack -= add
			grew = true
		}
		if !grew {
			break
		}
	}
	for used > avail {
		shrunk := false
		for i := range out {
			if used <= avail {
				break
			}
			if out[i].w > 1 {
				out[i].w--
				used--
				shrunk = true
			}
		}
		if !shrunk {
			break
		}
	}
	return out
}

func clampW(v, min, max int) int {
	if v < min {
		v = min
	}
	if max > 0 && v > max {
		v = max
	}
	return v
}

// windowLines returns the [start,end) bounds of a height-line scroll window that
// keeps focus visible, centering it within the window where possible.
func windowLines(focus, n, height int) (start, end int) {
	if height <= 0 || height >= n {
		return 0, n
	}
	start = focus - height/2
	if start < 0 {
		start = 0
	}
	end = start + height
	if end > n {
		end = n
		start = end - height
	}
	return start, end
}

func (m Model) move(delta int) (tea.Model, tea.Cmd) {
	m.validateField(m.focus)
	m.inputs[m.focus].Blur()
	next := (int(m.focus) + delta + int(fieldCount)) % int(fieldCount)
	m.focus = field(next)
	cmd := m.inputs[m.focus].Focus()
	return m, cmd
}

func (m Model) submit() (tea.Model, tea.Cmd) {
	result, errs := validateValues(m.values(), m.existing)
	m.result = result
	m.clearErrors()
	if len(errs) == 0 {
		m.result.Submitted = true
		m.done = true
		return m, nil
	}
	for i, key := range fieldKeys {
		m.errs[i] = errs[key]
	}
	for i := range m.errs {
		if m.errs[i] != "" {
			m.inputs[m.focus].Blur()
			m.focus = field(i)
			return m, m.inputs[m.focus].Focus()
		}
	}
	return m, nil
}

func (m *Model) validateField(f field) {
	_, errs := validateValues(m.values(), m.existing)
	m.errs[f] = errs[fieldKeys[f]]
}

func (m Model) values() formValues {
	return formValues{
		name:     m.inputs[fieldName].Value(),
		addr:     m.inputs[fieldAddr].Value(),
		user:     m.inputs[fieldUser].Value(),
		port:     m.inputs[fieldPort].Value(),
		tags:     m.inputs[fieldTags].Value(),
		alias:    m.inputs[fieldAlias].Value(),
		identity: m.inputs[fieldIdentity].Value(),
		password: m.inputs[fieldPassword].Value(),
	}
}

func (m *Model) clearErrors() {
	for i := range m.errs {
		m.errs[i] = ""
	}
}
