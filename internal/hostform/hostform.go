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
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.keys.Cancel), key.Matches(keyMsg, m.keys.ForceQuit):
			m.result = Result{Submitted: false}
			m.done = true
			return m, nil
		case key.Matches(keyMsg, m.keys.Next):
			return m.move(1)
		case key.Matches(keyMsg, m.keys.Prev):
			return m.move(-1)
		case key.Matches(keyMsg, m.keys.Submit):
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
	var b strings.Builder
	b.WriteString(m.styles.title.Render("Add inventory host"))
	b.WriteString("\n\n")

	b.WriteString(m.groupHeader("Connection"))
	b.WriteString("\n")
	b.WriteString(joinFields(m.field(fieldName), m.field(fieldUser), m.field(fieldPort)))
	b.WriteString("\n")
	b.WriteString(m.field(fieldAddr))
	b.WriteString("\n\n")

	b.WriteString(m.groupHeader("Routing"))
	b.WriteString("\n")
	b.WriteString(joinFields(m.field(fieldTags), m.field(fieldAlias)))
	b.WriteString("\n\n")

	b.WriteString(m.groupHeader("Auth"))
	b.WriteString("\n")
	b.WriteString(m.field(fieldIdentity))
	b.WriteString("\n")
	b.WriteString(m.field(fieldPassword))
	b.WriteString("\n")
	b.WriteString(m.styles.help.Render("identity_file is a path saved in inventory; password is encrypted (age) and never shown."))
	b.WriteString("\n")
	if strings.TrimSpace(m.inputs[fieldPassword].Value()) != "" && os.Getenv("AGENTSSH_MASTER_PASSWORD") == "" {
		b.WriteString(m.styles.warn.Render(m.styles.glyphs.Warn + " AGENTSSH_MASTER_PASSWORD not set — the password won't be saved."))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(m.styles.help.Render("tab/down next · shift+tab/up prev · enter submit · esc cancel"))
	return b.String()
}

func (m Model) groupHeader(name string) string {
	return m.styles.group.Render("── " + name + " " + strings.Repeat("─", 24-len(name)))
}

// field renders one labelled input plus its inline error, as a block for
// horizontal joining.
func (m Model) field(f field) string {
	var b strings.Builder
	b.WriteString(m.styles.label.Render(fieldLabels[f]))
	b.WriteString("\n")
	b.WriteString(m.inputs[f].View())
	if m.errs[f] != "" {
		b.WriteString("\n")
		b.WriteString(m.styles.err.Render(m.errs[f]))
	}
	return b.String()
}

// joinFields lays out field blocks side by side with a gutter between them.
func joinFields(blocks ...string) string {
	parts := make([]string, 0, len(blocks)*2-1)
	for i, blk := range blocks {
		if i > 0 {
			parts = append(parts, "  ")
		}
		parts = append(parts, blk)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
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
