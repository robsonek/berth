package ui

import (
	"io"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/robsonek/berth/internal/provision"
)

// stepModel is the pure, testable state behind the TUI.
type stepModel struct {
	order    []string
	statuses map[string]string // started|applied|already|planned|failed
	err      error
}

func newStepModel() stepModel {
	return stepModel{statuses: map[string]string{}}
}

func (m stepModel) apply(e provision.Event) stepModel {
	if _, seen := m.statuses[e.Step]; !seen && e.Step != "" {
		m.order = append(m.order, e.Step)
	}
	switch e.Kind {
	case provision.EventStarted:
		m.statuses[e.Step] = "started"
	case provision.EventSatisfied:
		m.statuses[e.Step] = "already"
	case provision.EventApplied:
		m.statuses[e.Step] = "applied"
	case provision.EventPlanned:
		m.statuses[e.Step] = "planned"
	case provision.EventFailed:
		m.statuses[e.Step] = "failed"
		m.err = e.Err
	}
	return m
}

func (m stepModel) status(step string) string { return m.statuses[step] }
func (m stepModel) failed() bool              { return m.err != nil }

var (
	okStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	failStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

func (m stepModel) view() string {
	out := ""
	for _, name := range m.order {
		switch m.statuses[name] {
		case "applied":
			out += okStyle.Render("⚙ "+name) + "\n"
		case "already":
			out += okStyle.Render("✔ "+name+" (already)") + "\n"
		case "failed":
			out += failStyle.Render("✗ "+name+": "+errText(m.err)) + "\n"
		default:
			out += "… " + name + "\n"
		}
	}
	return out
}

func errText(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// TUIRenderer drives a bubbletea program from the engine's event stream.
type TUIRenderer struct{ w io.Writer }

func NewTUIRenderer(w io.Writer) *TUIRenderer { return &TUIRenderer{w: w} }

// Render consumes events live and returns the terminal failure error, if any.
func (t *TUIRenderer) Render(events <-chan provision.Event) error {
	p := tea.NewProgram(teaModel{m: newStepModel(), events: events}, tea.WithOutput(t.w))
	final, err := p.Run()
	if err != nil {
		return err
	}
	return final.(teaModel).m.err
}

// teaModel adapts stepModel to the bubbletea Model interface.
type teaModel struct {
	m      stepModel
	events <-chan provision.Event
}

type eventMsg provision.Event
type doneMsg struct{}

func (tm teaModel) waitForEvent() tea.Cmd {
	return func() tea.Msg {
		e, ok := <-tm.events
		if !ok {
			return doneMsg{}
		}
		return eventMsg(e)
	}
}

// Bubble Tea v2 Model interface (confirmed against the v2 upgrade guide):
// Init() tea.Cmd, Update(tea.Msg) (tea.Model, tea.Cmd), View() tea.View.
func (tm teaModel) Init() tea.Cmd { return tm.waitForEvent() }

func (tm teaModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case eventMsg:
		tm.m = tm.m.apply(provision.Event(m))
		return tm, tm.waitForEvent()
	case doneMsg:
		return tm, tea.Quit
	case tea.KeyPressMsg:
		if m.String() == "ctrl+c" {
			return tm, tea.Quit
		}
	}
	return tm, nil
}

func (tm teaModel) View() tea.View { return tea.NewView(tm.m.view()) }
