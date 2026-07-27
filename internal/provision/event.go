package provision

// EventKind classifies a progress event.
type EventKind int

const (
	EventStarted EventKind = iota
	EventSatisfied
	EventApplied
	EventPlanned // dry-run: would change
	EventFailed
)

// Event is emitted by the engine for each step transition.
type Event struct {
	Step      string
	Kind      EventKind
	Reason    string
	Changes   []string
	Sensitive bool // Changes may contain secrets → renderers must redact
	// Warnings collected during the step's Apply (RunCtx.Warnf), attached to
	// the terminal event (EventApplied or EventFailed) rather than emitted as
	// separate events: the channel buffer is sized for exactly one Started +
	// one terminal event per step, and that no-extra-sends property is what
	// keeps the engine goroutine from blocking when nobody consumes (the TUI
	// stops reading after ctrl+c). Never set on EventSatisfied/EventPlanned —
	// Check does not warn.
	Warnings []string
	Err      error
}
