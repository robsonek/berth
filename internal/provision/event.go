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
	Err       error
}
