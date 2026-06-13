package ui

import (
	"fmt"
	"io"

	"github.com/robsonek/berth/internal/provision"
)

// PlainRenderer prints one stable, parseable line per terminal event.
// It emits no ANSI and does no in-place updates — safe for CI and pipes.
type PlainRenderer struct{ w io.Writer }

func NewPlainRenderer(w io.Writer) *PlainRenderer { return &PlainRenderer{w: w} }

func (p *PlainRenderer) Render(events <-chan provision.Event) error {
	var failure error
	for e := range events {
		switch e.Kind {
		case provision.EventSatisfied:
			fmt.Fprintf(p.w, "ok    %s (already)\n", e.Step)
		case provision.EventApplied:
			fmt.Fprintf(p.w, "apply %s\n", e.Step)
		case provision.EventPlanned:
			changes := e.Changes
			if e.Sensitive {
				changes = []string{"[redacted]"}
			}
			fmt.Fprintf(p.w, "plan  %s: %v\n", e.Step, changes)
		case provision.EventFailed:
			fmt.Fprintf(p.w, "FAIL  %s: %v\n", e.Step, e.Err)
			failure = e.Err
		}
	}
	return failure
}
