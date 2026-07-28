package ui

import (
	"fmt"
	"io"

	"github.com/robsonek/berth/internal/provision"
)

// PlainRenderer prints one stable, parseable line per terminal event.
// It emits no ANSI and does no in-place updates — safe for CI and pipes.
// In verbose mode it ADDS lines (the Check reason after "ok", one "      + "
// line per applied change) but never alters the non-verbose lines, which are
// a parseable contract.
type PlainRenderer struct {
	w       io.Writer
	verbose bool
}

func NewPlainRenderer(w io.Writer, verbose bool) *PlainRenderer {
	return &PlainRenderer{w: w, verbose: verbose}
}

func (p *PlainRenderer) Render(events <-chan provision.Event) error {
	var failure error
	for e := range events {
		switch e.Kind {
		case provision.EventSatisfied:
			if p.verbose && e.Reason != "" {
				_, _ = fmt.Fprintf(p.w, "ok    %s (already): %s\n", e.Step, e.Reason)
			} else {
				_, _ = fmt.Fprintf(p.w, "ok    %s (already)\n", e.Step)
			}
		case provision.EventApplied:
			_, _ = fmt.Fprintf(p.w, "apply %s\n", e.Step)
			if p.verbose {
				changes := e.Changes
				if e.Sensitive {
					changes = []string{"[redacted]"}
				}
				for _, c := range changes {
					_, _ = fmt.Fprintf(p.w, "      + %s\n", c)
				}
			}
			p.printWarnings(e)
		case provision.EventPlanned:
			changes := e.Changes
			if e.Sensitive {
				changes = []string{"[redacted]"}
			}
			_, _ = fmt.Fprintf(p.w, "plan  %s: %v\n", e.Step, changes)
		case provision.EventFailed:
			_, _ = fmt.Fprintf(p.w, "FAIL  %s: %v\n", e.Step, e.Err)
			p.printWarnings(e)
			failure = e.Err
		}
	}
	return failure
}

// printWarnings emits one stable `warn  ` line per warning attached to a
// terminal event, in both verbose modes: a warning is operator-facing signal
// (e.g. a unit validation deferred to the site step), not verbose detail.
// Warnf normalizes messages to a single line, keeping the prefix contract.
func (p *PlainRenderer) printWarnings(e provision.Event) {
	for _, w := range e.Warnings {
		_, _ = fmt.Fprintf(p.w, "warn  %s: %s\n", e.Step, w)
	}
}
