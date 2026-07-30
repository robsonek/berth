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

// Render sanitizes every event field that can carry remote-derived text
// (Reason, Changes, Warnings, Err — see sanitize.go) at its print site; step
// names are berth's own constants. The returned failure error stays RAW: it
// is the value callers compare with errors.Is, and cmd sanitizes it at its
// own final print.
func (p *PlainRenderer) Render(events <-chan provision.Event) error {
	var failure error
	for e := range events {
		switch e.Kind {
		case provision.EventSatisfied:
			if p.verbose && e.Reason != "" {
				_, _ = fmt.Fprintf(p.w, "ok    %s (already): %s\n", e.Step, SanitizeCell(e.Reason))
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
					_, _ = fmt.Fprintf(p.w, "      + %s\n", SanitizeCell(c))
				}
			}
			p.printWarnings(e)
		case provision.EventPlanned:
			changes := e.Changes
			if e.Sensitive {
				changes = []string{"[redacted]"}
			}
			_, _ = fmt.Fprintf(p.w, "plan  %s: %v\n", e.Step, sanitizeAll(changes))
		case provision.EventFailed:
			// Errors keep their deliberate newlines (multi-line remedies).
			_, _ = fmt.Fprintf(p.w, "FAIL  %s: %s\n", e.Step, sanitizeErr(e.Err))
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
		_, _ = fmt.Fprintf(p.w, "warn  %s: %s\n", e.Step, SanitizeCell(w))
	}
}
