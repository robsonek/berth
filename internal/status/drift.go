package status

import (
	"context"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// Drift runs the pipeline read-only and summarises the verdicts.
//
// It reuses the engine's DryRun mode rather than a second Check-only code
// path: DryRun already gates Apply, so "this cannot mutate the host" is an
// existing, tested property instead of a new promise, and secret redaction
// plus fail-fast come with it.
//
// The returned report is never nil. A fail-fast abort sets StoppedAt and the
// report is then PARTIAL — callers must present it as such, never as clean.
func Drift(ctx context.Context, s *config.Server, r bssh.Runner, pipeline []provision.Step, red provision.Redactor) *DriftReport {
	rep := &DriftReport{}
	exempt := map[string]bool{}
	for _, st := range pipeline {
		if provision.IsDeliberatelyUnsatisfied(st) {
			exempt[st.Name()] = true
		}
	}
	events, err := provision.New(pipeline...).Run(ctx, s, r, provision.Options{DryRun: true, Redact: red})
	if err != nil {
		// The engine's synchronous channel: --only pre-flight problems only.
		// A full-pipeline scan passes no Only, so this is not expected — but
		// reporting it beats dropping it.
		rep.Error = err.Error()
		return rep
	}
	for e := range events {
		switch e.Kind {
		case provision.EventSatisfied:
			rep.Steps = append(rep.Steps, StepState{Step: e.Step, Satisfied: true})
		case provision.EventPlanned:
			changes := e.Changes
			if e.Sensitive {
				changes = []string{"[redacted]"}
			}
			rep.Steps = append(rep.Steps, StepState{Step: e.Step, Satisfied: false, Changes: changes})
			if !exempt[e.Step] {
				rep.Drifted++
			}
		case provision.EventFailed:
			rep.StoppedAt = e.Step
			if e.Err != nil {
				rep.Error = e.Err.Error()
			}
		case provision.EventStarted, provision.EventApplied:
			// Started carries no verdict; Applied is unreachable under DryRun.
		}
	}
	return rep
}
