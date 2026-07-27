package provision

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// Options controls a pipeline run.
type Options struct {
	DryRun     bool
	Only       string // run only this step (after verifying its transitive deps)
	Force      bool   // overwrite resources not managed by berth (drift policy)
	SSLStaging bool   // use Let's Encrypt staging in the TLS step
	// Redact masks registered secrets in EVERY engine output: each event's
	// Reason/Changes/Warnings, event errors, and the synchronous pre-flight
	// error Run returns. Pass the SAME *secret.Redactor the steps were built
	// with (steps register secrets on it as they acquire them); nil = no-op.
	// This is the engine's output policy — the renderers' [redacted] literal
	// for Sensitive changes remains an independent second layer.
	Redact Redactor
}

// Redactor is the minimal masking dependency Options needs (satisfied by
// *secret.Redactor without importing that package here).
type Redactor interface{ Apply(string) string }

// redactedError wraps an error so its printed text is masked while errors.Is
// and errors.As keep working through Unwrap — cmd.Execute prints the returned
// error a second time, so masking only the event stream would still leak.
type redactedError struct {
	orig error
	msg  string
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.orig }

// RedactError masks err's text via red, preserving the original for
// Is/As/Unwrap. nil-safe on both arguments. Exported so cmd can apply the
// same policy at the command boundary (renderer-internal errors, defence in
// depth for double-wrapped event errors — masking is a no-op the second time
// for berth's `*`-free secret domain).
func RedactError(red Redactor, err error) error {
	if err == nil {
		return nil
	}
	if red == nil {
		return err
	}
	masked := red.Apply(err.Error())
	if masked == err.Error() {
		return err // nothing to hide — keep the original shape
	}
	return &redactedError{orig: err, msg: masked}
}

// Engine runs steps in registration order.
type Engine struct{ steps []Step }

func New(steps ...Step) *Engine { return &Engine{steps: steps} }

// Run executes the pipeline, returning a channel of progress events that is
// closed when the run finishes. Step Check/Apply failures are reported as
// EventFailed and stop the pipeline (fail-fast). The returned error is non-nil
// ONLY for pre-flight problems (an unknown --only target or an unmet --only
// dependency); per-step errors travel on the event stream and are surfaced by
// the renderer (see internal/ui).
func (e *Engine) Run(ctx context.Context, s *config.Server, r bssh.Runner, opt Options) (<-chan Event, error) {
	rc := RunCtx{Force: opt.Force, SSLStaging: opt.SSLStaging, FullRun: opt.Only == ""}
	if opt.Only != "" {
		if err := e.checkDependencies(ctx, rc, s, r, opt.Only); err != nil {
			// The engine's SECOND output channel — the synchronous pre-flight
			// error — is masked here too, not only the event stream.
			return nil, RedactError(opt.Redact, err)
		}
	}
	ch := make(chan Event, len(e.steps)*2+1)
	// emit is the single exit for every event: whatever path produced it
	// (step transition, interruption, trailing failure), all operator-visible
	// text is masked before it reaches the channel.
	emit := func(ev Event) {
		if opt.Redact != nil {
			ev.Reason = opt.Redact.Apply(ev.Reason)
			// Masked copies, not in-place writes: the slices came from the
			// step's CheckResult and a step could legitimately retain them.
			if len(ev.Changes) > 0 {
				masked := make([]string, len(ev.Changes))
				for i, c := range ev.Changes {
					masked[i] = opt.Redact.Apply(c)
				}
				ev.Changes = masked
			}
			if len(ev.Warnings) > 0 {
				masked := make([]string, len(ev.Warnings))
				for i, w := range ev.Warnings {
					masked[i] = opt.Redact.Apply(w)
				}
				ev.Warnings = masked
			}
			ev.Err = RedactError(opt.Redact, ev.Err)
		}
		ch <- ev
	}
	go func() {
		defer close(ch)
		for _, step := range e.steps {
			// With --only, run the target step plus any always-run steps (e.g.
			// preflight) — they re-apply every run and are not gated, so they
			// still execute ahead of the target.
			if opt.Only != "" && step.Name() != opt.Only && !isAlwaysRun(step) {
				continue
			}
			// Interruption: stop before starting another step. Emitted as an
			// EventFailed so both renderers surface it as the run's error; the
			// two-error-channels contract is unchanged (Run's returned error
			// remains --only pre-flight only). Placed after the --only gate so
			// a skipped step is never reported as interrupted.
			select {
			case <-ctx.Done():
				emit(Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("interrupted before %s: %w", step.Name(), ctx.Err())})
				return
			default:
			}
			emit(Event{Step: step.Name(), Kind: EventStarted})
			cr, err := step.Check(ctx, rc, s, r)
			if err != nil {
				emit(Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("%s: check: %w", step.Name(), err)})
				return
			}
			if cr.Satisfied {
				emit(Event{Step: step.Name(), Kind: EventSatisfied, Reason: cr.Reason})
				continue
			}
			if opt.DryRun {
				emit(Event{Step: step.Name(), Kind: EventPlanned, Reason: cr.Reason, Changes: cr.Changes, Sensitive: cr.Sensitive})
				continue
			}
			// Warnings ride on the step's terminal event instead of being sent
			// as extra events: the buffer above is sized for exactly the
			// events this loop can emit, and that bound is what lets the
			// goroutine finish even when the consumer stopped reading (TUI
			// after ctrl+c). Apply runs in this goroutine, so the append is
			// race-free.
			var warnings []string
			applyRC := rc
			applyRC.Warn = func(msg string) { warnings = append(warnings, msg) }
			if err := step.Apply(ctx, applyRC, s, r); err != nil {
				emit(Event{Step: step.Name(), Kind: EventFailed, Warnings: warnings, Err: fmt.Errorf("%s: apply: %w", step.Name(), err)})
				return
			}
			emit(Event{Step: step.Name(), Kind: EventApplied, Changes: cr.Changes, Sensitive: cr.Sensitive, Warnings: warnings})
		}
		// A signal that lands during the last step has no next step to observe
		// it. Emit a trailing failure so an interrupted run never exits 0, even
		// when all remaining work happened to complete.
		select {
		case <-ctx.Done():
			emit(Event{Step: "pipeline", Kind: EventFailed, Err: fmt.Errorf("interrupted: %w", ctx.Err())})
		default:
		}
	}()
	return ch, nil
}

// checkDependencies fails if any TRANSITIVE Requires of target is unsatisfied.
// It walks the dependency graph depth-first (detecting cycles) and Checks each
// prerequisite, so `--only ssl` correctly refuses when an indirect dependency
// (e.g. php, needed by site, needed by tls) is not yet satisfied.
func (e *Engine) checkDependencies(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner, target string) error {
	byName := map[string]Step{}
	for _, st := range e.steps {
		byName[st.Name()] = st
	}
	if _, ok := byName[target]; !ok {
		return fmt.Errorf("unknown step %q", target)
	}
	var missing []string
	visiting, done := map[string]bool{}, map[string]bool{}
	var walk func(name string) error
	walk = func(name string) error {
		// Stop probing over SSH once the run is cancelled; pre-flight problems
		// are exactly what Run's returned error is for.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("interrupted: %w", err)
		}
		if done[name] {
			return nil
		}
		if visiting[name] {
			return fmt.Errorf("dependency cycle at %q", name)
		}
		visiting[name] = true
		st, ok := byName[name]
		if !ok {
			missing = append(missing, name+" (undefined)")
		} else {
			for _, dep := range st.Requires() {
				if err := walk(dep); err != nil {
					return err
				}
			}
			// Re-check after the recursion: a signal that lands during a
			// transitive prerequisite's Check would otherwise let this node
			// resume and run its own Check on a cancelled context — surfacing
			// as "unmet prerequisites" instead of an interruption.
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("interrupted: %w", err)
			}
			// The target itself need not be satisfied, and an always-run step
			// (preflight) is excluded from the gate: it reports Satisfied:false
			// by design, so it is never a "missing" prerequisite.
			if name != target && !isAlwaysRun(st) {
				cr, err := st.Check(ctx, rc, s, r)
				if err != nil {
					return fmt.Errorf("%s: check: %w", name, err)
				}
				if !cr.Satisfied {
					missing = append(missing, name)
				}
			}
		}
		visiting[name], done[name] = false, true
		return nil
	}
	if err := walk(target); err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("cannot run %q: unmet prerequisites: %v", target, missing)
	}
	return nil
}
