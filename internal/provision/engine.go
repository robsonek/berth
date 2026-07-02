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
	rc := RunCtx{Force: opt.Force, SSLStaging: opt.SSLStaging}
	if opt.Only != "" {
		if err := e.checkDependencies(ctx, rc, s, r, opt.Only); err != nil {
			return nil, err
		}
	}
	ch := make(chan Event, len(e.steps)*2+1)
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
				ch <- Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("interrupted before %s: %w", step.Name(), ctx.Err())}
				return
			default:
			}
			ch <- Event{Step: step.Name(), Kind: EventStarted}
			cr, err := step.Check(ctx, rc, s, r)
			if err != nil {
				ch <- Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("%s: check: %w", step.Name(), err)}
				return
			}
			if cr.Satisfied {
				ch <- Event{Step: step.Name(), Kind: EventSatisfied, Reason: cr.Reason}
				continue
			}
			if opt.DryRun {
				ch <- Event{Step: step.Name(), Kind: EventPlanned, Reason: cr.Reason, Changes: cr.Changes, Sensitive: cr.Sensitive}
				continue
			}
			if err := step.Apply(ctx, rc, s, r); err != nil {
				ch <- Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("%s: apply: %w", step.Name(), err)}
				return
			}
			ch <- Event{Step: step.Name(), Kind: EventApplied, Changes: cr.Changes, Sensitive: cr.Sensitive}
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
