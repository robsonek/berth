// Package provision runs an ordered pipeline of idempotent steps.
package provision

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// CheckResult reports the current state of a step.
type CheckResult struct {
	Satisfied bool
	Reason    string
	Changes   []string
	Sensitive bool
}

// RunCtx carries run-time flags steps need beyond the static config.
type RunCtx struct {
	Force      bool // overwrite resources not managed by berth (drift policy, §6.5)
	SSLStaging bool // use Let's Encrypt staging in the TLS step
	// FullRun is true when the whole registered pipeline executes (no --only
	// target), i.e. every later step is guaranteed to run barring fail-fast.
	// Steps that defer work to a later step (php/nginx defer a unit-wide
	// validation failure to site's re-render+reload) may only do so when this
	// is true: under --only, returning nil would report Applied and exit 0
	// while the deferred work never happens.
	FullRun bool
	// Warn records an operator-visible warning from Apply without failing the
	// step. The engine attaches collected warnings to the step's terminal
	// event. Nil outside an engine run (step unit tests, the --only
	// dependency pre-flight) — call it through Warnf, which nil-guards.
	Warn func(msg string)
}

// Warnf formats and records a warning via rc.Warn. It is safe on a zero
// RunCtx (no-op) and collapses newlines to "; ": validator stderr is often
// multi-line (nginx -t emits at least two lines) while the plain renderer
// prints each warning as a single prefixed line.
func (rc RunCtx) Warnf(format string, a ...any) {
	if rc.Warn == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	msg = strings.ReplaceAll(msg, "\r", "\n")
	lines := strings.Split(msg, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			kept = append(kept, t)
		}
	}
	rc.Warn(strings.Join(kept, "; "))
}

// Step is one idempotent unit of provisioning.
type Step interface {
	Name() string
	Requires() []string
	Check(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner) (CheckResult, error)
	Apply(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner) error
}

// AlwaysRun is an optional Step trait. A step that implements it with AlwaysRun()
// == true deliberately re-applies every run (e.g. preflight's `apt-get update`)
// and reports Satisfied:false by design. Such a step is NOT a durable-state
// prerequisite: the dependency gate for `--only` walks it for ordering but does
// not treat its unsatisfied Check as a missing prerequisite, and an `--only` run
// still executes it.
type AlwaysRun interface {
	AlwaysRun() bool
}

// isAlwaysRun reports whether s opts into the AlwaysRun trait.
func isAlwaysRun(s Step) bool {
	ar, ok := s.(AlwaysRun)
	return ok && ar.AlwaysRun()
}
