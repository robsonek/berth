// Package provision runs an ordered pipeline of idempotent steps.
package provision

import (
	"context"

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
}

// Step is one idempotent unit of provisioning.
type Step interface {
	Name() string
	Requires() []string
	Check(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner) (CheckResult, error)
	Apply(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner) error
}
