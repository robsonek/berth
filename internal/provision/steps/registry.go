package steps

import (
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
)

// Pipeline returns the ordered steps for a server, honoring toggles and flags.
func Pipeline(s *config.Server, red *secret.Redactor, skipSSL bool) []provision.Step {
	steps := []provision.Step{
		// identity FIRST: it reconciles the local secret-cache identity
		// (bind/upgrade/migrate/endpoint check) and must settle before
		// preflight performs the run's first remote mutation.
		Identity(),
		Preflight(), SystemBase(), System(), Accounts(red), Hardening(),
		PHP(), Nginx(), Composer(),
	}
	// valkey is ALWAYS registered: its disabled mode sweeps instances a
	// previous valkey:true provision left behind (P14) — omitting the step
	// made the true->false flip an undeclared state transition.
	steps = append(steps, Valkey())
	if s.NeedsSupervisor() {
		steps = append(steps, Supervisor())
	}
	steps = append(steps, AppDirs(), Database(red))
	if s.Database.Engine == "mariadb" {
		steps = append(steps, Tuning())
	}
	steps = append(steps, Site(), Backups())
	if !skipSSL && anySiteSSL(s) {
		steps = append(steps, TLS())
	}
	return steps
}

// anySiteSSL reports whether at least one configured site requests TLS.
func anySiteSSL(s *config.Server) bool {
	for _, site := range s.Sites {
		if site.SSL {
			return true
		}
	}
	return false
}
