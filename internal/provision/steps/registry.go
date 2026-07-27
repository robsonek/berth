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
		// (bind/migrate/endpoint check) and must settle before
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
	// manifest LAST: it attests that the FULL pipeline for this config
	// completed on this binary's version, so nothing may run after it — and
	// it is NOT registered when --skip-ssl artificially truncated a pipeline
	// that would otherwise carry TLS (the attestation would be a lie).
	// Semantics note: "completed" includes runs that ended with warnings
	// (e.g. the documented LE DNS-mismatch skip) — warnings never affect the
	// exit code by contract, and future migrations branch on VERSION, not on
	// certificate state.
	if !(skipSSL && anySiteSSL(s)) {
		steps = append(steps, Manifest())
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
