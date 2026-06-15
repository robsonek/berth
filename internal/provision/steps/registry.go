package steps

import (
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
)

// Pipeline returns the ordered steps for a server, honoring toggles and flags.
func Pipeline(s *config.Server, red *secret.Redactor, skipSSL bool) []provision.Step {
	steps := []provision.Step{
		Preflight(), SystemBase(), Accounts(), Hardening(),
		PHP(), Nginx(), Composer(),
	}
	if s.Valkey {
		steps = append(steps, Valkey())
	}
	if s.NeedsSupervisor() {
		steps = append(steps, Supervisor())
	}
	steps = append(steps, AppDirs(), Database(red))
	steps = append(steps, Site())
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
