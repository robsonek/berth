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
		Preflight(), SystemBase(), System(),
		// apt (user repos + extra packages) is ALWAYS registered (the
		// valkey/P14 pattern): with no apt: block its disabled mode still
		// sweeps previously-declared berth-*.list leftovers — one find probe
		// on a clean host. Registered early so later steps run against the
		// declared package set.
		Apt(),
		Accounts(red), Hardening(),
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
	// offsite is ALWAYS registered (the valkey/P14 pattern): its disabled
	// mode owns the drift-removal of the script/cron/env a previous
	// offsite-enabled provision left behind — the remote repository itself
	// is never touched.
	steps = append(steps, Site(), Backups(), Offsite(red))
	// tls is ALWAYS registered outside --skip-ssl (the valkey/P14 pattern):
	// with no SSL site left in the config it still owns the orphan sweep
	// (lineages, webroots, self-signed dirs) and the deploy-hook
	// drift-removal — a config that drops its last SSL site would otherwise
	// strand both forever. On a host with no TLS traces this costs three
	// discovery probes plus the existing deploy-hook probe per run.
	if !skipSSL {
		steps = append(steps, TLS())
	}
	// manifest LAST: it attests that the FULL pipeline for this config
	// completed on this binary's version, so nothing may run after it — and
	// it is NOT registered under --skip-ssl at all: tls is an always-run
	// step now (orphan sweep + hook drift-removal), so every --skip-ssl run
	// truncates the pipeline and must not attest, SSL sites or not.
	// Semantics note: "completed" means completed AND converged — a run that
	// knowingly left work undone (the documented LE DNS-mismatch skip) marks
	// itself unconverged via RunCtx, and manifest's Apply then withholds the
	// write with a warning, leaving any attestation from a prior converged
	// run intact. Warnings alone (host still converged) do not block the
	// stamp, and warnings never affect the exit code by contract.
	if !skipSSL {
		steps = append(steps, Manifest())
	}
	return steps
}
