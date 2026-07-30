package status

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// dbUnit is the systemd unit of the configured database engine. Note the
// steps package spells the MariaDB unit "mariadb.service" (tuning.go:17);
// systemd resolves the suffix-less form to the same unit, and the shorter
// name keeps the rendered table narrow.
//
// KNOWN LIMITATION for postgres: Debian's postgresql.service is an umbrella
// (Type=oneshot, RemainAfterExit=yes) whose real work lives in per-cluster
// postgresql@<version>-<cluster>.service units, so the Active axis reflects
// the umbrella, not the cluster — a killed or crashed cluster can still read
// as active here. Do NOT mistake this column for a cluster health check.
// Probing the instance unit needs the cluster version and name, which the
// config does not carry; real cluster liveness is deferred along with
// database health (spec §11).
func dbUnit(engine string) string {
	if engine == "postgres" {
		return "postgresql"
	}
	return "mariadb"
}

// unitList is the set of units this server's config implies. Order is stable
// so the rendered table does not shuffle between runs.
func unitList(s *config.Server) []string {
	// ssh and certbot.timer are included because provisioning REQUIRES them:
	// hardening asserts ssh active+enabled (hardening.go:270) and tls asserts
	// the renewal timer active (tls.go:385). Omitting them would let the two
	// failures the operator most needs to hear about — locked out on reboot,
	// certificates silently not renewing — pass unnoticed.
	units := []string{"nginx", config.FPMServiceName(s.PHP.Version), dbUnit(s.Database.Engine), "fail2ban", "cron", "ssh"}
	if s.NeedsSupervisor() {
		units = append(units, "supervisor")
	}
	// AnyLetsEncrypt, NOT anySiteSSL: provisioning only requires the renewal
	// timer when a Let's Encrypt site exists (tls.go:360). On a server whose
	// TLS sites are all selfsigned, certbot is correctly absent — gating on
	// site.SSL would report that healthy server's missing timer as DOWN.
	if config.AnyLetsEncrypt(s) {
		units = append(units, "certbot.timer")
	}
	if s.Valkey {
		for _, site := range s.Sites {
			units = append(units, config.ValkeyInstanceUnit(site.Domain))
		}
	}
	return units
}

// servicesCmd asks for every unit's active and enabled state in one round
// trip. is-active/is-enabled exit non-zero for a down or absent unit and
// print nothing useful on stderr, so both are captured as empty fields and
// read as "not active" / "not enabled" — never as up.
//
// A unit name containing a single quote would break the quoting. Unit names
// here derive from config.PoolName (domain with "."->"_") and validated PHP
// versions, so none can — but do not extend this helper to operator-supplied
// strings without proper quoting.
func servicesCmd(units []string) string {
	quoted := make([]string, 0, len(units))
	for _, u := range units {
		quoted = append(quoted, "'"+u+"'")
	}
	return "for u in " + strings.Join(quoted, " ") +
		`; do printf '%s\t%s\t%s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)" "$(systemctl is-enabled "$u" 2>/dev/null)"; done`
}

func probeServices(ctx context.Context, r bssh.Runner, s *config.Server) ([]Service, error) {
	units := unitList(s)
	res, err := r.Run(ctx, servicesCmd(units), nil)
	if err != nil {
		return nil, err
	}
	// A non-zero exit is data, not a Go error (Runner contract) — without
	// this check a failing command (sudo denied on a half-broken host, the
	// exact situation a status tool exists to surface) would return an empty,
	// error-free slice that renders as a clean-looking blank at exit 0
	// instead of the loud partial-probe failure the spec requires.
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = "(no stderr)"
		}
		return nil, fmt.Errorf("services probe: exit %d: %s", res.ExitCode, msg)
	}
	out := make([]Service, 0, len(units))
	for _, line := range strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 || parts[0] == "" {
			continue
		}
		out = append(out, Service{
			Name:    parts[0],
			Active:  strings.TrimSpace(parts[1]) == "active",
			Enabled: strings.TrimSpace(parts[2]) == "enabled",
		})
	}
	return out, nil
}
