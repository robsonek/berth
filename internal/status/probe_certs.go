package status

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// certPath is the fullchain the provisioning steps write, built from the
// single-sourced derivation rather than re-assembled here.
func certPath(site config.Site) string { return config.CertDir(site) + "/fullchain.pem" }

// certsCmd reads every certificate's notAfter in one round trip. A missing
// file yields an empty second field rather than an error, so one un-issued
// site never hides the rest.
func certsCmd(paths []string) string {
	quoted := make([]string, 0, len(paths))
	for _, p := range paths {
		quoted = append(quoted, "'"+p+"'")
	}
	return "for c in " + strings.Join(quoted, " ") +
		`; do printf '%s\t%s\n' "$c" "$(openssl x509 -enddate -noout -in "$c" 2>/dev/null)"; done`
}

func probeCerts(ctx context.Context, r bssh.Runner, s *config.Server, hostTime time.Time) (map[string]CertStatus, error) {
	out := map[string]CertStatus{}
	var paths []string
	byPath := map[string]config.Site{}
	for _, site := range s.Sites {
		if !site.SSL {
			continue
		}
		p := certPath(site)
		paths = append(paths, p)
		byPath[p] = site
	}
	if len(paths) == 0 {
		return out, nil
	}
	res, err := r.Run(ctx, certsCmd(paths), nil)
	if err != nil {
		return nil, err
	}
	// The loop's own exit status is the last printf's (0) even when an
	// individual openssl call fails, so a non-zero exit means the loop never
	// ran cleanly (sudo -n denied on a half-broken host). That must surface
	// loudly, not as an empty map at exit 0 — same contract as probeServices.
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = "(no stderr)"
		}
		return nil, fmt.Errorf("certs probe: exit %d: %s", res.ExitCode, msg)
	}
	for _, line := range strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		site, ok := byPath[parts[0]]
		if !ok {
			continue
		}
		cs := CertStatus{Mode: site.CertMode()}
		if raw := strings.TrimPrefix(strings.TrimSpace(parts[1]), "notAfter="); raw != "" && raw != strings.TrimSpace(parts[1]) {
			// openssl prints e.g. "Sep 28 07:31:00 2026 GMT".
			if na, err := time.Parse("Jan _2 15:04:05 2006 MST", raw); err == nil {
				days := int(na.Sub(hostTime).Hours() / 24)
				cs.Present = true
				cs.NotAfter = &na
				cs.DaysLeft = &days
			}
		}
		out[site.Domain] = cs
	}
	return out, nil
}
