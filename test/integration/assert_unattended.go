//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const unattendedDropIn = "/etc/apt/apt.conf.d/52berth-unattended-upgrades"

// stockDebianPatterns are the three Origins-Pattern entries of Debian 13's
// stock 50unattended-upgrades; berth's drop-in must ADD to them, never
// displace them.
var stockDebianPatterns = []string{
	"origin=Debian,codename=${distro_codename},label=Debian",
	"origin=Debian,codename=${distro_codename},label=Debian-Security",
	"origin=Debian,codename=${distro_codename}-security,label=Debian-Security",
}

// uuProbeScript loads /usr/bin/unattended-upgrade as a module and answers with
// its OWN code: the effective Origins-Pattern and Package-Blacklist lists,
// whether each package's candidate comes from an allowed origin on the
// expected site, and whether each name is blacklisted. The local dpkg-status
// origin ("now", empty site) is allowed by unattended-upgrades by default, so
// the site filter is what makes the origin check meaningful on a host where
// the installed version IS the candidate. The probe runs as root, so it writes
// nothing: `python3 -B` keeps exec_module from caching bytecode under
// /usr/bin/__pycache__, and the apt cache is built in memory only. `import apt`
// already initialises the configuration (a second apt_pkg.init() would read
// apt.conf.d again and duplicate every list entry).
const uuProbeScript = `import json, sys, importlib.util, importlib.machinery
loader = importlib.machinery.SourceFileLoader("uu", "/usr/bin/unattended-upgrade")
spec = importlib.util.spec_from_loader("uu", loader)
uu = importlib.util.module_from_spec(spec)
loader.exec_module(uu)
import apt, apt_pkg
req = json.loads(sys.argv[1])
patterns = apt_pkg.config.value_list("Unattended-Upgrade::Origins-Pattern")
blacklist = apt_pkg.config.value_list("Unattended-Upgrade::Package-Blacklist")
allowed = uu.get_allowed_origins()
cache = apt.Cache(memonly=True)
out = {"patterns": patterns, "blacklist": blacklist, "allowed": {}, "blacklisted": {}}
for item in req.get("origins") or []:
    ok = False
    if item["pkg"] in cache and cache[item["pkg"]].candidate is not None:
        for o in cache[item["pkg"]].candidate.origins:
            if o.site == item["site"] and uu.is_allowed_origin(o, allowed):
                ok = True
    out["allowed"][item["pkg"]] = ok
for name in req.get("names") or []:
    out["blacklisted"][name] = bool(uu.is_pkgname_in_blacklist(name, blacklist))
print(json.dumps(out))
`

type uuOriginProbe struct {
	Pkg  string `json:"pkg"`
	Site string `json:"site"`
}

type uuProbeRequest struct {
	Origins []uuOriginProbe `json:"origins"`
	Names   []string        `json:"names"`
}

type uuProbeResult struct {
	Patterns    []string        `json:"patterns"`
	Blacklist   []string        `json:"blacklist"`
	Allowed     map[string]bool `json:"allowed"`
	Blacklisted map[string]bool `json:"blacklisted"`
}

// Sury/PGDG blacklist entries berth must contribute (exact strings, spec rule 3).
var (
	suryBlacklist = []string{`php(?![0-9])(?!.*common)(-.+)?$`, `libapache2-mod-php$`, `libphp-embed$`}
	pgdgBlacklist = []string{`postgresql(?!.*common)(?!.*-[0-9][0-9.]*(-|$))(-.+)?$`}
)

// assertUnattendedOrigins verifies berth's drop-in end to end: the EFFECTIVE
// configuration contains berth's exact pattern and blacklist entries for every
// upstream repo the config uses plus all stock Debian patterns (additional
// operator entries are allowed); unattended-upgrades' own matcher allows each
// repo's package from its site and blacklists exactly the metapackages; with no
// upstream repo, berth's own file is gone (a foreign file there is preserved).
func assertUnattendedOrigins(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	checks := aptProvenanceChecks(srv)
	req := uuProbeRequest{Origins: []uuOriginProbe{}, Names: []string{}}
	var wantPatterns, wantBlacklist, mustBlock, mustPass []string
	for _, ck := range checks {
		wantPatterns = append(wantPatterns, "origin="+ck.repo.Origin+",codename="+ck.repo.Suite+",site="+ck.repo.Site())
		switch ck.repo.Name {
		case "pgdg":
			wantBlacklist = append(wantBlacklist, pgdgBlacklist...)
			mustBlock = append(mustBlock, "postgresql", "postgresql-client", "postgresql-postgis")
			mustPass = append(mustPass, "postgresql-18", "postgresql-client-18", "postgresql-common", "postgresql-client-common")
		case "sury-php":
			wantBlacklist = append(wantBlacklist, suryBlacklist...)
			mustBlock = append(mustBlock, "php", "php-fpm", "php-bz2", "libapache2-mod-php", "libphp-embed")
			mustPass = append(mustPass, "php"+srv.PHP.Version+"-fpm", "php-common", "libapache2-mod-php"+srv.PHP.Version)
		}
		req.Origins = append(req.Origins, uuOriginProbe{Pkg: ck.pkg, Site: repoHost(ck.repo.URI)})
	}
	req.Names = append(append(req.Names, mustBlock...), mustPass...)

	if len(checks) == 0 {
		res, err := c.Run(ctx, "cat "+unattendedDropIn, nil)
		if err != nil {
			t.Fatalf("read %s: %v", unattendedDropIn, err)
		}
		if res.ExitCode == 0 && strings.HasPrefix(res.Stdout, "# managed by berth") {
			t.Errorf("berth's %s survives although the config uses no upstream repo", unattendedDropIn)
		}
		// absent, or a foreign operator file (preserved by design) — both fine.
	}

	arg, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(ctx, "python3 -B - "+shQuote(string(arg)), []byte(uuProbeScript))
	if err != nil {
		t.Fatalf("unattended-upgrades probe: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("unattended-upgrades probe exited %d: %s", res.ExitCode, res.Stderr)
	}
	var out uuProbeResult
	if err := json.Unmarshal([]byte(lastLine(res.Stdout)), &out); err != nil {
		t.Fatalf("parse probe output %q: %v", res.Stdout, err)
	}
	for _, p := range append(slices.Clone(stockDebianPatterns), wantPatterns...) {
		if !slices.Contains(out.Patterns, p) {
			t.Errorf("effective Origins-Pattern lacks %q; have %q", p, out.Patterns)
		}
	}
	for _, b := range wantBlacklist {
		if !slices.Contains(out.Blacklist, b) {
			t.Errorf("effective Package-Blacklist lacks %q; have %q", b, out.Blacklist)
		}
	}
	for _, o := range req.Origins {
		if !out.Allowed[o.Pkg] {
			t.Errorf("unattended-upgrades does not allow %s from %s — the drop-in's pattern does not match", o.Pkg, o.Site)
		}
	}
	for _, n := range mustBlock {
		if !out.Blacklisted[n] {
			t.Errorf("%s must be blacklisted (default-major metapackage)", n)
		}
	}
	for _, n := range mustPass {
		if out.Blacklisted[n] {
			t.Errorf("%s must NOT be blacklisted", n)
		}
	}
}

// lastLine returns the last non-empty line (the probe prints one JSON object;
// the module import logs to stderr, never stdout, but be tolerant).
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
