package steps

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/secret"
	"github.com/robsonek/berth/internal/templates"
)

// TestContractServerRegistersEveryStep is the fixture's load-bearing property.
// Several steps are gated on config (supervisor on a worker, tls on an SSL site,
// tuning on the engine, the keyring probe on a declared apt repo), so a fixture
// missing any of them would leave that step silently unexercised while every
// other guard still passed.
func TestContractServerRegistersEveryStep(t *testing.T) {
	s := contractServer(t)
	pipeline := Pipeline(s, secret.NewRedactor(), false)

	seen := map[string]bool{}
	for _, st := range pipeline {
		if seen[st.Name()] {
			t.Errorf("duplicate step %q — the contract counts steps by name", st.Name())
		}
		seen[st.Name()] = true
	}
	for _, want := range []string{
		"identity", "preflight", "base", "system", "apt", "php", "nginx",
		"composer", "valkey", "supervisor", "accounts", "hardening", "appdirs",
		"database", "site", "tls", "tuning", "backups", "offsite", "manifest",
	} {
		if !seen[want] {
			t.Errorf("step %q is not registered — contractServer() must make the pipeline complete", want)
		}
	}
	// An apt repo must be declared, or nothing reaches KeyringHoldsExactly and
	// the gpg offender this contract exists to catch is never recorded.
	if len(s.Apt.Repos) == 0 {
		t.Error("contractServer must declare an apt repo so the keyring probe is exercised")
	}
}

// TestFakeHostProfilesDifferWhereItMatters: profiles exist to walk DIFFERENT
// branches, so one that is accidentally a copy of another buys nothing.
func TestFakeHostProfilesDifferWhereItMatters(t *testing.T) {
	s := contractServer(t)
	const path = "/etc/logrotate.d/berth"

	fresh := newFakeHost(t, "fresh", s)
	if _, ok := fresh.files[path]; ok {
		t.Error("fresh: no managed file may exist")
	}
	if _, ok := fresh.packages["nginx"]; ok {
		t.Error("fresh: no package may be installed")
	}

	conv := newFakeHost(t, "converged", s)
	if !strings.Contains(conv.files[path].content, templates.ManagedMarker) {
		t.Error("converged: the managed file must carry the marker")
	}
	if !conv.units["nginx"].active || !conv.units["nginx"].enabled {
		t.Error("converged: nginx must be active and enabled")
	}

	drift := newFakeHost(t, "drifted", s)
	if !strings.Contains(drift.files[path].content, templates.ManagedMarker) {
		t.Error("drifted: the file must carry the marker — that is what makes it drift, not foreign")
	}
	if drift.files[path].content == conv.files[path].content {
		t.Error("drifted: the content must differ from converged, or nothing drifts")
	}

	foreign := newFakeHost(t, "foreign", s)
	if strings.Contains(foreign.files[path].content, templates.ManagedMarker) {
		t.Error("foreign: the file must NOT carry the marker")
	}
	if foreign.files[s.Sites[0].DeployPath].owner == s.SiteUser(s.Sites[0]) {
		t.Error("foreign: the site tree must be owned by someone else, or the owner guard never fires")
	}

	// runtime-stale is byte-identical to converged on disk but stale at RUNTIME:
	// it is the only profile that reaches serviceConfigLoaded/reloadedSince and
	// the valkey exec probe, which converged skips and drifted never gets to.
	stale := newFakeHost(t, "runtime-stale", s)
	if stale.files[path].content != conv.files[path].content {
		t.Error("runtime-stale: on-disk content must MATCH converged — the staleness is in the runtime, not the bytes")
	}
	if stale.units["nginx"].props["NeedDaemonReload"] != "yes" {
		t.Error("runtime-stale: the daemon-reload flag must be set, or the runtime branch is unreachable")
	}
}

// TestConvergedProfileUsesRenderedBytes is the fleet-status lesson applied up
// front: a fixture for a file berth RENDERS must BE the rendered output. A
// hand-typed approximation there let a loader that rejected berth's own file
// pass a green suite.
func TestConvergedProfileUsesRenderedBytes(t *testing.T) {
	conv := newFakeHost(t, "converged", contractServer(t))
	want, err := templates.Render("logrotate.conf.tmpl", nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := conv.files["/etc/logrotate.d/berth"].content; got != string(want) {
		t.Errorf("converged content is not the rendered output:\n got %q\nwant %q", got, want)
	}
}

// TestUnknownProfilePanics: a typo must be loud, not a silently empty host that
// makes every Check report "absent" and the contract look green.
func TestUnknownProfilePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("newFakeHost must panic on an unknown profile name")
		}
	}()
	newFakeHost(t, "nonesuch", contractServer(t))
}

// fakeFile is one path on the fake host. The metadata is exactly what this
// package's Checks probe: owner and uid for the tenant-ownership guards, group
// and mode for the accounts and backups checks, mtime for the reload-stamp
// comparisons, kind for `stat -c %F`, and linkTarget for the symlink identity
// checks. A review of the first draft found the model could not honestly reach
// several Checks' tail verdicts without these.
type fakeFile struct {
	content string
	owner   string
	group   string
	uid     int
	gid     int
	// mode holds what `stat -c %a` prints, which has NO leading zero ("710",
	// not "0710"): berth compares the raw stat stdout against literals like
	// "root:root 755" (statOwnerMode), so the printed form IS the compared form.
	mode       string
	kind       string // as `stat -c %F` prints it
	mtimeUnix  int64
	linkTarget string
}

// fakeUnit is one systemd unit. An ABSENT property is an error rather than blank
// success: answering every unknown property with "" would let a Check silently
// take a branch the model never modelled.
type fakeUnit struct {
	active  bool
	enabled bool
	props   map[string]string
}

// fakeHost is an in-memory host state. It knows nothing about commands — the
// runner maps command shapes onto these fields.
type fakeHost struct {
	profile  string
	files    map[string]fakeFile
	packages map[string]string // package -> its `Status:` line
	units    map[string]fakeUnit
	tools    map[string]bool // command -v
	users    map[string]bool // accounts that exist (`id <user>` exit code)
	timezone string
	hostname string
	swapRows string
	dfRows   string
	gpgKeys  string // `gpg --show-keys --with-colons` colon output
}

// fakeHostProfiles is the matrix the contract runs. runtime-stale is the fifth,
// added because the other four all stop before the runtime probes: converged is
// healthy, drifted stops at byte drift, fresh at absence, foreign at refusal.
var fakeHostProfiles = []string{"fresh", "converged", "drifted", "foreign", "runtime-stale"}

// contractServer is the fixture the whole contract uses. It is built so
// steps.Pipeline registers EVERY step, and so no Check depends on the
// developer's machine: the ssh key and the secret cache live under t.TempDir().
//
// The field spellings here were checked against internal/config/config.go — an
// earlier draft used a type name that does not exist (config.Queue; it is
// config.QueueConfig) and would not have compiled.
func contractServer(t *testing.T) *config.Server {
	t.Helper()
	dir := t.TempDir()
	// The secret cache is anchored at $HOME/.berth (os.UserHomeDir,
	// internal/secret/env.go), and identity.Check reads it. Redirect HOME here,
	// in the fixture, so EVERY consumer gets the isolation — a contract that
	// read the developer's real ~/.berth would be machine-dependent.
	// USERPROFILE is what os.UserHomeDir reads on Windows (CI runs 3 OSes).
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("write fixture key: %v", err)
	}
	if err := os.WriteFile(keyPath+".pub", []byte("ssh-ed25519 AAAAC3Nza fixture\n"), 0o600); err != nil {
		t.Fatalf("write fixture pubkey: %v", err)
	}
	return &config.Server{
		ID: "contract", Host: "203.0.113.10",
		SSH:       config.SSH{User: "berth", Port: 22, Key: keyPath},
		PHP:       config.PHP{Version: "8.4", Source: "auto"},
		Nginx:     config.Nginx{Source: "debian"},
		Database:  config.Database{Engine: "mariadb", Source: "debian"},
		Valkey:    true,
		Queue:     true,
		Scheduler: true,
		// A declared apt repo is what makes the keyring probe reachable. Without
		// it the gpg command this contract exists to police is never issued.
		Apt: config.Apt{Repos: []config.AptRepo{{
			Name: "example", URI: "https://apt.example.com/debian",
			Suite: "trixie", Components: []string{"main"},
			KeyURL:      "https://apt.example.com/key.asc",
			Fingerprint: strings.Repeat("A", 40),
		}}},
		Backups: config.Backups{
			Enabled: true, Schedule: "30 3 * * *", Retention: 7,
			Offsite: &config.Offsite{
				Backend: "s3", Endpoint: "s3.example.com", Bucket: "b",
				Prefix: "contract", Schedule: "0 4 * * *",
			},
		},
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/var/www/app.example.com",
			User:       "appuser",
			Database:   config.SiteDatabase{Name: "app", User: "app"},
			SSL:        true,
			SSLEmail:   "ops@example.com",
			Queue:      &config.QueueConfig{Processes: 2, Tries: 3},
		}},
	}
}

// newFakeHost builds the named profile. It PANICS on an unknown name so a typo
// cannot silently produce an empty host.
func newFakeHost(t *testing.T, profile string, s *config.Server) *fakeHost {
	t.Helper()
	// fakeHostProfiles is the single source of the valid names: the matrix
	// Task 4 iterates and this guard can never drift apart.
	if !slices.Contains(fakeHostProfiles, profile) {
		panic("unknown fake-host profile: " + profile)
	}
	h := &fakeHost{
		profile:  profile,
		files:    map[string]fakeFile{},
		packages: map[string]string{},
		units:    map[string]fakeUnit{},
		tools:    map[string]bool{},
		users:    map[string]bool{},
		timezone: "Etc/UTC",
		hostname: "box-1",
		dfRows: "Filesystem 1B-blocks Used Available Capacity Mounted on\n" +
			"/dev/vda1 41000000000 16000000000 22000000000 41% /\n",
		// The colon output KeyringHoldsExactly parses: a pub record followed by
		// the fpr whose field 10 is the pinned fingerprint.
		gpgKeys: "pub:u:255:22:0000000000000000:::::::::\nfpr:::::::::" + strings.Repeat("A", 40) + ":\n",
	}
	// Every profile carries /etc/os-release, fresh included: a Debian host
	// without it is not a state berth supports, and preflight's codename probe
	// must read a verdict, not a modelling gap. The content is the file
	// debian:trixie ships; preflight parses only the VERSION_CODENAME line.
	h.files["/etc/os-release"] = fakeFile{
		content: `PRETTY_NAME="Debian GNU/Linux 13 (trixie)"` + "\n" +
			`NAME="Debian GNU/Linux"` + "\n" +
			`VERSION_ID="13"` + "\n" +
			`VERSION="13 (trixie)"` + "\n" +
			"VERSION_CODENAME=trixie\n" +
			"ID=debian\n" +
			`HOME_URL="https://www.debian.org/"` + "\n" +
			`SUPPORT_URL="https://www.debian.org/support"` + "\n" +
			`BUG_REPORT_URL="https://bugs.debian.org/"` + "\n",
		owner: "root", group: "root", mode: "644", kind: "regular file",
		mtimeUnix: 1500000000,
	}
	if profile == "fresh" {
		return h // everything berth-touched absent; only the OS itself exists
	}
	populateInstalled(h, s, profile)
	populateManagedFiles(h, s, profile)
	return h
}

// populateInstalled marks packages installed, units up and tools present. Under
// runtime-stale the units are up but flagged as needing a reload, which is the
// state that reaches serviceConfigLoaded and reloadedSince.
func populateInstalled(h *fakeHost, s *config.Server, profile string) {
	needReload, stamp := "no", "@2000000000"
	if profile == "runtime-stale" {
		needReload, stamp = "yes", "@1000000000" // active since BEFORE the files
	}
	for _, p := range []string{
		"nginx", "php" + s.PHP.Version + "-fpm", "php" + s.PHP.Version + "-cli",
		"mariadb-server", "valkey-server", "supervisor", "fail2ban", "ufw",
		"certbot", "restic", "cron", "unattended-upgrades", "curl", "gnupg",
	} {
		h.packages[p] = "Status: install ok installed"
	}
	units := []string{
		"nginx", config.FPMServiceName(s.PHP.Version), "mariadb", "fail2ban",
		"cron", "ssh", "supervisor", "certbot.timer", "ufw",
	}
	for _, site := range s.Sites {
		units = append(units, config.ValkeyInstanceUnit(site.Domain))
	}
	for _, u := range units {
		h.units[u] = fakeUnit{active: true, enabled: true, props: map[string]string{
			"NeedDaemonReload":     needReload,
			"ActiveEnterTimestamp": stamp,
			"MainPID":              "1234",
			"FragmentPath":         "/lib/systemd/system/" + u,
		}}
	}
	for _, tool := range []string{"nginx", "php-fpm" + s.PHP.Version, "restic", "certbot", "gpg", "logrotate", "supervisorctl"} {
		h.tools[tool] = true
	}
	// Every berth-owned account exists on a once-provisioned host. fresh gets
	// none: userExists reads only the exit code of `id <user>`, and the absent
	// account is the branch accounts.Check exists to walk there.
	for _, u := range managedAccounts(s) {
		h.users[u] = true
	}
	h.swapRows = "NAME TYPE SIZE USED PRIO\n/swapfile file 2G 0B -2\n"
}

// putManaged registers one managed file for the current profile. The three
// non-fresh content states are exactly the distinction checkManagedFile draws:
//
//	converged / runtime-stale — the rendered bytes           -> fileUpToDate
//	drifted                   — the marker plus other bytes  -> fileDrifted
//	foreign                   — no marker at all             -> fileUnmanaged
//
// Callers pass the RENDERED body, never a hand-typed approximation, so the
// converged profile stays converged after a template change.
func (h *fakeHost) putManaged(path string, body []byte, profile string) {
	f := fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
		mode: "644", kind: "regular file", mtimeUnix: 1500000000}
	switch profile {
	case "converged", "runtime-stale":
		f.content = string(body)
	case "drifted":
		f.content = templates.ManagedMarker + "\n# stale content from an older berth\n"
	case "foreign":
		f.content = "# hand-written by the operator, no marker\n"
	}
	h.files[path] = f
}

// populateManagedFiles fills in what is knowable before the discovery run.
// Task 5 extends this until every Check reports Satisfied:true under converged —
// that is the task where the authoritative artifact list comes from, and until
// it is done the contract's converged assertion fails BY DESIGN.
func populateManagedFiles(h *fakeHost, s *config.Server, profile string) {
	site := s.Sites[0]
	owner, uid := s.SiteUser(site), 1001
	if profile == "foreign" {
		owner, uid = "someoneelse", 1999
	}
	h.files[site.DeployPath] = fakeFile{owner: owner, group: "www-data", uid: uid, gid: 33,
		mode: "710", kind: "directory", mtimeUnix: 1500000000}
	h.files[site.DeployPath+"/shared"] = fakeFile{owner: owner, group: owner, uid: uid, gid: uid,
		mode: "700", kind: "directory", mtimeUnix: 1500000000}

	// The enabled-vhost symlink is real state on every once-provisioned host:
	// site's Check probes its identity with `[ -L … ]` and `[ … -ef … ]`
	// (site.go), which is what fakeFile.linkTarget exists to answer.
	h.files[nginxEnabledPath(site.Domain)] = fakeFile{owner: "root", group: "root",
		mode: "777", kind: "symbolic link", mtimeUnix: 1500000000,
		linkTarget: nginxAvailablePath(site.Domain)}

	body, err := templates.Render("logrotate.conf.tmpl", nil)
	if err != nil {
		panic("render logrotate.conf.tmpl: " + err.Error())
	}
	h.putManaged("/etc/logrotate.d/berth", body, profile)

	// preflight's apt lock-timeout drop-in. Its body is the step's own const —
	// there is no template; Apply writes []byte(aptLockTimeoutBody) verbatim,
	// so the const IS the rendered form.
	h.putManaged(aptLockTimeoutPath, []byte(aptLockTimeoutBody), profile)
}
