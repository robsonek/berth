package steps

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	"github.com/robsonek/berth/internal/templates"
	"github.com/robsonek/berth/internal/version"
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
	// memTotalKB backs tuning's /proc/meminfo probe on EVERY profile — the
	// buffer-pool RAM guard runs before any managed-file classify, fresh
	// included, and /proc/meminfo exists on any host berth can reach.
	memTotalKB int64
	// databases / dbGrants back the database step's information_schema
	// probes: which tenant databases exist, and which "user:db" grant pairs.
	databases map[string]bool
	dbGrants  map[string]bool
	// certExpiry backs the `certbot certificates` answer: the notAfter of
	// every modelled Let's Encrypt lineage. Set relative to the wall clock
	// because tls.Check compares it against time.Now() (certRenewWindow) —
	// a pinned date would rot into "needs renewal" as real time passed.
	certExpiry time.Time
}

// unit resolves a systemd unit name against the model, accepting the
// ".service"-suffixed spelling of a unit modelled under its bare name —
// systemd treats "mariadb" and "mariadb.service" identically, and the Checks
// use both spellings. Only ".service" is trimmed — "x.timer" must never
// resolve to a service modelled as "x" — and only ONCE, onto a bare name:
// "x.service.service" is not a spelling systemd equates with "x.service",
// so a doubled suffix must not resolve to a unit modelled WITH its suffix.
func (h *fakeHost) unit(name string) (fakeUnit, bool) {
	if u, ok := h.units[name]; ok {
		return u, true
	}
	if base, ok := strings.CutSuffix(name, ".service"); ok && !strings.HasSuffix(base, ".service") {
		u, found := h.units[base]
		return u, found
	}
	return fakeUnit{}, false
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
	srv := &config.Server{
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
	// database.Check compares the LIVE shared/.env against the LOCAL secret
	// cache (value agreement, DB password always, APP_KEY when berth-shaped);
	// HOME is redirected above, so the cache is seeded here the way the step
	// itself leaves it after a successful provision — saveSecrets is the
	// production writer (v1 envelope bound to the endpoint), and the values
	// are the same ones the modelled .env carries. Seeded for EVERY profile
	// alike: the cache is workstation state, not host state, and a fresh box
	// re-provisioned from the same workstation (the documented reset drill)
	// keeps yesterday's cache by design.
	//
	// The offsite secrets are seeded on the same reasoning (wave 4): an
	// operator who declared backups.offsite ran `berth secret set` for both
	// s3 keys (ingestion validates them) and the restic password was
	// auto-generated by the first Apply — all three live in the same
	// workstation cache. Modelling the S3 PAIR's absence instead would make
	// offsite.Check hard-error on every profile ("credentials missing"),
	// which is a workstation-setup failure, not a host-state verdict — and
	// silencing it via expectedRefusals would only cover the foreign leg.
	// (A missing restic password alone is handled leniently — the Check
	// just plans its generation — but a converged workstation has it, so it
	// is seeded with the pair.) The values are the ones the modelled
	// /etc/berth/offsite.env carries, so a healthy host agrees with its
	// cache.
	if err := saveSecrets(srv, map[string]string{
		srv.SiteDBUser(srv.Sites[0]):                 fixtureDBValue,
		appKeyCacheKey(srv.SiteDBUser(srv.Sites[0])): fixtureAppKey,
		secret.OffsiteResticPassword:                 fixtureResticValue,
		secret.OffsiteS3AccessKey:                    fixtureOffsiteKeyID,
		secret.OffsiteS3SecretKey:                    fixtureOffsiteKeyVal,
	}); err != nil {
		t.Fatalf("seed the fixture secret cache: %v", err)
	}
	// Converge the LOCAL cache identity the way the step itself does: one
	// identity.Apply call in setup (local-only — its signature discards the
	// Runner, so nil is safe) writes the host-key tombstone beside the
	// id-keyed envelope seeded above. The production Apply rather than a
	// hand-composed SaveEnvelope on purpose: the fixture then tracks the
	// step's own convergence shape by construction, so identity.Check reads
	// a genuinely converged workstation — one that actually FINISHED a
	// provision — instead of an exemption entrenching a half-done fiction.
	if err := (identity{}).Apply(context.Background(), provision.RunCtx{}, srv, nil); err != nil {
		t.Fatalf("converge the fixture cache identity: %v", err)
	}
	return srv
}

// fixtureOffsiteSecrets is the offsite slice of the seeded cache, shaped the
// way loadVerifiedSecrets hands it to renderOffsiteEnv — the modelled env
// file and the cache must carry the same values or offsite.Check honestly
// reports drift.
func fixtureOffsiteSecrets() map[string]string {
	return map[string]string{
		secret.OffsiteResticPassword: fixtureResticValue,
		secret.OffsiteS3AccessKey:    fixtureOffsiteKeyID,
		secret.OffsiteS3SecretKey:    fixtureOffsiteKeyVal,
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
		profile:   profile,
		files:     map[string]fakeFile{},
		packages:  map[string]string{},
		units:     map[string]fakeUnit{},
		tools:     map[string]bool{},
		users:     map[string]bool{},
		databases: map[string]bool{},
		dbGrants:  map[string]bool{},
		timezone:  "Etc/UTC",
		hostname:  "box-1",
		// ~3.8 GiB, a realistic small VPS; comfortably above the 80% cap for
		// the default 256M buffer pool, so the RAM guard passes on its data.
		memTotalKB: 3986812,
		dfRows: "Filesystem 1B-blocks Used Available Capacity Mounted on\n" +
			"/dev/vda1 41000000000 16000000000 22000000000 41% /\n",
		// The colon output KeyringHoldsExactly parses: a pub record followed by
		// the fpr whose field 10 is the pinned fingerprint.
		gpgKeys: "pub:u:255:22:0000000000000000:::::::::\nfpr:::::::::" + strings.Repeat("A", 40) + ":\n",
	}
	// The base filesystem every Debian host has, fresh included: the ancestry
	// probes (accounts' /home/x pattern, appdirs' deploy-path chain) PARSE
	// '%n %u %a %F' lines for every component that exists, so the components a
	// real host always has must exist here too — an all-absent ancestry would
	// pass the guard vacuously and never exercise its parser. /var/www is NOT
	// here: it arrives with nginx, so only the provisioned profiles carry it.
	for _, d := range []string{"/", "/home", "/var"} {
		h.files[d] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
			mode: "755", kind: "directory", mtimeUnix: 1400000000}
	}
	// /etc/default/ssh ships with openssh-server on every host berth can reach
	// (it connects over sshd), fresh included. hardening's sshdOptsGuard PARSES
	// it for the last SSHD_OPTS assignment; this is the stock Debian content,
	// whose empty assignment is exactly what the guard must prove.
	h.files["/etc/default/ssh"] = fakeFile{
		content: "# Default settings for openssh-server. This file is sourced by /bin/sh from\n" +
			"# /etc/init.d/ssh.\n\n# Options to pass to sshd\nSSHD_OPTS=\n",
		owner: "root", group: "root", mode: "644", kind: "regular file",
		mtimeUnix: 1400000000,
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
		// The engine PDO driver php.Check probes last (mariadb -> pdo_mysql).
		"php" + s.PHP.Version + "-mysql",
		"mariadb-server", "valkey-server", "supervisor", "fail2ban", "ufw",
		"certbot", "restic", "cron", "unattended-upgrades", "curl", "gnupg",
		// The rest of basePackages (systembase.go): a converged host has them
		// all, or base.Check honestly reports it unconverged.
		"git", "rsync", "unzip", "ca-certificates",
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
	// The stock shared valkey-server.service exists on any host with the
	// package but is disabled AND stopped — the unauthenticated 6379 listener
	// the valkey step replaces with per-site instances. Its inactivity is
	// exactly what valkey.Check requires, so it must be modelled as present-
	// but-down, not absent.
	h.units["valkey-server.service"] = fakeUnit{active: false, enabled: false, props: map[string]string{}}
	for _, tool := range []string{"nginx", "php-fpm" + s.PHP.Version, "restic", "certbot", "gpg", "logrotate", "supervisorctl", "composer", "mysqldump"} {
		h.tools[tool] = true
	}
	// Every modelled LE lineage is comfortably outside the 30-day renew
	// window: 60 days out, the midpoint of a lineage certbot's timer keeps
	// renewed. tls.Check compares this against the real clock.
	h.certExpiry = time.Now().Add(60 * 24 * time.Hour)
	// The valkey exec probe compares the inode behind /usr/bin/valkey-server
	// with the running process's /proc/<pid>/exe using stat -L on BOTH sides:
	// the packaged path is a SYMLINK to the multi-call binary valkey-check-rdb
	// (argv[0]-dispatched), and modelling it as a plain file would hide the
	// very stat-vs-stat -L confusion that broke idempotency on a live box.
	h.files["/usr/bin/valkey-server"] = fakeFile{owner: "root", group: "root",
		mode: "777", kind: "symbolic link", mtimeUnix: 1400000000,
		linkTarget: "/usr/bin/valkey-check-rdb"}
	h.files["/usr/bin/valkey-check-rdb"] = fakeFile{owner: "root", group: "root",
		mode: "755", kind: "regular file", mtimeUnix: 1400000000}
	// nginx's package-shipped core config. nginx.Check keys its reload stamp
	// on this file's MTIME (reloadedSince); the content is only ever grepped
	// under nginx.source=nginx, which the fixture does not select.
	h.files["/etc/nginx/nginx.conf"] = fakeFile{
		content: "user www-data;\nworker_processes auto;\n",
		owner:   "root", group: "root", mode: "644", kind: "regular file",
		mtimeUnix: 1500000000,
	}
	// The fixture site's database and grant exist on any once-provisioned
	// host; the information_schema probes read them.
	h.databases[s.SiteDBName(s.Sites[0])] = true
	h.dbGrants[s.SiteDBUser(s.Sites[0])+":"+s.SiteDBName(s.Sites[0])] = true
	// Every berth-owned account exists on a once-provisioned host, with the
	// 0700 home ensureUser locks and the ~/.ssh directory berth creates as the
	// account. fresh gets none: userExists reads only the exit code of
	// `id <user>`, and the absent account is the branch accounts.Check exists
	// to walk there — and assertOwnSSHDir's exit-92 "absent" signal is only
	// reachable while ~/.ssh does not exist. uid 1000+i keeps the site user at
	// 1001, matching the uid populateManagedFiles pins on the site tree.
	for i, u := range managedAccounts(s) {
		h.users[u] = true
		for _, d := range []string{"/home/" + u, "/home/" + u + "/.ssh"} {
			h.files[d] = fakeFile{owner: u, group: u, uid: 1000 + i, gid: 1000 + i,
				mode: "700", kind: "directory", mtimeUnix: 1500000000}
		}
	}
	h.swapRows = "NAME TYPE SIZE USED PRIO\n/swapfile file 2G 0B -2\n"
}

// setMeta adjusts the probed metadata of an existing modelled file. putManaged
// pins root:root 644 — right for /etc config drop-ins, wrong for the artifacts
// whose owner/mode IS part of the step's contract (sudoers 0440, the reload
// wrapper 0755, a tenant's authorized_keys), which their Checks stat.
func (h *fakeHost) setMeta(path, owner, group, mode string) {
	f := h.files[path]
	f.owner, f.group, f.mode = owner, group, mode
	h.files[path] = f
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
	// shared/tmp and the ACME webroot complete the four paths appdirs.Check
	// stats (appdirs.go): shared/tmp mirrors shared's private tenant identity;
	// the webroot and its base are root:root — certbot writes there as root,
	// nginx only reads. /var/www itself arrives with nginx on any provisioned
	// host and is what the appdirs ancestry probe reports.
	h.files[site.DeployPath+"/shared/tmp"] = fakeFile{owner: owner, group: owner, uid: uid, gid: uid,
		mode: "700", kind: "directory", mtimeUnix: 1500000000}
	for _, d := range []string{"/var/www", acmeWebrootBase, acmeWebroot(site.Domain)} {
		h.files[d] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
			mode: "755", kind: "directory", mtimeUnix: 1500000000}
	}

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

	// base's APT Periodic config, rendered by the same function base.Check
	// compares against. The foreign variant putManaged writes is NOT the
	// debconf stock copy, so it stays outside the stockAutoUpgrades adoption
	// allowlist and walks the refusal branch the drift policy means to give.
	autoUp, err := renderAutoUpgrades()
	if err != nil {
		panic("render apt_auto_upgrades.conf.tmpl: " + err.Error())
	}
	h.putManaged(autoUpgradesPath, autoUp, profile)

	// The declared apt repos: the source list is rendered by the same
	// SourceContent the step compares against. The pinned keyring exists only
	// where the list reads up-to-date (converged/runtime-stale) — those are
	// the profiles whose Check reaches KeyringHoldsExactly, and its presence
	// is what lets the gpg answer serve the modelled key material (guard 4b).
	for _, cfg := range s.Apt.Repos {
		repo := userRepo(cfg)
		src, err := repo.SourceContent()
		if err != nil {
			panic("render apt source list for " + repo.Name + ": " + err.Error())
		}
		h.putManaged(repo.SourceListPath(), src, profile)
		if profile == "converged" || profile == "runtime-stale" {
			h.files[repo.KeyringPath()] = fakeFile{owner: "root", group: "root",
				mode: "644", kind: "regular file", mtimeUnix: 1500000000}
		}
	}
	// accounts' artifacts. The sudoers bodies come from the same sources the
	// step compares against: the berth grant is the step's own const, the site
	// grant the same renderer, and authorized_keys the same composer over the
	// same fixture pubkey. Owner/mode are part of the sudoers contract (sudo
	// refuses a drop-in that is not root:root 0440), so accounts.Check stats
	// them; the reload wrapper's root:root 0755 IS the security boundary its
	// Check enforces.
	h.putManaged(sudoersBerthPath, []byte(sudoersBerthBody), profile)
	h.setMeta(sudoersBerthPath, "root", "root", "440")
	siteSudoers, err := renderSiteSudoers(s, site)
	if err != nil {
		panic("render sudoers_deploy.tmpl: " + err.Error())
	}
	h.putManaged(sudoersPath(s.SiteUser(site)), siteSudoers, profile)
	h.setMeta(sudoersPath(s.SiteUser(site)), "root", "root", "440")
	operatorKey, err := operatorPublicKey(s.SSH.Key)
	if err != nil {
		panic("read the fixture operator key: " + err.Error())
	}
	for _, u := range managedAccounts(s) {
		h.putManaged(authorizedKeysPath(u), authorizedKeys(operatorKey), profile)
		h.setMeta(authorizedKeysPath(u), u, u, "600")
	}
	reloadWrapper, err := renderReloadFPMScript(s)
	if err != nil {
		panic("render reload_fpm.sh.tmpl: " + err.Error())
	}
	h.putManaged(reloadFPMScriptPath, reloadWrapper, profile)
	h.setMeta(reloadFPMScriptPath, "root", "root", "755")

	// hardening's two managed files: the sshd drop-in is the step's own const,
	// the jail the same renderer its Check calls.
	h.putManaged(sshdDropInPath, []byte(sshdDropInBody), profile)
	jail, err := renderFail2banJail(s)
	if err != nil {
		panic("render fail2ban_jail.tmpl: " + err.Error())
	}
	h.putManaged(fail2banJailPath, jail, profile)

	// php's two FPM drop-ins (INI marker), from the same renderers its Check
	// compares against, plus the per-site FPM error-log dir its Apply creates.
	opcache, err := renderOpcache()
	if err != nil {
		panic("render php_opcache.ini.tmpl: " + err.Error())
	}
	h.putManaged(opcacheDropInPath(s.PHP.Version), opcache, profile)
	phpTuning, err := renderPHPTuning(s)
	if err != nil {
		panic("render php_tuning.ini.tmpl: " + err.Error())
	}
	h.putManaged(phpTuningDropInPath(s.PHP.Version), phpTuning, profile)
	h.files[phpLogDir] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
		mode: "755", kind: "directory", mtimeUnix: 1500000000}

	// tuning's MariaDB drop-in and valkey's per-site instance unit, same
	// renderer-fed discipline.
	mariadbTuning, err := renderMariaDBTuning(s)
	if err != nil {
		panic("render mariadb_tuning.cnf.tmpl: " + err.Error())
	}
	h.putManaged(mariadbTuningPath, mariadbTuning, profile)
	for _, st := range s.Sites {
		unit, err := renderValkeyUnit(s, st)
		if err != nil {
			panic("render berth_valkey.service.tmpl: " + err.Error())
		}
		h.putManaged(valkeyUnitPath(st.Domain), unit, profile)
	}

	// The site's shared/.env and ~/.my.cnf are secret-bearing, seed-if-absent
	// files — NEVER marker-managed, so putManaged's foreign/drifted grammar
	// does not apply. Provisioned profiles carry them with the values the
	// seeded local cache also holds (a healthy host agrees with its cache);
	// foreign carries neither — a tree berth never provisioned has no berth
	// .env, and database.Check honestly stops at "credential not yet
	// persisted" instead of refusing. The .env body is built by the same
	// secret.EnvFile serializer the seed uses, over a kv mirroring
	// seedSharedEnv's (database.go).
	if profile != "foreign" {
		user := s.SiteUser(site)
		h.files[sharedEnvPath(site)] = fakeFile{content: string(fixtureSharedEnvBody()),
			owner: user, group: user, uid: 1001, gid: 1001,
			mode: "600", kind: "regular file", mtimeUnix: 1500000000}
		h.files["/home/"+user+"/.my.cnf"] = fakeFile{
			content: string(dbpkg.MariaDB{}.ClientAuthFile(s.SiteDBName(site), s.SiteDBUser(site), fixtureDBValue)),
			owner:   user, group: user, uid: 1001, gid: 1001,
			mode: "600", kind: "regular file", mtimeUnix: 1500000000}
	}

	// Reload stamps for the units whose Checks compare via reloadedSince
	// (hardening: ssh + fail2ban; nginx: its core config; php: the two FPM
	// drop-ins). Under runtime-stale the stamps PREDATE the managed files
	// (mtime 1500000000), which is the crash-between-write-and-reload state
	// that probe exists to catch; everywhere else they postdate them.
	stampM := int64(2000000000)
	if profile == "runtime-stale" {
		stampM = 1000000000
	}
	for _, unit := range []string{"ssh", "fail2ban", "nginx", config.FPMServiceName(s.PHP.Version)} {
		h.files[stampPath(unit)] = fakeFile{owner: "root", group: "root",
			mode: "644", kind: "regular file", mtimeUnix: stampM}
	}

	// The sweep namespace: drifted models an UNDECLARED berth-owned list (the
	// exact state the apt step's sweep exists to remove — strict marker as the
	// first line, canonical berth-*.list name); foreign models a marker-less
	// impostor at the same path, which the sweep must classify as foreign and
	// leave alone. converged has neither — nothing undeclared lingers there.
	const ghostList = "/etc/apt/sources.list.d/berth-oldrepo.list"
	switch profile {
	case "drifted":
		h.files[ghostList] = fakeFile{
			content: templates.ManagedMarker + "\ndeb [signed-by=/usr/share/keyrings/berth-oldrepo.gpg] https://old.example.com/debian trixie main\n",
			owner:   "root", group: "root", mode: "644", kind: "regular file",
			mtimeUnix: 1500000000}
	case "foreign":
		h.files[ghostList] = fakeFile{
			content: "deb https://old.example.com/debian trixie main\n",
			owner:   "root", group: "root", mode: "644", kind: "regular file",
			mtimeUnix: 1500000000}
	}

	// ---- wave 4: site / tls / backups / offsite / manifest ----

	// Cert modelling, deliberate per profile: every provisioned profile
	// (converged, drifted, foreign, runtime-stale) carries the Let's Encrypt
	// material — the live fullchain (site.Check's test -e cert probe) and the
	// certbot renewal conf (tls's orphan discovery cats and parses it) — so
	// renderSiteNginx takes the HTTPS branch, the branch whose byte-identical
	// site↔tls re-render invariant the contract must hold under, and tls's
	// foreign leg gets PAST the certificate loop to the deploy-hook drift
	// guard, the refusal that step means to give. fresh has neither: it
	// honestly renders the HTTP-only ACME vhost and stops at "no valid
	// certificate". The renewal conf is certbot's own file (third-party
	// state like /etc/os-release, hand-modelled from the real 2.x format,
	// never marker-managed); the fullchain is modelled as a regular file —
	// only its existence is ever probed.
	h.files[certFullchainPath(site)] = fakeFile{owner: "root", group: "root",
		mode: "644", kind: "regular file", mtimeUnix: 1500000000}
	h.files[letsencryptRenewalDir] = fakeFile{owner: "root", group: "root",
		mode: "700", kind: "directory", mtimeUnix: 1500000000}
	h.files[letsencryptRenewalDir+"/"+site.Domain+".conf"] = fakeFile{
		content: fixtureRenewalConf(site.Domain),
		owner:   "root", group: "root", mode: "644", kind: "regular file",
		mtimeUnix: 1500000000}

	// The site step's per-site artifacts, from the exact renderers its Check
	// compares against. The vhost is the HTTPS block (cert present, see
	// above) — renderNginxHTTPS is the SAME function the cert-aware
	// renderSiteNginx resolves to and the tls swap calls.
	vhost, err := renderNginxHTTPS(s, site)
	if err != nil {
		panic("render nginx_https.conf.tmpl: " + err.Error())
	}
	h.putManaged(nginxAvailablePath(site.Domain), vhost, profile)
	pool, err := renderFPMPool(s, site)
	if err != nil {
		panic("render fpm_pool.conf.tmpl: " + err.Error())
	}
	h.putManaged(fpmPoolPath(s.PHP.Version, site.Domain), pool, profile)
	worker, err := renderSupervisorProgram(programName(site.Domain), queueCommand(s, site), queueNumprocs(site), s.SiteUser(site), site.DeployPath)
	if err != nil {
		panic("render supervisor.conf.tmpl: " + err.Error())
	}
	h.putManaged(supervisorProgramPath(site.Domain), worker, profile)
	cron, err := renderCron(s, site)
	if err != nil {
		panic("render scheduler.cron.tmpl: " + err.Error())
	}
	h.putManaged(cronPath(site.Domain), cron, profile)
	// The governing directories site.Check pairs with the reload stamps
	// (their mtime covers link/file topology drift the per-file probes miss).
	for _, d := range []string{nginxEnabledDir, fpmPoolDir(s.PHP.Version)} {
		h.files[d] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
			mode: "755", kind: "directory", mtimeUnix: 1500000000}
	}

	// tls's managed renewal deploy hook (written iff any LE site exists AND
	// certbot is installed — both true here).
	hook, err := renderCertbotDeployHook()
	if err != nil {
		panic("render certbot_deploy_hook.sh.tmpl: " + err.Error())
	}
	h.putManaged(certbotDeployHookPath, hook, profile)
	h.setMeta(certbotDeployHookPath, "root", "root", "755")

	// backups' per-site script/cron/manifest plus the global logrotate
	// fragment and the root-owned directory skeleton (Decision 1: a root
	// cron must never write into tenant territory, so owner/mode ARE the
	// step's contract and its Check stats them all).
	bscript, err := renderBackupScript(s, site, dbpkg.MariaDB{})
	if err != nil {
		panic("render backup.sh.tmpl: " + err.Error())
	}
	h.putManaged(backupScriptPath(site.Domain), bscript, profile)
	h.setMeta(backupScriptPath(site.Domain), "root", "root", "755")
	bcron, err := renderBackupCron(s, site)
	if err != nil {
		panic("render backup.cron.tmpl: " + err.Error())
	}
	h.putManaged(backupCronPath(site.Domain), bcron, profile)
	bman, err := renderBackupManifest(s, site)
	if err != nil {
		panic("render backup_manifest.tmpl: " + err.Error())
	}
	h.putManaged(backupManifestPath(site.Domain), bman, profile)
	h.setMeta(backupManifestPath(site.Domain), "root", "root", "600")
	blr, err := renderBackupLogrotate()
	if err != nil {
		panic("render backup_logrotate.conf.tmpl: " + err.Error())
	}
	h.putManaged(backupLogrotatePath, blr, profile)
	h.files[backupDir(site.Domain)] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
		mode: "700", kind: "directory", mtimeUnix: 1500000000}
	for _, d := range []string{backupBaseDir, backupLogDir} {
		h.files[d] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
			mode: "755", kind: "directory", mtimeUnix: 1500000000}
	}

	// offsite's env/script/cron and the per-repository init stamp. The env
	// content comes from the step's own renderer over the SAME values the
	// seeded cache holds (fixtureOffsiteSecrets); the stamp content from the
	// step's own composer, keyed by the fixture repository string.
	h.files[offsiteEnvDir] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
		mode: "755", kind: "directory", mtimeUnix: 1500000000}
	oenv, err := renderOffsiteEnv(s, fixtureOffsiteSecrets())
	if err != nil {
		panic("render offsite_env.tmpl: " + err.Error())
	}
	h.putManaged(offsiteEnvPath, oenv, profile)
	h.setMeta(offsiteEnvPath, "root", "root", "600")
	oscript, err := renderOffsiteScript(s)
	if err != nil {
		panic("render offsite.sh.tmpl: " + err.Error())
	}
	h.putManaged(offsiteScriptPath, oscript, profile)
	h.setMeta(offsiteScriptPath, "root", "root", "755")
	ocron, err := renderOffsiteCron(s)
	if err != nil {
		panic("render backup.cron.tmpl for offsite: " + err.Error())
	}
	h.putManaged(offsiteCronPath, ocron, profile)
	repo := s.Backups.Offsite.Repository(s.ID)
	h.putManaged(offsiteStampPath(repo), offsiteStampContent(repo), profile)
	h.setMeta(offsiteStampPath(repo), "root", "root", "600")
	// berth's state dir itself: offsite.Check stats it, and the reload
	// stamps modelled above live inside it.
	h.files[berthStateDir] = fakeFile{owner: "root", group: "root", uid: 0, gid: 0,
		mode: "755", kind: "directory", mtimeUnix: 1500000000}

	// The terminal manifest, per profile: converged/runtime-stale record THIS
	// binary's version (rendered by the same template Apply uses; the
	// timestamp is data Check deliberately ignores), drifted records an older
	// berth — the honest "provisioned before the upgrade" state. foreign has
	// none: /var/lib/berth is berth-exclusive (no operator file is expected
	// there, manifest.go), so a foreign file at this path is not a state the
	// profile models.
	switch profile {
	case "converged", "runtime-stale":
		h.files[manifestPath] = fakeFile{content: fixtureManifest(version.Version),
			owner: "root", group: "root", mode: "644", kind: "regular file",
			mtimeUnix: 1500000000}
	case "drifted":
		h.files[manifestPath] = fakeFile{content: fixtureManifest("0.0.0-previous"),
			owner: "root", group: "root", mode: "644", kind: "regular file",
			mtimeUnix: 1500000000}
	}
}

// fixtureManifest renders /var/lib/berth/manifest via the same template
// manifest.Apply uses; the pinned timestamp is fine because Check compares
// only the VERSION field (a bumped timestamp is never drift, by contract).
func fixtureManifest(v string) string {
	body, err := templates.Render("manifest.tmpl", struct{ Version, ProvisionedAt string }{
		Version: v, ProvisionedAt: "2026-07-30T00:00:00Z",
	})
	if err != nil {
		panic("render manifest.tmpl: " + err.Error())
	}
	return string(body)
}

// fixtureRenewalConf is the certbot renewal conf a berth-issued lineage has
// on a real host — certbot's file, not berth's, so it is hand-modelled from
// the live 2.x format (the third-party-state precedent of /etc/os-release).
// The fields tls's parseRenewalConf consumes are exactly the ones berth's
// issuance produces: authenticator = webroot and the domain's berth webroot
// in webroot_path and [[webroot_map]].
func fixtureRenewalConf(domain string) string {
	webroot := acmeWebroot(domain)
	return "# renew_before_expiry = 30 days\n" +
		"version = 2.11.0\n" +
		"archive_dir = /etc/letsencrypt/archive/" + domain + "\n" +
		"cert = /etc/letsencrypt/live/" + domain + "/cert.pem\n" +
		"privkey = /etc/letsencrypt/live/" + domain + "/privkey.pem\n" +
		"chain = /etc/letsencrypt/live/" + domain + "/chain.pem\n" +
		"fullchain = /etc/letsencrypt/live/" + domain + "/fullchain.pem\n" +
		"\n" +
		"# Options used in the renewal process\n" +
		"[renewalparams]\n" +
		"account = 0123456789abcdef0123456789abcdef\n" +
		"authenticator = webroot\n" +
		"webroot_path = " + webroot + ",\n" +
		"server = https://acme-v02.api.letsencrypt.org/directory\n" +
		"key_type = ecdsa\n" +
		"[[webroot_map]]\n" +
		domain + " = " + webroot + "\n"
}

// fixtureSharedEnvBody is the modelled site's shared/.env as a successful
// provision leaves it: the kv mirrors seedSharedEnv's map (database.go) for
// the fixture site over the mariadb engine with Valkey on — a copy on
// purpose, so a production seed change makes database.Check's probes read
// honestly different bytes here — and the serialization is the SAME
// secret.EnvFile the seed calls (sorted keys, one KEY=value per line).
// database.Check never hashes this file; it greps the DB_CONNECTION,
// DB_PASSWORD and APP_KEY lines and compares the latter two against the
// seeded local cache, so the fixture values must be the cache's values.
// The other keys (DB_HOST/DB_PORT/DB_SOCKET, the cache/queue/redis block)
// are mirrored for the seed-map fidelity above but VERIFIED BY NO CHECK
// today — no probe reads them, so a wrong value there cannot fail a test.
func fixtureSharedEnvBody() []byte {
	body, err := secret.EnvFile(map[string]string{
		"APP_ENV":          "production",
		"APP_DEBUG":        "false",
		"APP_URL":          "https://app.example.com",
		"APP_KEY":          fixtureAppKey,
		"DB_CONNECTION":    "mysql",
		"DB_HOST":          "localhost",
		"DB_PORT":          "3306",
		"DB_DATABASE":      "app",
		"DB_USERNAME":      "app",
		"DB_PASSWORD":      fixtureDBValue,
		"DB_SOCKET":        "/run/mysqld/mysqld.sock",
		"CACHE_DRIVER":     "redis",
		"CACHE_STORE":      "redis",
		"SESSION_DRIVER":   "redis",
		"QUEUE_CONNECTION": "redis",
		"REDIS_CLIENT":     "phpredis",
		"REDIS_HOST":       "/run/berth-valkey/app_example_com/valkey.sock",
		"REDIS_PORT":       "0",
		"REDIS_DB":         "0",
		"REDIS_CACHE_DB":   "1",
	})
	if err != nil {
		panic("render the fixture shared/.env: " + err.Error())
	}
	return body
}

// aptUserLists returns the modelled paths the apt step's find discovery
// (aptUserListsCmd) would print: entries directly under
// /etc/apt/sources.list.d whose name matches berth-*.list. Sorted, because a
// Go map has no iteration order and the answer must be deterministic.
func (h *fakeHost) aptUserLists() []string {
	var out []string
	for p := range h.files {
		base, ok := strings.CutPrefix(p, "/etc/apt/sources.list.d/")
		if !ok || strings.Contains(base, "/") {
			continue
		}
		if strings.HasPrefix(base, "berth-") && strings.HasSuffix(base, ".list") {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}
