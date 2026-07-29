package wizard

import (
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/secret"
)

// fakePrompter scripts orchestration without a TTY. Each *func slice is consumed
// in call order; Confirm answers come from the confirms queue; ShowError is recorded.
type fakePrompter struct {
	serverCore     func(*Answers)
	serverAdvanced func(*Answers)
	serverOps      func(*Answers)
	siteCore       []func(int, *SiteAnswers) // one per SiteCore call (incl. retries)
	siteCoreN      int
	siteOverrides  func(*SiteAnswers)
	queue          func(*QueueAnswers)
	daemons        []func(*DaemonAnswers)
	daemonsN       int
	aptRepo        func(*AptRepoAnswers)
	confirms       []bool
	confirmsN      int
	errors         []error
}

func (f *fakePrompter) ServerCore(a *Answers) error     { f.serverCore(a); return nil }
func (f *fakePrompter) ServerAdvanced(a *Answers) error { f.serverAdvanced(a); return nil }
func (f *fakePrompter) SiteCore(i int, sa *SiteAnswers) error {
	fn := f.siteCore[f.siteCoreN]
	f.siteCoreN++
	fn(i, sa)
	return nil
}
func (f *fakePrompter) ServerOps(a *Answers) error {
	if f.serverOps != nil {
		f.serverOps(a)
	}
	return nil
}
func (f *fakePrompter) SiteOverrides(sa *SiteAnswers) error {
	if f.siteOverrides != nil {
		f.siteOverrides(sa)
	}
	return nil
}
func (f *fakePrompter) Queue(q *QueueAnswers) error { f.queue(q); return nil }
func (f *fakePrompter) Daemon(d *DaemonAnswers) error {
	fn := f.daemons[f.daemonsN]
	f.daemonsN++
	fn(d)
	return nil
}
func (f *fakePrompter) AptRepo(ar *AptRepoAnswers) error {
	if f.aptRepo != nil {
		f.aptRepo(ar)
	}
	return nil
}
func (f *fakePrompter) Confirm(string) (bool, error) {
	b := f.confirms[f.confirmsN]
	f.confirmsN++
	return b, nil
}
func (f *fakePrompter) ShowError(err error) { f.errors = append(f.errors, err) }

// baseServer fills the server-level fields with a valid baseline.
func baseServer(a *Answers) {
	*a = defaults()
	a.Name = "t"
	a.Host = "203.0.113.10"
}

func TestFakeCompiles(_ *testing.T) {
	var _ prompter = &fakePrompter{}
}

func TestRunSingleSiteNoAdvanced(t *testing.T) {
	f := &fakePrompter{
		serverCore: baseServer,
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
			},
		},
		// confirms: server-advanced? apt-repo? site-advanced? add-another?
		confirms: []bool{false, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(a.Sites) != 1 || a.Sites[0].Domain != "a.example.com" {
		t.Fatalf("sites = %+v", a.Sites)
	}
	if len(a.AptRepos) != 0 {
		t.Errorf("declined apt-repo confirm must leave AptRepos empty: %+v", a.AptRepos)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("assembled server invalid: %v", err)
	}
	if len(f.errors) != 0 {
		t.Errorf("unexpected errors: %v", f.errors)
	}
}

func TestRunDuplicateDomainReprompts(t *testing.T) {
	f := &fakePrompter{
		serverCore: baseServer,
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
			},
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/b", "bd", "bu"
			}, // dup domain
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "b.example.com", "/srv/b", "bd", "bu"
			}, // fixed
		},
		// site0: advanced? add-another? | site1 retry has no extra confirms until valid | site1: advanced? add-another?
		confirms: []bool{false /*srv adv*/, false /*apt*/, false /*s0 adv*/, true /*add*/, false /*s1 adv*/, false /*add*/},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(a.Sites) != 2 || a.Sites[1].Domain != "b.example.com" {
		t.Fatalf("sites = %+v", a.Sites)
	}
	if len(f.errors) != 1 {
		t.Errorf("expected exactly 1 shown error (the duplicate), got %v", f.errors)
	}
}

func TestRunHTTP3DeclineDropsHTTP3(t *testing.T) {
	f := &fakePrompter{
		serverCore: func(a *Answers) { baseServer(a); a.NginxSource = "debian" },
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
				sa.SSL, sa.SSLMode, sa.SSLEmail, sa.HTTP3 = true, "letsencrypt", "x@y.com", true
			},
		},
		// srv-adv? | apt-repo? | http3-switch? (decline) | site-adv? | add-another?
		confirms: []bool{false, false, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if a.NginxSource != "debian" || a.Sites[0].HTTP3 {
		t.Errorf("expected http3 dropped and nginx unchanged: nginx=%q http3=%v", a.NginxSource, a.Sites[0].HTTP3)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Errorf("declined http3 config should be valid: %v", err)
	}
}

func TestRunHTTP3AcceptSwitchesNginx(t *testing.T) {
	f := &fakePrompter{
		serverCore: func(a *Answers) { baseServer(a); a.NginxSource = "debian" },
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
				sa.SSL, sa.SSLMode, sa.SSLEmail, sa.HTTP3 = true, "selfsigned", "", true
			},
		},
		// srv-adv? | apt-repo? | http3-switch? (accept) | site-adv? | add-another?
		confirms: []bool{false, false, true, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if a.NginxSource != "nginx" || !a.Sites[0].HTTP3 {
		t.Errorf("expected nginx switched + http3 kept: nginx=%q http3=%v", a.NginxSource, a.Sites[0].HTTP3)
	}
}

func TestRunDaemonSubLoop(t *testing.T) {
	f := &fakePrompter{
		serverCore: baseServer,
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
			},
		},
		siteOverrides: func(sa *SiteAnswers) { sa.SchedulerOverride = "inherit" },
		daemons: []func(*DaemonAnswers){
			func(d *DaemonAnswers) { d.Name, d.Command, d.Processes = "reverb", "php artisan reverb:start", 1 },
			func(d *DaemonAnswers) { d.Name, d.Command, d.Processes = "horizon", "php artisan horizon", 1 },
		},
		// srv-adv? | apt-repo? | s0 adv?(yes) | dedicated-queue?(no) | add-daemon?(yes) | another-daemon?(yes) | another-daemon?(no) | add-site?(no)
		confirms: []bool{false, false, true, false, true, true, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(a.Sites[0].Daemons) != 2 || a.Sites[0].Daemons[1].Name != "horizon" {
		t.Fatalf("daemons = %+v", a.Sites[0].Daemons)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("daemon config should validate: %v", err)
	}
}

// A per-site cloudflare_only override is collected AFTER the core validation,
// so only the post-advanced re-validation can catch cloudflare_only+letsencrypt.
// First attempt: LE site + override "on" -> rejected, site re-prompted from
// scratch. Second attempt: selfsigned + same override -> valid.
func TestRunRepromptsSiteWhenOverrideBreaksValidation(t *testing.T) {
	f := &fakePrompter{
		serverCore: baseServer,
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
				sa.SSL, sa.SSLMode, sa.SSLEmail = true, "letsencrypt", "ops@example.com"
			},
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
				sa.SSL, sa.SSLMode = true, "selfsigned"
			},
		},
		siteOverrides: func(sa *SiteAnswers) { sa.CloudflareOverride = "on" },
		confirms: []bool{
			false, // server advanced gate
			false, // add an apt repository?
			true,  // site advanced (attempt 1)
			false, // dedicated queue worker? (attempt 1)
			false, // add a daemon? (attempt 1)
			true,  // site advanced (attempt 2)
			false, // dedicated queue worker? (attempt 2)
			false, // add a daemon? (attempt 2)
			false, // add another site?
		},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(f.errors) != 1 || !strings.Contains(f.errors[0].Error(), "cloudflare_only") {
		t.Fatalf("errors = %v, want exactly one cloudflare_only rejection", f.errors)
	}
	if len(a.Sites) != 1 || a.Sites[0].SSLMode != "selfsigned" || a.Sites[0].CloudflareOverride != "on" {
		t.Fatalf("sites = %+v, want one selfsigned site with the override kept", a.Sites)
	}
	if verr := a.ToServer().Validate(); verr != nil {
		t.Fatalf("assembled server invalid: %v", verr)
	}
}

func TestRunServerOpsAndSiteOverrides(t *testing.T) {
	f := &fakePrompter{
		serverCore:     baseServer,
		serverAdvanced: func(*Answers) {},
		serverOps: func(a *Answers) {
			a.System = SystemAnswers{Swap: "2G", Sysctl: true}
			a.CloudflareOnly = true
			a.Backups = BackupsAnswers{Enabled: true, RetentionDays: 7}
		},
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "a", "a"
			},
		},
		siteOverrides: func(sa *SiteAnswers) { sa.BackupsOverride = "off" },
		// confirms: server advanced gate=true, apt-repo=false, site advanced
		// gate=true, dedicated-queue=false, add-daemon=false, add another=false
		confirms: []bool{true, false, true, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if a.System.Swap != "2G" || !a.CloudflareOnly || !a.Backups.Enabled {
		t.Errorf("server ops not collected: %+v", a)
	}
	if a.Sites[0].BackupsOverride != "off" {
		t.Errorf("site backups override = %q, want off", a.Sites[0].BackupsOverride)
	}
	srv := a.ToServer()
	if srv.Sites[0].Backups == nil || *srv.Sites[0].Backups {
		t.Error("site backups should map to *false")
	}
	if r := a.SecretRecipe(); r != "" {
		t.Errorf("a run without offsite must print no secret recipe, got:\n%s", r)
	}
}

func TestRunOffsiteS3CollectsAnswersAndRecipe(t *testing.T) {
	f := &fakePrompter{
		serverCore:     baseServer,
		serverAdvanced: func(*Answers) {},
		serverOps: func(a *Answers) {
			a.Backups = BackupsAnswers{Enabled: true, Offsite: OffsiteAnswers{
				Enabled: true, Backend: "s3", Endpoint: "s3.example.com", Bucket: "bkt",
			}}
		},
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
			},
		},
		// confirms: server-advanced? apt-repo? site-advanced? add-another?
		confirms: []bool{true, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("s3 offsite config should validate: %v", err)
	}
	recipe := a.SecretRecipe()
	for _, want := range []string{
		"berth secret set servers/t.yml " + secret.OffsiteS3AccessKey,
		"berth secret set servers/t.yml " + secret.OffsiteS3SecretKey,
	} {
		if !strings.Contains(recipe, want) {
			t.Errorf("recipe missing %q:\n%s", want, recipe)
		}
	}
	if len(f.errors) != 0 {
		t.Errorf("unexpected errors: %v", f.errors)
	}
}

func TestRunOffsiteSFTPPrintsNoRecipe(t *testing.T) {
	f := &fakePrompter{
		serverCore:     baseServer,
		serverAdvanced: func(*Answers) {},
		serverOps: func(a *Answers) {
			a.Backups = BackupsAnswers{Enabled: true, Offsite: OffsiteAnswers{
				Enabled: true, Backend: "sftp", Host: "backup.example.com", User: "restic",
				Path:    "/srv/restic/t",
				HostKey: "backup.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExample",
			}}
		},
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
			},
		},
		// confirms: server-advanced? apt-repo? site-advanced? add-another?
		confirms: []bool{true, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("sftp offsite config should validate: %v", err)
	}
	if r := a.SecretRecipe(); r != "" {
		t.Errorf("sftp offsite must print no recipe (the provision run hands out the public key), got:\n%s", r)
	}
}

func TestRunAptRepoSubLoop(t *testing.T) {
	entries := []AptRepoAnswers{
		{Name: "signal-cli", URI: "https://packaging.gitlab.io/signal-cli", Suite: "signalcli",
			Components: "main", KeyURL: "https://packaging.gitlab.io/signal-cli/gpg.key",
			Fingerprint: "02BD5FB7BA4650D50ED69002797DFE3F4F80269B"},
		{Name: "grafana", URI: "https://apt.grafana.com", Suite: "stable",
			Components: "", KeyURL: "https://apt.grafana.com/gpg.key",
			Fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	n := 0
	f := &fakePrompter{
		serverCore: baseServer,
		aptRepo:    func(ar *AptRepoAnswers) { *ar = entries[n]; n++ },
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
			},
		},
		// srv-adv? | apt-repo?(yes) | another-repo?(yes) | another-repo?(no) | site-adv? | add-site?
		confirms: []bool{false, true, true, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(a.AptRepos) != 2 || a.AptRepos[0].Name != "signal-cli" || a.AptRepos[1].Name != "grafana" {
		t.Fatalf("apt repos = %+v", a.AptRepos)
	}
	if len(f.errors) != 0 {
		t.Errorf("unexpected errors: %v", f.errors)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("assembled server invalid: %v", err)
	}
}

func TestRunAptRepoDuplicateNameDropped(t *testing.T) {
	entries := []AptRepoAnswers{
		{Name: "alpha", URI: "https://alpha.example.com/apt", Suite: "stable", Components: "main",
			KeyURL: "https://alpha.example.com/gpg.key", Fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{Name: "alpha", URI: "https://alpha.example.com/apt", Suite: "stable", Components: "main",
			KeyURL: "https://alpha.example.com/gpg.key", Fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, // dup name
		{Name: "beta", URI: "https://beta.example.com/apt", Suite: "stable", Components: "main",
			KeyURL: "https://beta.example.com/gpg.key", Fingerprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
	}
	n := 0
	f := &fakePrompter{
		serverCore: baseServer,
		aptRepo:    func(ar *AptRepoAnswers) { *ar = entries[n]; n++ },
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
			},
		},
		// srv-adv? | apt-repo?(yes) | another?(yes, dup attempt) | another?(yes) | another?(no) | site-adv? | add-site?
		confirms: []bool{false, true, true, true, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(a.AptRepos) != 2 || a.AptRepos[0].Name != "alpha" || a.AptRepos[1].Name != "beta" {
		t.Fatalf("apt repos = %+v, want exactly [alpha beta] (dup dropped)", a.AptRepos)
	}
	if len(f.errors) != 1 || !strings.Contains(f.errors[0].Error(), "duplicate repo name") {
		t.Fatalf("errors = %v, want exactly one duplicate-name rejection", f.errors)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("assembled server invalid: %v", err)
	}
}

func TestRunServerAdvancedSlowLogPairingReprompts(t *testing.T) {
	// A slow-query threshold with the slow log off is a SERVER-level violation;
	// it must re-prompt ServerAdvanced itself — the site retry loop cannot edit
	// server fields, so surfacing it there would trap the user forever.
	calls := 0
	f := &fakePrompter{
		serverCore: baseServer,
		serverAdvanced: func(a *Answers) {
			calls++
			if calls == 1 {
				a.Tuning.MariaDBLongQueryTime = 5 // threshold without the log
			} else {
				a.Tuning.MariaDBSlowQueryLog = true // fixed on the re-prompt
			}
		},
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
			},
		},
		// confirms: server-advanced? apt-repo? site-advanced? add-another?
		confirms: []bool{true, false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("ServerAdvanced calls = %d, want 2 (one re-prompt)", calls)
	}
	if len(f.errors) != 1 || !strings.Contains(f.errors[0].Error(), "slow query log") {
		t.Errorf("expected exactly 1 shown pairing error, got %v", f.errors)
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("assembled server invalid: %v", err)
	}
}
