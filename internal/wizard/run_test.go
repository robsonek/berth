package wizard

import (
	"strconv"
	"testing"
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

func TestFakeCompiles(t *testing.T) {
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
		// confirms: server-advanced? site-advanced? add-another?
		confirms: []bool{false, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(a.Sites) != 1 || a.Sites[0].Domain != "a.example.com" {
		t.Fatalf("sites = %+v", a.Sites)
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
		confirms: []bool{false /*srv adv*/, false /*s0 adv*/, true /*add*/, false /*s1 adv*/, false /*add*/},
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
		// srv-adv? | http3-switch? (decline) | site-adv? | add-another?
		confirms: []bool{false, false, false, false},
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
		// srv-adv? | http3-switch? (accept) | site-adv? | add-another?
		confirms: []bool{false, true, false, false},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if a.NginxSource != "nginx" || !a.Sites[0].HTTP3 {
		t.Errorf("expected nginx switched + http3 kept: nginx=%q http3=%v", a.NginxSource, a.Sites[0].HTTP3)
	}
}

func TestRunValkeyCapsAtSixteen(t *testing.T) {
	makeSite := func(i int, sa *SiteAnswers) {
		n := strconv.Itoa(i)
		sa.Domain, sa.DeployPath = "s"+n+".example.com", "/srv/"+n
		sa.DBName, sa.DBUser = "d"+n, "u"+n
		sa.User = "user" + n // explicit, distinct, avoids derived-name edge cases
	}
	cores := make([]func(int, *SiteAnswers), 16)
	for i := range cores {
		cores[i] = makeSite
	}
	// confirms: srv-adv? then per site: site-adv?(false) add-another?(true) — but the
	// 16th site never gets an "add another?" (gated), so 1 + (15*2 + 1) = 32 confirms.
	confirms := []bool{false}
	for i := 0; i < 16; i++ {
		confirms = append(confirms, false) // site-advanced?
		if i < 15 {
			confirms = append(confirms, true) // add another?
		}
	}
	f := &fakePrompter{serverCore: func(a *Answers) { baseServer(a); a.Valkey = true }, siteCore: cores, confirms: confirms}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(a.Sites) != 16 {
		t.Fatalf("expected 16 sites (capped), got %d", len(a.Sites))
	}
	if err := a.ToServer().Validate(); err != nil {
		t.Fatalf("16-site valkey config should validate: %v", err)
	}
	if len(f.errors) != 1 {
		t.Errorf("expected the cap note once, got %v", f.errors)
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
		// srv-adv? | s0 adv?(yes) | dedicated-queue?(no) | add-daemon?(yes) | another-daemon?(yes) | another-daemon?(no) | add-site?(no)
		confirms: []bool{false, true, false, true, true, false, false},
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
		// confirms: server advanced gate=true, site advanced gate=true,
		// dedicated-queue=false, add-daemon=false, add another=false
		confirms: []bool{true, true, false, false, false},
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
}
