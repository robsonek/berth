package wizard

import (
	"testing"
)

// fakePrompter scripts orchestration without a TTY. Each *func slice is consumed
// in call order; Confirm answers come from the confirms queue; ShowError is recorded.
type fakePrompter struct {
	serverCore     func(*Answers)
	serverAdvanced func(*Answers)
	siteCore       []func(int, *SiteAnswers) // one per SiteCore call (incl. retries)
	siteCoreN      int
	siteScheduler  func(*SiteAnswers)
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
func (f *fakePrompter) SiteScheduler(sa *SiteAnswers) error { f.siteScheduler(sa); return nil }
func (f *fakePrompter) Queue(q *QueueAnswers) error         { f.queue(q); return nil }
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
