package status

import (
	"context"
	"errors"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// fakeStep is a Step whose Check verdict is fixed by the test. Apply records
// that it was called — it must never be, because the scan runs with DryRun.
type fakeStep struct {
	name      string
	satisfied bool
	changes   []string
	checkErr  error
	deliberate
	applied *bool
}

// deliberate is embedded so a fake step can opt into the marker.
type deliberate struct{ marked bool }

func (d deliberate) DeliberatelyUnsatisfied() bool { return d.marked }

func (f *fakeStep) Name() string       { return f.name }
func (f *fakeStep) Requires() []string { return nil }
func (f *fakeStep) Check(_ context.Context, _ provision.RunCtx, _ *config.Server, _ bssh.Runner) (provision.CheckResult, error) {
	if f.checkErr != nil {
		return provision.CheckResult{}, f.checkErr
	}
	return provision.CheckResult{Satisfied: f.satisfied, Changes: f.changes}, nil
}
func (f *fakeStep) Apply(_ context.Context, _ provision.RunCtx, _ *config.Server, _ bssh.Runner) error {
	*f.applied = true
	return nil
}

func TestDriftCountsUnsatisfiedStepsAndNeverApplies(t *testing.T) {
	applied := false
	pipeline := []provision.Step{
		&fakeStep{name: "base", satisfied: true, applied: &applied},
		&fakeStep{name: "site", satisfied: false, changes: []string{"rewrite vhost"}, applied: &applied},
	}
	rep := Drift(context.Background(), &config.Server{ID: "t"}, bssh.NewFakeRunner(), pipeline, nil)

	if applied {
		t.Fatal("Apply ran during a read-only scan")
	}
	if rep.Drifted != 1 {
		t.Errorf("Drifted = %d, want 1", rep.Drifted)
	}
	if len(rep.Steps) != 2 {
		t.Fatalf("Steps = %+v, want 2 entries", rep.Steps)
	}
	if rep.Steps[1].Satisfied || len(rep.Steps[1].Changes) != 1 {
		t.Errorf("site state = %+v, want unsatisfied with one change", rep.Steps[1])
	}
	if rep.StoppedAt != "" {
		t.Errorf("StoppedAt = %q, want empty", rep.StoppedAt)
	}
}

// preflight reports Satisfied:false by design. Counting it would report every
// healthy host as drifted.
func TestDriftExcludesDeliberatelyUnsatisfiedSteps(t *testing.T) {
	applied := false
	pipeline := []provision.Step{
		&fakeStep{name: "preflight", satisfied: false, deliberate: deliberate{marked: true}, applied: &applied},
		&fakeStep{name: "base", satisfied: true, applied: &applied},
	}
	rep := Drift(context.Background(), &config.Server{ID: "t"}, bssh.NewFakeRunner(), pipeline, nil)
	if rep.Drifted != 0 {
		t.Errorf("Drifted = %d, want 0 — preflight is deliberately unsatisfied", rep.Drifted)
	}
}

// A fail-fast abort must be reported as partial, never as clean.
func TestDriftRecordsWhereItStopped(t *testing.T) {
	applied := false
	pipeline := []provision.Step{
		&fakeStep{name: "base", satisfied: true, applied: &applied},
		&fakeStep{name: "database", checkErr: errors.New("mariadb unreachable"), applied: &applied},
		&fakeStep{name: "site", satisfied: true, applied: &applied},
	}
	rep := Drift(context.Background(), &config.Server{ID: "t"}, bssh.NewFakeRunner(), pipeline, nil)
	if rep.StoppedAt != "database" {
		t.Errorf("StoppedAt = %q, want \"database\"", rep.StoppedAt)
	}
	if rep.Error == "" {
		t.Error("Error must carry the reason the scan aborted")
	}
	for _, s := range rep.Steps {
		if s.Step == "site" {
			t.Error("steps after the abort must not appear as inspected")
		}
	}
}

// noteStep is a step whose Check has something to say that is not drift.
type noteStep struct {
	name      string
	satisfied bool
	notes     []string
}

func (s noteStep) Name() string       { return s.name }
func (s noteStep) Requires() []string { return nil }
func (s noteStep) Check(context.Context, provision.RunCtx, *config.Server, bssh.Runner) (provision.CheckResult, error) {
	return provision.CheckResult{Satisfied: s.satisfied, Changes: []string{"change"}, Warnings: s.notes}, nil
}
func (s noteStep) Apply(context.Context, provision.RunCtx, *config.Server, bssh.Runner) error {
	return nil
}

// A step can be converged and still have something the operator must hear
// (a pending reboot, a service berth does not restart). The scan carries
// those warnings — per step, whatever its verdict — and they are not drift.
func TestDriftCarriesCheckWarningsWithoutCountingThemAsDrift(t *testing.T) {
	pipeline := []provision.Step{
		noteStep{name: "restarts", satisfied: true, notes: []string{"a reboot is pending"}},
		noteStep{name: "site", satisfied: false, notes: []string{"heads up"}},
		noteStep{name: "nginx", satisfied: true},
	}
	rep := Drift(context.Background(), &config.Server{}, bssh.NewFakeRunner(), pipeline, nil)
	if rep.Drifted != 1 {
		t.Errorf("Drifted = %d, want 1 (warnings are not drift)", rep.Drifted)
	}
	got := map[string][]string{}
	for _, st := range rep.Steps {
		got[st.Step] = st.Warnings
	}
	if len(got["restarts"]) != 1 || got["restarts"][0] != "a reboot is pending" || len(got["site"]) != 1 || len(got["nginx"]) != 0 {
		t.Errorf("warnings per step = %v", got)
	}
}
