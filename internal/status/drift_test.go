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
