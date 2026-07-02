package provision

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stepStub is a configurable Step for tests.
type stepStub struct {
	name      string
	requires  []string
	satisfied bool
	applyErr  error
	applied   *bool
	checked   *bool
	onCheck   func() // invoked at the top of Check when non-nil (e.g. to cancel the run context)
	alwaysRun bool
}

func (s *stepStub) Name() string       { return s.name }
func (s *stepStub) Requires() []string { return s.requires }
func (s *stepStub) AlwaysRun() bool    { return s.alwaysRun }
func (s *stepStub) Check(context.Context, RunCtx, *config.Server, bssh.Runner) (CheckResult, error) {
	if s.onCheck != nil {
		s.onCheck()
	}
	if s.checked != nil {
		*s.checked = true
	}
	return CheckResult{Satisfied: s.satisfied, Reason: "stub", Changes: []string{"do x"}}, nil
}
func (s *stepStub) Apply(context.Context, RunCtx, *config.Server, bssh.Runner) error {
	if s.applied != nil {
		*s.applied = true
	}
	return s.applyErr
}

func collect(ch <-chan Event) []Event {
	var out []Event
	for e := range ch {
		out = append(out, e)
	}
	return out
}

func TestEngineSkipsSatisfiedAndAppliesOthers(t *testing.T) {
	appliedB := false
	eng := New(
		&stepStub{name: "a", satisfied: true},
		&stepStub{name: "b", satisfied: false, applied: &appliedB},
	)
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	evs := collect(events) // blocks until the pipeline goroutine closes the channel
	if !appliedB {
		t.Error("step b should have been applied")
	}
	if !hasKind(evs, "a", EventSatisfied) || !hasKind(evs, "b", EventApplied) {
		t.Errorf("unexpected events: %+v", evs)
	}
}

func TestEngineDryRunDoesNotApply(t *testing.T) {
	applied := false
	eng := New(&stepStub{name: "b", satisfied: false, applied: &applied})
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{DryRun: true})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if applied {
		t.Error("dry-run must not apply")
	}
	if !hasKind(collect(events), "b", EventPlanned) {
		t.Error("expected EventPlanned in dry-run")
	}
}

func TestEngineFailFastStopsPipeline(t *testing.T) {
	secondApplied := false
	eng := New(
		&stepStub{name: "a", satisfied: false, applyErr: errors.New("boom")},
		&stepStub{name: "b", satisfied: false, applied: &secondApplied},
	)
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("preflight error = %v", err)
	}
	evs := collect(events) // blocks until the pipeline goroutine closes the channel
	if !hasKind(evs, "a", EventFailed) {
		t.Error("expected EventFailed for step a")
	}
	if secondApplied {
		t.Error("pipeline must stop after a failure")
	}
}

func TestEngineOnlyRefusesUnmetDependency(t *testing.T) {
	eng := New(
		&stepStub{name: "a", satisfied: false},
		&stepStub{name: "b", satisfied: false, requires: []string{"a"}},
	)
	_, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{Only: "b"})
	if err == nil {
		t.Fatal("expected refusal: b requires a which is unsatisfied")
	}
}

func TestEngineOnlyRefusesUnmetTransitiveDependency(t *testing.T) {
	// c → b → a; a is unsatisfied. `--only c` must refuse on the transitive a.
	eng := New(
		&stepStub{name: "a", satisfied: false},
		&stepStub{name: "b", satisfied: true, requires: []string{"a"}},
		&stepStub{name: "c", satisfied: false, requires: []string{"b"}},
	)
	_, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{Only: "c"})
	if err == nil {
		t.Fatal("expected refusal: c depends transitively on unsatisfied a")
	}
}

func TestEngineOnlyAllowsAlwaysRunPrereqAndRunsIt(t *testing.T) {
	preApplied, targetApplied := false, false
	eng := New(
		&stepStub{name: "pre", satisfied: false, alwaysRun: true, applied: &preApplied},
		&stepStub{name: "x", satisfied: false, requires: []string{"pre"}, applied: &targetApplied},
	)
	// --only x must NOT refuse on the always-run, never-satisfied "pre", and the
	// always-run step still executes ahead of the target.
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{Only: "x"})
	if err != nil {
		t.Fatalf("Run(--only x) refused on an always-run prerequisite: %v", err)
	}
	collect(events)
	if !preApplied {
		t.Error("always-run prerequisite should still execute under --only")
	}
	if !targetApplied {
		t.Error("target step should have been applied under --only")
	}
}

func TestEngineCancelledContextStopsBeforeNextStep(t *testing.T) {
	aChecked := false
	eng := New(
		&stepStub{name: "a", checked: &aChecked},
		&stepStub{name: "b"},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the pipeline starts
	events, err := eng.Run(ctx, &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	evs := collect(events)
	if len(evs) != 1 || evs[0].Kind != EventFailed || evs[0].Step != "a" {
		t.Fatalf("expected exactly one EventFailed for step a, got %+v", evs)
	}
	if evs[0].Err == nil || !strings.Contains(evs[0].Err.Error(), "interrupted") {
		t.Errorf("Err = %v, want it to mention interruption", evs[0].Err)
	}
	if aChecked {
		t.Error("no step Check may run after cancellation")
	}
}

func TestEngineCancelledContextWithOnlySkipsUnselectedSteps(t *testing.T) {
	// A ctx cancelled before Run means the --only pre-flight dependency walk
	// must stop immediately: no prerequisite Check (no further SSH probes), and
	// the interruption surfaces through Run's returned error — the pre-flight
	// error channel — not as a confusing "unmet prerequisites" failure.
	aChecked := false
	eng := New(
		&stepStub{name: "a", satisfied: true, checked: &aChecked},
		&stepStub{name: "b", requires: []string{"a"}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events, err := eng.Run(ctx, &config.Server{}, bssh.NewFakeRunner(), Options{Only: "b"})
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("Run() error = %v, want pre-flight refusal mentioning interruption", err)
	}
	if events != nil {
		t.Error("events channel must be nil when pre-flight refuses")
	}
	if aChecked {
		t.Error("no prerequisite Check may run after cancellation")
	}
}

func TestEngineOnlyMidRunCancelSkipsUnselectedAndFailsTrailing(t *testing.T) {
	// Cancellation mid-run under --only: the unselected step must never be
	// reported as interrupted (the ctx gate sits after the --only skip gate),
	// and a signal landing during the last selected step still surfaces as the
	// trailing "pipeline" EventFailed even though all work completed.
	ctx, cancel := context.WithCancel(context.Background())
	eng := New(
		&stepStub{name: "a", satisfied: true},
		&stepStub{name: "b", satisfied: true, requires: []string{"a"}, onCheck: cancel},
	)
	events, err := eng.Run(ctx, &config.Server{}, bssh.NewFakeRunner(), Options{Only: "b"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	evs := collect(events)
	for _, e := range evs {
		if e.Step == "a" {
			t.Errorf("unselected step must emit no events, got %+v", e)
		}
	}
	last := evs[len(evs)-1]
	if last.Step != "pipeline" || last.Kind != EventFailed {
		t.Fatalf("expected trailing pipeline EventFailed, got %+v", evs)
	}
	if last.Err == nil || !strings.Contains(last.Err.Error(), "interrupted") {
		t.Errorf("Err = %v, want it to mention interruption", last.Err)
	}
}

func TestEngineInterruptDuringLastStepStillFails(t *testing.T) {
	// A signal landing while the final step is in flight has no next step to
	// observe the cancelled ctx: the step completes, the loop ends. The run
	// must still end with a trailing pipeline EventFailed, never exit clean.
	ctx, cancel := context.WithCancel(context.Background())
	eng := New(&stepStub{name: "a", satisfied: true, onCheck: cancel})
	events, err := eng.Run(ctx, &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	evs := collect(events)
	if len(evs) == 0 {
		t.Fatal("expected events, got none")
	}
	last := evs[len(evs)-1]
	if last.Step != "pipeline" || last.Kind != EventFailed {
		t.Fatalf("expected the run to end with a pipeline EventFailed, got %+v", evs)
	}
	if last.Err == nil || !strings.Contains(last.Err.Error(), "interrupted") {
		t.Errorf("Err = %v, want it to mention interruption", last.Err)
	}
	if !hasKind(evs, "a", EventSatisfied) {
		t.Errorf("the last step itself completed and should report satisfied, got %+v", evs)
	}
}

func hasKind(evs []Event, step string, k EventKind) bool {
	for _, e := range evs {
		if e.Step == step && e.Kind == k {
			return true
		}
	}
	return false
}
