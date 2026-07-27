package provision

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
	onCheck   func()       // invoked at the top of Check when non-nil (e.g. to cancel the run context)
	onApply   func(RunCtx) // invoked inside Apply when non-nil (e.g. to warn or observe the RunCtx)
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
func (s *stepStub) Apply(_ context.Context, rc RunCtx, _ *config.Server, _ bssh.Runner) error {
	if s.onApply != nil {
		s.onApply(rc)
	}
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

func TestEngineOnlyCancelDuringTransitivePrereqCheckStopsWalk(t *testing.T) {
	// Chain c → b → a. Cancellation lands during a's Check: the walk must stop
	// before b's Check (no further SSH probes) and return "interrupted" through
	// Run's pre-flight error — never a misleading "unmet prerequisites".
	ctx, cancel := context.WithCancel(context.Background())
	bChecked := false
	eng := New(
		&stepStub{name: "a", satisfied: true, onCheck: cancel},
		&stepStub{name: "b", satisfied: false, requires: []string{"a"}, checked: &bChecked},
		&stepStub{name: "c", requires: []string{"b"}},
	)
	events, err := eng.Run(ctx, &config.Server{}, bssh.NewFakeRunner(), Options{Only: "c"})
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("Run() error = %v, want pre-flight refusal mentioning interruption", err)
	}
	if strings.Contains(err.Error(), "unmet prerequisites") {
		t.Errorf("Run() error = %v, must not misreport cancellation as unmet prerequisites", err)
	}
	if events != nil {
		t.Error("events channel must be nil when pre-flight refuses")
	}
	if bChecked {
		t.Error("no further prerequisite Check may run after cancellation")
	}
}

func TestEngineOnlyMidRunCancelSkipsUnselectedAndFailsTrailing(t *testing.T) {
	// Cancellation mid-run under --only: the unselected step must never be
	// reported as interrupted (the ctx gate sits after the --only skip gate),
	// and a signal landing during the last selected step still surfaces as the
	// trailing "pipeline" EventFailed even though all work completed.
	// The unselected step comes AFTER the target, so the loop reaches it with
	// the ctx already cancelled — proving the gate ordering, not just timing.
	ctx, cancel := context.WithCancel(context.Background())
	eng := New(
		&stepStub{name: "b", satisfied: true, onCheck: cancel},
		&stepStub{name: "a", satisfied: true},
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

// findEvent returns the first event for step with kind k, or nil.
func findEvent(evs []Event, step string, k EventKind) *Event {
	for i := range evs {
		if evs[i].Step == step && evs[i].Kind == k {
			return &evs[i]
		}
	}
	return nil
}

func TestEngineAttachesWarningsToAppliedEvent(t *testing.T) {
	warner := &stepStub{name: "a", onApply: func(rc RunCtx) {
		rc.Warnf("first %d", 1)
		rc.Warnf("second")
	}}
	nextApplied := false
	eng := New(warner, &stepStub{name: "b", applied: &nextApplied})
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	evs := collect(events)
	ev := findEvent(evs, "a", EventApplied)
	if ev == nil {
		t.Fatalf("no EventApplied for a; events: %+v", evs)
	}
	if len(ev.Warnings) != 2 || ev.Warnings[0] != "first 1" || ev.Warnings[1] != "second" {
		t.Errorf("Warnings = %q, want [first 1, second] in emission order", ev.Warnings)
	}
	// A warning must never stop the pipeline.
	if !nextApplied {
		t.Error("pipeline must continue past a step that warned")
	}
	// Warnings belong to their step only: b applied without warning.
	if b := findEvent(evs, "b", EventApplied); b == nil || len(b.Warnings) != 0 {
		t.Errorf("step b must carry no warnings; got %+v", b)
	}
}

func TestEngineAttachesWarningsToFailedEvent(t *testing.T) {
	boom := errors.New("boom")
	eng := New(&stepStub{name: "a", applyErr: boom, onApply: func(rc RunCtx) {
		rc.Warnf("context before the failure")
	}})
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	ev := findEvent(collect(events), "a", EventFailed)
	if ev == nil {
		t.Fatal("no EventFailed for a")
	}
	if !errors.Is(ev.Err, boom) {
		t.Errorf("Err = %v, want boom", ev.Err)
	}
	if len(ev.Warnings) != 1 || ev.Warnings[0] != "context before the failure" {
		t.Errorf("Warnings = %q, want the pre-failure warning", ev.Warnings)
	}
}

func TestEngineWarningsDoNotBlockWithoutReader(t *testing.T) {
	// The channel buffer is sized so the engine NEVER blocks even when nobody
	// consumes (the TUI stops reading after ctrl+c). Warnings ride on the
	// terminal events instead of adding sends, so a warn-heavy pipeline must
	// still finish with no reader attached.
	done := make(chan struct{})
	warn := func(rc RunCtx) {
		for i := 0; i < 5; i++ {
			rc.Warnf("w%d", i)
		}
	}
	last := &stepStub{name: "c", onApply: func(rc RunCtx) { warn(rc); close(done) }}
	eng := New(
		&stepStub{name: "a", onApply: warn},
		&stepStub{name: "b", onApply: warn},
		last,
	)
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("engine blocked before finishing the pipeline with no reader draining events")
	}
	evs := collect(events)
	for _, step := range []string{"a", "b", "c"} {
		if ev := findEvent(evs, step, EventApplied); ev == nil || len(ev.Warnings) != 5 {
			t.Errorf("step %s: want 5 warnings on the applied event, got %+v", step, ev)
		}
	}
}

func TestEngineFullRunFlag(t *testing.T) {
	var sawFull, sawOnly *bool
	full := &stepStub{name: "a", onApply: func(rc RunCtx) { v := rc.FullRun; sawFull = &v }}
	eng := New(full)
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	collect(events)
	if sawFull == nil || !*sawFull {
		t.Error("FullRun must be true when no --only target is set")
	}

	only := &stepStub{name: "a", onApply: func(rc RunCtx) { v := rc.FullRun; sawOnly = &v }}
	eng = New(only)
	events, err = eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{Only: "a"})
	if err != nil {
		t.Fatalf("Run(--only) error = %v", err)
	}
	collect(events)
	if sawOnly == nil || *sawOnly {
		t.Error("FullRun must be false under --only")
	}
}

func TestRunCtxWarnfNilGuardAndNormalization(t *testing.T) {
	// Literal RunCtx{} (step unit tests, checkDependencies) must not panic.
	RunCtx{}.Warnf("ignored %d", 1)

	var got []string
	rc := RunCtx{Warn: func(msg string) { got = append(got, msg) }}
	// Validator stderr is often multi-line (nginx -t emits at least two lines);
	// the plain renderer's `warn  ` prefix contract needs one line per warning.
	rc.Warnf("line1\nline2\r\nline3\n")
	if len(got) != 1 || got[0] != "line1; line2; line3" {
		t.Errorf("Warnf normalization = %q, want %q", got, "line1; line2; line3")
	}
}
