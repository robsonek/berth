package ui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/robsonek/berth/internal/status"
)

func twoHosts() []status.HostStatus {
	a := hostFixture()
	b := hostFixture()
	b.ID = "staging"
	return []status.HostStatus{a, b}
}

func TestFleetModelCursorStaysInBounds(t *testing.T) {
	m := newFleetModel(twoHosts())
	m = m.move(-1)
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0 at the top", m.cursor)
	}
	m = m.move(1).move(1).move(1)
	if m.cursor != 1 {
		t.Errorf("cursor = %d, want 1 at the bottom", m.cursor)
	}
}

func TestFleetModelDetailShowsPerSiteFacts(t *testing.T) {
	m := newFleetModel(twoHosts()).toggleDetail()
	view := m.View()
	for _, want := range []string{"app.example.com", "letsencrypt", "203.0.113.10:22"} {
		if !strings.Contains(view, want) {
			t.Errorf("detail view missing %q:\n%s", want, view)
		}
	}
}

// The detail view is where an operator goes to understand a sick host, so a
// drift abort's reason and any partial probe failures must be rendered there —
// a reachable host with failed probes must not read as fully healthy.
func TestFleetModelDetailShowsDriftErrorAndProbeErrors(t *testing.T) {
	hosts := twoHosts()
	hosts[0].ProbeErrors = []string{"backups: exit 1: sudo denied"}
	hosts[0].Drift = &status.DriftReport{
		StoppedAt: "identity",
		Error:     "identity: endpoint mismatch: re-bind with --only identity --force",
	}
	view := newFleetModel(hosts).toggleDetail().View()
	for _, want := range []string{"--only identity --force", "sudo denied"} {
		if !strings.Contains(view, want) {
			t.Errorf("detail view missing %q:\n%s", want, view)
		}
	}
}

// Same single-render rule as the plain table: the OFFSITE line is the one
// place a failed query shows in the drill-down.
func TestFleetModelDetailRendersFailedOffsiteOnce(t *testing.T) {
	hosts := twoHosts()
	hosts[0].Offsite = &status.OffsiteStatus{Configured: true, Error: "restic could not read the repository"}
	hosts[0].ProbeErrors = []string{"offsite: restic could not read the repository"}
	view := newFleetModel(hosts).toggleDetail().View()
	if got := strings.Count(view, "could not read the repository"); got != 1 {
		t.Errorf("offsite failure must render exactly once, got %d:\n%s", got, view)
	}
	if !strings.Contains(view, "OFFSITE FAILED: restic could not read the repository") {
		t.Errorf("the surviving copy must be the OFFSITE line:\n%s", view)
	}
}

func TestFleetModelListViewShowsEveryHost(t *testing.T) {
	view := newFleetModel(twoHosts()).View()
	for _, want := range []string{"prod", "staging"} {
		if !strings.Contains(view, want) {
			t.Errorf("list view missing %q:\n%s", want, view)
		}
	}
}

func TestFleetModelRefreshMarksLoadingThenApplies(t *testing.T) {
	m := newFleetModel(twoHosts()).startLoading()
	if !m.loading {
		t.Fatal("refresh must mark the model loading")
	}
	if !strings.Contains(m.View(), "probing") {
		t.Errorf("a loading view must say so:\n%s", m.View())
	}
	one := twoHosts()[:1]
	m = m.applyResults(one)
	if m.loading {
		t.Error("results must clear the loading flag")
	}
	if len(m.hosts) != 1 {
		t.Errorf("hosts = %d, want 1", len(m.hosts))
	}
	// The cursor pointed at index 1, which no longer exists.
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want it clamped to 0 after a shorter refresh", m.cursor)
	}
}

// A slow earlier sweep must not overwrite a newer one. Without the generation
// guard, mashing `r` reverts the view to older data at random.
func TestFleetProgramDiscardsStaleResults(t *testing.T) {
	p := fleetProgram{model: newFleetModel(twoHosts()).startLoading()} // gen == 1
	stale := resultsMsg{gen: 0, hosts: nil}
	next, _ := p.Update(stale)
	got := next.(fleetProgram)
	if len(got.model.hosts) != 2 {
		t.Errorf("stale results were applied: %d hosts left", len(got.model.hosts))
	}
	if !got.model.loading {
		t.Error("a discarded stale result must not clear the loading flag")
	}
}

func TestFleetProgramIgnoresRefreshWhileLoading(t *testing.T) {
	calls := 0
	src := func(context.Context, bool) []status.HostStatus { calls++; return nil }
	p := fleetProgram{model: newFleetModel(twoHosts()).startLoading(), src: src, ctx: context.Background()}
	// This is the form internal/ui/tui_test.go:31 already uses — copy it
	// rather than inventing a literal.
	_, cmd := p.Update(tea.KeyPressMsg(tea.Key{Code: 'r'}))
	if cmd != nil {
		t.Error("a second sweep must not start while one is in flight")
	}
	if calls != 0 {
		t.Errorf("source called %d times, want 0", calls)
	}
}

// RunFleetTUI's return value drives the exit code, so it must be the model's
// CURRENT hosts, not the slice it was handed. Asserting on applyResults alone
// would still pass if the wrapper returned the original slice — so extract the
// projection RunFleetTUI performs and test THAT.
//
// Implementation note: give fleetProgram a `func (p fleetProgram) result()
// []status.HostStatus { return p.model.hosts }` and have RunFleetTUI call it,
// so this test covers the real path.
func TestFleetProgramResultIsTheRefreshedSlice(t *testing.T) {
	p := fleetProgram{model: newFleetModel(twoHosts()).startLoading()}
	fresh := []status.HostStatus{{ID: "only", Reachable: false, Error: "gone"}}
	next, _ := p.Update(resultsMsg{gen: p.model.gen, hosts: fresh})

	got := next.(fleetProgram).result()
	if len(got) != 1 || got[0].ID != "only" {
		t.Fatalf("result = %+v, want the refreshed slice", got)
	}
}
