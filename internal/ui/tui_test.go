package ui

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/robsonek/berth/internal/provision"
)

func TestReducerTracksStatusesAndFailure(t *testing.T) {
	m := newStepModel()
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventStarted})
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventApplied})
	m = m.apply(provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errTest})

	if m.statuses["php"] != "applied" {
		t.Errorf("php status = %q, want applied", m.statuses["php"])
	}
	if !m.failed() {
		t.Error("model should record failure")
	}
	if m.err == nil {
		t.Error("failure error must be retained for Render's return")
	}
}

func TestUpdateCtrlCSetsInterruptedAndQuits(t *testing.T) {
	tm := teaModel{m: newStepModel()}
	next, cmd := tm.Update(tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	got := next.(teaModel)
	if !errors.Is(got.m.err, ErrInterrupted) {
		t.Errorf("err = %v, want ErrInterrupted", got.m.err)
	}
	if cmd == nil {
		t.Error("ctrl+c must quit the program")
	}
}

func TestUpdateCtrlCKeepsStepFailure(t *testing.T) {
	m := newStepModel()
	m = m.apply(provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errTest})
	tm := teaModel{m: m}
	next, _ := tm.Update(tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	if got := next.(teaModel).m.err; !errors.Is(got, errTest) {
		t.Errorf("err = %v, want the original step failure %v", got, errTest)
	}
}

var errTest = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }

func TestReducerCollectsWarningsWithoutChangingStatus(t *testing.T) {
	m := newStepModel()
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventStarted})
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventApplied,
		Warnings: []string{"reload deferred to site"}})

	if m.statuses["php"] != "applied" {
		t.Errorf("php status = %q, want applied (a warning must not change it)", m.statuses["php"])
	}
	if m.failed() {
		t.Error("a warning must not mark the run failed")
	}
	view := m.view()
	if !strings.Contains(view, "⚠ php: reload deferred to site") {
		t.Errorf("view must show the warning; got:\n%s", view)
	}

	// No warnings → no warning block at all.
	clean := newStepModel().apply(provision.Event{Step: "php", Kind: provision.EventApplied})
	if strings.Contains(clean.view(), "⚠") {
		t.Errorf("view must not show a warning marker without warnings:\n%s", clean.view())
	}
}
