package ui

import (
	"errors"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/robsonek/berth/internal/provision"
)

func TestReducerTracksStatusesAndFailure(t *testing.T) {
	m := newStepModel()
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventStarted})
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventApplied})
	m = m.apply(provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errTest})

	if m.status("php") != "applied" {
		t.Errorf("php status = %q, want applied", m.status("php"))
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
	if got := next.(teaModel).m.err; got != errTest {
		t.Errorf("err = %v, want the original step failure %v", got, errTest)
	}
}

var errTest = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }
