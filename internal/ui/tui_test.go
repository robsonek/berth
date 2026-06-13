package ui

import (
	"testing"

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

var errTest = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }
