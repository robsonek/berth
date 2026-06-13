package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/provision"
)

func feed(evs ...provision.Event) <-chan provision.Event {
	ch := make(chan provision.Event, len(evs))
	for _, e := range evs {
		ch <- e
	}
	close(ch)
	return ch
}

func TestPlainRendererPrintsStatuses(t *testing.T) {
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf)
	err := r.Render(feed(
		provision.Event{Step: "php", Kind: provision.EventStarted},
		provision.Event{Step: "php", Kind: provision.EventApplied},
		provision.Event{Step: "nginx", Kind: provision.EventSatisfied},
	))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "php") || !strings.Contains(out, "nginx") {
		t.Errorf("missing steps in output: %q", out)
	}
}

func TestPlainRendererSurfacesFailure(t *testing.T) {
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf)
	err := r.Render(feed(
		provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errors.New("dns not ready")},
	))
	if err == nil || !strings.Contains(err.Error(), "dns not ready") {
		t.Fatalf("expected failure surfaced, got %v", err)
	}
}
