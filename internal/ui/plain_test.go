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
	r := NewPlainRenderer(&buf, false)
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
	r := NewPlainRenderer(&buf, false)
	err := r.Render(feed(
		provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errors.New("dns not ready")},
	))
	if err == nil || !strings.Contains(err.Error(), "dns not ready") {
		t.Fatalf("expected failure surfaced, got %v", err)
	}
}

func TestPlainRendererVerbosePrintsReasonAndChanges(t *testing.T) {
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf, true)
	if err := r.Render(feed(
		provision.Event{Step: "php", Kind: provision.EventSatisfied, Reason: "php8.4-fpm installed"},
		provision.Event{Step: "site", Kind: provision.EventApplied, Changes: []string{"write vhost", "reload nginx"}},
		provision.Event{Step: "database", Kind: provision.EventApplied, Sensitive: true, Changes: []string{"seed shared/.env"}},
	)); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"ok    php (already): php8.4-fpm installed",
		"apply site",
		"      + write vhost",
		"      + reload nginx",
		"      + [redacted]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "seed shared/.env") {
		t.Errorf("sensitive changes must be redacted in verbose output; got:\n%s", out)
	}
}

func TestPlainRendererNonVerboseOutputIsByteStable(t *testing.T) {
	// The plain renderer's non-verbose lines are a parseable contract (CI,
	// pipes); the verbose mode must not change them — for ANY event kind
	// (planned and failed included; Codex plan-review finding #13).
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf, false)
	err := r.Render(feed(
		provision.Event{Step: "php", Kind: provision.EventSatisfied, Reason: "php8.4-fpm installed"},
		provision.Event{Step: "site", Kind: provision.EventApplied, Changes: []string{"write vhost"}},
		provision.Event{Step: "database", Kind: provision.EventPlanned, Sensitive: true, Changes: []string{"seed shared/.env"}},
		provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errors.New("dns not ready")},
	))
	if err == nil || err.Error() != "dns not ready" {
		t.Fatalf("Render() error = %v, want the surfaced failure", err)
	}
	want := "ok    php (already)\napply site\nplan  database: [[redacted]]\nFAIL  tls: dns not ready\n"
	if got := buf.String(); got != want {
		t.Errorf("non-verbose output changed:\ngot  %q\nwant %q", got, want)
	}
}

func TestPlainRendererPrintsWarnings(t *testing.T) {
	// Warnings ride on the terminal event; each becomes one stable `warn  `
	// line right after the step's terminal line, in both verbose modes.
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf, false)
	err := r.Render(feed(
		provision.Event{Step: "php", Kind: provision.EventApplied,
			Warnings: []string{"unit validation failed outside berth's drop-ins; reload deferred to site"}},
		provision.Event{Step: "site", Kind: provision.EventFailed,
			Warnings: []string{"collected before the failure"}, Err: errors.New("nginx -t failed")},
	))
	if err == nil || err.Error() != "nginx -t failed" {
		t.Fatalf("Render() error = %v, want the surfaced failure", err)
	}
	want := "apply php\n" +
		"warn  php: unit validation failed outside berth's drop-ins; reload deferred to site\n" +
		"FAIL  site: nginx -t failed\n" +
		"warn  site: collected before the failure\n"
	if got := buf.String(); got != want {
		t.Errorf("warning output:\ngot  %q\nwant %q", got, want)
	}
	// A warning alone must never turn into a failure exit.
	var buf2 bytes.Buffer
	if err := NewPlainRenderer(&buf2, true).Render(feed(
		provision.Event{Step: "php", Kind: provision.EventApplied, Warnings: []string{"w"}},
	)); err != nil {
		t.Errorf("warnings must not fail the run: %v", err)
	}
	if !strings.Contains(buf2.String(), "warn  php: w") {
		t.Errorf("verbose mode must print warnings too; got %q", buf2.String())
	}
}
