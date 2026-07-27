package secret

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateLengthAndCharset(t *testing.T) {
	p, err := Generate(32)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(p) != 32 {
		t.Errorf("len = %d, want 32", len(p))
	}
	if strings.ContainsAny(p, " /+=\n") {
		t.Errorf("password %q contains shell/url-unsafe characters", p)
	}
}

func TestGenerateUnique(t *testing.T) {
	a, _ := Generate(24)
	b, _ := Generate(24)
	if a == b {
		t.Error("two generated passwords should differ")
	}
}

func TestAppKey(t *testing.T) {
	k, err := AppKey()
	if err != nil {
		t.Fatalf("AppKey() error = %v", err)
	}
	if !strings.HasPrefix(k, "base64:") {
		t.Fatalf("APP_KEY %q must carry the base64: prefix", k)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(k, "base64:"))
	if err != nil {
		t.Fatalf("APP_KEY payload is not valid base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("APP_KEY decodes to %d bytes, want 32 (AES-256)", len(raw))
	}
	if k2, _ := AppKey(); k == k2 {
		t.Error("AppKey() must be random per call")
	}
}

func TestRedactorMasksRegisteredSecrets(t *testing.T) {
	r := NewRedactor()
	r.Add("s3cr3t-pw")
	got := r.Apply("mysql -p s3cr3t-pw -e ...")
	if strings.Contains(got, "s3cr3t-pw") {
		t.Errorf("redacted output still contains the secret: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("expected mask in %q", got)
	}
}

func TestRedactorIgnoresEmpty(t *testing.T) {
	r := NewRedactor()
	r.Add("")
	if got := r.Apply("hello"); got != "hello" {
		t.Errorf("empty secret should be a no-op, got %q", got)
	}
}

func TestRedactorPrefixOrderingAndSafety(t *testing.T) {
	r := NewRedactor()
	r.Add("abc")    // shorter first — the historical shredding order
	r.Add("abcdef") // longer must still win
	r.Add("abcdef") // duplicate dropped
	if got := r.Apply("x abcdef y abc z"); got != "x *** y *** z" {
		t.Errorf("Apply = %q, want longest-first masking", got)
	}
	var nilR *Redactor
	nilR.Add("boom") // must not panic
	if got := nilR.Apply("boom"); got != "boom" {
		t.Errorf("typed-nil Apply must be a no-op; got %q", got)
	}
}

func TestRedactorConcurrentAddApply(t *testing.T) {
	// Add (steps, engine goroutine) can overlap Apply (command boundary after
	// a TUI quit) — must be race-free under -race.
	r := NewRedactor()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			r.Add(strings.Repeat("s", i%17+1))
		}
		close(done)
	}()
	for i := 0; i < 200; i++ {
		_ = r.Apply("sssssss payload")
	}
	<-done
}
