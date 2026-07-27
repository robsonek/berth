package wizard

import (
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

func TestGenerateServerID(t *testing.T) {
	cases := []struct{ name, wantPrefix string }{
		{"smoke", "smoke-"},
		{"My Server!", "my-server-"},
		{"  ..--  ", ""}, // nothing usable -> bare hex
		{strings.Repeat("x", 100), strings.Repeat("x", 55) + "-"},
	}
	for _, c := range cases {
		got, err := GenerateServerID(c.name)
		if err != nil {
			t.Fatalf("%q: %v", c.name, err)
		}
		if !strings.HasPrefix(got, c.wantPrefix) {
			t.Errorf("GenerateServerID(%q) = %q, want prefix %q", c.name, got, c.wantPrefix)
		}
		if len(got) < 2 || len(got) > 64 {
			t.Errorf("id %q length out of range", got)
		}
		// Must satisfy the authoritative config validator.
		if err := config.ValidateServerID(got); err != nil {
			t.Errorf("generated id %q fails the authoritative validator: %v", got, err)
		}
		a := Answers{ID: got}
		if srv := a.ToServer(); srv.ID != got {
			t.Errorf("ToServer must carry the id; got %q", srv.ID)
		}
	}
	a, err := GenerateServerID("same")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateServerID("same")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated ids for the same name must differ (random suffix)")
	}
}
