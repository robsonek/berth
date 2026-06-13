package version

import (
	"strings"
	"testing"
)

func TestStringContainsVersion(t *testing.T) {
	Version = "1.2.3"
	got := String()
	if !strings.Contains(got, "1.2.3") {
		t.Fatalf("String() = %q, want it to contain %q", got, "1.2.3")
	}
}
