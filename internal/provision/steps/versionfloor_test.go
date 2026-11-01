package steps

import (
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/templates"
	"github.com/robsonek/berth/internal/version"
)

func TestParseVersionFloor(t *testing.T) {
	ok := map[string]string{
		"# managed by berth\nVERSION=v0.37.0\n": "v0.37.0",
		"VERSION=0.37.0\r\n":                    "v0.37.0",
		"VERSION=v0.37.0  \t\n":                 "v0.37.0",
		"VERSION=v0.36.0-3-ge363573\n":          "v0.36.0-3-ge363573",
		"VERSION=v0.36.0\nVERSION=v0.99.0\n":    "v0.36.0", // first line wins
	}
	for in, want := range ok {
		if v, err := parseVersionFloor(in); err != nil || v.String() != want {
			t.Errorf("parseVersionFloor(%q) = %v,%v want %s", in, v, err, want)
		}
	}
	for _, bad := range []string{"", "VERSION=\n", "VERSION=dev\n", "garbage\n", "# managed by berth\n"} {
		if _, err := parseVersionFloor(bad); err == nil {
			t.Errorf("parseVersionFloor(%q) accepted", bad)
		}
	}
}

func TestDecideVersionFloor(t *testing.T) {
	bin, _ := version.ParseBuild("0.37.0")
	describe, _ := version.ParseBuild("v0.37.0-3-gabc1234")
	cases := []struct {
		name          string
		bin           version.V
		present       bool
		content, fail string
		allow         bool
		act           floorAction
		line, errSub  string
	}{
		{"absent", bin, false, "", "", false, floorRecord, "record version floor v0.37.0 in /var/lib/berth/version-floor", ""},
		{"older", bin, true, "VERSION=v0.36.0\n", "", false, floorRaise, "raise version floor v0.36.0 → v0.37.0", ""},
		{"equal", bin, true, "VERSION=v0.37.0\n", "", false, floorKeep, "", ""},
		{"equal-no-v", bin, true, "VERSION=0.37.0\n", "", false, floorKeep, "", ""},
		{"newer", bin, true, "VERSION=v0.38.0\n", "", false, 0, "", "host was last changed by berth v0.38.0, this binary is v0.37.0"},
		{"newer-allowed", bin, true, "VERSION=v0.38.0\n", "", true, floorLower, "lower version floor v0.38.0 → v0.37.0 (--allow-downgrade)", ""},
		{"empty-file", bin, true, "", "", false, 0, "", "unreadable or malformed"},
		{"malformed-allowed", bin, true, "junk\n", "", true, floorRewrite, "rewrite version floor as v0.37.0 (--allow-downgrade)", ""},
		{"cat-failed", bin, true, "", "Permission denied", false, 0, "", "unreadable or malformed (Permission denied"},
		{"cat-failed-allowed", bin, true, "", "Permission denied", true, floorRewrite, "rewrite version floor as v0.37.0 (--allow-downgrade)", ""},
		{"describe-over-tag", describe, true, "VERSION=v0.37.0\n", "", false, floorRaise, "raise version floor v0.37.0 → v0.37.0-3-gabc1234", ""},
		{"tag-under-describe", bin, true, "VERSION=v0.37.0-3-gabc1234\n", "", false, 0, "", "host was last changed by berth v0.37.0-3-gabc1234"},
	}
	// The advice names the command: `berth status --drift` surfaces the same
	// refusal and has no --allow-downgrade flag of its own.
	const advice = "re-run `berth provision` with --allow-downgrade"
	for _, c := range cases {
		act, line, err := decideVersionFloor(c.present, c.content, c.fail, c.bin, c.allow)
		switch {
		case c.errSub != "":
			if err == nil || !strings.Contains(err.Error(), c.errSub) || !strings.Contains(err.Error(), advice) || strings.Contains(err.Error(), "--force") {
				t.Errorf("%s: err = %v, want %q, %q and no mention of --force", c.name, err, c.errSub, advice)
			}
		case err != nil || act != c.act || line != c.line:
			t.Errorf("%s: got (%v, %q, %v), want (%v, %q)", c.name, act, line, err, c.act, c.line)
		}
	}
}

// Every future berth must read what this one writes (E5 stamp rule).
func TestVersionFloorPathAndFormatAreFrozen(t *testing.T) {
	if versionFloorPath != "/var/lib/berth/version-floor" {
		t.Fatalf("versionFloorPath = %q — frozen (README \"Version floors\", AGENTS.md \"Frozen surfaces\")", versionFloorPath)
	}
	v, _ := version.ParseBuild("0.37.0")
	body, err := templates.Render("version_floor.tmpl", struct{ Version string }{v.String()})
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "# managed by berth\nVERSION=v0.37.0\n" {
		t.Fatalf("rendered floor = %q", body)
	}
	if got, err := parseVersionFloor(string(body)); err != nil || got.Compare(v) != 0 {
		t.Fatalf("round-trip = %v, %v", got, err)
	}
}
