package version

import "testing"

func TestParseRelease(t *testing.T) {
	for _, ok := range []string{"v1.0.0", "1.0.0", "v10.2.30", "0.0.0"} {
		if _, err := ParseRelease(ok); err != nil {
			t.Errorf("ParseRelease(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{"", "v1.0", "1.0", "v1.0.0-rc1", "v1.0.0-3-gabc1234",
		"latest", "v01.2.3", " v1.0.0", "V1.0.0", "v1.0.0-dirty"} {
		if _, err := ParseRelease(bad); err == nil {
			t.Errorf("ParseRelease(%q) accepted, want error", bad)
		}
	}
}

func TestParseBuild(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want string // String()
		base string
	}{
		{"0.36.0", true, "v0.36.0", "v0.36.0"},  // GoReleaser
		{"v0.35.0", true, "v0.35.0", "v0.35.0"}, // make build on a tag
		{"v0.36.0-dirty", true, "v0.36.0", "v0.36.0"},
		{"v0.36.0-3-ge363573", true, "v0.36.0-3-ge363573", "v0.36.0"},
		{"v0.36.0-3-ge363573-dirty", true, "v0.36.0-3-ge363573", "v0.36.0"},
		{"dev", false, "", ""},
		{"e363573", false, "", ""}, // --always without tags
		{"unknown", false, "", ""},
		{"", false, "", ""},
	}
	for _, c := range cases {
		v, ok := ParseBuild(c.in)
		if ok != c.ok || (ok && (v.String() != c.want || v.Base() != c.base)) {
			t.Errorf("ParseBuild(%q) = %+v,%v; want ok=%v String=%q Base=%q", c.in, v, ok, c.ok, c.want, c.base)
		}
	}
}

func TestCompare(t *testing.T) {
	mk := func(s string) V {
		v, ok := ParseBuild(s)
		if !ok {
			t.Fatalf("parse %q", s)
		}
		return v
	}
	if mk("0.36.0").Compare(mk("v0.36.0")) != 0 {
		t.Error("0.36.0 and v0.36.0 must be equal")
	}
	order := []string{"v0.9.0", "v0.10.0", "v0.36.0", "v0.36.0-3-gabc1234", "v0.36.0-12-gdef5678", "v1.0.0", "v2.0.0"}
	for i := 1; i < len(order); i++ {
		if mk(order[i-1]).Compare(mk(order[i])) >= 0 {
			t.Errorf("%s must sort before %s", order[i-1], order[i])
		}
	}
}

func TestBinary(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "1.0.0"
	if v, ok := Binary(); !ok || v.String() != "v1.0.0" {
		t.Errorf("Binary() = %v,%v", v, ok)
	}
	Version = "dev"
	if _, ok := Binary(); ok {
		t.Error("dev must be a development build")
	}
}
