package wizard

import "testing"

func TestParseIntInRange(t *testing.T) {
	cases := []struct {
		s       string
		lo, hi  int
		want    int
		wantErr bool
	}{
		{"22", 1, 65535, 22, false},
		{" 5 ", 1, 100, 5, false},
		{"x", 1, 100, 0, true},
		{"0", 1, 100, 0, true},
		{"101", 1, 100, 0, true},
	}
	for _, c := range cases {
		got, err := parseIntInRange("field", c.s, c.lo, c.hi)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("parseIntInRange(%q,%d,%d) = (%d,%v), want (%d,err=%v)", c.s, c.lo, c.hi, got, err, c.want, c.wantErr)
		}
	}
}

func TestInlineValidators(t *testing.T) {
	if validHostname("host")("bad host!") == nil {
		t.Error("hostname validator accepted spaces")
	}
	if validHostname("host")("203.0.113.10") != nil {
		t.Error("hostname validator rejected an IP")
	}
	if validSQLIdent("db")("1bad") == nil {
		t.Error("sql ident validator accepted a leading digit")
	}
	if validDeployPath("rel/path") == nil {
		t.Error("deploy path validator accepted a relative path")
	}
	if validDeployPath("/srv/ok") != nil {
		t.Error("deploy path validator rejected a clean absolute path")
	}
	ssl, mode := true, "letsencrypt"
	if validTLSEmail(&ssl, &mode)("") == nil {
		t.Error("tls email validator accepted empty for letsencrypt")
	}
	ss := "selfsigned"
	if validTLSEmail(&ssl, &ss)("") != nil {
		t.Error("tls email validator should skip self-signed")
	}
	if validIntField("port", 1, 65535)("70000") == nil {
		t.Error("int field validator accepted out-of-range")
	}
	if validOSUser("") != nil {
		t.Error("validOSUser rejected blank")
	}
	if validOSUser("onee-sync") != nil {
		t.Error("validOSUser rejected a valid hyphenated name")
	}
	if validOSUser("Bad User") == nil {
		t.Error("validOSUser accepted spaces/uppercase")
	}
}

func TestOptionalSwapSize(t *testing.T) {
	for _, ok := range []string{"", "2G", "512M", "1g", "16m"} {
		if err := optionalSwapSize(ok); err != nil {
			t.Errorf("optionalSwapSize(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"2", "2GB", "0G", "G", "2T", "-1G", "2 G"} {
		if err := optionalSwapSize(bad); err == nil {
			t.Errorf("optionalSwapSize(%q) = nil, want error", bad)
		}
	}
}

func TestOptionalCronSchedule(t *testing.T) {
	for _, ok := range []string{"", "30 3 * * *", "*/15 * * * *", "0 2 * * 0"} {
		if err := optionalCronSchedule(ok); err != nil {
			t.Errorf("optionalCronSchedule(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"30 3 * *", "30 3 * * * *", "30 3 * * mon", "30 3 * * *\nroot id"} {
		if err := optionalCronSchedule(bad); err == nil {
			t.Errorf("optionalCronSchedule(%q) = nil, want error", bad)
		}
	}
}
