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
