package wizard

import (
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

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

func TestValidDeployPathMatchesConfigRules(t *testing.T) {
	// The wizard field validator must refuse exactly what config.Load refuses,
	// so the operator learns at the field, not at the final ToServer error.
	for _, bad := range []string{"/etc/nginx", "/home/deploy/app", "/var/www/app/", "/app", "/var/www", "/var/lib/app"} {
		if err := validDeployPath(bad); err == nil {
			t.Errorf("validDeployPath(%q) = nil, want error", bad)
		}
	}
	if err := validDeployPath("/var/www/app"); err != nil {
		t.Errorf("validDeployPath(/var/www/app) = %v, want nil", err)
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

func TestOptionalTimezone(t *testing.T) {
	for _, ok := range []string{"", "UTC", "Europe/Warsaw", "Etc/GMT+8", "America/Argentina/Buenos_Aires"} {
		if err := optionalTimezone(ok); err != nil {
			t.Errorf("optionalTimezone(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"Europe/Warsaw; rm -rf /", "../etc/passwd", "Europe Warsaw", "/Europe", "A/B/C/D"} {
		if err := optionalTimezone(bad); err == nil {
			t.Errorf("optionalTimezone(%q) expected error, got nil", bad)
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

// TestParseIntInRangeTrims locks the trim behavior that ServerOps' retention
// conversion relies on: an accepted " 14 " must yield 14 (not be silently dropped
// to 0/default), while blank/"0"/out-of-range return (0, err) so a `, _ =` caller
// keeps 0 = "use default".
func TestParseIntInRangeTrims(t *testing.T) {
	if n, err := parseIntInRange("retention", " 14 ", 1, 3650); err != nil || n != 14 {
		t.Errorf("parseIntInRange(\" 14 \") = (%d, %v), want (14, nil)", n, err)
	}
	if n, err := parseIntInRange("retention", "", 1, 3650); err == nil || n != 0 {
		t.Errorf("parseIntInRange(\"\") = (%d, %v), want (0, error)", n, err)
	}
	if n, err := parseIntInRange("retention", "0", 1, 3650); err == nil || n != 0 {
		t.Errorf("parseIntInRange(\"0\") = (%d, %v), want (0, error)", n, err)
	}
}

func TestOptionalPHPSize(t *testing.T) {
	for _, ok := range []string{"", "256M", "32m", "1G", "512k", "134217728", "64G"} {
		if err := optionalPHPSize(ok); err != nil {
			t.Errorf("optionalPHPSize(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "-1", "08M", "010M", "256MB", "1.5G", "abc", "64M; rm -rf /", "65G", "18446744073709551615", "99999999999999999999"} {
		if err := optionalPHPSize(bad); err == nil {
			t.Errorf("optionalPHPSize(%q) expected error, got nil", bad)
		}
	}
}

func TestHasControlChars(t *testing.T) {
	for _, ctl := range []string{"\x00", "a\nb", "a\rb", "a\tb", "\x1f", "\x7f"} {
		if !hasControlChars(ctl) {
			t.Errorf("hasControlChars(%q) = false, want true", ctl)
		}
	}
	for _, ok := range []string{"", "plain-word", "a b", "\x7e", "s3.example.com"} {
		if hasControlChars(ok) {
			t.Errorf("hasControlChars(%q) = true, want false", ok)
		}
	}
}

func TestOffsiteWord(t *testing.T) {
	for _, ok := range []string{"s3.example.com", "bkt", "berth/custom", "a.b-c_d"} {
		if err := offsiteWord("f", true)(ok); err != nil {
			t.Errorf("offsiteWord(required)(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "two words", "tab\tsep", "qu'ote", `qu"ote`, `back\slash`, "ctl\nchar", "del\x7fchar"} {
		if err := offsiteWord("f", true)(bad); err == nil {
			t.Errorf("offsiteWord(required)(%q) = nil, want error", bad)
		}
	}
	// Optional variant: blank is the only extra acceptance.
	if err := offsiteWord("f", false)(""); err != nil {
		t.Errorf("offsiteWord(optional)(\"\") = %v, want nil", err)
	}
	if err := offsiteWord("f", false)("two words"); err == nil {
		t.Error("offsiteWord(optional)(\"two words\") = nil, want error")
	}
}

func TestValidOffsiteHost(t *testing.T) {
	for _, ok := range []string{"backup.example.com", "203.0.113.10", "b"} {
		if err := validOffsiteHost(ok); err != nil {
			t.Errorf("validOffsiteHost(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "Backup.example.com", "h|e", "-x.example.com", "x-", "bad host", "host;id", "host'quote"} {
		if err := validOffsiteHost(bad); err == nil {
			t.Errorf("validOffsiteHost(%q) = nil, want error", bad)
		}
	}
}

func TestValidOffsitePath(t *testing.T) {
	for _, ok := range []string{"/srv/restic", "/x"} {
		if err := validOffsitePath(ok); err != nil {
			t.Errorf("validOffsitePath(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "relative/path", "/pa th", "/pa'th", `/pa\th`, "/pa\nth"} {
		if err := validOffsitePath(bad); err == nil {
			t.Errorf("validOffsitePath(%q) = nil, want error", bad)
		}
	}
}

func TestValidOffsiteHostKey(t *testing.T) {
	// Both canonical token forms: bare host (port 22/0) and [host]:port.
	for _, token := range []string{"backup.example.com", "[backup.example.com]:2222"} {
		v := validOffsiteHostKey(token)
		for _, ok := range []string{
			token + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExample",
			token + " ssh-rsa AAAAB3NzaExample comment@host", // trailing comment field is fine
		} {
			if err := v(ok); err != nil {
				t.Errorf("validOffsiteHostKey(%q)(%q) = %v, want nil", token, ok, err)
			}
		}
		for _, bad := range []string{
			"",
			token + " ssh-ed25519", // two fields
			"other.example.com ssh-ed25519 AAAAExample", // wrong pinned token
			token + " ssh-ed25519 AAAA'Example",         // quote
			token + " ssh-ed25519 AAAA\nExample",        // control char
		} {
			if err := v(bad); err == nil {
				t.Errorf("validOffsiteHostKey(%q)(%q) = nil, want error", token, bad)
			}
		}
	}
	// Cross-form: a bare-host first field must not satisfy a bracket token and
	// vice versa (the port decides which token config demands).
	if err := validOffsiteHostKey("[backup.example.com]:2222")("backup.example.com ssh-ed25519 AAAAExample"); err == nil {
		t.Error("bare-host key line accepted against a [host]:port token")
	}
	if err := validOffsiteHostKey("backup.example.com")("[backup.example.com]:2222 ssh-ed25519 AAAAExample"); err == nil {
		t.Error("[host]:port key line accepted against a bare-host token")
	}
}

// offsiteConfigVerdict runs config.Server.Validate over a known-valid baseline
// server carrying the given offsite block, so the only possible failure is the
// offsite field under test.
func offsiteConfigVerdict(t *testing.T, o config.Offsite) error {
	t.Helper()
	a := defaults()
	a.Name, a.Host = "drift", "203.0.113.10"
	a.ID = "test-machine-0001"
	a.Backups = BackupsAnswers{Enabled: true}
	a.Sites = []SiteAnswers{{Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr"}}
	srv := a.ToServer()
	srv.Backups.Offsite = &o
	return srv.Validate()
}

// TestOffsiteMirrorsMatchConfigRules is the drift guard for the offsite mirror
// validators: ServerOps has no re-prompt loop, so a mirror that ever drifts
// LOOSER than config would trap the operator at the final Write/Load instead
// of at the field. Each case feeds the SAME value through the wizard mirror
// and config.Server.Validate and asserts the accept/reject verdicts agree
// (mirror of TestValidDeployPathMatchesConfigRules).
func TestOffsiteMirrorsMatchConfigRules(t *testing.T) {
	agree := func(t *testing.T, field, value string, cfg, mirror error) {
		t.Helper()
		if (cfg == nil) != (mirror == nil) {
			t.Errorf("%s %q: config=%v mirror=%v — verdicts drifted", field, value, cfg, mirror)
		}
	}

	// s3 word fields (endpoint required, prefix optional) over the injection
	// alphabet config's plain() rejects.
	s3Base := config.Offsite{Backend: "s3", Endpoint: "s3.example.com", Bucket: "bkt"}
	wordCases := []string{"s3.example.com", "a.b-c_d", "berth/custom", "", "two words", "tab\tsep", "qu'ote", `qu"ote`, `back\slash`, "ctl\nchar", "del\x7fchar"}
	for _, v := range wordCases {
		o := s3Base
		o.Endpoint = v
		agree(t, "endpoint", v, offsiteConfigVerdict(t, o), offsiteWord("backups.offsite.endpoint", true)(v))
		o = s3Base
		o.Prefix = v
		agree(t, "prefix", v, offsiteConfigVerdict(t, o), offsiteWord("backups.offsite.prefix", false)(v))
	}

	// sftp host/path. The host key is re-derived from the candidate host so the
	// only verdict-flipping rule left is the one under test.
	sftpBase := func(host string, port int) config.Offsite {
		o := config.Offsite{Backend: "sftp", Host: host, Port: port, User: "restic", Path: "/srv/restic"}
		o.HostKey = o.KnownHostsToken() + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExample"
		return o
	}
	for _, v := range []string{"backup.example.com", "203.0.113.10", "b", "", "Backup.example.com", "h|e", "-x.example.com", "x-", "bad host", "host;id"} {
		agree(t, "host", v, offsiteConfigVerdict(t, sftpBase(v, 0)), validOffsiteHost(v))
	}
	for _, v := range []string{"/srv/restic", "/x", "", "relative/path", "/pa th", "/pa'th", `/pa\th`} {
		o := sftpBase("backup.example.com", 0)
		o.Path = v
		agree(t, "path", v, offsiteConfigVerdict(t, o), validOffsitePath(v))
	}

	// host_key against both canonical token forms (bare host for port 22/0,
	// [host]:port otherwise) — including the cross-form lines, which only one
	// of the two ports may accept.
	for _, port := range []int{0, 2222} {
		base := sftpBase("backup.example.com", port)
		token := (&config.Offsite{Host: "backup.example.com", Port: port}).KnownHostsToken()
		for _, v := range []string{
			token + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExample",
			token + " ssh-rsa AAAAB3NzaExample comment@host",
			token + " ssh-ed25519",
			"other.example.com ssh-ed25519 AAAAExample",
			token + " ssh-ed25519 AAAA'Example",
			token + " ssh-ed25519 AAAA\nExample",
			"",
			"backup.example.com ssh-ed25519 AAAAExample",
			"[backup.example.com]:2222 ssh-ed25519 AAAAExample",
		} {
			o := base
			o.HostKey = v
			agree(t, "host_key", v, offsiteConfigVerdict(t, o), validOffsiteHostKey(token)(v))
		}
	}
}

func TestOptionalSystemHostname(t *testing.T) {
	for _, ok := range []string{"", "web1", "web-1.example.com"} {
		if err := optionalSystemHostname(ok); err != nil {
			t.Errorf("optionalSystemHostname(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"bad host",
		"-x.example.com",
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 32), // 65 chars, over HOST_NAME_MAX
	} {
		if err := optionalSystemHostname(bad); err == nil {
			t.Errorf("optionalSystemHostname(%q) = nil, want error", bad)
		}
	}
}
