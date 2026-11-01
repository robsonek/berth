package config

import (
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/version/versiontest"
)

func TestLoadRequiresBerthMissing(t *testing.T) {
	body := strings.Replace(baseCfg, "requires_berth: v0.37.0\n", "", 1)
	versiontest.Set(t, "0.37.0")
	_, err := Load(writeTmpConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "requires_berth is missing") ||
		!strings.Contains(err.Error(), `"requires_berth: v0.37.0"`) {
		t.Fatalf("err = %v, want the missing-key error suggesting this binary's version", err)
	}
	versiontest.Set(t, "dev")
	if _, err := Load(writeTmpConfig(t, body)); err == nil || !strings.Contains(err.Error(), "requires_berth is missing") {
		t.Fatalf("dev build: err = %v, the key stays required", err)
	}
}

func TestLoadRequiresBerthMalformed(t *testing.T) {
	for _, raw := range []string{"0.37", "1", "v0.37", "v0.37.0-rc1", "v0.37.0-3-gabc1234", "latest", `" v0.37.0"`} {
		body := strings.Replace(baseCfg, "requires_berth: v0.37.0", "requires_berth: "+raw, 1)
		if _, err := Load(writeTmpConfig(t, body)); err == nil || !strings.Contains(err.Error(), "is not a release version") {
			t.Errorf("requires_berth: %s → err = %v, want the format error", raw, err)
		}
	}
}

func TestLoadRequiresBerthTooOld(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	body := strings.Replace(baseCfg, "requires_berth: v0.37.0", "requires_berth: v0.38.0", 1)
	_, err := Load(writeTmpConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "requires berth >= v0.38.0, this binary is v0.37.0") {
		t.Fatalf("err = %v", err)
	}
}

// The point of checking before UnmarshalExact: a config written for a newer
// berth names keys this binary does not know — the operator must read
// "upgrade", not "invalid keys".
func TestLoadRequiresBerthWinsOverUnknownKey(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	body := strings.Replace(baseCfg, "requires_berth: v0.37.0", "requires_berth: v0.38.0", 1) + "future_knob: true\n"
	_, err := Load(writeTmpConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "requires berth >= v0.38.0") || strings.Contains(err.Error(), "invalid keys") {
		t.Fatalf("err = %v, want the version error, not the strict-decode one", err)
	}
}

func TestLoadRequiresBerthAcceptsOlderAndEqual(t *testing.T) {
	for bin, reqs := range map[string][]string{
		"0.37.0":                   {"v0.36.0", "0.37.0", "v0.37.0"},
		"v0.37.0-3-gabc1234-dirty": {"v0.37.0"},
	} {
		versiontest.Set(t, bin)
		for _, req := range reqs {
			body := strings.Replace(baseCfg, "requires_berth: v0.37.0", "requires_berth: "+req, 1)
			if _, err := Load(writeTmpConfig(t, body)); err != nil {
				t.Errorf("binary %s, requires_berth %s: %v", bin, req, err)
			}
		}
	}
}

func TestLoadRequiresBerthDevSkipsComparison(t *testing.T) {
	versiontest.Set(t, "dev")
	body := strings.Replace(baseCfg, "requires_berth: v0.37.0", "requires_berth: v9.9.9", 1)
	if _, err := Load(writeTmpConfig(t, body)); err != nil {
		t.Fatalf("dev build must skip the comparison: %v", err)
	}
}

func TestValidateRequiresBerthIsFormatOnly(t *testing.T) {
	// Same minimal literal as TestServerYAMLOmitsEmptyOptionalFields.
	s := &Server{
		ID:   "test-machine-0001",
		Host: "h.example", SSH: SSH{User: "root", Port: 22, Key: "~/.ssh/id_ed25519"},
		PHP: PHP{Version: "8.5", Source: "auto"}, Nginx: Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Source: "debian"},
		Sites:    []Site{{Domain: "a.example", DeployPath: "/srv/a", Database: SiteDatabase{Name: "app", User: "app"}}},
	}
	if err := s.Validate(); err != nil {
		t.Errorf("empty requires_berth must pass Validate (presence is Load's job): %v", err)
	}
	s.RequiresBerth = "v0.37"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "requires_berth") {
		t.Errorf("malformed requires_berth must fail Validate: %v", err)
	}
}
