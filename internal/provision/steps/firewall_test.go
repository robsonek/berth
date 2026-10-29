package steps

import (
	"reflect"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

// ufwShowAddedProd is the exact `sudo ufw show added` output of a host
// provisioned by berth v0.35.0 (ufw 0.36.2, Debian 13): the text header, then
// one line per rule with IPv4/IPv6 twins collapsed, no comments on berth's
// built-in rules.
const ufwShowAddedProd = "Added user rules (see 'ufw status' for running firewall):\n" +
	"ufw allow 22/tcp\n" +
	"ufw allow 80,443/tcp\n" +
	"ufw allow 443/udp\n"

// ufwStatusProd is the matching `sudo ufw status` output, trailing column
// padding included — the only thing berth reads from it is the first line.
const ufwStatusProd = "Status: active\n\n" +
	"To                         Action      From\n" +
	"--                         ------      ----\n" +
	"22/tcp                     ALLOW       Anywhere                  \n" +
	"80,443/tcp                 ALLOW       Anywhere                  \n" +
	"443/udp                    ALLOW       Anywhere                  \n" +
	"22/tcp (v6)                ALLOW       Anywhere (v6)             \n" +
	"80,443/tcp (v6)            ALLOW       Anywhere (v6)             \n" +
	"443/udp (v6)               ALLOW       Anywhere (v6)\n"

func TestUfwAddedRulesFrame(t *testing.T) {
	out := ufwShowAddedProd +
		"ufw allow 5432/tcp comment 'ops'\n" +
		"ufw allow 10050/tcp comment 'berth:zabbix'\n" +
		"ufw allow from 203.0.113.0/24 to any port 9100 proto tcp comment 'berth:node-exporter'\n" +
		"ufw allow 8/tcp comment 'x berth:y'\n"
	cmds, err := ufwAddedRules(out)
	if err != nil {
		t.Fatalf("ufwAddedRules(valid) error = %v", err)
	}
	want := []string{
		"allow 22/tcp", "allow 80,443/tcp", "allow 443/udp",
		"allow 5432/tcp comment 'ops'",
		"allow 10050/tcp comment 'berth:zabbix'",
		"allow from 203.0.113.0/24 to any port 9100 proto tcp comment 'berth:node-exporter'",
		"allow 8/tcp comment 'x berth:y'",
	}
	if !reflect.DeepEqual(cmds, want) {
		t.Errorf("ufwAddedRules = %q, want %q", cmds, want)
	}
	none, err := ufwAddedRules(ufwAddedHeader + "\n(None)\n")
	if err != nil || len(none) != 0 {
		t.Errorf("ufwAddedRules((None)) = %q, %v; want none, nil", none, err)
	}
	for name, bad := range map[string]string{
		"empty output":            "",
		"header only":             ufwAddedHeader + "\n",
		"other header":            "Added rules:\nufw allow 22/tcp\n",
		"line without prefix":     ufwAddedHeader + "\nufw allow 22/tcp\nname'\n",
		"newline inside comment":  ufwAddedHeader + "\nufw allow 22/tcp comment 'berth:bad\nname'\n",
		"comment without closing": ufwAddedHeader + "\nufw allow 22/tcp comment 'berth:x\n",
		"(None) beside a rule":    ufwAddedHeader + "\n(None)\nufw allow 22/tcp\n",
	} {
		if got, err := ufwAddedRules(bad); err == nil {
			t.Errorf("ufwAddedRules(%s) = %q, want an error (fail closed)", name, got)
		}
	}
}

func TestUfwOwnedRules(t *testing.T) {
	cmds := []string{
		"allow 22/tcp", "allow 80,443/tcp",
		"allow 5432/tcp comment 'ops'",
		"allow 10050/tcp comment 'berth:zabbix'",
		"allow from 203.0.113.0/24 to any port 9100 proto tcp comment 'berth:node-exporter'",
		"allow 8/tcp comment 'x berth:y'",
	}
	owned, err := ufwOwnedRules(cmds)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"zabbix":        {"allow 10050/tcp comment 'berth:zabbix'"},
		"node-exporter": {"allow from 203.0.113.0/24 to any port 9100 proto tcp comment 'berth:node-exporter'"},
	}
	if !reflect.DeepEqual(owned, want) {
		t.Errorf("ufwOwnedRules = %q, want %q (foreign 'ops', built-ins and 'x berth:y' must stay out)", owned, want)
	}
	// A berth: comment on a shape berth never writes is not berth's to delete:
	// ufw would expand an application profile without the comment and refuses
	// `delete route …` — refuse loudly instead of sweeping or ignoring.
	for _, foreign := range []string{
		"allow ExampleApp comment 'berth:app'",
		"route allow 10050/tcp comment 'berth:r'",
		"allow in on eth0 to any port 10050 proto tcp comment 'berth:i'",
		"deny 10050/tcp comment 'berth:d'",
		"allow 10050/tcp comment 'berth:Zabbix'",
		"allow from 203.0.113.10 port 1 to any port 10050 proto tcp comment 'berth:sport'",
	} {
		if _, err := ufwOwnedRules([]string{foreign}); err == nil || !strings.Contains(err.Error(), "berth's comment") {
			t.Errorf("ufwOwnedRules(%q) error = %v, want a refusal naming berth's comment", foreign, err)
		}
	}
	if c, ok := ufwRuleComment("allow 22/tcp"); ok || c != "" {
		t.Errorf("ufwRuleComment(no comment) = %q, %v; want \"\", false", c, ok)
	}
	if c, ok := ufwRuleComment("allow 22/tcp comment 'berth:ssh'"); !ok || c != "berth:ssh" {
		t.Errorf("ufwRuleComment = %q, %v; want berth:ssh, true", c, ok)
	}
	if bare, had := ufwBare("allow 9100/tcp comment 'x'"); bare != "allow 9100/tcp" || !had {
		t.Errorf("ufwBare = %q, %v", bare, had)
	}
	if bare, had := ufwBare("allow 9100/tcp"); bare != "allow 9100/tcp" || had {
		t.Errorf("ufwBare(no comment) = %q, %v", bare, had)
	}
}

func TestUfwPlan(t *testing.T) {
	zabbix := config.FirewallRule{Name: "zabbix", Port: 10050, From: "203.0.113.10"}
	metrics := config.FirewallRule{Name: "metrics", Port: 9100}
	zabbixLine := "allow from 203.0.113.10 to any port 10050 proto tcp comment 'berth:zabbix'"
	metricsLine := "allow 9100/tcp comment 'berth:metrics'"
	builtins := []string{"allow 2222/tcp", "allow 80,443/tcp", "allow 443/udp"}
	have := func(extra ...string) []string {
		return append([]string{"allow 2222/tcp", "allow 80,443/tcp", "allow 443/udp"}, extra...)
	}
	for _, tc := range []struct {
		name                  string
		have                  []string
		want                  []config.FirewallRule
		dels, adds, takeovers []string
		adopts                bool // ufwAdopts(have, want[0]) when want is non-empty
	}{
		{name: "converged", have: have(zabbixLine, metricsLine), want: []config.FirewallRule{zabbix, metrics}},
		{name: "missing", have: have(), want: []config.FirewallRule{zabbix, metrics},
			adds: []string{"ufw " + zabbixLine, "ufw " + metricsLine}},
		{name: "stale name", have: have("allow 9/tcp comment 'berth:stale'"), want: nil,
			dels: []string{"ufw delete allow 9/tcp comment 'berth:stale'"}},
		{name: "changed source", have: have("allow from 203.0.113.11 to any port 10050 proto tcp comment 'berth:zabbix'"), want: []config.FirewallRule{zabbix},
			dels: []string{"ufw delete allow from 203.0.113.11 to any port 10050 proto tcp comment 'berth:zabbix'"},
			adds: []string{"ufw " + zabbixLine}},
		{name: "two lines one name", have: have(zabbixLine, "allow 10051/tcp comment 'berth:zabbix'"), want: []config.FirewallRule{zabbix},
			dels: []string{"ufw delete allow 10051/tcp comment 'berth:zabbix'"}},
		{name: "leftover equal to the built-in QUIC rule is taken over, not deleted",
			have: have("allow 443/udp comment 'berth:quic'"), want: nil,
			takeovers: []string{"ufw allow 443/udp (built-in; replaces the berth:quic rule sharing its port/proto/source)"}},
		{name: "leftover equal to the built-in SSH rule is taken over, not deleted",
			have: have("allow 2222/tcp comment 'berth:alt'"), want: nil,
			takeovers: []string{"ufw allow 2222/tcp (built-in; replaces the berth:alt rule sharing its port/proto/source)"}},
		{name: "foreign uncommented same tuple is adopted", have: have("allow 9100/tcp"), want: []config.FirewallRule{metrics},
			adds: []string{"ufw " + metricsLine}, adopts: true},
		{name: "foreign other comment same tuple is adopted", have: have("allow 9100/tcp comment 'ops'"), want: []config.FirewallRule{metrics},
			adds: []string{"ufw " + metricsLine}, adopts: true},
		{name: "other port is not an adoption", have: have("allow 9101/tcp"), want: []config.FirewallRule{metrics},
			adds: []string{"ufw " + metricsLine}},
		{name: "other action is not an adoption", have: have("deny 9100/tcp"), want: []config.FirewallRule{metrics},
			adds: []string{"ufw " + metricsLine}},
		{name: "foreign route rule is not an adoption (whole bare compared, not a substring)",
			have: have("route allow 9100/tcp comment 'ops'"), want: []config.FirewallRule{metrics},
			adds: []string{"ufw " + metricsLine}},
		{name: "expected line present is not an adoption", have: have(metricsLine), want: []config.FirewallRule{metrics}},
		{name: "deletes sorted by name, adds in config order",
			have: have("allow 2/tcp comment 'berth:b'", "allow 1/tcp comment 'berth:a'"), want: []config.FirewallRule{zabbix, metrics},
			dels: []string{"ufw delete allow 1/tcp comment 'berth:a'", "ufw delete allow 2/tcp comment 'berth:b'"},
			adds: []string{"ufw " + zabbixLine, "ufw " + metricsLine}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dels, adds, takeovers, err := ufwPlan(tc.have, tc.want, builtins)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(dels, tc.dels) {
				t.Errorf("dels = %q, want %q", dels, tc.dels)
			}
			if !reflect.DeepEqual(adds, tc.adds) {
				t.Errorf("adds = %q, want %q", adds, tc.adds)
			}
			if !reflect.DeepEqual(takeovers, tc.takeovers) {
				t.Errorf("takeovers = %q, want %q", takeovers, tc.takeovers)
			}
			if len(tc.want) > 0 {
				if got := ufwAdopts(tc.have, tc.want[0]); got != tc.adopts {
					t.Errorf("ufwAdopts = %v, want %v", got, tc.adopts)
				}
			}
		})
	}
	if _, _, _, err := ufwPlan([]string{"allow ExampleApp comment 'berth:app'"}, nil, builtins); err == nil {
		t.Error("a berth: comment on a foreign shape must make the plan fail, not sweep or skip")
	}
}
