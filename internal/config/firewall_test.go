package config

import (
	"strings"
	"testing"
)

// firewall.enabled is a tri-state knob like nginx.gzip: unset means ON
// (today's ufw with the built-in rules), an explicit false keeps ufw disabled,
// an explicit true is the default spelled out.
func TestFirewallIsEnabled(t *testing.T) {
	var f Firewall
	if !f.IsEnabled() {
		t.Error("Firewall{}.IsEnabled() = false, want true (unset = on)")
	}
	off := false
	f.Enabled = &off
	if f.IsEnabled() {
		t.Error("enabled: false must report the firewall off")
	}
	on := true
	f.Enabled = &on
	if !f.IsEnabled() {
		t.Error("enabled: true must report the firewall on")
	}
}

func TestFirewallRuleProtoEff(t *testing.T) {
	if got := (FirewallRule{}).ProtoEff(); got != "tcp" {
		t.Errorf("ProtoEff() of an unset proto = %q, want tcp", got)
	}
	if got := (FirewallRule{Proto: "udp"}).ProtoEff(); got != "udp" {
		t.Errorf("ProtoEff() = %q, want udp", got)
	}
}

// FirewallRuleCommand spells a rule the way `ufw show added` prints it back:
// the short form without a source, the full form with one; the comment is
// always the last clause, single-quoted.
func TestFirewallRuleCommand(t *testing.T) {
	for _, tc := range []struct {
		rule       FirewallRule
		want, bare string
	}{
		{FirewallRule{Name: "zabbix", Port: 10050}, "allow 10050/tcp comment 'berth:zabbix'", "allow 10050/tcp"},
		{FirewallRule{Name: "zabbix", Port: 10050, Proto: "udp"}, "allow 10050/udp comment 'berth:zabbix'", "allow 10050/udp"},
		{FirewallRule{Name: "zabbix", Port: 10050, Proto: "tcp", From: "203.0.113.10"},
			"allow from 203.0.113.10 to any port 10050 proto tcp comment 'berth:zabbix'", "allow from 203.0.113.10 to any port 10050 proto tcp"},
		{FirewallRule{Name: "office", Port: 9100, From: "203.0.113.0/24"},
			"allow from 203.0.113.0/24 to any port 9100 proto tcp comment 'berth:office'", "allow from 203.0.113.0/24 to any port 9100 proto tcp"},
		{FirewallRule{Name: "v6", Port: 53, Proto: "udp", From: "2001:db8::/32"},
			"allow from 2001:db8::/32 to any port 53 proto udp comment 'berth:v6'", "allow from 2001:db8::/32 to any port 53 proto udp"},
	} {
		if got := FirewallRuleCommand(tc.rule); got != tc.want {
			t.Errorf("FirewallRuleCommand(%+v) = %q, want %q", tc.rule, got, tc.want)
		}
		if got := FirewallRuleCommandBare(tc.rule); got != tc.bare {
			t.Errorf("FirewallRuleCommandBare(%+v) = %q, want %q", tc.rule, got, tc.bare)
		}
	}
}

func TestLoadFirewallRoundTrip(t *testing.T) {
	s, err := Load(writeTmpConfig(t, `id: firewall-knob
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
firewall:
  allow:
    - name: zabbix
      port: 10050
      proto: tcp
      from: 203.0.113.10
    - name: metrics
      port: 9100
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.Firewall.Enabled != nil || !s.Firewall.IsEnabled() {
		t.Errorf("enabled unset must stay nil and read as on; got %v", s.Firewall.Enabled)
	}
	if len(s.Firewall.Allow) != 2 {
		t.Fatalf("Allow = %+v, want 2 rules", s.Firewall.Allow)
	}
	if got, want := s.Firewall.Allow[0], (FirewallRule{Name: "zabbix", Port: 10050, Proto: "tcp", From: "203.0.113.10"}); got != want {
		t.Errorf("Allow[0] = %+v, want %+v", got, want)
	}
	if got, want := s.Firewall.Allow[1], (FirewallRule{Name: "metrics", Port: 9100}); got != want {
		t.Errorf("Allow[1] = %+v, want %+v", got, want)
	}

	off, err := Load(writeTmpConfig(t, `id: firewall-off
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
firewall:
  enabled: false
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
	if err != nil {
		t.Fatalf("Load(enabled: false) error = %v", err)
	}
	if off.Firewall.Enabled == nil || off.Firewall.IsEnabled() {
		t.Errorf("enabled: false must decode as an explicit off; got %v", off.Firewall.Enabled)
	}

	none, err := Load(writeTmpConfig(t, `id: firewall-none
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
	if err != nil {
		t.Fatalf("Load(no block) error = %v", err)
	}
	if none.Firewall.Enabled != nil || len(none.Firewall.Allow) != 0 {
		t.Errorf("no firewall block must leave the zero value; got %+v", none.Firewall)
	}
}

func TestValidateFirewallBlock(t *testing.T) {
	rule := func(name string, port int, proto, from string) FirewallRule {
		return FirewallRule{Name: name, Port: port, Proto: proto, From: from}
	}
	ok := map[string][]FirewallRule{
		"bare ipv4":              {rule("zabbix", 10050, "tcp", "203.0.113.10")},
		"ipv4 cidr":              {rule("office", 10050, "tcp", "203.0.113.0/24")},
		"bare ipv6":              {rule("v6", 10050, "tcp", "2001:db8::10")},
		"ipv6 loopback":          {rule("lo6", 10050, "tcp", "::1")},
		"ipv6 cidr":              {rule("v6net", 10050, "tcp", "2001:db8::/32")},
		"udp":                    {rule("dns", 53, "udp", "")},
		"proto unset":            {rule("metrics", 9100, "", "")},
		"443 tcp alone":          {rule("https", 443, "tcp", "")}, // the built-in is the multiport 80,443 — a different tuple
		"443 udp without http3":  {rule("quic", 443, "udp", "")},
		"ssh port with source":   {rule("ssh-office", 22, "tcp", "203.0.113.0/24")},
		"pair differs in port":   {rule("a", 10050, "tcp", ""), rule("b", 10051, "tcp", "")},
		"pair differs in proto":  {rule("a", 10050, "tcp", ""), rule("b", 10050, "udp", "")},
		"pair differs in source": {rule("a", 10050, "tcp", "203.0.113.10"), rule("b", 10050, "tcp", "203.0.113.11")},
		"pair any vs source":     {rule("a", 10050, "tcp", ""), rule("b", 10050, "tcp", "203.0.113.10")},
	}
	for name, allow := range ok {
		t.Run("ok/"+name, func(t *testing.T) {
			s := base()
			s.Firewall.Allow = allow
			if err := s.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}

	one := func(r FirewallRule) func(*Server) { return func(s *Server) { s.Firewall.Allow = []FirewallRule{r} } }
	bad := map[string]struct {
		mutate func(*Server)
		want   string // substring of the error
	}{
		"missing name":          {one(rule("", 10050, "", "")), "name"},
		"uppercase name":        {one(rule("Zabbix", 10050, "", "")), "name"},
		"space in name":         {one(rule("zab bix", 10050, "", "")), "name"},
		"name too long":         {one(rule(strings.Repeat("a", 33), 10050, "", "")), "name"},
		"duplicate name":        {func(s *Server) { s.Firewall.Allow = []FirewallRule{rule("x", 1, "", ""), rule("x", 2, "", "")} }, "duplicate"},
		"port zero":             {one(rule("x", 0, "", "")), "port"},
		"port negative":         {one(rule("x", -1, "", "")), "port"},
		"port too high":         {one(rule("x", 65536, "", "")), "port"},
		"proto icmp":            {one(rule("x", 10050, "icmp", "")), "proto"},
		"from any literal":      {one(rule("x", 10050, "", "any")), "from"},
		"from garbage":          {one(rule("x", 10050, "", "203.0.113")), "from"},
		"from host bits set v4": {one(rule("x", 10050, "", "203.0.113.5/24")), "203.0.113.0/24"},
		"from host bits set v6": {one(rule("x", 10050, "", "2001:db8::10/64")), "2001:db8::/64"},
		"from /32":              {one(rule("x", 10050, "", "203.0.113.10/32")), "bare address"},
		"from /128":             {one(rule("x", 10050, "", "2001:db8::10/128")), "bare address"},
		"from /0 v4":            {one(rule("x", 10050, "", "0.0.0.0/0")), "omit"},
		"from /0 v6":            {one(rule("x", 10050, "", "::/0")), "omit"},
		"from ipv4-compatible":  {one(rule("x", 10050, "", "::cb00:710a")), "IPv4-compatible"},
		"from ipv4-compat cidr": {one(rule("x", 10050, "", "::cb00:7100/120")), "IPv4-compatible"},
		"from uppercase ipv6":   {one(rule("x", 10050, "", "2001:DB8::10")), "2001:db8::10"},
		"from ipv4-mapped":      {one(rule("x", 10050, "", "::ffff:203.0.113.10")), "203.0.113.10"},
		"from bad prefix":       {one(rule("x", 10050, "", "2001:db8::/129")), "from"},
		"disabled with allow": {func(s *Server) {
			off := false
			s.Firewall.Enabled = &off
			s.Firewall.Allow = []FirewallRule{rule("x", 10050, "", "")}
		}, "enabled is false"},
		"built-in ssh":          {func(s *Server) { s.SSH.Port = 2222; s.Firewall.Allow = []FirewallRule{rule("ssh", 2222, "", "")} }, "built-in SSH"},
		"built-in ssh explicit": {one(rule("ssh", 22, "tcp", "")), "built-in SSH"},
		"built-in http3 udp": {func(s *Server) {
			s.Nginx.Source = "nginx"
			s.Sites[0].SSL, s.Sites[0].SSLEmail, s.Sites[0].HTTP3 = true, "ops@example.com", true
			s.Firewall.Allow = []FirewallRule{rule("quic", 443, "udp", "")}
		}, "HTTP/3"},
		"same tuple two names": {func(s *Server) {
			s.Firewall.Allow = []FirewallRule{rule("a", 10050, "tcp", ""), rule("b", 10050, "", "")}
		}, "same rule"},
		"same tuple two names with from": {func(s *Server) {
			s.Firewall.Allow = []FirewallRule{rule("a", 10050, "tcp", "203.0.113.10"), rule("b", 10050, "tcp", "203.0.113.10")}
		}, "same rule"},
	}
	for name, tc := range bad {
		t.Run("bad/"+name, func(t *testing.T) {
			s := base()
			tc.mutate(s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
