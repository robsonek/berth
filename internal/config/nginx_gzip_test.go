package config

import "testing"

// nginx.gzip is a tri-state knob: unset means ON (berth writes the conf.d
// gzip drop-in), an explicit false means "do not manage gzip" (stock nginx
// behaviour), an explicit true is the default spelled out.
func TestNginxGzipEnabledDefaultsOn(t *testing.T) {
	var n Nginx
	if !n.GzipEnabled() {
		t.Error("Nginx{}.GzipEnabled() = false, want true (unset = on)")
	}
	off := false
	n.Gzip = &off
	if n.GzipEnabled() {
		t.Error("gzip: false must disable the drop-in")
	}
	on := true
	n.Gzip = &on
	if !n.GzipEnabled() {
		t.Error("gzip: true must enable the drop-in")
	}
}

func TestLoadNginxGzipRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want bool
		set  bool
	}{
		{"", true, false},
		{"  gzip: false\n", false, true},
		{"  gzip: true\n", true, true},
	} {
		s, err := Load(writeTmpConfig(t, `id: gzip-knob
host: 203.0.113.10
php:
  version: "8.5"
nginx:
  source: debian
`+tc.yaml+`database:
  engine: mariadb
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
		if err != nil {
			t.Fatalf("Load(%q) error = %v", tc.yaml, err)
		}
		if got := s.Nginx.GzipEnabled(); got != tc.want {
			t.Errorf("Load(%q).Nginx.GzipEnabled() = %v, want %v", tc.yaml, got, tc.want)
		}
		if (s.Nginx.Gzip != nil) != tc.set {
			t.Errorf("Load(%q).Nginx.Gzip set = %v, want %v (no SetDefault: unset stays nil)", tc.yaml, s.Nginx.Gzip != nil, tc.set)
		}
	}
}
