package config

import "testing"

// composer.auto_update is a tri-state knob: unset means ON (berth writes the
// daily self-update cron), an explicit false means "do not manage Composer
// updates" (the cron is removed, the binary stays), an explicit true is the
// default spelled out.
func TestComposerAutoUpdateEnabledDefaultsOn(t *testing.T) {
	var c Composer
	if !c.AutoUpdateEnabled() {
		t.Error("Composer{}.AutoUpdateEnabled() = false, want true (unset = on)")
	}
	off := false
	c.AutoUpdate = &off
	if c.AutoUpdateEnabled() {
		t.Error("auto_update: false must disable the cron")
	}
	on := true
	c.AutoUpdate = &on
	if !c.AutoUpdateEnabled() {
		t.Error("auto_update: true must enable the cron")
	}
}

func TestLoadComposerAutoUpdateRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want bool
		set  bool
	}{
		{"", true, false},
		{"composer:\n  auto_update: false\n", false, true},
		{"composer:\n  auto_update: true\n", true, true},
	} {
		s, err := Load(writeTmpConfig(t, `id: composer-knob
requires_berth: v1.0.0
host: 203.0.113.10
php:
  version: "8.5"
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
		if got := s.Composer.AutoUpdateEnabled(); got != tc.want {
			t.Errorf("Load(%q).Composer.AutoUpdateEnabled() = %v, want %v", tc.yaml, got, tc.want)
		}
		if (s.Composer.AutoUpdate != nil) != tc.set {
			t.Errorf("Load(%q).Composer.AutoUpdate set = %v, want %v (no SetDefault: unset stays nil)", tc.yaml, s.Composer.AutoUpdate != nil, tc.set)
		}
	}
}
