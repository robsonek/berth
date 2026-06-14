package config

import "testing"

func TestLoadValid(t *testing.T) {
	s, err := Load("testdata/valid.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.Host != "203.0.113.10" {
		t.Errorf("Host = %q, want 203.0.113.10", s.Host)
	}
	if s.SSH.Port != 22 {
		t.Errorf("SSH.Port = %d, want 22", s.SSH.Port)
	}
	if s.PHP.Source != "auto" {
		t.Errorf("PHP.Source = %q, want auto", s.PHP.Source)
	}
	if len(s.Sites) != 1 || s.Sites[0].Domain != "app.example.com" {
		t.Errorf("Sites = %+v, want one site app.example.com", s.Sites)
	}
}

func TestLoadDefaultsPort(t *testing.T) {
	// minimal.yml omits ssh.port → default 22 applies (created inline below).
	s, err := Load("testdata/valid.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.SSH.Port == 0 {
		t.Error("expected default ssh.port to be applied")
	}
}

func TestLoadFail2banDefaults(t *testing.T) {
	s, err := Load("testdata/defaults.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.Fail2ban.Bantime != "1h" || s.Fail2ban.Findtime != "10m" || s.Fail2ban.Maxretry != 5 {
		t.Errorf("fail2ban defaults not applied: %+v", s.Fail2ban)
	}
}

func TestLoadSchedulerDefaultsOn(t *testing.T) {
	s, err := Load("testdata/defaults.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !s.Scheduler {
		t.Error("scheduler should default to true when the key is absent")
	}
}
