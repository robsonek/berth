package config

import "testing"

func TestBackupsEff(t *testing.T) {
	if got := (Backups{}).RetentionDaysEff(); got != 7 {
		t.Errorf("default retention = %d, want 7", got)
	}
	if got := (Backups{Retention: 30}).RetentionDaysEff(); got != 30 {
		t.Errorf("retention = %d, want 30", got)
	}
	if got := (Backups{}).ScheduleEff(); got != "30 3 * * *" {
		t.Errorf("default schedule = %q, want \"30 3 * * *\"", got)
	}
	if got := (Backups{Schedule: "0 2 * * 0"}).ScheduleEff(); got != "0 2 * * 0" {
		t.Errorf("schedule = %q, want \"0 2 * * 0\"", got)
	}
}

func TestBackupsEnabled(t *testing.T) {
	on, off := true, false
	s := &Server{Backups: Backups{Enabled: true}, Sites: []Site{
		{Domain: "a.example.com"},                // inherits server: on
		{Domain: "b.example.com", Backups: &off}, // override: off
	}}
	if !s.BackupsEnabled(s.Sites[0]) {
		t.Error("site a should inherit enabled")
	}
	if s.BackupsEnabled(s.Sites[1]) {
		t.Error("site b override off ignored")
	}
	if !s.AnyBackupsEnabled() {
		t.Error("AnyBackupsEnabled should be true (site a)")
	}
	s2 := &Server{Backups: Backups{Enabled: false}, Sites: []Site{{Domain: "c.example.com", Backups: &on}}}
	if !s2.AnyBackupsEnabled() {
		t.Error("AnyBackupsEnabled should be true via per-site override")
	}
	s3 := &Server{Sites: []Site{{Domain: "d.example.com"}}}
	if s3.AnyBackupsEnabled() {
		t.Error("AnyBackupsEnabled should be false by default")
	}
}
