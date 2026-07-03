package config

import "testing"

func TestFail2banAccessorsDefaultWhenZero(t *testing.T) {
	var f Fail2ban // all zero -> defaults
	if got := f.BantimeEff(); got != "1h" {
		t.Errorf("BantimeEff() = %q, want 1h", got)
	}
	if got := f.FindtimeEff(); got != "10m" {
		t.Errorf("FindtimeEff() = %q, want 10m", got)
	}
	if got := f.MaxretryEff(); got != 5 {
		t.Errorf("MaxretryEff() = %d, want 5", got)
	}
	// Defensive: a negative maxretry (rejected by validate() on the Load path,
	// but literal callers bypass it) also falls back to the default.
	if got := (Fail2ban{Maxretry: -1}).MaxretryEff(); got != 5 {
		t.Errorf("MaxretryEff(-1) = %d, want 5", got)
	}
}

func TestFail2banAccessorsHonorOverrides(t *testing.T) {
	f := Fail2ban{Bantime: "2h", Findtime: "5m", Maxretry: 3}
	if got := f.BantimeEff(); got != "2h" {
		t.Errorf("BantimeEff() = %q, want 2h", got)
	}
	if got := f.FindtimeEff(); got != "5m" {
		t.Errorf("FindtimeEff() = %q, want 5m", got)
	}
	if got := f.MaxretryEff(); got != 3 {
		t.Errorf("MaxretryEff() = %d, want 3", got)
	}
}
