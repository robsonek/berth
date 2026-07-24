package config

import "testing"

func TestSystemTimezoneValidate(t *testing.T) {
	for _, ok := range []string{
		"", // empty = don't manage, lenient
		"UTC",
		"Europe/Warsaw",
		"Etc/GMT+8",
		"America/Argentina/Buenos_Aires", // three segments (IANA max)
		"America/Port-au-Prince",         // hyphens
	} {
		if err := (System{Timezone: ok}).validate(); err != nil {
			t.Errorf("validate(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"Europe/Warsaw; rm -rf /", // the value reaches a command line
		"../etc/passwd",
		"Europe Warsaw",
		"/Europe",
		"Europe/",
		"A/B/C/D", // four segments
	} {
		if err := (System{Timezone: bad}).validate(); err == nil {
			t.Errorf("validate(%q) expected error, got nil", bad)
		}
	}
}
