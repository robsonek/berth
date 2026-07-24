package config

import (
	"strings"
	"testing"
)

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

func TestSystemHostnameValidate(t *testing.T) {
	for _, ok := range []string{
		"", // empty = don't manage, lenient
		"web1",
		"web-1.example.com",
		strings.Repeat("a", 31) + "." + strings.Repeat("b", 32), // exactly HOST_NAME_MAX (64)
	} {
		if err := (System{Hostname: ok}).validate(); err != nil {
			t.Errorf("validate(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"bad host",         // whitespace
		"web1; rm -rf /",   // the value reaches a command line
		"-bad.example.com", // label starting with '-'
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 32), // 65 chars, over the kernel HOST_NAME_MAX
	} {
		if err := (System{Hostname: bad}).validate(); err == nil {
			t.Errorf("validate(%q) expected error, got nil", bad)
		}
	}
}
