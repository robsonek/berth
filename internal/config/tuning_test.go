package config

import "testing"

func TestTuningAccessorsDefaultWhenEmpty(t *testing.T) {
	var tn Tuning // all empty -> conservative defaults
	if got := tn.ValkeyMaxmemoryEff(); got != "256mb" {
		t.Errorf("ValkeyMaxmemoryEff() = %q, want 256mb", got)
	}
	if got := tn.ValkeyMaxmemoryPolicyEff(); got != "allkeys-lru" {
		t.Errorf("ValkeyMaxmemoryPolicyEff() = %q, want allkeys-lru", got)
	}
	if got := tn.MariaDBBufferPoolEff(); got != "256M" {
		t.Errorf("MariaDBBufferPoolEff() = %q, want 256M", got)
	}
}

func TestTuningAccessorsHonorOverrides(t *testing.T) {
	tn := Tuning{ValkeyMaxmemory: "512mb", ValkeyMaxmemoryPolicy: "volatile-lru", MariaDBBufferPool: "1G"}
	if got := tn.ValkeyMaxmemoryEff(); got != "512mb" {
		t.Errorf("ValkeyMaxmemoryEff() = %q, want 512mb", got)
	}
	if got := tn.ValkeyMaxmemoryPolicyEff(); got != "volatile-lru" {
		t.Errorf("ValkeyMaxmemoryPolicyEff() = %q, want volatile-lru", got)
	}
	if got := tn.MariaDBBufferPoolEff(); got != "1G" {
		t.Errorf("MariaDBBufferPoolEff() = %q, want 1G", got)
	}
}

func TestTuningValidateAcceptsEmptyAndValid(t *testing.T) {
	for _, tn := range []Tuning{
		{}, // empty = use defaults
		{ValkeyMaxmemory: "256mb", ValkeyMaxmemoryPolicy: "allkeys-lru", MariaDBBufferPool: "256M"},
		{ValkeyMaxmemory: "1gb", ValkeyMaxmemoryPolicy: "volatile-ttl", MariaDBBufferPool: "2G"},
		{ValkeyMaxmemory: "104857600"}, // bare bytes
	} {
		if err := tn.validate(); err != nil {
			t.Errorf("validate(%+v) unexpected error: %v", tn, err)
		}
	}
}

func TestTuningValidateRejectsBad(t *testing.T) {
	for _, tn := range []Tuning{
		{ValkeyMaxmemory: "256 mb; rm -rf /"},
		{ValkeyMaxmemory: "lots"},
		{ValkeyMaxmemoryPolicy: "allkeys-bogus"},
		{MariaDBBufferPool: "256MB"}, // MariaDB uses K/M/G, not MB
		{MariaDBBufferPool: "big"},
	} {
		if err := tn.validate(); err == nil {
			t.Errorf("validate(%+v) expected error, got nil", tn)
		}
	}
}
