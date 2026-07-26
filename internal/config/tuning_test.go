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
	if got := tn.PHPMemoryLimitEff(); got != "256M" {
		t.Errorf("PHPMemoryLimitEff() = %q, want 256M", got)
	}
	if got := tn.PHPUploadMaxEff(); got != "32M" {
		t.Errorf("PHPUploadMaxEff() = %q, want 32M", got)
	}
	if got := tn.PHPMaxExecutionTimeEff(); got != 30 {
		t.Errorf("PHPMaxExecutionTimeEff() = %d, want 30", got)
	}
	if got := tn.PHPMaxInputVarsEff(); got != 1000 {
		t.Errorf("PHPMaxInputVarsEff() = %d, want 1000", got)
	}
}

func TestTuningAccessorsHonorOverrides(t *testing.T) {
	tn := Tuning{
		ValkeyMaxmemory: "512mb", ValkeyMaxmemoryPolicy: "volatile-lru", MariaDBBufferPool: "1G",
		PHPMemoryLimit: "768M", PHPUploadMax: "64M", PHPMaxExecutionTime: 120, PHPMaxInputVars: 5000,
	}
	if got := tn.ValkeyMaxmemoryEff(); got != "512mb" {
		t.Errorf("ValkeyMaxmemoryEff() = %q, want 512mb", got)
	}
	if got := tn.ValkeyMaxmemoryPolicyEff(); got != "volatile-lru" {
		t.Errorf("ValkeyMaxmemoryPolicyEff() = %q, want volatile-lru", got)
	}
	if got := tn.MariaDBBufferPoolEff(); got != "1G" {
		t.Errorf("MariaDBBufferPoolEff() = %q, want 1G", got)
	}
	if got := tn.PHPMemoryLimitEff(); got != "768M" {
		t.Errorf("PHPMemoryLimitEff() = %q, want 768M", got)
	}
	if got := tn.PHPUploadMaxEff(); got != "64M" {
		t.Errorf("PHPUploadMaxEff() = %q, want 64M", got)
	}
	if got := tn.PHPMaxExecutionTimeEff(); got != 120 {
		t.Errorf("PHPMaxExecutionTimeEff() = %d, want 120", got)
	}
	if got := tn.PHPMaxInputVarsEff(); got != 5000 {
		t.Errorf("PHPMaxInputVarsEff() = %d, want 5000", got)
	}
}

func TestTuningPHPIntAccessorsTreatNonPositiveAsDefault(t *testing.T) {
	// The Fail2ban.MaxretryEff precedent: <= 0 means "unset", never a literal 0.
	tn := Tuning{PHPMaxExecutionTime: -5, PHPMaxInputVars: -1}
	if got := tn.PHPMaxExecutionTimeEff(); got != 30 {
		t.Errorf("PHPMaxExecutionTimeEff() = %d, want 30", got)
	}
	if got := tn.PHPMaxInputVarsEff(); got != 1000 {
		t.Errorf("PHPMaxInputVarsEff() = %d, want 1000", got)
	}
}

func TestPHPSizeBytes(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint64
	}{{"1", 1}, {"512k", 524288}, {"32M", 33554432}, {"1G", 1073741824}, {"134217728", 134217728}} {
		got, err := phpSizeBytes(c.in)
		if err != nil || got != c.want {
			t.Errorf("phpSizeBytes(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "abc", "1.5G", "99999999999999999999G"} {
		if _, err := phpSizeBytes(bad); err == nil {
			t.Errorf("phpSizeBytes(%q) expected error, got nil", bad)
		}
	}
}

func TestTuningPHPPostBodyMaxDerivation(t *testing.T) {
	// bytes(upload) + max(2 MiB, 5%) rendered as an exact byte count — valid
	// size syntax for both PHP ini shorthand and nginx client_max_body_size.
	cases := []struct{ upload, want string }{
		{"", "35651584"},        // default 32M; 5% (1677721) is below the 2 MiB floor
		{"32M", "35651584"},     // explicit default
		{"64M", "70464307"},     // 5% headroom (3355443) above the floor
		{"1G", "1127428915"},    // 1073741824 + 53687091
		{"garbage", "35651584"}, // literal-Server fallback to the default derivation
	}
	for _, c := range cases {
		if got := (Tuning{PHPUploadMax: c.upload}).PHPPostBodyMaxEff(); got != c.want {
			t.Errorf("PHPPostBodyMaxEff(upload=%q) = %s, want %s", c.upload, got, c.want)
		}
	}
}

func TestTuningValidateAcceptsEmptyAndValid(t *testing.T) {
	for _, tn := range []Tuning{
		{}, // empty = use defaults
		{ValkeyMaxmemory: "256mb", ValkeyMaxmemoryPolicy: "allkeys-lru", MariaDBBufferPool: "256M"},
		{ValkeyMaxmemory: "1gb", ValkeyMaxmemoryPolicy: "volatile-ttl", MariaDBBufferPool: "2G"},
		{ValkeyMaxmemory: "104857600"}, // bare bytes
		{PHPMemoryLimit: "768M", PHPUploadMax: "1G", PHPMaxExecutionTime: 300, PHPMaxInputVars: 1000000},
		{PHPMemoryLimit: "134217728"}, // bare bytes
		{PHPUploadMax: "512k"},        // suffixes are case-insensitive
		{PHPUploadMax: "64G"},         // exactly the 64 GiB bound is accepted (reject is >)
		{PHPMaxExecutionTime: -1},     // non-positive = unset, lenient
		{MariaDBLogFileSize: "1G", MariaDBTmpTableSize: "128M", MariaDBMaxConnections: 256, MariaDBMaxAllowedPacket: "64M"},
		{MariaDBMaxConnections: 10},          // range floor
		{MariaDBMaxConnections: 100000},      // range ceiling
		{MariaDBMaxAllowedPacket: "1G"},      // exactly MariaDB's ceiling is accepted (reject is >)
		{MariaDBMaxAllowedPacket: "1048576"}, // bare bytes
		{MariaDBMaxAllowedPacket: "1024"},    // exactly MariaDB's 1024-byte floor, bare bytes
		{MariaDBMaxAllowedPacket: "1k"},      // lowercase suffix; exactly one 1024-byte block
		{MariaDBLogFileSize: "4M"},           // exactly MariaDB's 4M redo-log floor
		{MariaDBLogFileSize: "512G"},         // exactly MariaDB's 512G redo-log ceiling
		{MariaDBLogFileSize: "4100K"},        // K value, 4096-aligned (4100 % 4 == 0)
		{MariaDBTmpTableSize: "131072k"},     // suffixes are case-insensitive
		{PHPFPMMaxChildren: 4},               // floor: static pm.max_spare_servers = 4
		{PHPFPMMaxChildren: 10000},           // ceiling
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
		{PHPMemoryLimit: "-1"},  // no sign in the grammar: berth never ships unlimited
		{PHPMemoryLimit: "0"},   // 0 = unlimited in PHP post/upload and nginx body checks
		{PHPMemoryLimit: "08M"}, // leading zeros: PHP shorthand parses octal, nginx decimal
		{PHPUploadMax: "010M"},
		{PHPMemoryLimit: "256MB"},
		{PHPUploadMax: "1.5G"},
		{PHPUploadMax: "64M; rm -rf /"},
		{PHPUploadMax: "65G"},                    // > 64 GiB bound
		{PHPMemoryLimit: "18446744073709551615"}, // would wrap PHP's int64 parse to -1
		{PHPMaxExecutionTime: 301},               // opinionated 300 s cap
		{PHPMaxInputVars: 1000001},               // matches the wizard's domain
		{MariaDBLogFileSize: "1GB"},              // MariaDB uses K/M/G, not GB
		{MariaDBLogFileSize: "huge"},
		{MariaDBLogFileSize: "0"},                    // below the 4M minimum (the regex alone allows 0)
		{MariaDBLogFileSize: "1M"},                   // below MariaDB's 4M minimum
		{MariaDBLogFileSize: "513G"},                 // above MariaDB's 512G maximum
		{MariaDBLogFileSize: "4101K"},                // not 4096-aligned: MariaDB would adjust it
		{MariaDBLogFileSize: "99999999999999999999"}, // overflows uint64: the phpSizeBytes error branch
		{MariaDBTmpTableSize: "128M; rm -rf /"},
		{MariaDBMaxConnections: 9},              // below MariaDB's own floor
		{MariaDBMaxConnections: 100001},         // above MariaDB's own ceiling
		{MariaDBMaxConnections: -1},             // negative would render verbatim
		{MariaDBMaxAllowedPacket: "2G"},         // > 1G: server would silently truncate
		{MariaDBMaxAllowedPacket: "1073741825"}, // 1G + 1 byte
		{MariaDBMaxAllowedPacket: "64MB"},
		{MariaDBMaxAllowedPacket: "1"},                    // below MariaDB's 1024-byte floor (server clamps up)
		{MariaDBMaxAllowedPacket: "1025"},                 // not 1024-aligned: server rounds down
		{MariaDBMaxAllowedPacket: "99999999999999999999"}, // overflows uint64: the phpSizeBytes error branch
		{PHPFPMMaxChildren: 3},                            // pm.max_spare_servers = 4 would exceed it: php-fpm -t rejects
		{PHPFPMMaxChildren: 10001},
		{PHPFPMMaxChildren: -1},
	} {
		if err := tn.validate(); err == nil {
			t.Errorf("validate(%+v) expected error, got nil", tn)
		}
	}
}

func TestTuningValidateSlowQueryLog(t *testing.T) {
	for _, tn := range []Tuning{
		{MariaDBSlowQueryLog: true},
		{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 5},
		{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 86400},
	} {
		if err := tn.validate(); err != nil {
			t.Errorf("validate(%+v) unexpected error: %v", tn, err)
		}
	}
	for _, tn := range []Tuning{
		{MariaDBLongQueryTime: 5},                             // threshold without the log = silently-ignored knob
		{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: -1}, // negative
		{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 86401},
	} {
		if err := tn.validate(); err == nil {
			t.Errorf("validate(%+v) expected error, got nil", tn)
		}
	}
}

func TestTuningMariaDBLongQueryTimeEff(t *testing.T) {
	if got := (Tuning{}).MariaDBLongQueryTimeEff(); got != 2 {
		t.Errorf("default long_query_time = %d, want 2", got)
	}
	if got := (Tuning{MariaDBLongQueryTime: -3}).MariaDBLongQueryTimeEff(); got != 2 {
		t.Errorf("non-positive long_query_time = %d, want the default 2", got)
	}
	if got := (Tuning{MariaDBLongQueryTime: 10}).MariaDBLongQueryTimeEff(); got != 10 {
		t.Errorf("explicit long_query_time = %d, want 10", got)
	}
}

func TestPHPFPMMaxChildrenEff(t *testing.T) {
	if got := (Tuning{}).PHPFPMMaxChildrenEff(); got != 10 {
		t.Errorf("PHPFPMMaxChildrenEff() = %d, want 10", got)
	}
	if got := (Tuning{PHPFPMMaxChildren: -1}).PHPFPMMaxChildrenEff(); got != 10 {
		t.Errorf("PHPFPMMaxChildrenEff(-1) = %d, want 10 (non-positive = unset)", got)
	}
	if got := (Tuning{PHPFPMMaxChildren: 16}).PHPFPMMaxChildrenEff(); got != 16 {
		t.Errorf("PHPFPMMaxChildrenEff(16) = %d, want 16", got)
	}
}
