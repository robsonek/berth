package steps

import (
	"strings"
	"testing"
)

func TestParseSwapBytes(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"512M", 512 * 1024 * 1024, false},
		{"1G", 1024 * 1024 * 1024, false},
		{"2g", 2 * 1024 * 1024 * 1024, false},
		{"512m", 512 * 1024 * 1024, false},
		{"0G", 0, true},
		{"2", 0, true},
		{"2GB", 0, true},
		{"", 0, true},
		{"G", 0, true},
	}
	for _, tc := range cases {
		got, err := parseSwapBytes(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseSwapBytes(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("parseSwapBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFstabSwapState(t *testing.T) {
	const fstab = "UUID=abc / ext4 defaults 0 1\n" +
		"/swapfile none swap sw 0 0 # managed by berth\n"
	marked, foreign := fstabSwapState(fstab)
	if !marked || foreign {
		t.Errorf("marked line: marked=%v foreign=%v, want true,false", marked, foreign)
	}

	const foreignFstab = "UUID=abc / ext4 defaults 0 1\n" +
		"/swapfile none swap sw 0 0\n"
	marked, foreign = fstabSwapState(foreignFstab)
	if marked || !foreign {
		t.Errorf("foreign line: marked=%v foreign=%v, want false,true", marked, foreign)
	}

	const none = "UUID=abc / ext4 defaults 0 1\n# /swapfile none swap sw 0 0\n"
	marked, foreign = fstabSwapState(none)
	if marked || foreign {
		t.Errorf("no/commented line: marked=%v foreign=%v, want false,false", marked, foreign)
	}

	// Marker present but NOT at end-of-line -> foreign (the removal sed anchors at $,
	// so ownership must require the marker at EOL, not merely contained).
	const markerMidLine = "/swapfile none swap sw 0 0 # managed by berth tail\n"
	marked, foreign = fstabSwapState(markerMidLine)
	if marked || !foreign {
		t.Errorf("marker mid-line: marked=%v foreign=%v, want false,true", marked, foreign)
	}

	// Leading whitespace before a properly-marked line -> still owned (trimmed).
	const indented = "  /swapfile none swap sw 0 0 # managed by berth\n"
	marked, foreign = fstabSwapState(indented)
	if !marked || foreign {
		t.Errorf("indented marked line: marked=%v foreign=%v, want true,false", marked, foreign)
	}
}

func TestSysctlKeysMatchTemplate(t *testing.T) {
	out, err := renderSysctl()
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range sysctlKeys {
		want := kv.Key + " = " + kv.Value
		if !strings.Contains(string(out), want) {
			t.Errorf("sysctl_berth.conf.tmpl missing %q (keep sysctlKeys in sync with the template)", want)
		}
	}
}
