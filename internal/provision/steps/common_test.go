package steps

import "testing"

func TestHasManagedMarkerRequiresExactLine(t *testing.T) {
	for _, tc := range []struct {
		content string
		want    bool
	}{
		{managedMarker + "\nbody\n", true},
		{managedMarkerINI + "\nbody\n", true},
		{managedMarker, true}, // marker-only file, no trailing newline
		{managedMarkerINI, true},
		{managedMarker + "-backup v2\nbody\n", false}, // foreign tool mimicking the prefix
		{managedMarker + " (v2)\nbody\n", false},
		{"body\n" + managedMarker + "\n", false}, // marker not on the first line
		{"", false},
	} {
		if got := hasManagedMarker(tc.content); got != tc.want {
			t.Errorf("hasManagedMarker(%q) = %v, want %v", tc.content, got, tc.want)
		}
	}
}
