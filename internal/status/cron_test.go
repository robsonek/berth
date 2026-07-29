package status

import (
	"testing"
	"time"
)

func at(y int, mo time.Month, d, h, mi int) time.Time {
	return time.Date(y, mo, d, h, mi, 0, 0, time.UTC)
}

func TestLastFired(t *testing.T) {
	tests := []struct {
		name string
		spec string
		now  time.Time
		want time.Time
		ok   bool
	}{
		{"daily before today's run", "30 3 * * *", at(2026, 7, 29, 2, 0), at(2026, 7, 28, 3, 30), true},
		{"daily after today's run", "30 3 * * *", at(2026, 7, 29, 9, 0), at(2026, 7, 29, 3, 30), true},
		{"exactly on the minute", "30 3 * * *", at(2026, 7, 29, 3, 30), at(2026, 7, 29, 3, 30), true},
		{"step minutes", "*/15 * * * *", at(2026, 7, 29, 9, 7), at(2026, 7, 29, 9, 0), true},
		{"list of hours", "0 2,14 * * *", at(2026, 7, 29, 9, 0), at(2026, 7, 29, 2, 0), true},
		{"range of hours", "0 9-17 * * *", at(2026, 7, 29, 20, 0), at(2026, 7, 29, 17, 0), true},
		{"weekly by day-of-week", "0 4 * * 0", at(2026, 7, 29, 9, 0), at(2026, 7, 26, 4, 0), true},
		// POSIX: when BOTH day-of-month and day-of-week are restricted they OR,
		// they do not AND. Getting this backwards silently doubles or halves
		// the computed cadence.
		{"dom and dow are ORed", "0 4 1 * 0", at(2026, 7, 29, 9, 0), at(2026, 7, 26, 4, 0), true},
		{"unparseable spec", "not a cron", at(2026, 7, 29, 9, 0), time.Time{}, false},
		{"wrong field count", "30 3 * *", at(2026, 7, 29, 9, 0), time.Time{}, false},
		{"out of range value", "99 3 * * *", at(2026, 7, 29, 9, 0), time.Time{}, false},
		// Fires only on Feb 30, i.e. never — must degrade to "unknown cadence"
		// rather than scanning forever.
		{"never fires", "0 0 30 2 *", at(2026, 7, 29, 9, 0), time.Time{}, false},
		// Leap day: the previous firing is 2024-02-29, over two years back.
		// This is what the nine-year lookback exists for — an eight-day or
		// 400-day bound reports it as unknown cadence and never stale.
		{"leap day", "0 0 29 2 *", at(2026, 7, 29, 9, 0), at(2024, 2, 29, 0, 0), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := LastFired(tc.spec, tc.now)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && !got.Equal(tc.want) {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestStaleCutoffIsTwoCyclesBack(t *testing.T) {
	got, ok := StaleCutoff("30 3 * * *", at(2026, 7, 29, 9, 0))
	if !ok {
		t.Fatal("expected a cutoff for a daily schedule")
	}
	if want := at(2026, 7, 28, 3, 30); !got.Equal(want) {
		t.Errorf("got %s, want %s (one full cycle of grace)", got, want)
	}
}

func TestStaleCutoffUnknownCadence(t *testing.T) {
	if _, ok := StaleCutoff("bogus", at(2026, 7, 29, 9, 0)); ok {
		t.Error("an unparseable schedule must yield no cutoff, so staleness is never claimed")
	}
}
