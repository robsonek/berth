package status

import (
	"strconv"
	"strings"
	"time"
)

// cronLookback bounds the backwards scan. It must cover every schedule the
// config validator accepts — validate.go:563 checks syntax only, so `0 4 1 * *`
// (monthly) and even `0 0 29 2 *` (leap day: up to 8 years apart) reach this
// code. Eight days would have reported every monthly backup as "unknown
// cadence" and therefore never stale; 400 days still missed leap-day
// schedules. A schedule that does not fire inside the window is reported
// unknown rather than scanned indefinitely.
//
// Worst case is ~4.7M iterations of an integer set lookup — measured at about
// 44ms, so under ~90ms for the two scans StaleCutoff performs, once per host.
// Acceptable for a bound that only bites on exotic schedules; the loop exits
// on the FIRST match, so an ordinary daily schedule stops within a day's worth
// of iterations.
const cronLookback = 9 * 366 * 24 * 60

// LastFired returns the most recent minute at or before now at which the
// 5-field cron expression spec fires. It reports false when spec does not
// parse or does not fire within cronLookback minutes.
//
// now MUST already be in the timezone cron will evaluate the schedule in —
// pass HostTime from probeHostMeta, which is already located in the host's
// zone. Matching a schedule in UTC while cron runs it in the server's
// local zone produces wrong answers by the offset, and wrong-by-an-hour twice
// a year at DST boundaries.
//
// Field syntax: `*`, `N`, `A-B`, lists of those separated by commas, and a
// `/step` suffix on any of them. Names (jan, mon) are deliberately not
// supported: berth writes numeric schedules, and an unrecognised spec
// degrades safely to "unknown cadence".
func LastFired(spec string, now time.Time) (time.Time, bool) {
	fields := strings.Fields(spec)
	if len(fields) != 5 {
		return time.Time{}, false
	}
	// Day-of-week upper bound is 7, not 6: Debian cron accepts both 0 and 7
	// for Sunday (crontab(5)), and rejecting `7` would make a legal weekly
	// schedule read as unparseable.
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	var sets [5]map[int]bool
	for i, f := range fields {
		s, ok := parseCronField(f, bounds[i][0], bounds[i][1])
		if !ok {
			return time.Time{}, false
		}
		sets[i] = s
	}
	if sets[4][7] { // normalise Sunday-as-7 onto Go's Weekday numbering
		sets[4][0] = true
	}
	// "Restricted" per crontab(5) means the field does not START with `*` —
	// not `field != "*"`. `*/2` in day-of-month is a restriction and must
	// participate in the dom/dow OR rule.
	domRestricted := !strings.HasPrefix(fields[2], "*")
	dowRestricted := !strings.HasPrefix(fields[4], "*")
	t := now.Truncate(time.Minute)
	for range cronLookback {
		if cronMatches(t, sets, domRestricted, dowRestricted) {
			return t, true
		}
		t = t.Add(-time.Minute)
	}
	return time.Time{}, false
}

// cronMatches reports whether t satisfies the parsed field sets. When BOTH
// day-of-month and day-of-week are restricted they are ORed, per POSIX cron —
// ANDing them would silently misreport the cadence.
func cronMatches(t time.Time, sets [5]map[int]bool, domRestricted, dowRestricted bool) bool {
	if !sets[0][t.Minute()] || !sets[1][t.Hour()] || !sets[3][int(t.Month())] {
		return false
	}
	dom, dow := sets[2][t.Day()], sets[4][int(t.Weekday())]
	switch {
	case domRestricted && dowRestricted:
		return dom || dow
	case domRestricted:
		return dom
	case dowRestricted:
		return dow
	default:
		return true
	}
}

// parseCronField expands one comma-separated field into the set of values it
// matches, reporting false on any syntax or range violation.
func parseCronField(f string, low, high int) (map[int]bool, bool) {
	out := map[int]bool{}
	for _, part := range strings.Split(f, ",") {
		step := 1
		if slash := strings.Index(part, "/"); slash >= 0 {
			n, err := strconv.Atoi(part[slash+1:])
			if err != nil || n <= 0 {
				return nil, false
			}
			step = n
			part = part[:slash]
		}
		lo, hi := low, high
		switch {
		case part == "*":
			// full range
		case strings.Contains(part, "-"):
			ends := strings.SplitN(part, "-", 2)
			a, errA := strconv.Atoi(ends[0])
			b, errB := strconv.Atoi(ends[1])
			if errA != nil || errB != nil || a > b {
				return nil, false
			}
			lo, hi = a, b
		default:
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, false
			}
			lo, hi = n, n
		}
		if lo < low || hi > high {
			return nil, false
		}
		for v := lo; v <= hi; v += step {
			out[v] = true
		}
	}
	return out, len(out) > 0
}

// StaleCutoff returns the SECOND most recent scheduled fire time at or before
// now. An artifact older than this has missed two consecutive runs, which is
// the staleness rule: one full cycle of grace, so a single transient failure
// does not immediately flag the site. Reports false when the cadence is
// unknown — the caller must then leave Stale false rather than guess.
func StaleCutoff(spec string, now time.Time) (time.Time, bool) {
	first, ok := LastFired(spec, now)
	if !ok {
		return time.Time{}, false
	}
	return LastFired(spec, first.Add(-time.Minute))
}
