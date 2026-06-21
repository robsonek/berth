package wizard

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// parseIntInRange parses s as an int in [lo, hi]. Used both as a huh input
// validator (returns the error) and to convert the bound string into the typed
// Answers field afterwards.
func parseIntInRange(field, s string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%s %q must be a whole number", field, s)
	}
	if n < lo || n > hi {
		return 0, fmt.Errorf("%s %d out of range (%d-%d)", field, n, lo, hi)
	}
	return n, nil
}

// These mirror config.Server.Validate for inline feedback as the user types;
// config.Server.Validate (run in Write and incrementally in run) stays authoritative.
var (
	reHostname = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	reSQLIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	reEmail    = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
)

func required(field string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
}

func validHostname(field string) func(string) error {
	return func(s string) error {
		if !reHostname.MatchString(s) {
			return fmt.Errorf("%s %q is not a valid hostname or IP", field, s)
		}
		return nil
	}
}

func validSQLIdent(field string) func(string) error {
	return func(s string) error {
		if !reSQLIdent.MatchString(s) {
			return fmt.Errorf("%s %q is not a valid SQL identifier", field, s)
		}
		return nil
	}
}

func validDeployPath(s string) error {
	if !path.IsAbs(s) || strings.ContainsAny(s, " ;&|$`\n\t") {
		return fmt.Errorf("deploy path %q must be absolute without shell metacharacters", s)
	}
	return nil
}

// validTLSEmail requires a valid address only when ssl is on with letsencrypt.
func validTLSEmail(ssl *bool, mode *string) func(string) error {
	return func(s string) error {
		if !*ssl || *mode == "selfsigned" {
			return nil
		}
		if !reEmail.MatchString(s) {
			return fmt.Errorf("TLS email %q is not a valid email address", s)
		}
		return nil
	}
}

// validIntField is a huh input validator wrapping parseIntInRange.
func validIntField(field string, lo, hi int) func(string) error {
	return func(s string) error {
		_, err := parseIntInRange(field, s, lo, hi)
		return err
	}
}

var (
	reFail2banTime = regexp.MustCompile(`^[0-9]+[smhdw]?$`)
	reValkeyMem    = regexp.MustCompile(`^(?i)[0-9]+(b|kb|mb|gb|k|m|g)?$`)
	reMariaDBSize  = regexp.MustCompile(`^(?i)[0-9]+[kmg]?$`)
	reDaemonName   = regexp.MustCompile(`^[a-z0-9-]+$`)
)

func optionalFail2banTime(s string) error {
	if s == "" || reFail2banTime.MatchString(s) {
		return nil
	}
	return fmt.Errorf("%q must be a number optionally suffixed s/m/h/d/w", s)
}

func optionalValkeyMem(s string) error {
	if s == "" || reValkeyMem.MatchString(s) {
		return nil
	}
	return fmt.Errorf("%q must be a number optionally suffixed b/kb/mb/gb", s)
}

func optionalMariaDBSize(s string) error {
	if s == "" || reMariaDBSize.MatchString(s) {
		return nil
	}
	return fmt.Errorf("%q must be a number optionally suffixed K/M/G", s)
}

// reSwapSize / reCronSchedule mirror config.reSwapSize / config.reCronSchedule
// (unexported there) for inline feedback; config.Server.Validate stays authoritative.
// The cron class [0-9*,/-] already excludes newlines (and Go's $ is not multiline),
// so the regex alone rejects control-char injection — no extra check needed here.
var (
	reSwapSize     = regexp.MustCompile(`^[1-9][0-9]*[MmGg]$`)
	reCronSchedule = regexp.MustCompile(`^[0-9*,/-]+( [0-9*,/-]+){4}$`)
)

func optionalSwapSize(s string) error {
	if s == "" || reSwapSize.MatchString(s) {
		return nil
	}
	return fmt.Errorf("swap %q must be a positive number suffixed M or G (e.g. 2G)", s)
}

func optionalCronSchedule(s string) error {
	if s == "" || reCronSchedule.MatchString(s) {
		return nil
	}
	return fmt.Errorf("schedule %q must be 5 cron fields over [0-9*,/-] (e.g. \"30 3 * * *\")", s)
}

func optionalInt(field string, lo, hi int) func(string) error {
	return func(s string) error {
		if s == "" || s == "0" {
			return nil
		}
		_, err := parseIntInRange(field, s, lo, hi)
		return err
	}
}

func validDaemonName(s string) error {
	if !reDaemonName.MatchString(s) {
		return fmt.Errorf("daemon name %q must match [a-z0-9-]+", s)
	}
	return nil
}

// reOSUser mirrors config.reLinuxUser for inline feedback (the reserved-name
// check stays authoritative in config.Validate).
var reOSUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// validOSUser allows blank (the user is then derived) or a valid Linux username.
func validOSUser(s string) error {
	if s == "" || reOSUser.MatchString(s) {
		return nil
	}
	return fmt.Errorf("os user %q must be lowercase [a-z_][a-z0-9_-]{0,31} or blank to derive", s)
}
