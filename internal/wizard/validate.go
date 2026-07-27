package wizard

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/robsonek/berth/internal/config"
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
	// Delegate to the config rule so the wizard refuses exactly what
	// config.Load would refuse (system trees, /home, unclean or shallow paths).
	return config.ValidateDeployPath(s)
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
	rePHPSize      = regexp.MustCompile(`^[1-9][0-9]*[KMGkmg]?$`)
	reDaemonName   = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// phpSizeMaxBytes mirrors config's unexported 64 GiB bound on the PHP size
// knobs, so a server-level answer over the bound is rejected inline — run.go's
// site-retry loop assumes any late Validate() failure is site-local, and an
// escape here would loop the operator on a site prompt they cannot fix.
const phpSizeMaxBytes = 64 << 30

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

// mariadbPacketCeiling / mariadbPacketFloor mirror config's
// mariadbMaxAllowedPacketCeiling / mariadbMaxAllowedPacketFloor (unexported
// there) for inline feedback; config.Server.Validate stays authoritative.
const (
	mariadbPacketCeiling = 1 << 30
	mariadbPacketFloor   = 1 << 10
)

func optionalMariaDBPacket(s string) error {
	if s == "" {
		return nil
	}
	if !reMariaDBSize.MatchString(s) {
		return fmt.Errorf("%q must be a number optionally suffixed K/M/G", s)
	}
	num, mult := s, uint64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		num, mult = s[:len(s)-1], 1<<10
	case 'M', 'm':
		num, mult = s[:len(s)-1], 1<<20
	case 'G', 'g':
		num, mult = s[:len(s)-1], 1<<30
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil || n > math.MaxUint64/mult || n*mult > mariadbPacketCeiling {
		return fmt.Errorf("%q exceeds MariaDB's 1G max_allowed_packet ceiling", s)
	}
	if n*mult < mariadbPacketFloor {
		return fmt.Errorf("%q is below MariaDB's 1024-byte max_allowed_packet floor", s)
	}
	if n*mult%mariadbPacketFloor != 0 {
		return fmt.Errorf("%q is not a multiple of 1024 (MariaDB rounds max_allowed_packet down)", s)
	}
	return nil
}

// mariadbLogSizeMin/Max and the 4096-byte block mirror config's
// mariadbLogFileSize{Min,Max,Block} innodb_log_file_size domain (unexported
// there) for inline feedback; config.Server.Validate stays authoritative.
const (
	mariadbLogSizeMin = 4 << 20
	mariadbLogSizeMax = 512 << 30
)

func optionalMariaDBLogSize(s string) error {
	if s == "" {
		return nil
	}
	if !reMariaDBSize.MatchString(s) {
		return fmt.Errorf("%q must be a number optionally suffixed K/M/G", s)
	}
	num, mult := s, uint64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		num, mult = s[:len(s)-1], 1<<10
	case 'M', 'm':
		num, mult = s[:len(s)-1], 1<<20
	case 'G', 'g':
		num, mult = s[:len(s)-1], 1<<30
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil || n > math.MaxUint64/mult || n*mult > mariadbLogSizeMax {
		return fmt.Errorf("%q exceeds MariaDB's 512G innodb_log_file_size maximum", s)
	}
	if n*mult < mariadbLogSizeMin {
		return fmt.Errorf("%q is below MariaDB's 4M innodb_log_file_size minimum", s)
	}
	if n*mult%4096 != 0 {
		return fmt.Errorf("%q is not a multiple of 4096 (the redo-log block size)", s)
	}
	return nil
}

func optionalPHPSize(s string) error {
	if s == "" {
		return nil
	}
	if !rePHPSize.MatchString(s) {
		return fmt.Errorf("%q must be a positive number optionally suffixed K/M/G, no leading zeros", s)
	}
	num, mult := s, uint64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		num, mult = s[:len(s)-1], 1<<10
	case 'M', 'm':
		num, mult = s[:len(s)-1], 1<<20
	case 'G', 'g':
		num, mult = s[:len(s)-1], 1<<30
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil || n > math.MaxUint64/mult || n*mult > phpSizeMaxBytes {
		return fmt.Errorf("%q exceeds the 64G bound", s)
	}
	return nil
}

// reCronSchedule / reTimezone mirror config.reCronSchedule / config.reTimezone
// (unexported there) for inline feedback; config.Server.Validate stays
// authoritative.
// The cron class [0-9*,/-] already excludes newlines (and Go's $ is not multiline),
// so the regex alone rejects control-char injection — no extra check needed
// here. (Swap sizes have NO mirror regex anymore: optionalSwapSize delegates
// to the authoritative config.ParseSwapBytes — shape and cap in one place.)
var (
	reCronSchedule = regexp.MustCompile(`^[0-9*,/-]+( [0-9*,/-]+){4}$`)
	reTimezone     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
)

func optionalSwapSize(s string) error {
	if s == "" {
		return nil
	}
	// Delegate to the authoritative parser (shape AND the 1 TiB cap).
	_, err := config.ParseSwapBytes(s)
	return err
}

func optionalTimezone(s string) error {
	if s == "" || reTimezone.MatchString(s) {
		return nil
	}
	return fmt.Errorf("timezone %q must be an IANA zone name like Europe/Warsaw", s)
}

// optionalSystemHostname allows blank (leave untouched) or a valid hostname of
// at most 64 chars (kernel HOST_NAME_MAX); config.Server.Validate stays
// authoritative.
func optionalSystemHostname(s string) error {
	if s == "" || (len(s) <= 64 && reHostname.MatchString(s)) {
		return nil
	}
	return fmt.Errorf("hostname %q must be a valid hostname of at most 64 characters", s)
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
