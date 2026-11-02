package config

import (
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/version"
)

// checkRequiresBerth gates a config on its requires_berth key, given the raw
// value viper read (nil when the key is absent). Load calls it after reading
// the file and BEFORE the strict decode: a config written for a newer berth
// usually names keys this binary does not know, and the operator must be told
// to upgrade, not that the keys are invalid. The key is required even on a
// development build; only the comparison is skipped there (a dev binary has
// no position in the release history).
func checkRequiresBerth(path string, raw any) error {
	bin, release := version.Binary()
	s, isString := raw.(string)
	if raw == nil || (isString && strings.TrimSpace(s) == "") {
		example := "vX.Y.Z"
		suffix := ""
		if release {
			example, suffix = bin.Base(), " (this binary's version)"
		}
		return fmt.Errorf("config %s: requires_berth is missing — declare the oldest berth version this config works with, e.g. \"requires_berth: %s\"%s", path, example, suffix)
	}
	if !isString {
		// YAML reads an unquoted 0.37 or 1 as a number: never a release.
		s = fmt.Sprint(raw)
	}
	req, err := version.ParseRelease(s)
	if !isString || err != nil {
		return fmt.Errorf("config %s: requires_berth %q is not a release version (want vMAJOR.MINOR.PATCH, e.g. v0.37.0)", path, s)
	}
	if release && bin.Compare(req) < 0 {
		return fmt.Errorf("config %s requires berth >= %s, this binary is %s — download a newer release", path, req.String(), bin.String())
	}
	return nil
}
