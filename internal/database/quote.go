package database

import "strings"

// shQuote single-quotes s for safe shell use (mirrors the helper in the steps
// and ssh packages; kept local so engines can build shell command strings
// without a cross-package export).
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
