package integration

// This file carries NO integration build tag on purpose: envOverwriteScript
// rewrites a live shared/.env as root, so its shell semantics are pinned by a
// real-/bin/sh test (envoverwrite_test.go) that must run in the plain unit
// suite (`go test ./...`), not only when the integration tag is set.

import "strings"

// sqQuote single-quotes s for safe embedding in a shell command.
func sqQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// envOverwriteScript builds the remote script that swaps the DB_PASSWORD and
// APP_KEY values of a live shared/.env in place. The two replacement values
// are awk's FIRST input file — SSH stdin, one per line — so they never touch
// argv, the command string, or stdout (the production probes' transport
// contract). `cat > file` rewrites through the existing inode, so the site
// user's ownership and 0600 mode survive the root write.
//
// Hardening (the original NR==FNR form truncated the .env on empty stdin —
// with zero stdin records NR stays equal to FNR for every line of the SECOND
// file, so the whole .env was swallowed as "values" and the rewrite emptied
// it):
//   - stdin records are discriminated by FILENAME=="-" (the literal ARGV
//     operand), never by record counters;
//   - exactly 2 stdin records are required BEFORE any replacement: the first
//     .env record aborts (exit 9) on a wrong count, and the END guard catches
//     an empty .env, so a malformed stdin can never reach `cat > env`;
//   - the secret-bearing temp file is removed on EVERY exit path: an EXIT trap
//     at the script head plus an explicit rm on the awk failure branch.
func envOverwriteScript(envPath string) string {
	q := sqQuote(envPath)
	return `tmp=$(mktemp) || exit 1; trap 'rm -f -- "$tmp"' EXIT; ` +
		`awk 'FILENAME=="-"{v[++n]=$0;next} n!=2{exit 9} /^DB_PASSWORD=/{print "DB_PASSWORD=" v[1];next} /^APP_KEY=/{print "APP_KEY=" v[2];next} {print} END{if(n!=2)exit 9}' - ` + q + ` > "$tmp" || { rm -f -- "$tmp"; exit 9; }; ` +
		`cat "$tmp" > ` + q
}
