package ssh

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// AncestryComponent is one existing path component as reported by the ancestry
// probe. Callers get these back so they can add their own requirements without
// paying for a second round-trip.
type AncestryComponent struct {
	Path string
	UID  string // decimal, as stat's %u prints it ("0" for root)
	Mode uint32 // permission bits from stat's %a, including any setuid/setgid/sticky digit
	Type string // stat's %F, e.g. "directory", "symbolic link", "regular file"
}

// AncestorsOf returns every ancestor of p from / down to path.Dir(p) inclusive:
// /var/www/app -> ["/", "/var", "/var/www"].
//
// / is included on purpose: it is a component like any other, and a
// non-root-owned or writable root directory would let an unprivileged user
// replace an existing top-level entry (or create a missing one) between a probe
// and the mutation it guards.
func AncestorsOf(p string) []string {
	out := []string{"/"}
	dir := path.Dir(p)
	if dir == "/" || dir == "." {
		return out
	}
	cur := ""
	for _, part := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		cur += "/" + part
		out = append(out, cur)
	}
	return out
}

// AssertRootControlledAncestry refuses unless every EXISTING ancestor of every
// given path is a real directory owned by uid 0 and neither group- nor
// other-writable. Absent components pass: only root can create them under a
// verified parent, and what root creates is root-owned.
//
// This is the premise every root-run filesystem mutation rests on. Ownership of
// a file protects its inode, not its pathname: whoever can write the parent
// directory can unlink an entry and put their own inode under the same name,
// which is what a privileged reader or a service will then consume. It also
// closes the staging window — berth's privileged write creates its temp file
// beside the destination, and a writable parent would let an attacker swap that
// temp file for a hard link to a file they keep and continue rewriting.
//
// The probe deliberately does not follow symlinks (no -L): a symlinked
// component must be refused, not resolved. It costs one round-trip regardless
// of path depth. Exit 91 is the probe's own signal that stat failed on a
// component that exists — a hard error, never read as "absent", because
// failing open here would defeat the guard entirely.
//
// The returned components are those that exist, in probe order.
func AssertRootControlledAncestry(ctx context.Context, r Runner, subject string, paths ...string) ([]AncestryComponent, error) {
	seen := map[string]bool{}
	var probe []string
	for _, p := range paths {
		for _, a := range AncestorsOf(p) {
			if !seen[a] {
				seen[a] = true
				probe = append(probe, a)
			}
		}
	}
	if len(probe) == 0 {
		return nil, nil
	}
	q := make([]string, 0, len(probe))
	for _, p := range probe {
		q = append(q, shQuote(p))
	}
	// %F goes last: file types contain spaces, and the paths berth probes cannot.
	cmd := "export LC_ALL=C; for p in " + strings.Join(q, " ") +
		"; do if [ -e \"$p\" ] || [ -L \"$p\" ]; then stat -c '%n %u %a %F' \"$p\" || exit 91; fi; done"
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("probing the directory ancestry for %s failed: %s", subject, strings.TrimSpace(res.Stderr))
	}
	var comps []AncestryComponent
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("unexpected ancestry probe output for %s: %q", subject, line)
		}
		name, uid, modeStr, ftype := fields[0], fields[1], fields[2], strings.Join(fields[3:], " ")
		if ftype != "directory" {
			return nil, fmt.Errorf("refusing to provision %s: %s is a %s, not a directory — berth mutates paths under it as root, so every component must be a root-owned directory; inspect and fix it before re-running", subject, name, ftype)
		}
		if uid != "0" {
			return nil, fmt.Errorf("refusing to provision %s: %s is owned by uid %s, not root — a non-root owner can replace an entry berth is about to create as root, so what a privileged reader later opens would be theirs; chown it to root or choose a path under a root-owned tree such as /var/www", subject, name, uid)
		}
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("unexpected mode %q for %s while probing ancestry for %s", modeStr, name, subject)
		}
		if mode&0o022 != 0 {
			return nil, fmt.Errorf("refusing to provision %s: %s is group- or other-writable (mode %s) — anyone in that group can replace an entry berth is about to create as root; chmod g-w,o-w it before re-running", subject, name, modeStr)
		}
		comps = append(comps, AncestryComponent{Path: name, UID: uid, Mode: uint32(mode), Type: ftype})
	}
	return comps, nil
}
