package version

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
)

// These patterns deliberately replace golang.org/x/mod/semver: that package
// reads the describe suffix as a SemVer pre-release and so sorts
// "v0.36.0-3-ge363573" BEFORE "v0.36.0", while that build is v0.36.0 plus
// three commits and must sort after its tag.
var (
	releaseRE = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	buildRE   = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([1-9][0-9]*)-g([0-9a-f]{4,40}))?(?:-dirty)?$`)
)

// V is a parsed berth version. Commits and Hash come from git describe (the
// number of commits past the tag and the abbreviated commit hash); they are
// 0 and "" for a release.
type V struct {
	Major, Minor, Patch int
	Commits             int
	Hash                string
}

// ParseRelease accepts a release version only: "vX.Y.Z" or "X.Y.Z" without
// leading zeros. A describe suffix, a pre-release tag or "-dirty" is refused.
func ParseRelease(s string) (V, error) {
	m := releaseRE.FindStringSubmatch(s)
	if m == nil {
		return V{}, fmt.Errorf("version %q is not a release version (want vX.Y.Z)", s)
	}
	n, err := numbers(m[1:4]...)
	if err != nil {
		return V{}, fmt.Errorf("version %q: %w", s, err)
	}
	return V{Major: n[0], Minor: n[1], Patch: n[2]}, nil
}

// ParseBuild accepts what a berth binary reports as its version: a release
// form, optionally followed by a git describe "-N-gHASH" suffix and/or
// "-dirty". The dirty flag is dropped (it is working-tree state, not a
// position in history). false means a development build ("dev", a bare
// --always hash, or anything else that is not a version).
func ParseBuild(s string) (V, bool) {
	m := buildRE.FindStringSubmatch(s)
	if m == nil {
		return V{}, false
	}
	n, err := numbers(m[1:5]...)
	if err != nil {
		return V{}, false
	}
	return V{Major: n[0], Minor: n[1], Patch: n[2], Commits: n[3], Hash: m[5]}, true
}

// Binary parses this binary's Version with ParseBuild; false marks a
// development build.
func Binary() (V, bool) {
	return ParseBuild(Version)
}

// Compare returns -1, 0 or 1 ordering by (Major, Minor, Patch, Commits). A
// describe build sorts after its tag and before the next release; Hash is
// not compared, so two builds the same distance past one tag are equal.
func (v V) Compare(o V) int {
	return cmp.Or(
		cmp.Compare(v.Major, o.Major),
		cmp.Compare(v.Minor, o.Minor),
		cmp.Compare(v.Patch, o.Patch),
		cmp.Compare(v.Commits, o.Commits),
	)
}

// String renders "v1.0.0" for a release and "v0.36.0-3-ge363573" for a
// describe build.
func (v V) String() string {
	if v.Commits == 0 {
		return v.Base()
	}
	return fmt.Sprintf("%s-%d-g%s", v.Base(), v.Commits, v.Hash)
}

// Base renders the release part only, e.g. "v0.36.0" for
// "v0.36.0-3-ge363573".
func (v V) Base() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// numbers converts the regexp's numeric groups; an empty group (no describe
// suffix) stays 0. Atoi still fails on a component too large for an int.
func numbers(groups ...string) ([]int, error) {
	out := make([]int, len(groups))
	for i, g := range groups {
		if g == "" {
			continue
		}
		n, err := strconv.Atoi(g)
		if err != nil {
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}
