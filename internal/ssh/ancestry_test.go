package ssh

import (
	"context"
	"strings"
	"testing"
)

// ancestryCmd mirrors the production probe so FakeRunner stubs match. Keep it in
// lockstep with AssertRootControlledAncestry.
func ancestryCmd(paths ...string) string {
	q := make([]string, 0, len(paths))
	for _, p := range paths {
		q = append(q, shQuote(p))
	}
	return "export LC_ALL=C; for p in " + strings.Join(q, " ") +
		"; do if [ -e \"$p\" ] || [ -L \"$p\" ]; then stat -c '%n %u %a %F' \"$p\" || exit 91; fi; done"
}

func TestAncestorsOfIncludesRoot(t *testing.T) {
	// / is a component like any other: a writable root directory would let an
	// unprivileged user replace a top-level entry between probe and mutation.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"/etc/nginx/app.conf", "/,/etc,/etc/nginx"},
		{"/var/www/app", "/,/var,/var/www"},
		{"/swapfile", "/"},
	} {
		if got := strings.Join(AncestorsOf(tc.in), ","); got != tc.want {
			t.Errorf("AncestorsOf(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestAncestryAcceptsRootControlledChain(t *testing.T) {
	f := NewFakeRunner()
	f.On(ancestryCmd("/", "/etc", "/etc/nginx"), Result{
		Stdout: "/ 0 755 directory\n/etc 0 755 directory\n/etc/nginx 0 755 directory\n",
	})
	comps, err := AssertRootControlledAncestry(context.Background(), f, "nginx vhost", "/etc/nginx/app.conf")
	if err != nil {
		t.Fatalf("a root-owned chain must pass; got %v", err)
	}
	if len(comps) != 3 {
		t.Fatalf("want the 3 inspected components returned for the caller's own checks, got %d", len(comps))
	}
	// The returned modes are what lets appdirs add its o+x requirement without
	// paying for a second probe.
	if comps[0].Mode&0o001 == 0 {
		t.Errorf("mode not parsed: %+v", comps[0])
	}
}

func TestAncestryAcceptsAbsentComponents(t *testing.T) {
	// Only root can create an entry under a verified parent, and what root
	// creates is root-owned — so a missing component is safe, not suspicious.
	f := NewFakeRunner()
	f.On(ancestryCmd("/", "/srv", "/srv/apps"), Result{Stdout: "/ 0 755 directory\n/srv 0 755 directory\n"})
	if _, err := AssertRootControlledAncestry(context.Background(), f, "site", "/srv/apps/x"); err != nil {
		t.Fatalf("absent components must pass; got %v", err)
	}
}

func TestAncestryRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		stdout string
		want   string
	}{
		"non-root owner": {
			"/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 1001 755 directory\n",
			"owned by uid 1001",
		},
		"group-writable": {
			"/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 0 775 directory\n",
			"group- or other-writable",
		},
		"world-writable root": {
			"/ 0 777 directory\n/srv 0 755 directory\n/srv/apps 0 755 directory\n",
			"group- or other-writable",
		},
		"symlinked component": {
			"/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 0 777 symbolic link\n",
			"symbolic link",
		},
		"malformed output": {
			"/ 0 755\n",
			"unexpected ancestry probe output",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := NewFakeRunner()
			f.On(ancestryCmd("/", "/srv", "/srv/apps"), Result{Stdout: tc.stdout})
			_, err := AssertRootControlledAncestry(context.Background(), f, "site", "/srv/apps/x")
			if err == nil {
				t.Fatalf("this ancestry must be refused: %q", tc.stdout)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestAncestryHardErrorsOnProbeFailure(t *testing.T) {
	// Exit 91 is the probe's own "stat failed on an existing component" signal.
	// Reading any failure as "absent" would fail open on the one check that
	// gates every root-run mutation.
	for _, code := range []int{91, 1} {
		f := NewFakeRunner()
		f.On(ancestryCmd("/", "/etc"), Result{ExitCode: code, Stderr: "stat: cannot read"})
		if _, err := AssertRootControlledAncestry(context.Background(), f, "x", "/etc/x"); err == nil {
			t.Fatalf("exit %d must be a hard error, not a pass", code)
		}
	}
}
