package ssh

import (
	"context"
	"strings"
	"testing"
)

// The privileged write path is only sound for destinations root controls. These
// tests pin each half of that contract: the static half (this file) must reject
// before a single command reaches the host, because the staging step itself —
// a temp file created beside the destination — is what an attacker-controlled
// directory abuses.
func TestValidateRootDestinationRejections(t *testing.T) {
	for name, tc := range map[string]struct {
		spec FileSpec
		want string
	}{
		"unprivileged write": {
			FileSpec{Path: "/etc/x", Mode: 0o644},
			"Sudo must be true",
		},
		"relative path": {
			FileSpec{Path: "etc/x", Mode: 0o644, Sudo: true},
			"absolute, clean path",
		},
		"unclean path": {
			FileSpec{Path: "/etc/../etc/x", Mode: 0o644, Sudo: true},
			"absolute, clean path",
		},
		"non-root owner": {
			FileSpec{Path: "/etc/x", Mode: 0o644, Owner: "deploy", Sudo: true},
			"writeFileAsUser",
		},
		"non-root group": {
			FileSpec{Path: "/etc/x", Mode: 0o644, Group: "deploy", Sudo: true},
			"root:root",
		},
		"group-writable mode": {
			FileSpec{Path: "/etc/x", Mode: 0o664, Sudo: true},
			"group- or other-writable",
		},
		"world-writable mode": {
			FileSpec{Path: "/etc/x", Mode: 0o666, Sudo: true},
			"group- or other-writable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateRootDestination(tc.spec)
			if err == nil {
				t.Fatalf("spec %+v was accepted; the privileged path must refuse it", tc.spec)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateRootDestinationAcceptsRootOwnedSpecs(t *testing.T) {
	// The counterweight: every shape production actually uses must pass, or the
	// contract would be a wall rather than a guard. An empty Owner/Group means
	// root (installCmd's default), which is why both forms are covered.
	for name, spec := range map[string]FileSpec{
		"explicit root":        {Path: "/etc/nginx/app.conf", Mode: 0o644, Owner: "root", Group: "root", Sudo: true},
		"implicit root":        {Path: "/etc/apt/apt.conf.d/99x", Mode: 0o644, Sudo: true},
		"executable script":    {Path: "/usr/local/sbin/berth-backup-x", Mode: 0o755, Owner: "root", Group: "root", Sudo: true},
		"private key material": {Path: "/etc/ssl/berth/x.key", Mode: 0o600, Owner: "root", Group: "root", Sudo: true},
		"sudoers drop-in":      {Path: "/etc/sudoers.d/berth", Mode: 0o440, Owner: "root", Group: "root", Sudo: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRootDestination(spec); err != nil {
				t.Errorf("a legitimate privileged write was refused: %v", err)
			}
		})
	}
}

func TestFakeRunnerEnforcesTheSameContract(t *testing.T) {
	// Without this, a unit test would accept a FileSpec production rejects and
	// the difference would only surface on a real host.
	f := NewFakeRunner()
	err := f.WriteFile(context.Background(), FileSpec{Path: "/home/deploy/.ssh/authorized_keys", Owner: "deploy", Mode: 0o600, Sudo: true})
	if err == nil {
		t.Fatal("FakeRunner accepted an account-owned privileged write")
	}
	if len(f.Writes()) != 0 {
		t.Errorf("a refused write must not be recorded; got %+v", f.Writes())
	}
}
