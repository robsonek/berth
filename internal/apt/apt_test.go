package apt

import (
	"context"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestEnsurePackagesFromDebianStock(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	m := New(f)
	if err := m.EnsurePackages(context.Background(), nil, "nginx"); err != nil {
		t.Fatalf("EnsurePackages() error = %v", err)
	}
}

func TestEnsureRepoVerifiesFingerprint(t *testing.T) {
	f := bssh.NewFakeRunner()
	// The key download succeeds; the fingerprint check is what must fail.
	f.On("curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor --yes -o /usr/share/keyrings/sury-php.gpg",
		bssh.Result{})
	// gpg show-keys returns a fingerprint that does NOT match the pinned one.
	f.On("gpg --show-keys --with-colons /usr/share/keyrings/sury-php.gpg",
		bssh.Result{Stdout: "fpr:::::::::DEADBEEF:\n"})
	m := New(f)
	err := m.EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected fingerprint mismatch error, got %v", err)
	}
}

func TestSuryRepoDefinition(t *testing.T) {
	r := Sury()
	if r.Fingerprint == "" || !strings.Contains(r.URI, "sury") {
		t.Errorf("Sury() looks wrong: %+v", r)
	}
}

func TestUpstreamRepoDefinitions(t *testing.T) {
	// Each upstream repo must carry a full 40-hex pinned fingerprint, a key URL,
	// and a recognizable URI/component so EnsureRepo can register it.
	for _, c := range []struct {
		repo              Repo
		uriContains, comp string
	}{
		{Sury(), "sury", "main"},
		{NginxOrg(), "nginx.org", "nginx"},
		{MariaDBOrg(), "mariadb.org", "main"},
	} {
		if len(c.repo.Fingerprint) != 40 {
			t.Errorf("%s: fingerprint %q is not a full 40-hex value", c.repo.Name, c.repo.Fingerprint)
		}
		if c.repo.KeyURL == "" {
			t.Errorf("%s: missing KeyURL", c.repo.Name)
		}
		if !strings.Contains(c.repo.URI, c.uriContains) {
			t.Errorf("%s: URI %q missing %q", c.repo.Name, c.repo.URI, c.uriContains)
		}
		if len(c.repo.Components) == 0 || c.repo.Components[0] != c.comp {
			t.Errorf("%s: components %v, want first %q", c.repo.Name, c.repo.Components, c.comp)
		}
	}
}

func TestIsAptLockBusy(t *testing.T) {
	for _, s := range []string{
		"E: Could not get lock /var/lib/apt/lists/lock. It is held by process 15055 (apt-get)",
		"E: Unable to lock directory /var/lib/apt/lists/",
		"E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 42",
	} {
		if !isAptLockBusy(s) {
			t.Errorf("isAptLockBusy(%q) = false, want true", s)
		}
	}
	if isAptLockBusy("E: Failed to fetch ... 404 Not Found") {
		t.Error("a non-lock error must not be treated as lock contention")
	}
}

func TestEnsureRepoRetriesOnAptLock(t *testing.T) {
	prev := aptLockSleep
	aptLockSleep = func() {}
	defer func() { aptLockSleep = prev }()

	f := bssh.NewFakeRunner()
	f.On("curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor --yes -o /usr/share/keyrings/sury-php.gpg", bssh.Result{})
	f.On("gpg --show-keys --with-colons /usr/share/keyrings/sury-php.gpg",
		bssh.Result{Stdout: "fpr:::::::::" + Sury().Fingerprint + ":\n"})
	// First update hits a concurrent unattended-upgrades holding the lists lock;
	// the retry, once the holder releases, succeeds.
	f.OnSeq("apt-get update",
		bssh.Result{ExitCode: 100, Stderr: "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 999 (apt-get)"},
		bssh.Result{ExitCode: 0})

	if err := New(f).EnsureRepo(context.Background(), Sury()); err != nil {
		t.Fatalf("EnsureRepo should wait out apt-lock contention; got %v", err)
	}
	var updates int
	for _, c := range f.Calls() {
		if c.Cmd == "apt-get update" {
			updates++
		}
	}
	if updates < 2 {
		t.Errorf("expected apt-get update to be retried past the lock; got %d call(s)", updates)
	}
}

func TestEnsureRepoUsesKeyURLNotURISuffix(t *testing.T) {
	// nginx.org's key lives at a path unrelated to URI+apt.gpg; EnsureRepo must
	// fetch from repo.KeyURL. Stub the exact KeyURL-based download command.
	f := bssh.NewFakeRunner()
	f.On("curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor --yes -o /usr/share/keyrings/nginx-org.gpg", bssh.Result{})
	f.On("gpg --show-keys --with-colons /usr/share/keyrings/nginx-org.gpg", bssh.Result{Stdout: "fpr:::::::::DEADBEEF:\n"})
	// Wrong fingerprint -> aborts, but only AFTER the KeyURL-based download was
	// the command actually issued (proving KeyURL is used, not URI+apt.gpg).
	if err := New(f).EnsureRepo(context.Background(), NginxOrg()); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected fingerprint mismatch, got %v", err)
	}
}
