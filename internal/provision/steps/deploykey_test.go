package steps

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// testDeployKey is one in-process ed25519 deploy key as the operator would
// keep it locally: the private-key file berth reads (repository_key) plus the
// public facts the tests compare against.
type testDeployKey struct {
	path          string // the local private-key file
	private       []byte // its exact bytes
	authorizedKey string // "<type> <base64>", no comment
	fingerprint   string // ssh.FingerprintSHA256
}

// newTestDeployKey generates an ed25519 key and writes it to a temp file in
// OpenSSH format — passphrase-protected when passphrase is non-empty.
func newTestDeployKey(t *testing.T, passphrase string) testDeployKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "deploy_key")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return testDeployKey{
		path:          path,
		private:       body,
		authorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		fingerprint:   ssh.FingerprintSHA256(sshPub),
	}
}

// keyBlob is the base64 half of an authorized key — what an error must never
// echo (fingerprints only).
func keyBlob(authorizedKey string) string { return strings.Fields(authorizedKey)[1] }

const (
	testDeployUser    = "appuser"
	testDeployKeyPath = "/home/appuser/.ssh/id_ed25519"
	testKnownHosts    = "/home/appuser/.ssh/known_hosts"
)

// deployKeyServer is the single-site test server with a repository and the
// given repository_key, running as appuser.
func deployKeyServer(t *testing.T, keyPath string) *config.Server {
	t.Helper()
	s := testServerWithKey(t)
	s.Sites[0].User = testDeployUser
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	s.Sites[0].RepositoryKey = keyPath
	return s
}

// hostKeyDeriveCmd is hostDeployKey's read probe (root runs it; it only
// prints the public half).
func hostKeyDeriveCmd() string { return "ssh-keygen -y -f " + shQuote(testDeployKeyPath) }

// knownHostLookupCmd is accounts.Check's unchanged known-host probe.
func knownHostLookupCmd() string {
	return "ssh-keygen -F " + shQuote("github.com") + " -f " + shQuote(testKnownHosts) + " >/dev/null 2>&1"
}

// knownHostsScanCmd is ensureDeployKey's unchanged known_hosts heal.
func knownHostsScanCmd() string {
	return "sudo -u " + testDeployUser + " sh -c " + shQuote("ssh-keygen -F "+shQuote("github.com")+" -f "+shQuote(testKnownHosts)+" >/dev/null 2>&1 || ssh-keyscan "+shQuote("github.com")+" >> "+shQuote(testKnownHosts))
}

// stubDeployKeyCheckBase stubs every accounts.Check probe ahead of the
// deploy-key loop for a fully provisioned berth + appuser.
func stubDeployKeyCheckBase(t *testing.T, f *bssh.FakeRunner, s *config.Server) {
	t.Helper()
	want := authorizedKeys(testOperatorKey)
	sudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, testDeployUser, sudoers, want)
	stubReloadScriptOK(t, f, s)
}

// stubDeployKeyApplyBase stubs a full fresh accounts.Apply up to the deploy
// key, plus the known_hosts heal and the console probe after it.
func stubDeployKeyApplyBase(f *bssh.FakeRunner) {
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, testDeployUser)
	stubReloadScriptAbsent(f)
	f.On(knownHostsScanCmd(), bssh.Result{})
	stubConsoleLocked(f)
}

// assertNoKeyInCommands fails when a command string carries private-key
// material — the key must ride stdin only.
func assertNoKeyInCommands(t *testing.T, f *bssh.FakeRunner, key testDeployKey) {
	t.Helper()
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "PRIVATE KEY") || strings.Contains(c.Cmd, strings.TrimSpace(string(key.private))) {
			t.Errorf("a command string carries the private key: %q", c.Cmd)
		}
	}
}

func TestDeployKeyFromFileInstallsWhenAbsent(t *testing.T) {
	chdirTemp(t)
	key := newTestDeployKey(t, "")
	s := deployKeyServer(t, key.path)
	f := bssh.NewFakeRunner()
	stubDeployKeyApplyBase(f)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{ExitCode: 1}) // no key on the host
	privWrite := writeAsUserModeCmd(testDeployUser, testDeployKeyPath, 0o600)
	pubWrite := writeAsUserModeCmd(testDeployUser, testDeployKeyPath+".pub", 0o644)
	f.On(privWrite, bssh.Result{})
	f.On(pubWrite, bssh.Result{})

	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var privStdin, pubStdin []byte
	var sawPriv, sawPub bool
	for _, c := range f.Calls() {
		switch c.Cmd {
		case privWrite:
			privStdin, sawPriv = c.Stdin, true
		case pubWrite:
			pubStdin, sawPub = c.Stdin, true
		}
		if strings.Contains(c.Cmd, "ssh-keygen -t") {
			t.Errorf("repository_key set: berth must install it, never generate a key: %q", c.Cmd)
		}
	}
	if !sawPriv {
		t.Fatalf("expected the private key written as %s with mode 0600; calls:\n%s", testDeployUser, strings.Join(callCmds(f), "\n"))
	}
	if string(privStdin) != string(key.private) {
		t.Errorf("private key content = %q, want the local repository_key bytes", privStdin)
	}
	if !sawPub {
		t.Fatalf("expected the .pub written as %s with mode 0644; calls:\n%s", testDeployUser, strings.Join(callCmds(f), "\n"))
	}
	if want := key.authorizedKey + " " + testDeployUser + "@github.com\n"; string(pubStdin) != want {
		t.Errorf(".pub content = %q, want %q (the <user>@<git-host> comment, as when generating)", pubStdin, want)
	}
	if !calledCmd(f, knownHostsScanCmd()) {
		t.Errorf("the known_hosts heal must stay as it is; calls:\n%s", strings.Join(callCmds(f), "\n"))
	}
	assertNoKeyInCommands(t, f, key)
	// The tenant writes into its own ~/.ssh: no root WriteFile may touch it.
	assertOnlyTenantMutates(t, f, testDeployUser, "/home/"+testDeployUser+"/.ssh")
}

func TestDeployKeyFromFileSatisfiedWhenEqual(t *testing.T) {
	chdirTemp(t)
	key := newTestDeployKey(t, "")
	s := deployKeyServer(t, key.path)
	f := bssh.NewFakeRunner()
	stubDeployKeyCheckBase(t, f, s)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	// Real ssh-keygen -y prints the key's stored comment as a third field.
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: key.authorizedKey + " some-comment\n"})
	f.On("test -e "+shQuote(testDeployKeyPath+".pub"), bssh.Result{})
	f.On(knownHostLookupCmd(), bssh.Result{})
	stubConsoleLocked(f)

	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with the host key equal to repository_key; got %+v", cr)
	}
	if strings.Contains(cr.Reason, "deploy key") {
		t.Errorf("Reason must not be about the deploy key: %q", cr.Reason)
	}
	// Satisfied must come from COMPARING the keys, not from mere presence.
	if !calledCmd(f, hostKeyDeriveCmd()) {
		t.Errorf("Check must derive the host key's public half to compare it; calls:\n%s", strings.Join(callCmds(f), "\n"))
	}
	if len(f.Writes()) != 0 {
		t.Errorf("Check wrote %d file(s)", len(f.Writes()))
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "mv -f") {
			t.Errorf("Check issued a write: %q", c.Cmd)
		}
	}
}

func TestDeployKeyFromFileMismatchRefusesWithoutForce(t *testing.T) {
	chdirTemp(t)
	key := newTestDeployKey(t, "")
	other := newTestDeployKey(t, "")
	s := deployKeyServer(t, key.path)

	// Check refuses...
	f := bssh.NewFakeRunner()
	stubDeployKeyCheckBase(t, f, s)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: other.authorizedKey + "\n"})
	_, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	assertDeployKeyMismatchError(t, "Check", err, key, other)

	// ...and so does Apply, before writing anything over the host's key.
	f = bssh.NewFakeRunner()
	stubDeployKeyApplyBase(f)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: other.authorizedKey + "\n"})
	err = Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	assertDeployKeyMismatchError(t, "Apply", err, key, other)
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, testDeployKeyPath) && strings.Contains(c.Cmd, "mv -f") {
			t.Errorf("Apply wrote over the host's deploy key without --force: %q", c.Cmd)
		}
	}
}

// assertDeployKeyMismatchError pins the refusal: both fingerprints and the
// remedy, led by the NARROW override (--only accounts --force, which also
// lets that step overwrite a foreign authorized_keys), never key material.
func assertDeployKeyMismatchError(t *testing.T, who string, err error, local, host testDeployKey) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a refusal for a host key that differs from repository_key", who)
	}
	msg := err.Error()
	for _, want := range []string{host.fingerprint, local.fingerprint, "re-run with --only accounts --force", "authorized_keys"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%s: error must contain %q; got %v", who, want, err)
		}
	}
	if narrow, bare := strings.Index(msg, "--only accounts --force"), strings.Index(msg, "bare --force"); bare >= 0 && bare < narrow {
		t.Errorf("%s: the remedy must lead with --only accounts --force, not a bare --force; got %v", who, err)
	}
	for _, leak := range []string{"PRIVATE KEY", keyBlob(local.authorizedKey), keyBlob(host.authorizedKey)} {
		if strings.Contains(msg, leak) {
			t.Errorf("%s: error leaks key material (%q); got %v", who, leak, err)
		}
	}
}

func TestDeployKeyFromFileMismatchReplacesWithForce(t *testing.T) {
	chdirTemp(t)
	key := newTestDeployKey(t, "")
	other := newTestDeployKey(t, "")
	s := deployKeyServer(t, key.path)

	// Check under --force: unsatisfied (Apply replaces it), not a refusal.
	f := bssh.NewFakeRunner()
	stubDeployKeyCheckBase(t, f, s)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: other.authorizedKey + "\n"})
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{Force: true}, s, f)
	if err != nil {
		t.Fatalf("Check(--force) error = %v", err)
	}
	if cr.Satisfied || !strings.Contains(cr.Reason, "deploy key") {
		t.Errorf("Check(--force) = %+v, want unsatisfied about the deploy key", cr)
	}

	f = bssh.NewFakeRunner()
	stubDeployKeyApplyBase(f)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: other.authorizedKey + "\n"})
	privWrite := writeAsUserModeCmd(testDeployUser, testDeployKeyPath, 0o600)
	pubWrite := writeAsUserModeCmd(testDeployUser, testDeployKeyPath+".pub", 0o644)
	f.On(privWrite, bssh.Result{})
	f.On(pubWrite, bssh.Result{})
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{Force: true}, s, f); err != nil {
		t.Fatalf("Apply(--force) error = %v", err)
	}
	if got := writtenContent(f, testDeployKeyPath); string(got) != string(key.private) {
		t.Errorf("private key content = %q, want the local repository_key bytes", got)
	}
	if got, want := string(writtenContent(f, testDeployKeyPath+".pub")), key.authorizedKey+" "+testDeployUser+"@github.com\n"; got != want {
		t.Errorf(".pub content = %q, want %q", got, want)
	}
	assertNoKeyInCommands(t, f, key)
}

func TestDeployKeyFromFileRestoresMissingPubOnly(t *testing.T) {
	// The host already holds repository_key but lost its .pub: Check flags
	// the gap, Apply restores the .pub alone and never rewrites the private
	// key it just proved identical.
	chdirTemp(t)
	key := newTestDeployKey(t, "")
	s := deployKeyServer(t, key.path)

	f := bssh.NewFakeRunner()
	stubDeployKeyCheckBase(t, f, s)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: key.authorizedKey + "\n"})
	f.On("test -e "+shQuote(testDeployKeyPath+".pub"), bssh.Result{ExitCode: 1})
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil || cr.Satisfied || !strings.Contains(cr.Reason, ".pub") {
		t.Fatalf("Check() = (%+v, %v), want unsatisfied naming the missing .pub", cr, err)
	}

	f = bssh.NewFakeRunner()
	stubDeployKeyApplyBase(f)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: key.authorizedKey + "\n"})
	f.On("test -e "+shQuote(testDeployKeyPath+".pub"), bssh.Result{ExitCode: 1})
	pubWrite := writeAsUserModeCmd(testDeployUser, testDeployKeyPath+".pub", 0o644)
	f.On(pubWrite, bssh.Result{})
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, pubWrite) {
		t.Errorf("expected the .pub restored; calls:\n%s", strings.Join(callCmds(f), "\n"))
	}
	if calledCmd(f, writeAsUserModeCmd(testDeployUser, testDeployKeyPath, 0o600)) {
		t.Error("the private key is already the configured one; it must not be rewritten")
	}
}

func TestDeployKeyFromFilePassphraseFailsBeforeHost(t *testing.T) {
	chdirTemp(t)
	key := newTestDeployKey(t, "correct horse")
	s := deployKeyServer(t, key.path)
	want := "repository_key " + key.path + " is passphrase-protected; a deploy key must work unattended"
	for _, run := range deployKeyRuns() {
		f := bssh.NewFakeRunner()
		err := run.call(s, f)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", run.name, err, want)
		}
		assertTouchedNothing(t, run.name, f)
	}
}

func TestDeployKeyFromFileMissingFile(t *testing.T) {
	chdirTemp(t)
	missing := filepath.Join(t.TempDir(), "no-such-key")
	s := deployKeyServer(t, missing)
	want := "repository_key " + missing + ": "
	for _, run := range deployKeyRuns() {
		f := bssh.NewFakeRunner()
		err := run.call(s, f)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want it to start with %q", run.name, err, want)
		}
		assertTouchedNothing(t, run.name, f)
	}
}

// deployKeyRuns is Check and Apply as plain calls: the local key loads first
// in both, so a bad repository_key must stop either before any probe.
func deployKeyRuns() []struct {
	name string
	call func(*config.Server, *bssh.FakeRunner) error
} {
	return []struct {
		name string
		call func(*config.Server, *bssh.FakeRunner) error
	}{
		{"Check", func(s *config.Server, f *bssh.FakeRunner) error {
			_, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
			return err
		}},
		{"Apply", func(s *config.Server, f *bssh.FakeRunner) error {
			return Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
		}},
	}
}

// assertTouchedNothing: a workstation-side key problem is refused before the
// host is probed at all — no ssh-keygen, no write, no command whatsoever.
func assertTouchedNothing(t *testing.T, who string, f *bssh.FakeRunner) {
	t.Helper()
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "ssh-keygen") || strings.Contains(c.Cmd, "mv -f") {
			t.Errorf("%s: touched the host's deploy key before loading repository_key: %q", who, c.Cmd)
		}
	}
	if len(f.Calls()) != 0 {
		t.Errorf("%s: issued %d command(s) before refusing the local key: %v", who, len(f.Calls()), callCmds(f))
	}
	if len(f.Writes()) != 0 {
		t.Errorf("%s: wrote %d file(s)", who, len(f.Writes()))
	}
}

func TestLoadLocalDeployKeyDerivesPublicFacts(t *testing.T) {
	key := newTestDeployKey(t, "")
	got, err := loadLocalDeployKey(key.path)
	if err != nil {
		t.Fatalf("loadLocalDeployKey() error = %v", err)
	}
	if string(got.Private) != string(key.private) {
		t.Errorf("Private = %q, want the file's bytes", got.Private)
	}
	if got.AuthorizedKey != key.authorizedKey {
		t.Errorf("AuthorizedKey = %q, want %q (type + base64, no comment)", got.AuthorizedKey, key.authorizedKey)
	}
	if got.Fingerprint != key.fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, key.fingerprint)
	}
}

func TestLoadLocalDeployKeyNormalizesCRLF(t *testing.T) {
	// A key saved with CRLF line endings (a Windows editor, a git checkout
	// with autocrlf) parses fine locally, but OpenSSH on the host refuses to
	// load it ("invalid format"): installed verbatim it breaks every deploy,
	// and the next Check refuses the very key berth installed. The installed
	// bytes must be the LF form.
	key := newTestDeployKey(t, "")
	crlfPath := filepath.Join(t.TempDir(), "deploy_key_crlf")
	crlf := strings.ReplaceAll(string(key.private), "\n", "\r\n")
	if err := os.WriteFile(crlfPath, []byte(crlf), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadLocalDeployKey(crlfPath)
	if err != nil {
		t.Fatalf("loadLocalDeployKey(CRLF copy) error = %v", err)
	}
	// Messages report counts, never the key bytes.
	if n := strings.Count(string(got.Private), "\r"); n != 0 {
		t.Errorf("Private still carries %d CR byte(s)", n)
	}
	if !strings.HasSuffix(string(got.Private), "\n") || strings.HasSuffix(string(got.Private), "\n\n") {
		t.Errorf("Private must end with exactly one newline (last bytes %q)", got.Private[max(0, len(got.Private)-3):])
	}
	if string(got.Private) != string(key.private) {
		t.Errorf("Private (%d bytes) differs from the LF original (%d bytes)", len(got.Private), len(key.private))
	}
	if got.Fingerprint != key.fingerprint {
		t.Errorf("Fingerprint = %q, want the LF original's %q", got.Fingerprint, key.fingerprint)
	}
}

func TestLoadLocalDeployKeyStripsEveryCR(t *testing.T) {
	// A doubled conversion (CRLF applied twice) leaves \r\r\n endings. The
	// Go parser still loads them, so rewriting only CRLF pairs would install
	// "\r\n" lines OpenSSH refuses — every CR must go.
	key := newTestDeployKey(t, "")
	path := filepath.Join(t.TempDir(), "deploy_key_crcrlf")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(key.private), "\n", "\r\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadLocalDeployKey(path)
	if err != nil {
		t.Fatalf("loadLocalDeployKey(\\r\\r\\n copy) error = %v", err)
	}
	if n := strings.Count(string(got.Private), "\r"); n != 0 {
		t.Errorf("Private still carries %d CR byte(s)", n)
	}
	if string(got.Private) != string(key.private) {
		t.Errorf("Private (%d bytes) differs from the LF original (%d bytes)", len(got.Private), len(key.private))
	}
	if got.Fingerprint != key.fingerprint {
		t.Errorf("Fingerprint = %q, want the LF original's %q", got.Fingerprint, key.fingerprint)
	}
}

func TestLoadLocalDeployKeyAppendsMissingNewline(t *testing.T) {
	// OpenSSH refuses a private key whose last line has no newline; berth
	// appends exactly one so the installed key loads.
	key := newTestDeployKey(t, "")
	path := filepath.Join(t.TempDir(), "deploy_key_nonl")
	if err := os.WriteFile(path, []byte(strings.TrimRight(string(key.private), "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadLocalDeployKey(path)
	if err != nil {
		t.Fatalf("loadLocalDeployKey(no final newline) error = %v", err)
	}
	if string(got.Private) != string(key.private) {
		t.Errorf("Private (%d bytes, ends %q) is not the file plus exactly one newline (%d bytes)",
			len(got.Private), got.Private[max(0, len(got.Private)-3):], len(key.private))
	}
}

func TestLoadLocalDeployKeyExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	key := newTestDeployKey(t, "")
	if err := os.WriteFile(filepath.Join(home, "deploy_key"), key.private, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadLocalDeployKey("~/deploy_key")
	if err != nil {
		t.Fatalf("loadLocalDeployKey(~/deploy_key) error = %v", err)
	}
	if got.Fingerprint != key.fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, key.fingerprint)
	}
}

func TestLoadLocalDeployKeyRefusesNonKey(t *testing.T) {
	// Pointing repository_key at the .pub is the likely slip: refused with
	// the path, before any host probe.
	key := newTestDeployKey(t, "")
	pubPath := key.path + ".pub"
	if err := os.WriteFile(pubPath, []byte(key.authorizedKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadLocalDeployKey(pubPath)
	if err == nil || !strings.Contains(err.Error(), "repository_key "+pubPath) {
		t.Fatalf("err = %v, want a refusal naming %s", err, pubPath)
	}
}

func TestHostDeployKeyReadsFirstTwoFields(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{Stdout: "ssh-ed25519 AAAAblob appuser@github.com\n"})
	got, present, err := hostDeployKey(context.Background(), f, testDeployUser)
	if err != nil || !present || got != "ssh-ed25519 AAAAblob" {
		t.Fatalf("hostDeployKey() = (%q, %v, %v), want (\"ssh-ed25519 AAAAblob\", true, nil)", got, present, err)
	}

	f = bssh.NewFakeRunner()
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{ExitCode: 1})
	got, present, err = hostDeployKey(context.Background(), f, testDeployUser)
	if err != nil || present || got != "" {
		t.Fatalf("absent: hostDeployKey() = (%q, %v, %v), want (\"\", false, nil)", got, present, err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "ssh-keygen") {
			t.Errorf("an absent key must not be derived: %q", c.Cmd)
		}
	}
}

func TestHostDeployKeyUnreadableCountsAsDifferent(t *testing.T) {
	// A key ssh-keygen cannot read (corrupt, or passphrase-protected on the
	// host) is present but matches nothing: without --force it is refused
	// like any other mismatch, with --force it is replaced.
	chdirTemp(t)
	key := newTestDeployKey(t, "")
	s := deployKeyServer(t, key.path)
	f := bssh.NewFakeRunner()
	stubDeployKeyCheckBase(t, f, s)
	f.On("test -e "+shQuote(testDeployKeyPath), bssh.Result{})
	f.On(hostKeyDeriveCmd(), bssh.Result{ExitCode: 255, Stderr: `Load key "/home/appuser/.ssh/id_ed25519": invalid format`})
	_, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), key.fingerprint) {
		t.Fatalf("err = %v, want a --force refusal naming the local fingerprint", err)
	}
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{Force: true}, s, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("Check(--force) = (%+v, %v), want unsatisfied so Apply replaces it", cr, err)
	}
}
