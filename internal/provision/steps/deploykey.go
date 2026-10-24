package steps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// localDeployKey is a site's repository_key as read on the workstation: the
// exact private-key bytes berth installs, plus the public facts it compares
// and reports. Only Private is secret. It reaches the host on stdin
// (writeFileAsUser) and never appears in a command, an error or a warning;
// errors name keys by Fingerprint alone.
type localDeployKey struct {
	Private       []byte
	AuthorizedKey string // "<type> <base64>", no comment
	Fingerprint   string // ssh.FingerprintSHA256
}

// loadLocalDeployKey reads and parses the private key at path (a leading ~
// is the local home). The key must work unattended — a deploy runs without
// anyone to type a passphrase — so a passphrase-protected key is refused
// here rather than installed and found broken at the first deploy.
//
// Private keeps the file's bytes, plus a final newline when the file lacks
// one: OpenSSH refuses to load a private key without it ("invalid format"),
// so installing the bytes verbatim would leave a key that neither git nor
// the next Check's ssh-keygen -y can read.
func loadLocalDeployKey(path string) (localDeployKey, error) {
	b, err := os.ReadFile(expandHomeLocal(path))
	if err != nil {
		return localDeployKey{}, fmt.Errorf("repository_key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return localDeployKey{}, fmt.Errorf("repository_key %s is passphrase-protected; a deploy key must work unattended", path)
		}
		// The parser's errors describe the format, never the bytes.
		return localDeployKey{}, fmt.Errorf("repository_key %s: not a private key ssh can load (point it at the private half, not the .pub): %w", path, err)
	}
	if !bytes.HasSuffix(b, []byte("\n")) {
		b = append(b, '\n')
	}
	pub := signer.PublicKey()
	return localDeployKey{
		Private:       b,
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Fingerprint:   ssh.FingerprintSHA256(pub),
	}, nil
}

// localDeployKeys loads every site's repository_key, keyed by domain (a site
// without one has no entry). Check and Apply call it FIRST, before any host
// probe: a missing, unparsable or passphrase-protected key is a workstation
// problem no host state can fix, so it is refused before the host is
// touched at all.
func localDeployKeys(s *config.Server) (map[string]*localDeployKey, error) {
	keys := map[string]*localDeployKey{}
	for _, site := range s.Sites {
		if site.RepositoryKey == "" {
			continue
		}
		key, err := loadLocalDeployKey(site.RepositoryKey)
		if err != nil {
			return nil, err
		}
		keys[site.Domain] = &key
	}
	return keys, nil
}

// hostDeployKey reports the site user's deploy key on the host: present is
// false when no key file exists; otherwise authorizedKey is the "<type>
// <base64>" ssh-keygen -y derives from it (the comment it may print is
// dropped). The probe only prints the public half — the private key never
// leaves the host. A key ssh-keygen cannot read (corrupt, or protected by a
// passphrase nobody is there to type) comes back present with an EMPTY
// authorizedKey, which matches no repository_key: it is refused without
// --force and replaced with it, like any other key that is not the one
// configured.
func hostDeployKey(ctx context.Context, r bssh.Runner, user string) (authorizedKey string, present bool, err error) {
	keyPath := deployKeyPath(user)
	ok, err := fileExists(ctx, r, keyPath)
	if err != nil || !ok {
		return "", false, err
	}
	res, err := r.Run(ctx, "ssh-keygen -y -f "+shQuote(keyPath), nil)
	if err != nil {
		return "", true, err
	}
	fields := strings.Fields(res.Stdout)
	if res.ExitCode != 0 || len(fields) < 2 {
		return "", true, nil
	}
	return fields[0] + " " + fields[1], true, nil
}

// deployKeyMismatch is the refusal for a host key that is not the site's
// repository_key. Both sides are named by fingerprint only; replacing the
// key is the operator's call, because the key on the host may be the one
// registered at the git host.
func deployKeyMismatch(site config.Site, keyPath, hostKey string, key *localDeployKey) error {
	held := "a key ssh-keygen -y cannot read"
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey)); err == nil {
		held = ssh.FingerprintSHA256(pub)
	}
	return fmt.Errorf("deploy key %s for %s does not match repository_key %s: the host holds %s, repository_key is %s; re-run with --force to replace the key on the host (--only accounts --force limits the override to this step; the replaced key stops working wherever it is registered)",
		keyPath, site.Domain, site.RepositoryKey, held, key.Fingerprint)
}

// installRepositoryKey makes the site user's deploy key the repository_key
// pair. An absent key is installed; a different one (or one ssh-keygen
// cannot read) is refused unless force; an identical one only gets a missing
// .pub restored. Both files are written AS the account — ~/.ssh is tenant
// territory (see writeFileAsUser) — and the private key rides stdin, never a
// command line. The .pub carries the <user>@<git-host> comment a generated
// key gets, so `berth site key` prints the same shape either way.
func installRepositoryKey(ctx context.Context, r bssh.Runner, force bool, site config.Site, user, gitHost string, key *localDeployKey) error {
	keyPath := deployKeyPath(user)
	pubPath := keyPath + ".pub"
	pubBody := []byte(key.AuthorizedKey + " " + user + "@" + gitHost + "\n")
	hostKey, present, err := hostDeployKey(ctx, r, user)
	if err != nil {
		return err
	}
	if present && hostKey == key.AuthorizedKey {
		pubOK, err := fileExists(ctx, r, pubPath)
		if err != nil || pubOK {
			return err
		}
		return writeFileAsUser(ctx, r, user, pubPath, 0o644, pubBody)
	}
	if present && !force {
		return deployKeyMismatch(site, keyPath, hostKey, key)
	}
	// Private half first: a run interrupted between the two writes leaves the
	// right key with a missing .pub, which the next run restores.
	if err := writeFileAsUser(ctx, r, user, keyPath, 0o600, key.Private); err != nil {
		return err
	}
	return writeFileAsUser(ctx, r, user, pubPath, 0o644, pubBody)
}
