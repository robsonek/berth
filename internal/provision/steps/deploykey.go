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
// Private is the file's bytes in the one form OpenSSH on the host loads:
// every CR is removed (CRLF endings, and the \r\r\n a doubled conversion
// leaves, become LF), and a final newline is added when the file lacks one.
// OpenSSH refuses a CR in a line or a missing final newline ("invalid
// format") while the Go parser accepts both, so installing the bytes
// verbatim would leave a key that git cannot use and that the next Check's
// ssh-keygen -y reads as foreign — refusing, or under --force rewriting, the
// key berth installed, every run. Both edits are lossless: the PEM/OpenSSH
// armor is line-based base64 with no meaningful CR.
func loadLocalDeployKey(path string) (localDeployKey, error) {
	b, err := os.ReadFile(expandHomeLocal(path))
	if err != nil {
		return localDeployKey{}, fmt.Errorf("repository_key %s: %w", path, err)
	}
	b = bytes.ReplaceAll(b, []byte("\r"), nil)
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

// hostDeployPub reports the key material ("<type> <base64>", the first two
// fields) of the site user's deploy .pub, read with a plain cat — it is a
// public key, and only the material leaves this function (no caller prints
// it). present is false when the file cannot be read (missing, or not a
// readable file); a file that does not start with a type and a key comes
// back present with EMPTY material, which matches no repository_key. Under
// repository_key the .pub is compared by material, not mere presence: a
// forced replacement writes the private key first and the .pub second, so a
// failed second write leaves the replaced key's .pub behind, and `berth
// site key` would print a key that no longer matches. The comment is not
// compared, so an operator's comment is never drift.
func hostDeployPub(ctx context.Context, r bssh.Runner, user string) (material string, present bool, err error) {
	res, err := r.Run(ctx, "cat "+shQuote(deployKeyPath(user)+".pub"), nil)
	if err != nil {
		return "", false, err
	}
	if res.ExitCode != 0 {
		return "", false, nil
	}
	fields := strings.Fields(res.Stdout)
	if len(fields) < 2 {
		return "", true, nil
	}
	return fields[0] + " " + fields[1], true, nil
}

// deployKeyMismatch is the refusal for a host key that is not the site's
// repository_key. Both sides are named by fingerprint only; replacing the
// key is the operator's call, because the key on the host may be the one
// registered at the git host. The remedy leads with the narrow override:
// --force is step-wide, so even scoped to accounts it also lets that step
// overwrite its other managed files that berth did not write (an operator's
// authorized_keys, say) — said up front, since a bare --force would widen
// that to every step.
func deployKeyMismatch(site config.Site, keyPath, hostKey string, key *localDeployKey) error {
	held := "a key ssh-keygen -y cannot read"
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey)); err == nil {
		held = ssh.FingerprintSHA256(pub)
	}
	return fmt.Errorf("deploy key %s for %s does not match repository_key %s: the host holds %s, repository_key is %s; to replace the key on the host, re-run with --only accounts --force (this also lets the accounts step overwrite other files it manages that berth did not write, such as an authorized_keys; a bare --force extends the override to every step). The replaced key stops working wherever it is registered",
		keyPath, site.Domain, site.RepositoryKey, held, key.Fingerprint)
}

// installRepositoryKey makes the site user's deploy key the repository_key
// pair. An absent key is installed; a different one (or one ssh-keygen
// cannot read) is refused unless force; an identical one only gets its .pub
// rewritten, and only when that .pub is missing or carries other key
// material (hostDeployPub) — the private key is never rewritten then. Both
// files are written AS the account — ~/.ssh is tenant
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
		pub, pubPresent, err := hostDeployPub(ctx, r, user)
		if err != nil || (pubPresent && pub == key.AuthorizedKey) {
			return err
		}
		return writeFileAsUser(ctx, r, user, pubPath, 0o644, pubBody)
	}
	if present && !force {
		return deployKeyMismatch(site, keyPath, hostKey, key)
	}
	// Private half first: a run interrupted between the two writes leaves the
	// right key with a missing or stale .pub, which the next run rewrites.
	if err := writeFileAsUser(ctx, r, user, keyPath, 0o600, key.Private); err != nil {
		return err
	}
	return writeFileAsUser(ctx, r, user, pubPath, 0o644, pubBody)
}
