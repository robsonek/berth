package steps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	offsiteScriptPath = "/usr/local/sbin/berth-offsite"
	offsiteCronPath   = "/etc/cron.d/berth-offsite"
	offsiteEnvDir     = "/etc/berth"
	offsiteEnvPath    = "/etc/berth/offsite.env"
	// offsiteLogPath deliberately matches the backup logrotate fragment's
	// backup-*.log glob — no logrotate change needed. No collision with a
	// site pool: pool names always carry '_' for the domain's dots.
	offsiteLogPath  = backupLogDir + "/backup-offsite.log"
	offsiteLockPath = backupBaseDir + "/.offsite.lock"
	// offsiteStampPrefix keys the init stamp by repository string; a changed
	// target gets a NEW stamp (E5 rule: unknown stamps are ignored, never
	// reused, never swept).
	offsiteStampPrefix       = "/var/lib/berth/offsite-init-"
	offsiteResticPasswordLen = 32
)

const (
	offsiteSSHKeyPath = "/root/.ssh/berth_offsite"
	// offsiteKnownHostsPath is a DEDICATED, fully berth-managed pin file —
	// the shared /root/.ssh/known_hosts is never touched, no config value is
	// ever composed into a sed/grep program (root-injection surface), and
	// key rotation is ordinary managed-file drift.
	offsiteKnownHostsPath = "/root/.ssh/berth_offsite_known_hosts"
)

// offsiteSweepPaths are the berth-managed host artifacts the disabled mode
// drift-removes, marker-guarded (single source for the disabled Check and
// sweepDisabled). The sftp keypair deliberately stays: it may still be
// authorized on the operator's remote target — remove
// /root/.ssh/berth_offsite* manually if unwanted.
var offsiteSweepPaths = []string{offsiteScriptPath, offsiteCronPath, offsiteEnvPath, offsiteKnownHostsPath}

// offsiteKnownHostsContent renders the pin file: the managed marker (a
// comment line to ssh) followed by the operator-declared ssh-keyscan line,
// whose first field validation has pinned to KnownHostsToken().
func offsiteKnownHostsContent(o *config.Offsite) []byte {
	return []byte(templates.ManagedMarker + "\n" + o.HostKey + "\n")
}

func offsiteStampPath(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return offsiteStampPrefix + hex.EncodeToString(sum[:4])
}

func offsiteStampContent(repo string) []byte {
	return []byte(templates.ManagedMarker + "\n" + repo + "\n")
}

// offsiteResticOpts renders the extra restic CLI flags for the backend:
// empty for s3 (credentials ride the env file); for sftp one fully-pinned
// sftp.command — -F /dev/null + IdentitiesOnly + StrictHostKeyChecking +
// GlobalKnownHostsFile=/dev/null (-F /dev/null does NOT neutralize the
// default /etc/ssh/ssh_known_hosts, which could widen or break the pin) +
// the dedicated UserKnownHostsFile mean root's personal ssh config, agent
// identities and TOFU can neither widen nor bypass the pin; BatchMode
// keeps cron from ever prompting, and ServerAliveInterval/CountMax kill
// the transport when a hung-but-TCP-alive peer stops answering (restic
// would otherwise wedge forever holding the shared artifacts lock).
// Values are config-validated to be quote- and whitespace-free, so the
// single-quoted composition is sound. Always empty or leading-space so
// "restic"+opts composes.
func offsiteResticOpts(o *config.Offsite) string {
	if o.Backend != "sftp" {
		return ""
	}
	return fmt.Sprintf(" -o sftp.command='ssh -F /dev/null -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=%s -i %s -p %d %s@%s -s sftp'",
		offsiteKnownHostsPath, offsiteSSHKeyPath, o.PortEff(), o.User, o.Host)
}

// assertNotSymlink hard-errors when path is a symlink: key material and its
// directory are a security boundary — a symlink would let key generation and
// pin writes land outside a root-controlled tree, so it is never converged
// over, with or without --force.
func assertNotSymlink(ctx context.Context, r bssh.Runner, path string) error {
	res, err := r.Run(ctx, "test -L "+shQuote(path), nil)
	if err != nil {
		return err
	}
	if res.ExitCode == 0 {
		return fmt.Errorf("%s is a symlink; refusing to manage offsite key material through it — remove the symlink and re-run", path)
	}
	return nil
}

func renderOffsiteEnv(s *config.Server, secrets map[string]string) ([]byte, error) {
	off := s.Backups.Offsite
	return templates.Render("offsite_env.tmpl", struct {
		Repository, Password string
		S3                   bool
		AccessKey, SecretKey string
	}{
		Repository: off.Repository(s.ID),
		Password:   secrets[secret.OffsiteResticPassword],
		S3:         off.Backend == "s3",
		AccessKey:  secrets[secret.OffsiteS3AccessKey],
		SecretKey:  secrets[secret.OffsiteS3SecretKey],
	})
}

func renderOffsiteScript(s *config.Server) ([]byte, error) {
	off := s.Backups.Offsite
	return templates.Render("offsite.sh.tmpl", struct {
		LogFile, LockFile, ArtifactsLock, EnvFile, ResticOpts, BackupBaseDir, HostID string
		KeepLast, KeepHourly, KeepDaily, KeepWeekly, KeepMonthly                     int
	}{
		LogFile:       offsiteLogPath,
		LockFile:      offsiteLockPath,
		ArtifactsLock: backupArtifactsLockPath,
		EnvFile:       offsiteEnvPath,
		ResticOpts:    offsiteResticOpts(off),
		BackupBaseDir: backupBaseDir,
		HostID:        s.ID,
		KeepLast:      off.Keep.Last,
		KeepHourly:    off.Keep.Hourly,
		KeepDaily:     off.Keep.DailyEff(),
		KeepWeekly:    off.Keep.WeeklyEff(),
		KeepMonthly:   off.Keep.MonthlyEff(),
	})
}

func renderOffsiteCron(s *config.Server) ([]byte, error) {
	return templates.Render("backup.cron.tmpl", struct{ Schedule, ScriptPath string }{
		Schedule:   s.Backups.Offsite.ScheduleEff(),
		ScriptPath: offsiteScriptPath,
	})
}

type offsite struct{ redactor *secret.Redactor }

// Offsite ships the local backup artifacts to an encrypted restic repository
// (S3-compatible or SFTP): one box-level script + cron produce one snapshot
// per night of the whole /var/backups/berth and prune by the keep policy.
// ALWAYS registered (valkey/P14 pattern): with no offsite target configured
// its disabled mode drift-removes the script/cron/env a previous provision
// left behind — the REMOTE repository is never touched (operator's data).
// Check is deliberately network-free; Apply owns the one-time repository
// probe/init behind a per-repository stamp under /var/lib/berth.
func Offsite(red *secret.Redactor) provision.Step { return offsite{redactor: red} }

func (offsite) Name() string       { return "offsite" }
func (offsite) Requires() []string { return []string{"backups"} }

// registerSecrets adds loaded secret values to the run's redactor (defense
// in depth: no offsite command string carries them, but any accidental echo
// must come out redacted).
func (o offsite) registerSecrets(secrets map[string]string) {
	if o.redactor == nil {
		return
	}
	for _, k := range []string{secret.OffsiteS3AccessKey, secret.OffsiteS3SecretKey, secret.OffsiteResticPassword} {
		if v := secrets[k]; v != "" {
			o.redactor.Add(v)
		}
	}
}

func (o offsite) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	if !s.OffsiteEnabled() {
		var changes []string
		for _, p := range offsiteSweepPaths {
			present, err := managedFilePresent(ctx, r, p)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if present {
				changes = append(changes, "remove "+p+" (offsite disabled)")
			}
		}
		if len(changes) == 0 {
			return provision.CheckResult{Satisfied: true, Reason: "no offsite target configured"}, nil
		}
		return provision.CheckResult{Satisfied: false, Reason: "offsite artifacts linger after disable", Changes: changes}, nil
	}

	off := s.Backups.Offsite
	repo := off.Repository(s.ID)
	var changes []string

	installed, err := pkgInstalled(ctx, r, "restic")
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !installed {
		changes = append(changes, "install restic")
	}

	secrets, err := loadVerifiedSecrets(s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if err := validateOffsiteSecrets(secrets); err != nil {
		return provision.CheckResult{}, err
	}
	o.registerSecrets(secrets)
	if off.Backend == "s3" && (secrets[secret.OffsiteS3AccessKey] == "" || secrets[secret.OffsiteS3SecretKey] == "") {
		return provision.CheckResult{}, fmt.Errorf(
			"offsite s3 credentials are missing from the local secret cache; run:\n"+
				"  berth secret set <server.yml> %s\n  berth secret set <server.yml> %s",
			secret.OffsiteS3AccessKey, secret.OffsiteS3SecretKey)
	}

	if meta, present, err := statOwnerMode(ctx, r, offsiteEnvDir); err != nil {
		return provision.CheckResult{}, err
	} else if !present || meta != "root:root 755" {
		changes = append(changes, "create "+offsiteEnvDir+" (root:root 755)")
	}

	// The env file is only comparable when every value it renders is known;
	// without the (auto-generated) password its desired content does not
	// exist yet, so the write is planned unconditionally and Check must not
	// read the live file at all (a content probe would be pure noise).
	if secrets[secret.OffsiteResticPassword] == "" {
		changes = append(changes, "generate restic repository password", "write "+offsiteEnvPath)
	} else {
		env, err := renderOffsiteEnv(s, secrets)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, err := managedFileOK(ctx, r, offsiteEnvPath, env, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, "write "+offsiteEnvPath)
		}
		if meta, present, err := statOwnerMode(ctx, r, offsiteEnvPath); err != nil {
			return provision.CheckResult{}, err
		} else if present && meta != "root:root 600" {
			changes = append(changes, "fix owner/mode of "+offsiteEnvPath)
		}
	}

	script, err := renderOffsiteScript(s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	ok, err := managedFileOK(ctx, r, offsiteScriptPath, script, rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !ok {
		changes = append(changes, "write "+offsiteScriptPath)
	}
	if meta, present, err := statOwnerMode(ctx, r, offsiteScriptPath); err != nil {
		return provision.CheckResult{}, err
	} else if present && meta != "root:root 755" {
		changes = append(changes, "fix owner/mode of "+offsiteScriptPath)
	}

	cron, err := renderOffsiteCron(s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	ok, err = managedFileOK(ctx, r, offsiteCronPath, cron, rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !ok {
		changes = append(changes, "write "+offsiteCronPath)
	}
	if meta, present, err := statOwnerMode(ctx, r, offsiteCronPath); err != nil {
		return provision.CheckResult{}, err
	} else if present && meta != "root:root 644" {
		changes = append(changes, "fix owner/mode of "+offsiteCronPath)
	}

	if off.Backend == "sftp" {
		for _, p := range []string{"/root/.ssh", offsiteSSHKeyPath} {
			if err := assertNotSymlink(ctx, r, p); err != nil {
				return provision.CheckResult{}, err
			}
		}
		if meta, present, err := statOwnerMode(ctx, r, "/root/.ssh"); err != nil {
			return provision.CheckResult{}, err
		} else if !present || meta != "root:root 700" {
			changes = append(changes, "create /root/.ssh (root:root 700)")
		}
		if meta, present, err := statOwnerMode(ctx, r, offsiteSSHKeyPath); err != nil {
			return provision.CheckResult{}, err
		} else if !present {
			changes = append(changes, "generate offsite ssh keypair "+offsiteSSHKeyPath)
		} else {
			if meta != "root:root 600" {
				changes = append(changes, "fix owner/mode of "+offsiteSSHKeyPath)
			}
			if res, err := r.Run(ctx, "test -f "+shQuote(offsiteSSHKeyPath+".pub"), nil); err != nil {
				return provision.CheckResult{}, err
			} else if res.ExitCode != 0 {
				changes = append(changes, "regenerate "+offsiteSSHKeyPath+".pub from the private key")
			}
		}
		khOK, err := managedFileOK(ctx, r, offsiteKnownHostsPath, offsiteKnownHostsContent(off), rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !khOK {
			changes = append(changes, "write "+offsiteKnownHostsPath+" (pin the sftp host key)")
		}
	}

	if meta, present, err := statOwnerMode(ctx, r, "/var/lib/berth"); err != nil {
		return provision.CheckResult{}, err
	} else if !present || meta != "root:root 755" {
		changes = append(changes, "create /var/lib/berth (root:root 755)")
	}
	stampOK, err := managedFileOK(ctx, r, offsiteStampPath(repo), offsiteStampContent(repo), rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !stampOK {
		changes = append(changes, "initialize or verify the restic repository ("+repo+")")
	}
	if meta, present, err := statOwnerMode(ctx, r, offsiteStampPath(repo)); err != nil {
		return provision.CheckResult{}, err
	} else if present && meta != "root:root 600" {
		changes = append(changes, "fix owner/mode of "+offsiteStampPath(repo))
	}

	if len(changes) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "offsite backups converged"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "offsite backups not in desired state", Changes: changes}, nil
}

// validateOffsiteSecrets re-runs the quoting-contract validator on every
// offsite value LOADED from the cache: the cache file is operator-editable
// and restorable, so loaded values are untrusted input until revalidated —
// a violating value must never reach the rendered env file. The error names
// the key, never the value.
func validateOffsiteSecrets(secrets map[string]string) error {
	for _, k := range []string{secret.OffsiteS3AccessKey, secret.OffsiteS3SecretKey, secret.OffsiteResticPassword} {
		if v := secrets[k]; v != "" {
			if err := secret.ValidateSecretValue(v); err != nil {
				return fmt.Errorf("cached secret %s violates the value contract (%w); fix it with: berth secret set <server.yml> %s", k, err, k)
			}
		}
	}
	return nil
}

func (o offsite) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if !s.OffsiteEnabled() {
		return o.sweepDisabled(ctx, r)
	}

	off := s.Backups.Offsite
	repo := off.Repository(s.ID)

	installed, err := pkgInstalled(ctx, r, "restic")
	if err != nil {
		return err
	}
	if !installed {
		if err := aptInstall(ctx, r, "restic"); err != nil {
			return err
		}
	}

	// No ensureCron here: offsite validates as enabled only on top of
	// enabled backups, and the backups step (earlier in the pipeline)
	// already installs + enables the cron daemon.

	secrets, err := o.loadOrSeedSecrets(s)
	if err != nil {
		return err
	}
	if off.Backend == "s3" && (secrets[secret.OffsiteS3AccessKey] == "" || secrets[secret.OffsiteS3SecretKey] == "") {
		return fmt.Errorf(
			"offsite s3 credentials are missing from the local secret cache; run:\n"+
				"  berth secret set <server.yml> %s\n  berth secret set <server.yml> %s",
			secret.OffsiteS3AccessKey, secret.OffsiteS3SecretKey)
	}
	o.registerSecrets(secrets)

	if err := runOK(ctx, r, "install -d -o root -g root -m 0755 "+shQuote(offsiteEnvDir)); err != nil {
		return err
	}
	env, err := renderOffsiteEnv(s, secrets)
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{Path: offsiteEnvPath, Content: env, Owner: "root", Group: "root", Mode: 0o600, Sudo: true}); err != nil {
		return fmt.Errorf("write %s: %w", offsiteEnvPath, err)
	}
	script, err := renderOffsiteScript(s)
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{Path: offsiteScriptPath, Content: script, Owner: "root", Group: "root", Mode: 0o755, Sudo: true}); err != nil {
		return fmt.Errorf("write %s: %w", offsiteScriptPath, err)
	}
	if err := runOK(ctx, r, "bash -n "+shQuote(offsiteScriptPath)); err != nil {
		return fmt.Errorf("offsite script failed bash -n: %w", err)
	}
	cron, err := renderOffsiteCron(s)
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{Path: offsiteCronPath, Content: cron, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
		return fmt.Errorf("write %s: %w", offsiteCronPath, err)
	}
	if off.Backend == "sftp" {
		for _, p := range []string{"/root/.ssh", offsiteSSHKeyPath} {
			if err := assertNotSymlink(ctx, r, p); err != nil {
				return err
			}
		}
		if err := runOK(ctx, r, "install -d -o root -g root -m 0700 '/root/.ssh'"); err != nil {
			return err
		}
		meta, present, err := statOwnerMode(ctx, r, offsiteSSHKeyPath)
		if err != nil {
			return err
		}
		switch {
		case !present:
			if err := runOK(ctx, r, "ssh-keygen -t ed25519 -N '' -C berth-offsite -f "+shQuote(offsiteSSHKeyPath)); err != nil {
				return err
			}
		case meta != "root:root 600":
			if err := runOK(ctx, r, "chown root:root "+shQuote(offsiteSSHKeyPath)+" && chmod 600 "+shQuote(offsiteSSHKeyPath)); err != nil {
				return err
			}
		}
		if present {
			if res, err := r.Run(ctx, "test -f "+shQuote(offsiteSSHKeyPath+".pub"), nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				if err := runOK(ctx, r, "ssh-keygen -y -f "+shQuote(offsiteSSHKeyPath)+" > "+shQuote(offsiteSSHKeyPath+".pub")); err != nil {
					return err
				}
			}
		}
		if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{Path: offsiteKnownHostsPath, Content: offsiteKnownHostsContent(off), Owner: "root", Group: "root", Mode: 0o600, Sudo: true}); err != nil {
			return fmt.Errorf("write %s: %w", offsiteKnownHostsPath, err)
		}
	}
	if err := runOK(ctx, r, "install -d -o root -g root -m 0755 '/var/lib/berth'"); err != nil {
		return err
	}
	return o.ensureRepo(ctx, rc, r, repo, off)
}

// loadOrSeedSecrets loads the offsite secrets, generating and persisting the
// repository password on first use (the DB-password pattern). The cache lock
// is held ONLY across load→generate→save — never across remote I/O: a slow
// target must not block a concurrent `berth secret set` (a value updated
// after this snapshot simply surfaces as env drift on the next run). Loaded
// values are revalidated: the cache file is operator-editable.
func (o offsite) loadOrSeedSecrets(s *config.Server) (map[string]string, error) {
	release, err := secret.LockCache(s.CacheKey())
	if err != nil {
		return nil, err
	}
	defer release()
	secrets, err := loadVerifiedSecrets(s)
	if err != nil {
		return nil, err
	}
	if err := validateOffsiteSecrets(secrets); err != nil {
		return nil, err
	}
	if secrets[secret.OffsiteResticPassword] == "" {
		pw, err := secret.Generate(offsiteResticPasswordLen)
		if err != nil {
			return nil, err
		}
		secrets[secret.OffsiteResticPassword] = pw
		if err := saveSecrets(s, secrets); err != nil {
			return nil, err
		}
	}
	return secrets, nil
}

// resticExit codes of restic 0.18 (Debian 13); message fallbacks cover
// older/newer versions.
const (
	resticExitNoRepository  = 10
	resticExitWrongPassword = 12
)

// ensureRepo probes the repository once per target (stamped): exit 0 =
// exists; exit 10 / missing-repo stderr = init; exit 12 / wrong-password
// stderr = hard error (the repo exists, data is at stake, re-init is
// impossible — only the correct password helps); anything else = warning +
// unconverged mark, retried next run because the stamp stays missing.
// Permanent backend-auth failures deliberately share the transient branch
// (spec amendment 10): telling them apart by stderr is fragile, and a run
// that warns loudly and withholds the manifest every time is the honest
// state. The stamp is only written after a VERIFIED repository.
func (o offsite) ensureRepo(ctx context.Context, rc provision.RunCtx, r bssh.Runner, repo string, off *config.Offsite) error {
	opts := offsiteResticOpts(off)
	res, err := r.Run(ctx, "set -a && . "+shQuote(offsiteEnvPath)+" && restic"+opts+" cat config >/dev/null", nil)
	if err != nil {
		return err
	}
	noRepo := res.ExitCode == resticExitNoRepository ||
		strings.Contains(res.Stderr, "Is there a repository at") ||
		strings.Contains(res.Stderr, "repository does not exist")
	wrongPassword := res.ExitCode == resticExitWrongPassword ||
		strings.Contains(res.Stderr, "wrong password")
	switch {
	case res.ExitCode == 0:
		// repository exists and opens with our password
	case wrongPassword:
		return fmt.Errorf("the restic repository %s exists but the cached password does not open it; restore the correct password with: berth secret set <server.yml> %s (%s)",
			repo, secret.OffsiteResticPassword, strings.TrimSpace(res.Stderr))
	case noRepo:
		ires, err := r.Run(ctx, "set -a && . "+shQuote(offsiteEnvPath)+" && restic"+opts+" init", nil)
		if err != nil {
			return err
		}
		if ires.ExitCode != 0 {
			return fmt.Errorf("restic init on %s: %s", repo, strings.TrimSpace(ires.Stderr))
		}
	default:
		msg := strings.TrimSpace(res.Stderr)
		if off.Backend == "sftp" {
			if pub, perr := r.Run(ctx, "cat "+shQuote(offsiteSSHKeyPath+".pub"), nil); perr == nil && pub.ExitCode == 0 {
				msg += " — if the key is not authorized on the target yet, authorize: " + strings.TrimSpace(pub.Stdout)
			}
		}
		rc.Warnf("cannot verify the restic repository %s yet: %s — it will be verified or initialized on the next run", repo, msg)
		rc.MarkUnconverged("offsite repository " + repo + " not verified")
		return nil
	}
	return writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{Path: offsiteStampPath(repo), Content: offsiteStampContent(repo), Owner: "root", Group: "root", Mode: 0o600, Sudo: true})
}

// sweepDisabled removes lingering berth-managed offsite host artifacts
// (offsiteSweepPaths — script, cron, env file, host-key pin). The remote
// repository is never touched (operator's data retention), a foreign
// (unmarked) file at any of the paths is never removed, and the sftp keypair
// stays (see offsiteSweepPaths).
func (o offsite) sweepDisabled(ctx context.Context, r bssh.Runner) error {
	for _, p := range offsiteSweepPaths {
		present, err := managedFilePresent(ctx, r, p)
		if err != nil {
			return err
		}
		if present {
			if err := runOK(ctx, r, "rm -f "+shQuote(p)); err != nil {
				return err
			}
		}
	}
	return nil
}
