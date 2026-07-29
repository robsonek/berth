package steps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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

func offsiteStampPath(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return offsiteStampPrefix + hex.EncodeToString(sum[:4])
}

func offsiteStampContent(repo string) []byte {
	return []byte(templates.ManagedMarker + "\n" + repo + "\n")
}

// offsiteResticOpts renders the extra restic CLI flags for the backend.
// Empty for s3 (credentials ride the env); the sftp branch lands with the
// sftp backend task. Always either empty or leading-space so
// "restic"+opts composes.
func offsiteResticOpts(_ *config.Offsite) string {
	return ""
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
		KeepDaily, KeepWeekly, KeepMonthly                                           int
	}{
		LogFile:       offsiteLogPath,
		LockFile:      offsiteLockPath,
		ArtifactsLock: backupArtifactsLockPath,
		EnvFile:       offsiteEnvPath,
		ResticOpts:    offsiteResticOpts(off),
		BackupBaseDir: backupBaseDir,
		HostID:        s.ID,
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
		for _, p := range []string{offsiteScriptPath, offsiteCronPath, offsiteEnvPath} {
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

func (o offsite) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if !s.OffsiteEnabled() {
		return o.sweepDisabled(ctx, r)
	}
	return fmt.Errorf("offsite enabled-mode Apply lands in the next commit")
}

// sweepDisabled removes lingering berth-managed offsite host artifacts.
// The remote repository is never touched (operator's data retention), and a
// foreign (unmarked) file at any of the paths is never removed.
func (o offsite) sweepDisabled(ctx context.Context, r bssh.Runner) error {
	for _, p := range []string{offsiteScriptPath, offsiteCronPath, offsiteEnvPath} {
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
