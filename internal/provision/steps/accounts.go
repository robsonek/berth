package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	sudoersBerthPath  = "/etc/sudoers.d/berth"
	sudoersDeployPath = "/etc/sudoers.d/deploy"
	sudoersBerthBody  = managedMarker + "\nberth ALL=(ALL) NOPASSWD:ALL\n"
)

// managedUsers are the two privilege-separated accounts berth provisions
// (design §6.3): berth (provisioning, full sudo) and deploy (deployment, narrow).
var managedUsers = []string{"berth", "deploy"}

type accounts struct{}

func Accounts() provision.Step { return accounts{} }

func (accounts) Name() string       { return "accounts" }
func (accounts) Requires() []string { return []string{"base"} }

// programName derives a stable Supervisor program name from a site domain; the
// deploy sudoers allowlist references it so deploy can manage only its worker.
func programName(s *config.Server) string {
	domain := "app"
	if len(s.Sites) > 0 && s.Sites[0].Domain != "" {
		domain = s.Sites[0].Domain
	}
	return "berth-" + strings.ReplaceAll(domain, ".", "_")
}

type sudoersDeployData struct {
	PHPVersion  string
	ProgramName string
}

// renderDeploySudoers renders the narrow deploy sudoers from the template.
func renderDeploySudoers(s *config.Server) ([]byte, error) {
	return templates.Render("sudoers_deploy.tmpl", sudoersDeployData{
		PHPVersion:  s.PHP.Version,
		ProgramName: programName(s),
	})
}

// authorizedKeys is the managed authorized_keys body for an account: the berth
// marker plus the operator's public key.
func authorizedKeys(operatorKey string) []byte {
	return []byte(managedMarker + "\n" + operatorKey + "\n")
}

func userExists(ctx context.Context, r bssh.Runner, user string) (bool, error) {
	res, err := r.Run(ctx, "id "+user, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

func sudoersValid(ctx context.Context, r bssh.Runner, path string) (bool, error) {
	res, err := r.Run(ctx, "visudo -cf "+shQuote(path), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

func (a accounts) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	// Both accounts must exist.
	for _, u := range managedUsers {
		ok, err := userExists(ctx, r, u)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			return provision.CheckResult{Satisfied: false, Reason: "account " + u + " missing", Changes: a.changes()}, nil
		}
	}
	// Both sudoers files must be present and valid.
	for _, p := range []string{sudoersBerthPath, sudoersDeployPath} {
		ok, err := fileExists(ctx, r, p)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			return provision.CheckResult{Satisfied: false, Reason: p + " missing", Changes: a.changes()}, nil
		}
		valid, err := sudoersValid(ctx, r, p)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !valid {
			return provision.CheckResult{Satisfied: false, Reason: p + " fails visudo -cf", Changes: a.changes()}, nil
		}
	}
	// Each authorized_keys must carry the managed marker + the expected key.
	operatorKey, err := operatorPublicKey(s.SSH.Key)
	if err != nil {
		return provision.CheckResult{}, err
	}
	want := authorizedKeys(operatorKey)
	for _, u := range managedUsers {
		state, err := checkManagedFile(ctx, r, authorizedKeysPath(u), want)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, err := managedFileSatisfied(state, authorizedKeysPath(u), rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			return provision.CheckResult{Satisfied: false, Reason: u + " authorized_keys not up to date", Changes: a.changes()}, nil
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: "accounts, sudoers and keys present"}, nil
}

func (a accounts) changes() []string {
	return []string{
		"create users berth, deploy",
		"write " + sudoersBerthPath + ", " + sudoersDeployPath,
		"install operator key into authorized_keys",
	}
}

func authorizedKeysPath(user string) string {
	return fmt.Sprintf("/home/%s/.ssh/authorized_keys", user)
}

func (a accounts) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	operatorKey, err := operatorPublicKey(s.SSH.Key)
	if err != nil {
		return err
	}

	// Create the two accounts (idempotent: skip when already present).
	for _, u := range managedUsers {
		ok, err := userExists(ctx, r, u)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		res, err := r.Run(ctx, "useradd -m -s /bin/bash "+u, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("create user %s: %s", u, res.Stderr)
		}
	}

	// Write the berth sudoers (full NOPASSWD) and validate it.
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: sudoersBerthPath, Content: []byte(sudoersBerthBody),
		Owner: "root", Group: "root", Mode: 0o440, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", sudoersBerthPath, err)
	}
	if valid, err := sudoersValid(ctx, r, sudoersBerthPath); err != nil {
		return err
	} else if !valid {
		return fmt.Errorf("%s failed visudo -cf validation", sudoersBerthPath)
	}

	// Write the narrow deploy sudoers from the template and validate it.
	deployBody, err := renderDeploySudoers(s)
	if err != nil {
		return fmt.Errorf("render deploy sudoers: %w", err)
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: sudoersDeployPath, Content: deployBody,
		Owner: "root", Group: "root", Mode: 0o440, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", sudoersDeployPath, err)
	}
	if valid, err := sudoersValid(ctx, r, sudoersDeployPath); err != nil {
		return err
	} else if !valid {
		return fmt.Errorf("%s failed visudo -cf validation", sudoersDeployPath)
	}

	// Install the operator key into both accounts' authorized_keys.
	want := authorizedKeys(operatorKey)
	for _, u := range managedUsers {
		sshDir := fmt.Sprintf("/home/%s/.ssh", u)
		if res, err := r.Run(ctx, fmt.Sprintf("install -d -o %s -g %s -m 700 %s", u, u, shQuote(sshDir)), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("create %s: %s", sshDir, res.Stderr)
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{
			Path: authorizedKeysPath(u), Content: want,
			Owner: u, Group: u, Mode: 0o600, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write %s authorized_keys: %w", u, err)
		}
	}

	// When any site has a repository, provision the deploy key + known_hosts.
	return a.ensureDeployKey(ctx, s, r)
}

// ensureDeployKey generates a deploy SSH key under ~deploy/.ssh and scans the
// Git host into known_hosts, but only when at least one site has a repository.
func (a accounts) ensureDeployKey(ctx context.Context, s *config.Server, r bssh.Runner) error {
	var host string
	for _, site := range s.Sites {
		if site.Repository == "" {
			continue
		}
		h, err := config.GitHost(site.Repository)
		if err != nil {
			return fmt.Errorf("parse git host from %q: %w", site.Repository, err)
		}
		host = h
		break
	}
	if host == "" {
		return nil // no repository configured; nothing to do
	}

	const keyPath = "/home/deploy/.ssh/id_ed25519"
	exists, err := fileExists(ctx, r, keyPath)
	if err != nil {
		return err
	}
	if !exists {
		// -N '' is an empty passphrase; -C labels the key for the Git host.
		gen := fmt.Sprintf("sudo -u deploy ssh-keygen -t ed25519 -N '' -f %s -C %s",
			shQuote(keyPath), shQuote("deploy@"+host))
		if res, err := r.Run(ctx, gen, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("ssh-keygen for deploy: %s", res.Stderr)
		}
	}

	const knownHosts = "/home/deploy/.ssh/known_hosts"
	// host is a validated hostname (config.GitHost); the path is a constant. The
	// redirection requires a shell, run as the deploy account.
	scan := fmt.Sprintf("sudo -u deploy sh -c %s",
		shQuote(fmt.Sprintf("ssh-keyscan %s >> %s", host, knownHosts)))
	if res, err := r.Run(ctx, scan, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("ssh-keyscan %s: %s", host, res.Stderr)
	}
	return nil
}
