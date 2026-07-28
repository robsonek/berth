package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// acmeWebrootBase is berth's own namespace for ACME webroots; berth issues
// Let's Encrypt certificates exclusively via --webroot under it, which is
// also the ownership fingerprint the TLS orphan sweep keys on.
const acmeWebrootBase = "/var/www/berth-acme"

// acmeWebroot is the dedicated ACME challenge root for a domain, kept separate
// from the application's deploy_path (design §6.4). It is owned by root:root:
// certbot runs as root and creates .well-known/acme-challenge/<token> itself,
// while nginx (www-data) only ever reads and traverses the webroot, which mode
// 0755 grants. An unprivileged owner here could swap .well-known or
// acme-challenge for a symlink and redirect certbot's root-run writes to an
// arbitrary path — the ancestry gate stops AT the webroot and does not protect
// its descendants, so the webroot itself must be root-controlled too.
func acmeWebroot(domain string) string {
	return acmeWebrootBase + "/" + domain
}

type appDirs struct{}

// AppDirs creates the per-site deployment directories and ACME webroot BEFORE any
// secret is persisted, so seeding shared/.env (the database step) has a place to
// write (design §6.4). Each site's directories are owned by that site's OS user
// for isolation: deploy_path is <user>:www-data mode 0710 (nginx/www-data may
// traverse to public/, other site users cannot), shared/ is <user>:<user> 0700.
// shared/tmp backs the site's FPM sys_temp_dir/upload_tmp_dir so PHP never
// stages uploads or temp files in the world-readable shared /tmp.
func AppDirs() provision.Step { return appDirs{} }

func (appDirs) Name() string       { return "appdirs" }
func (appDirs) Requires() []string { return []string{"accounts"} }

// noSymlinkInPath reports whether every EXISTING component of p — each prefix
// from the first component under / down to p itself — is a real directory:
// not a symlink and not any other file type. This is NOT what makes the step
// race-free: root-run mutations are confined to paths with a root-controlled
// ancestry (assertSafeAncestry) and everything inside tenant territory is
// created and written by the tenant itself, which is what closes the swap
// window. The probe's job is to turn a planted symlink into an early,
// actionable refusal instead of a raw EPERM, and to stop the owner guard's stat
// from reading an inode THROUGH a tenant-planted symlink. A non-directory
// ancestor must be refused too: it would make that stat fail with ENOTDIR and
// read as "absent" — fail-open. A non-existent component passes, so a fresh
// path is created normally. (`test -d` follows symlinks, but `test ! -L`
// short-circuits first.)
func noSymlinkInPath(ctx context.Context, r bssh.Runner, p string) (bool, error) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	var tests []string
	for _, part := range parts {
		cur += "/" + part
		q := shQuote(cur)
		tests = append(tests, "{ test ! -e "+q+" || { test ! -L "+q+" && test -d "+q+"; }; }")
	}
	res, err := r.Run(ctx, strings.Join(tests, " && "), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// assertNoSymlinkAt fails loudly if any existing component of p is a symlink
// or not a directory (see noSymlinkInPath).
func assertNoSymlinkAt(ctx context.Context, r bssh.Runner, domain, p string) error {
	ok, err := noSymlinkInPath(ctx, r, p)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("refusing to create directories for %s: a component of %s is a symlink or not a directory — remove the offending path before re-running", domain, p)
	}
	return nil
}

// assertNoSymlinkDeployTree covers a site's deploy tree: probing the deepest
// deploy target covers deploy_path, shared and shared/tmp and all their
// ancestors in one probe. The accounts step runs this too — its owner probe
// must never read inodes through a tenant-planted symlink, and --only
// accounts never reaches appdirs.
func assertNoSymlinkDeployTree(ctx context.Context, r bssh.Runner, site config.Site) error {
	return assertNoSymlinkAt(ctx, r, site.Domain, site.DeployPath+"/shared/tmp")
}

// assertNoSymlinkTargets is the appdirs-wide variant: the root-controlled
// ancestry requirement for the two directories root itself creates, then the
// deploy tree and the site's ACME webroot.
//
// Ancestry goes FIRST: it is the broadest condition (an unsafe ancestor makes
// every verdict below it meaningless) and it costs one round-trip.
func assertNoSymlinkTargets(ctx context.Context, r bssh.Runner, _ *config.Server, site config.Site) error {
	if err := assertSafeAncestry(ctx, r, site.Domain, site.DeployPath, acmeWebroot(site.Domain)); err != nil {
		return err
	}
	if err := assertNoSymlinkDeployTree(ctx, r, site); err != nil {
		return err
	}
	return assertNoSymlinkAt(ctx, r, site.Domain, acmeWebroot(site.Domain))
}

// assertSafeAncestry refuses when any EXISTING ancestor of any given path is
// not a root-controlled directory: it must be a real directory (not a symlink
// or other type), owned by uid 0, and neither group- nor other-writable.
//
// This is the premise the root-run mutations rest on. berth still creates
// deploy_path (owned by the site user, which only root can set) and the
// root-owned ACME webroot as root, and root's `install -d` follows a directory symlink
// and applies ownership to the target. That is only safe while nobody but root
// can replace a component of the path: the symlink probe checks a component's
// TYPE, never its OWNERSHIP, so a tenant-owned ancestor (ValidateDeployPath
// permits e.g. /srv/apps/site) would let the tenant swap the final component
// after the probe and redirect the chown. Absent components pass — root
// creates them, and what root creates is root-owned.
//
// Deliberately NOT bypassable with --force: --force is for adopting berth's
// own unmanaged files, never for lowering a guard that gates a root chown.
func assertSafeAncestry(ctx context.Context, r bssh.Runner, subject string, paths ...string) error {
	// The security half — real directory, uid 0, not group/other-writable — is
	// the write primitive's contract and lives in internal/ssh, so there is one
	// probe and one parser rather than two copies that can drift. The returned
	// components let this step add its own requirement without a second
	// round-trip.
	comps, err := bssh.AssertRootControlledAncestry(ctx, r, subject, paths...)
	if err != nil {
		return err
	}
	for _, c := range comps {
		// Searchability is a CONVERGENCE requirement, not a security one, which
		// is why it stays here instead of moving into the primitive: the site
		// user creates its own shared/ and shared/tmp, and www-data must reach
		// the ACME webroot and the site's public/. Neither is in root's group,
		// so an unsearchable ancestor (e.g. root-owned 0700) makes every run
		// fail with EACCES and the step never converges. The privileged write
		// path has no such need — root traverses its own 0700 directories fine —
		// so requiring o+x there would refuse legitimate system trees.
		if c.Mode&0o001 == 0 {
			return fmt.Errorf("refusing to provision %s: %s (mode %o) cannot be traversed by the site user or by www-data, so berth could create the directories but the site could never use them; run `chmod o+x %s` before re-running", subject, c.Path, c.Mode, c.Path)
		}
	}
	return nil
}

// assertSiteTreeOwners fails loudly when an EXISTING per-site directory
// (deploy_path, shared, shared/tmp) is owned by a different user than the
// configured/derived site user, or is not a directory at all. Adopting such
// a tree silently would be a lie: install -d -o re-owns only the directory
// itself, never its contents (the app would still 500 on an unreadable
// shared/.env), and the previous account, its deploy key and its sudoers
// entry would linger as orphans. Absent paths pass — a fresh provision
// creates them. Deliberately NOT bypassable with --force (like the symlink
// guard): after a deliberate migration the owner matches and the guard
// passes on its own. The probe is guard-specific (%U owner name, %u uid,
// %F type — type last, it contains spaces): GNU stat prints UNKNOWN for %U
// when the uid has no passwd entry, so the uid is captured too, and the pin
// suggestion is offered only for owners that are valid sites[].user
// candidates. %F is localized via gettext, so the probe pins LC_ALL=C.
func assertSiteTreeOwners(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site) error {
	user := s.SiteUser(site)
	for _, p := range []string{site.DeployPath, site.DeployPath + "/shared", site.DeployPath + "/shared/tmp"} {
		res, err := r.Run(ctx, "LC_ALL=C stat -c '%U %u %F' "+shQuote(p), nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			// Absent. The path-chain assertion already proved every existing
			// component is a real directory, so a nonzero exit here means
			// ENOENT — barring IO failure or a tenant swapping a symlink in
			// between (two separate SSH commands). That residual race can only
			// skew THIS verdict (adopt vs refuse); it can never hand anything
			// over, because no root-run mutation targets a tenant-controlled
			// path any more.
			continue
		}
		fields := strings.Fields(strings.TrimSpace(res.Stdout))
		if len(fields) < 3 {
			return fmt.Errorf("unexpected stat output probing %s: %q", p, strings.TrimSpace(res.Stdout))
		}
		owner, uid, ftype := fields[0], fields[1], strings.Join(fields[2:], " ")
		if ftype != "directory" {
			return fmt.Errorf("refusing to manage site %s: %s exists but is not a directory (%s) — inspect and remove it before re-running", site.Domain, p, ftype)
		}
		if owner != user {
			hint := "migrate the tree deliberately (create the target account first, chown the tree, move the deploy key, then run a full provision — see the site identity note in the README)"
			if config.IsValidSiteOSUser(owner) {
				hint = fmt.Sprintf("pin sites[].user: %q to keep the existing identity, or %s", owner, hint)
			}
			return fmt.Errorf("refusing to manage site %s: %s is owned by %s (uid %s) but the configured site user is %q; %s", site.Domain, p, owner, uid, user, hint)
		}
	}
	return nil
}

func (a appDirs) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	// Safety preflight over EVERY site before any drift verdict: the drift
	// loop below returns at the first unsatisfied entry, and a later site's
	// foreign-owned tree must fail the whole run loudly (also in dry-run).
	for _, site := range s.Sites {
		if err := assertNoSymlinkTargets(ctx, r, s, site); err != nil {
			return provision.CheckResult{}, err
		}
		if err := assertSiteTreeOwners(ctx, r, s, site); err != nil {
			return provision.CheckResult{}, err
		}
		// The site user creates shared/ and shared/tmp itself and can only
		// chgrp to a group it belongs to; a non-member account would fail with
		// a raw EPERM mid-Apply. mustExist=false: --only appdirs may run
		// before accounts creates the user.
		if err := assertGroupMembership(ctx, r, s.SiteUser(site), false); err != nil {
			return provision.CheckResult{}, err
		}
	}
	for _, site := range s.Sites {
		user := s.SiteUser(site)
		// Owner AND mode: deploy_path 0710 (<user>:www-data — nginx traverses,
		// sibling tenants cannot enter), shared/ and shared/tmp 0700 private,
		// ACME webroot 0755. A drifted mode silently breaks tenant isolation, so
		// it is probed exactly like ownership (stat prints modes without a
		// leading zero). Apply's install -d resets both on existing dirs.
		for _, d := range []struct{ path, meta string }{
			{site.DeployPath, user + ":www-data 710"},
			{site.DeployPath + "/shared", user + ":" + user + " 700"},
			{site.DeployPath + "/shared/tmp", user + ":" + user + " 700"},
			{acmeWebroot(site.Domain), "root:root 755"},
		} {
			meta, present, err := statOwnerMode(ctx, r, d.path)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !present || meta != d.meta {
				return provision.CheckResult{Satisfied: false, Reason: d.path + " missing or not " + d.meta, Changes: a.changes()}, nil
			}
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: "per-site application directories present with isolating owners"}, nil
}

func (appDirs) changes() []string {
	return []string{
		"install -d deploy_path (<user>:www-data 0710); shared and shared/tmp created as the site user (<user> 0700)",
		"install -d ACME webroot (owner root)",
	}
}

func (appDirs) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	// Same preflight as Check: no site may be mutated once ANY site's tree
	// is symlinked or foreign-owned.
	for _, site := range s.Sites {
		if err := assertNoSymlinkTargets(ctx, r, s, site); err != nil {
			return err
		}
		if err := assertSiteTreeOwners(ctx, r, s, site); err != nil {
			return err
		}
		if err := assertGroupMembership(ctx, r, s.SiteUser(site), false); err != nil {
			return err
		}
	}
	for _, site := range s.Sites {
		user := s.SiteUser(site)
		// Modes are five octal digits on purpose: GNU preserves a directory's
		// setuid/setgid bits under shorter numeric modes, so `-m 0700` could
		// leave an existing setgid directory at 2700 while Check demands 700 —
		// an endlessly re-applying step. Five digits clear the bits explicitly.
		//
		// Root creates only the two directories whose whole ancestry is
		// root-controlled (assertSafeAncestry proves it) and whose owner/group
		// the running account could not set for itself.
		rootDirs := []string{
			// deploy_path: site user owns it, group www-data + mode 0710 lets nginx
			// traverse to public/ while other site users cannot enter.
			fmt.Sprintf("install -d -o %s -g www-data -m 00710 %s", user, shQuote(site.DeployPath)),
			// ACME webroot: root-owned, because root-run certbot writes the
			// challenge files inside it and nginx only reads (see acmeWebroot).
			fmt.Sprintf("install -d -o root -g root -m 00755 %s", shQuote(acmeWebroot(site.Domain))),
		}
		// shared/ and shared/tmp live INSIDE deploy_path, which the site user
		// owns — a root-run install -d there is racy by construction: the probe
		// and the mutation are separate SSH commands, and install -d follows a
		// directory symlink and applies ownership to the target. Creating them
		// AS the site user removes root from the window: a swapped symlink can
		// then only reach what the tenant may already touch (chmod of a foreign
		// target fails EPERM, a dangling one fails EEXIST/ENOENT). -o is gone
		// because the creating account IS the owner; -g pins the group to the
		// account's own group, which is the state Check asserts.
		tenantDirs := []string{
			// shared/ holds .env and is private to the site user.
			fmt.Sprintf("sudo -u %s install -d -g %s -m 00700 %s", user, user, shQuote(site.DeployPath+"/shared")),
			// shared/tmp backs the pool's sys_temp_dir/upload_tmp_dir (no shared /tmp).
			fmt.Sprintf("sudo -u %s install -d -g %s -m 00700 %s", user, user, shQuote(site.DeployPath+"/shared/tmp")),
		}
		for _, cmd := range rootDirs {
			if res, err := r.Run(ctx, cmd, nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("create directories for %s: %s", site.Domain, res.Stderr)
			}
		}
		for _, cmd := range tenantDirs {
			if res, err := r.Run(ctx, cmd, nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("create directories for %s as %s: %s", site.Domain, user, res.Stderr)
			}
		}
	}
	return nil
}
