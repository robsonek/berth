package ssh

import (
	"fmt"
	"path"
)

// validateRootDestination enforces the contract of the privileged write path:
// WriteFile installs files into trees ROOT controls, and nothing else.
//
// Every requirement here exists because the alternative was exploitable. The
// primitive stages its temp file inside the destination directory and then
// renames it, so an unprivileged account that can write any component of the
// path can substitute the staged inode (a hard link it keeps) or replace the
// final name afterwards. Root ownership of the content does not help: a
// root-owned file is itself a capability — an authorized_keys landing in
// /root/.ssh through a swapped symlink grants root, and berth having generated
// the bytes does not make them harmless.
//
// Files inside territory an account owns are therefore NOT written here. They
// go through steps.writeFileAsUser, which performs the whole sequence as that
// account, so a swapped path can only reach what the account may already touch.
//
// This is a static check: it runs before any command reaches the host, so a
// violating call mutates nothing. The ancestry of the destination is verified
// separately, by a probe, because it depends on live host state.
//
// What this does NOT promise: Runner.Run remains an arbitrary shell, so a step
// can still perform a root-run mutation without going through this primitive.
// The guard against that is the mutation-intent assertion in the steps tests,
// not this function.
func validateRootDestination(f FileSpec) error {
	if !f.Sudo {
		// Sudo:false was never a privilege boundary: connected as root the write
		// runs as root regardless, so an identical FileSpec meant different
		// things depending on how berth logged in. The primitive is
		// unconditionally privileged; the field stays only to keep call sites
		// explicit about that.
		return fmt.Errorf("write %s: Sudo must be true — WriteFile is unconditionally privileged; an account-owned file belongs in steps.writeFileAsUser", f.Path)
	}
	if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path {
		return fmt.Errorf("write %s: destination must be an absolute, clean path", f.Path)
	}
	if f.Owner != "" && f.Owner != "root" {
		return fmt.Errorf("write %s: owner %q is not root — the privileged write path may only produce root-owned files; use steps.writeFileAsUser to write as %s", f.Path, f.Owner, f.Owner)
	}
	if f.Group != "" && f.Group != "root" {
		return fmt.Errorf("write %s: group %q is not root — the privileged write path may only produce root:root files; use steps.writeFileAsUser instead", f.Path, f.Group)
	}
	if f.Mode.Perm()&0o022 != 0 {
		return fmt.Errorf("write %s: mode %#o is group- or other-writable, so the file berth just created could be rewritten by someone else", f.Path, f.Mode.Perm())
	}
	return nil
}
