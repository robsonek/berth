# Design: swap file + kernel sysctl tuning (the "system" cluster)

**Status:** approved design, pending implementation plan
**Date:** 2026-06-20
**Branch:** `feat/system-swap-sysctl` (to be created off up-to-date `main`)

## 1. Problem & goal

berth provisions small-RAM VPS boxes (the typical target is a 1–2 GB Hetzner/DO/OVH
instance) into multi-tenant Laravel hosts: several PHP-FPM pools, a database, Valkey,
queue workers, plus a memory-hungry `composer install` during deploys. Two gaps exist
today (verified: a repo-wide grep for `swap`/`swappiness`/`sysctl` in non-test step
code returns nothing):

1. **No swap.** Under a load/memory spike the kernel OOM-killer terminates a process —
   usually the database or a queue worker. An idempotent re-provision cannot recover a
   killed runtime; the box just degrades. A swap file provides an emergency memory
   margin so the box throttles instead of killing.
2. **No kernel sysctl tuning.** Debian 13 (trixie) defaults are *mostly* sane, so this
   is the low-value half — included only as an explicit opt-in for operators who want
   the small web+DB tuning set.

### Goal

Add an opt-in, declarative, idempotent **`system`** step that:

- creates and activates a swap file of a configured size (default off), with a
  persistent `/etc/fstab` entry and a conservative `vm.swappiness` so swap behaves as
  an emergency margin rather than a routine offload;
- optionally (default off) writes a small, opinionated kernel sysctl drop-in for a
  web+DB host;
- is fully drift-managed: turning a knob **off** removes the artifacts berth created
  (no "config lie" where the YAML says off but the box still swaps), guarded so berth
  never touches a swap file or fstab line it did not create.

### Non-goals (explicit)

- **Swap is off by default.** Some cloud images and container hosts forbid or cannot
  use swap files; berth must not impose one. Absence of the knob = berth never touches
  swap.
- **No size-from-RAM heuristic.** The size is an explicit string (`swap: 2G`). A
  declarative provisioner's contract is "the YAML fully describes the box"; a
  RAM-derived size would make the same YAML produce different boxes. (Decided with the
  user.)
- **General sysctl tuning is off by default.** trixie defaults are already reasonable,
  so default-on would be near-zero-benefit churn and a surprising kernel-level side
  effect. It is available behind `system.sysctl: true`. (Decided with the user.)
- **No per-knob sysctl config.** The general set is a fixed, opinionated constant set
  (no per-value knobs) — same posture as berth's other opinionated hardening.
- **No `init` wizard integration in this change.** The wizard prompt for
  `system.swap`/`system.sysctl` is deferred to a separate, smaller change (§9), exactly
  as the `cloudflare_only` flag deferred its wizard prompt.
- **No runtime-value restore on disable.** When a knob is turned off, berth removes its
  managed files; the *running* kernel value reverts to the distro default on the next
  reboot (documented), rather than berth trying to compute and re-assert "the default".

## 2. Config surface

A new `system:` block on `Server`, grouping the OS-level knobs (mirrors how `tuning:`
and `fail2ban:` group related sub-settings):

```go
// System holds optional, opt-in host-level OS provisioning knobs. Both default off:
// an empty Swap and a false Sysctl mean berth never touches swap or kernel sysctl.
type System struct {
    Swap   string `mapstructure:"swap"   yaml:"swap,omitempty"`   // e.g. "2G"; empty = no swap
    Sysctl bool   `mapstructure:"sysctl" yaml:"sysctl,omitempty"` // default false = no sysctl drop-in
}
```

added to `Server`:

```go
System System `mapstructure:"system" yaml:"system,omitempty"`
```

YAML examples:

```yaml
system:
  swap: 2G        # create /swapfile (2 GiB) + fstab + vm.swappiness=10
  sysctl: true    # write the general web+DB sysctl drop-in
```

```yaml
# (no system: block) -> berth never touches swap or sysctl
```

### Validation (`config.Validate`)

- If `System.Swap != ""`, it must match `^[1-9][0-9]*[MG]$` (case-insensitive on the
  suffix; normalized to uppercase before use). Examples accepted: `512M`, `2G`.
  Rejected: `0G`, `2`, `2GB`, `2g ` (trailing space), `-1G`. Mirror the **lenient**
  posture used elsewhere: an empty `Swap` is simply "off" and always passes.
- **Units are binary** to match `fallocate -l` and `stat -c %s`: `M` = MiB (1024²),
  `G` = GiB (1024³). The size is passed verbatim to `fallocate -l <size>` and the
  parsed byte value (e.g. `2G` → `2*1024³`) is what `Check` compares against
  `stat -c %s /swapfile`, so creation and the size-match check agree exactly.
- `System.Sysctl` is a bool; no validation needed.
- **No `SetDefault`.** Empty/false already means off; the `swappiness` value and the
  general sysctl set are compile-time constants, not config-derived, so there is no
  default to seed (and wizard `ToServer()` / literal-`Server` callers that bypass
  `Load()` therefore need nothing). This matches the `*Eff()`/no-SetDefault rule the
  tuning step established.

## 3. Pipeline placement & step identity

- New step type `system struct{}`, exported constructor `func System() provision.Step`,
  `Name() == "system"`, `Requires() []string == {"preflight"}` (its only true
  dependency — it needs no packages from `base`; `fallocate`/`mkswap`/`swapon` are
  util-linux and `sysctl` is procps, both always present on Debian 13).
- **Placed in the `Pipeline` slice immediately after `SystemBase()`** (so before
  `php`/`composer`/`database`). Rationale: the swap margin then also protects the
  memory-hungry provisioning itself (`composer install`, package unpacks).
- **The step is ALWAYS in the pipeline (ungated)** — unlike `tuning` (gated on
  Valkey/MariaDB). If it were gated on `swap != "" || sysctl`, turning swap off would
  remove the step entirely and the orphaned `/swapfile` would keep swapping while the
  YAML says off — the exact "dead flag" class the scheduler fix (roadmap #11) closed.
  When both knobs are off and no berth artifacts exist, the step's `Check` is a cheap
  read-only no-op reporting `Satisfied`.

`Requires()` stays consistent with this position (it lists `preflight`, which precedes
it). Per CLAUDE.md, the slice order — not `Requires()` — drives a full run; the
placement is by hand.

## 4. Artifacts the `system` step owns

All berth-written config files carry the managed marker and are drift-checked via the
existing `checkManagedFile` → `managedFileSatisfied` mechanism. The swap *binary* file
is not a marker file; its berth ownership is tracked via the fstab marker line (§4.2).

| Path | Written when | Content |
|---|---|---|
| `/swapfile` | `Swap != ""` | binary swap area of the requested size; ownership tracked via the fstab marker |
| line in `/etc/fstab` | `Swap != ""` | `/swapfile none swap sw 0 0 # managed by berth` — appended/removed, **never a full-file rewrite** |
| `/etc/sysctl.d/99-berth-swap.conf` | `Swap != ""` | `vm.swappiness=10` (managed marker, `#`) |
| `/etc/sysctl.d/99-berth.conf` | `Sysctl == true` | general web+DB set (managed marker, `#`) |

### 4.1 swappiness drop-in (ships with swap)

`vm.swappiness=10` — a server should treat swap as an emergency margin: prefer
reclaiming page cache over swapping out active process memory. The default (60) swaps
too eagerly and hurts latency. Only meaningful when swap exists, so it is part of the
swap feature, not the general sysctl set. Rendered from a static template
`sysctl_swap.conf.tmpl`.

### 4.2 fstab handling (the one delicate area)

`/etc/fstab` is a **foreign, shared** system file (it holds the root/boot entries);
berth must never rewrite it wholesale. Instead:

- **Ownership marker (at end of line):** berth's line *ends with* `# managed by berth`.
  Ownership is decided by `strings.HasSuffix(strings.TrimSpace(line), managedMarker)` —
  NOT `strings.Contains`. This is load-bearing: the removal `sed` matches the marker at
  end-of-line (`$`), so the Go classifier MUST use the same "marker at trimmed EOL"
  criterion or the two disagree (a line with the marker mid-text would read as berth-owned
  yet the sed would not delete it). Leading whitespace is allowed (trimmed).
- **Add (newline-safe):** if berth's marked line is absent, first normalize (delete ANY
  `/swapfile` line — a no-op on a clean box, a clean takeover under `--force`), then
  append. The append uses `printf '\n%s\n'` (leading newline) so that even if
  `/etc/fstab` does not end in a newline, berth's entry starts on its own line instead of
  concatenating onto the previous entry. (A stray blank line is harmless — fstab ignores
  blanks; and the append happens at most once because the next run sees the marked line.)
- **Foreign = conflict:** if ANY `/swapfile` line exists **without** the berth marker (or
  a `/swapfile` file exists with no marked fstab line), berth treats it as unmanaged: do
  not touch; abort unless `--force` (consistent with `managedFileSatisfied`). This holds
  even when a berth-marked line ALSO exists (a mixed/duplicate state) — `foreign == true`
  alone is a conflict. Under `--force`, berth normalizes (delete-any + append one marked
  line) and **recreates** the swap file (`fallocate`+`mkswap`+`swapon`) rather than
  trusting an unmarked existing file (which a crash could have left as a non-swap file).
- **Remove:** delete only the line carrying both `/swapfile` and the berth marker at EOL
  (targeted `sed`, `fstabSedMarked`), never any other fstab line.

A broken fstab can impede boot, so this is the primary safety focus (§7, §8). Mitigation:
never rewrite; only append one newline-safe well-formed line, or delete our exactly-marked
line.

### 4.3 general sysctl drop-in (opt-in)

`/etc/sysctl.d/99-berth.conf`, rendered from a static `sysctl_berth.conf.tmpl`
(managed marker, `#`), fixed opinionated set:

```
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 1048576
fs.inotify.max_user_watches = 524288
```

These are conservative and broadly safe for a multi-tenant web+DB host. Values are
constants in the template (no per-server knobs). Applied with `sysctl --system`.

## 5. Idempotency: `Check` (side-effect-free, convergent)

`Check` is a read-only predicate. It evaluates each enabled concern and aggregates a
human-readable change list when unsatisfied.

**Swap enabled (`Swap != ""`):** satisfied iff ALL of:
- `/swapfile` exists AND its size equals the requested size (a `2G → 4G` change is
  detected, not silently ignored — size read via `stat -c %s`, compared to the parsed
  byte size);
- `swapon --show` reports `/swapfile` active;
- the berth-marked line is present in `/etc/fstab`;
- the swappiness drop-in is up-to-date (`managedFileSatisfied`) **and** the running
  value is loaded (`/proc/sys/vm/swappiness == 10`) — convergent, so an out-of-band
  change re-applies.

**Swap disabled (`Swap == ""`) but a berth-marked fstab line and/or `/swapfile` and/or
the swap drop-in exist:** unsatisfied → removal planned.

**Sysctl enabled (`Sysctl == true`):** satisfied iff the drop-in is up-to-date AND the
running values match (`sysctl -n <key>` equals each desired value) — convergent.

**Sysctl disabled (`Sysctl == false`) but `99-berth.conf` is berth-managed:**
unsatisfied → removal planned.

**Conflict** while `Swap != ""` — a `/swapfile` line in fstab without the berth marker
at EOL, OR a `/swapfile` file present with no berth-marked fstab line (`conflict :=
foreign || (exists && !marked)`): reported like an unmanaged file — abort unless
`--force`. Under `--force`, unsatisfied (takeover pending), no error.

If nothing is enabled and no berth artifacts exist: `Satisfied: true` (no-op).

## 6. `Apply` (mutating, re-entrant, only reconciles what `Check` flagged)

Like the `tuning` step, `Apply` re-runs the same per-concern predicate `Check` uses, so
a healthy concern is skipped (no spurious swapoff/restart).

**Swap create/converge (`Swap != ""`):** let `recreate := !exists || size-differs ||
!marked` (the `!marked` term forces a rebuild on a `--force` takeover of any unmarked
existing file — a crash between `fallocate` and `mkswap` could have left a non-swap file).
1. If a file exists and `recreate`: `swapoffIfActive` (see below) → `rm -f /swapfile`.
2. If `recreate`: `fallocate -l <size> /swapfile` → `chmod 600 /swapfile` → `mkswap
   /swapfile`. (Assumes an ext4 root, the Debian 13 default; verified on the live ext4
   host. A `dd` fallback for non-ext4 is out of scope.)
3. If `/swapfile` is not an active swap area: `swapon /swapfile`.
4. If the berth-marked fstab line is absent OR a foreign `/swapfile` line exists:
   `sed -i <fstabSedAny>` (delete any `/swapfile` line) → newline-safe append of the
   marked line (`printf '\n%s\n' …`).
5. Write `sysctl_swap.conf.tmpl` to `99-berth-swap.conf`; `sysctl -p
   /etc/sysctl.d/99-berth-swap.conf`.

**`swapoffIfActive`:** read `swapon --show=NAME --noheadings`; if `/swapfile` is active,
run `swapoff /swapfile` with the **fail-loud** `runOK` (so an active-swap `swapoff`
failure — e.g. ENOMEM on a memory-pressured small box, the typical target — aborts
*before* any `rm`/recreate). If inactive, it is a no-op. (This replaces a blanket
"ignore every swapoff error", which would let `rm -f` run over a still-active swap.)

**Swap remove (`Swap == ""`, berth artifacts present):**
1. `swapoffIfActive` (only swapoff an active swap; fail loud on a real failure).
2. Remove only the berth-marked `/swapfile` line from `/etc/fstab` (targeted `sed`,
   `fstabSedMarked`).
3. `rm -f /swapfile`.
4. `rm -f /etc/sysctl.d/99-berth-swap.conf`.
   (Running swappiness reverts on next reboot; not force-reset — see §1 non-goals.)

**Sysctl enable/converge (`Sysctl == true`):** write `99-berth.conf`; `sysctl --system`.

**Sysctl remove (`Sysctl == false`, file berth-managed):** `rm -f
/etc/sysctl.d/99-berth.conf`; `sysctl --system`.

All `r.Run` calls check both the Go error and a non-zero `ExitCode`; secrets are not
involved. File writes go through `r.WriteFile` with `root:root 0644` (drop-ins) /
`0600` (the swap file is `chmod 600`).

## 7. Error handling & safety

(This section was hardened after a Codex foreground review of the design+plan — see the
five points below, all folded in.)

- **fstab (highest risk):** never a full rewrite; append one newline-safe well-formed line
  (`printf '\n%s\n'`) or delete the exactly-marked line. Ownership is "marker at trimmed
  EOL" so the Go classifier and the removal `sed` agree. The conflict guard prevents
  clobbering an operator's own swap entry.
- **`swapoff` is fail-loud when active:** `swapoffIfActive` only `swapoff`s an active swap
  and propagates a genuine failure (e.g. ENOMEM under memory pressure) so `Apply` never
  `rm`s/recreates over a still-active swap. An inactive swap is a no-op (not an error).
- **`--force` takeover recreates:** taking over an unmarked existing `/swapfile` always
  rebuilds it (`fallocate`+`mkswap`+`swapon`) rather than trusting a possibly-non-swap
  file, and normalizes fstab to exactly one marked line.
- **swapon failure** (e.g. fallocate produced a holey file on an unexpected FS): `Apply`
  returns a loud error (non-zero exit surfaced), not a silent pass.
- **Ungated step on a box that forbids swap:** with `Swap == ""` the swap branch never
  runs, so a no-swap policy box is unaffected.

## 8. Testing

**Unit (no host):**
- `config` validation: table test of accepted/rejected `swap` sizes; `sysctl` bool;
  round-trip through `config.Load` on an `examples/` sample.
- `system` step `Check`/`Apply` via `FakeRunner` with exact, matchable command strings:
  create path, idempotent re-run (all satisfied → zero writes/mutations), size-change
  path, swap-off removal path (asserts only the marked fstab line is targeted and the
  foreign-`/swapfile` guard aborts), sysctl enable + disable paths.
- Golden tests for the two new templates (`sysctl_swap.conf.tmpl`,
  `sysctl_berth.conf.tmpl`): `go test -update ./internal/templates/...`, diff, commit.

**Live (integration, behind the `integration` tag, on a fresh Debian 13 ext4 host):**
- With `swap: 2G`: `swapon --show` lists `/swapfile` at the right size; the marked
  fstab line is present; `cat /proc/sys/vm/swappiness == 10`.
- With `sysctl: true`: each `sysctl -n <key>` equals the configured value.
- **Second-run idempotency:** every step (incl. `system`) reports `Satisfied` on an
  immediate re-run.
- **Disable round-trip:** re-provision with the knob removed; assert `/swapfile` gone,
  no berth fstab line, drop-ins removed, `swapon --show` empty — and an unrelated box
  state otherwise unchanged.

(Maps to roadmap test items: "swapon --show reports the file" and the second-run
all-Satisfied assertion.)

## 9. Deferred follow-ups (out of scope here)

- `init` wizard prompts for `system.swap` / `system.sysctl` (separate small change,
  consistent with the deferred `cloudflare_only` wizard prompt).
- `dd` fallback for non-ext4 roots; `vm.vfs_cache_pressure` and other knobs (YAGNI).
- README "Configuration reference" + an `examples/*.yml` line for the `system:` block
  (small docs task, can ride along or follow).
- **Swap-file permission drift is NOT reconciled (deliberate, YAGNI).** `/swapfile` is
  created `0600 root:root` at provision time; `Check` does not re-verify the mode/owner
  on later runs, so an out-of-band `chmod` is not healed. Fresh-provision correctness is
  the contract; long-lived perm-drift healing is out of scope (a Codex review flagged this
  as a possible security-drift hole — accepted as a documented limitation). Recorded as a
  code comment in `applySwap`.
- **A partial first-create is recovered via `--force`, not automatically.** If berth
  crashes between creating `/swapfile` and appending the marked fstab line, the next
  non-`--force` run sees an unmarked file and aborts as foreign (berth never adopts a swap
  file it cannot prove it created). Re-provisioning with `--force` takes it over and
  rebuilds it. (Also a Codex finding; accepted as a safe, documented limitation rather
  than an atomic temp-file rework.)

## 10. Docs

- Add the `system:` block (with `swap`/`sysctl`, their defaults and accepted values) to
  the README Configuration reference.
- Show it in one `examples/*.yml` (public test-data only — `203.0.113.x` /
  `example.com`), kept valid by the existing `TestExampleConfigsAreValid`.
