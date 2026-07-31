# Notes for coding agents

Short by design. This file lists only the places where the obvious move is the
wrong one. For what berth does and how to configure it, read `README.md`.

## The shape of the code

berth is one pipeline of idempotent **Steps** run over a single SSH connection.
Every step implements:

```go
Name() string
Requires() []string
Check(ctx, RunCtx, *config.Server, ssh.Runner) (CheckResult, error)  // read-only
Apply(ctx, RunCtx, *config.Server, ssh.Runner) error                 // mutates
```

`Apply` runs only when `Check` reports `Satisfied: false`. Steps reach the host
exclusively through the `ssh.Runner` interface, which is what makes them
testable without a server.

**`Check` must be side-effect-free, and this is enforced by test, not by
convention.** `TestChecksAreReadOnly` runs every step's `Check` against modelled
host states and classifies every command it issues. A command that writes fails
the build, naming the step and the command. If your new probe fails it, the fix
is almost always to move the write into `Apply` — not to widen the classifier.

## Traps

**Step order is by REGISTRATION, not topological.** `steps.Pipeline()` returns
the slice in execution order. `Requires()` is consulted only by the `--only`
gate; it never reorders a run. If you add a step, place it in the slice by hand
*and* keep its `Requires()` consistent with that position.

**Never run `go mod tidy`.** It prunes dependencies that are listed ahead of
use. Add dependencies with `go get`.

**Charm v2 import paths are `charm.land/<name>/v2`**, not
`github.com/charmbracelet/...` — that is the v1 path.

**There are zero `//nolint` directives in the tree. Keep it that way.** If the
linter objects, the code changes, not the linter. `golangci-lint` runs in two
passes: the default tree, then with `--build-tags integration`.

**A non-zero `Result.ExitCode` is data, not a Go error.** Many probes read
"absent" from a non-zero exit. Check both the error and the code; returning a Go
error where a real host would return exit 1 sends a step down a path it never
takes in production.

**Classifier and probe predicates are allowlists, never denylists.** Where the
code decides whether a command shape is acceptable, it enumerates what is
permitted. Denylists of "bad flags" have failed repeatedly here: a flag can be
spelled `-o value`, `-ovalue`, `--out=value`, or bundled, and one missed
spelling silently permits a write.

## Frozen surfaces

Each of these is pinned by a contract test. Changing one is a BREAKING change
and needs a deliberate changelog entry, because it reclassifies state on every
already-provisioned host:

- **The managed-marker text** (`# managed by berth`, `; managed by berth` for
  INI). It is part of the hashed content that drives drift detection, so editing
  it makes every managed file on every host read as unmanaged.
- **The name-derivation functions** — OS user, FPM pool, socket, supervisor
  program, database names. Never re-derive these ad hoc; call the helpers.
- **The on-host default values.**

Always write managed files through `templates.Render` / `RenderINI` so the
marker is prepended for you.

## Tests

`FakeRunner` matches **exact** command strings, so step code must emit stable,
matchable commands. Building a command by concatenating in a different order
will fail tests that were passing.

Template output is covered by golden files. After editing a `.tmpl`, run the
package's tests with `-update`, read the resulting diff, then commit it.

The integration suite lives behind the `integration` build tag and needs a real
Debian host, so `go test ./...` never runs it. It is not a substitute for the
unit tests, and the unit tests are not a substitute for it.

## Multi-tenant isolation

One config may describe many sites, and per-site resources are derived
deterministically. Two rules carry the isolation:

- Derive per-site identities with the shared helpers only. Ad-hoc derivation is
  how two sites end up sharing a user, a socket or a database.
- **Per-site sudoers grants are deliberately narrow** — a site user may reload
  PHP-FPM through a fixed wrapper and control its own supervisor programs, and
  nothing else. Widening them breaks the isolation the design exists for.

## Repository conventions

This is a public MIT repository. Code, comments, commit messages and
documentation are **English only** and must contain no host names, IP addresses,
credentials, or other environment-identifying data. Use `example.com` and the
reserved `203.0.113.0/24` range in tests and examples.

Commands worth knowing:

```bash
make build          # static build with version ldflags
make test           # go test ./...
go test -race ./... # what CI runs
make lint           # golangci-lint, pinned version
gofmt -l .          # must be empty
```
