# Supply-chain security

## Security objective

Users may grant `privr` administrator privileges. The build, catalogue, update,
and release processes must therefore prevent policy data or dependency changes
from becoming an unexpected privileged execution path.

## Built-in catalogue

Normal releases contain an offline control catalogue. Each definition binds an
adapter identifier, a target key, and a semantic state, all three resolving to
compiled variants at load. Catalogue data cannot add:

- shell or script execution;
- executable or dynamic-library paths;
- arbitrary Registry, service, task, preference, or file targets;
- a new privileged operation;
- unbounded IPC or journal content.

The governing invariant: **catalogue metadata may only narrow compiled
capability, never widen it.**

### The catalogue is embedded, not installed alongside

The catalogue is compiled into the signed binary rather than shipped as a
separate file next to it.

The reason is specific. A catalogue file beside an executable that requests
elevation is writable by anyone who can write the install directory. The adapter
ceiling would still hold, so no new privileged behavior could be introduced. But
an attacker could rewrite risk classes, rationale, and warning text to steer what
the operator approves, which defeats informed consent without ever breaking the
security model.

Embedding makes catalogue integrity identical to binary signature integrity, and
makes the catalogue digest a build-time constant.

New privileged adapter types require source review, native tests, and a signed
binary release.

### The elevated helper parses no data formats

The workspace split guarantees this structurally: the elevated helper depends
only on the typed operations crate and the bounded IPC crate. No JSON, TOML, or
other text parser is linked into the privileged component, so the class of
parser vulnerability that would otherwise sit behind an elevation prompt does not
exist there.

## Future catalogue updates

There is no automatic catalogue update. A future explicit update command should
use [The Update Framework specification](https://theupdateframework.github.io/specification/)
semantics:

- an offline, threshold-signed root of trust;
- signed target, snapshot, and timestamp metadata;
- expiration and monotonic version checks;
- consistent target naming and digest verification;
- rollback and freeze-attack resistance;
- a locally visible source, version, digest, and install result.

Canonical serialization and a digest help identify the reviewed input, but a
plan digest is correlation evidence, not authorization. The privileged helper
still rebuilds operations from trusted compiled adapters and fresh state.

## Rust dependencies

- Commit `Cargo.lock` and use `--locked` in CI and release builds.
- Keep the dependency tree small, especially for privileged components.
- Run advisory, license, source, and duplicate-version policy checks.
- Prefer crates with clear ownership, active maintenance, and narrow features.
- Consider vendored dependencies and `--frozen` for controlled release builds.
- Deny `unsafe` code by default. Any narrow platform FFI exception needs an
  explicit safety contract and focused review.
- Deny networking, TLS, and asynchronous runtime crates outright. See
  `deny.toml`. This is the first of four layers enforcing the offline guarantee;
  a denylist alone is insufficient because the standard library opens sockets
  with no crate at all. The remaining layers are in [TESTING.md](TESTING.md).
- Leave dependency-policy target filtering unset. Pinning it would evaluate only
  the named platforms, letting a platform-specific network dependency pass unseen
  in a single-platform job.
- Build with unwinding panics. Aborting skips destructors, which would prevent an
  interrupted apply from flushing its transaction journal.

Cargo documents locked and vendored builds in its
[Cargo source replacement guidance](https://doc.rust-lang.org/cargo/reference/source-replacement.html).

## Continuous integration

- Pin third-party actions to reviewed full commit identifiers.
- Grant only `contents: read` to ordinary validation jobs.
- Separate pull-request validation from protected release jobs.
- Never expose release or signing credentials to untrusted contributions.
- Require code-owner review for policy parsing, elevated adapters, IPC,
  journaling, rollback, and release workflows.
- Record toolchain and dependency versions used to produce artifacts.

GitHub's [secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
describes full-length commit pinning and least-privilege workflow permissions.

## Release artifacts

Before the first public release that requests elevation:

- build Windows x64 and ARM64 artifacts in a protected workflow;
- Authenticode-sign and timestamp Windows binaries;
- publish SHA-256 checksums;
- generate an SPDX or CycloneDX software bill of materials;
- publish provenance and GitHub artifact attestations;
- require two-person approval for release and privileged-component changes;
- verify the packaged binary in a clean VM before publication.

GitHub documents signed provenance through
[artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations).
Microsoft documents signing with
[SignTool](https://learn.microsoft.com/windows/win32/seccrypto/signtool).

macOS mutation releases must use Developer ID signing and notarization. A bare
command-line binary cannot have a notarization ticket stapled to it, so the
macOS distributable is an installer package rather than a loose executable.
Linux release archives and packages must carry checksums and provenance.

An Extended Validation certificate does not exempt a Windows binary from
reputation checks. Microsoft's current guidance is that reputation accrues
regardless of certificate class, so the release plan should not assume signing
alone removes the first-run warning.

**No binary is published for a platform whose adapters are unimplemented.** A
download that reports nothing useful is worse than no download, and it converts
an honest status statement into a broken promise at the moment someone runs it.

## Installation

Installation is a single command per platform, matching the norm for developer
command-line tools. Two properties keep that compatible with the trust model:

- **The installer is unprivileged.** It places a binary and does nothing else. It
  never requests elevation and never changes a system setting. `privr` requests
  elevation only at apply time, after a plan has been displayed and approved.
- **The script is reviewable.** It is short, served from this repository so the
  published URL and the file in the tree are visibly the same artifact, and
  linked directly from the README.

Package manager entries are listed alongside the one-line installer rather than
buried, because a signed package flow is preferable for operators who want one.

Until signed release artifacts exist, the README documents building from source.
An installer that fetches unsigned binaries would undercut the trust position it
is meant to support.

## Update ownership

There is no elevated self-updater. Package managers or explicit user downloads
own binary updates. Catalogue and binary updates remain separate trust events.

Published versions are never silently replaced. A compromised signing key or
release workflow requires a documented revocation and recovery procedure before
the first stable release.

## Verification checklist

- [ ] Locked build succeeds from a clean checkout.
- [ ] Dependency and license policy passes.
- [ ] CI action revisions are reviewed and pinned.
- [ ] Release permissions are minimal and protected.
- [ ] Checksums, SBOM, provenance, and attestations match every artifact.
- [ ] Windows signatures and timestamps verify on a clean machine.
- [ ] Catalogue signatures, expiry, version, and digest checks fail closed.
- [ ] Downloaded metadata cannot select an unknown privileged adapter.
- [ ] Core commands remain offline when no explicit update is requested, proven
      by dependency policy, lint, import-table assertion, and runtime isolation.
- [ ] No data-format parser is linked into the elevated helper.
- [ ] The installer requests no elevation and changes no system setting.
- [ ] No artifact is published for a platform without implemented adapters.
- [ ] Release binaries unwind on panic.

## Scheduled maintenance tooling

Repository automation may re-verify citations, detect platform change, and open
pull requests. It is subject to a hard boundary: **nothing merges
automatically.** No scheduled run may commit to the catalogue, change a risk or
reversibility class, alter rationale or warning text, or promote a control's
maturity.

Catalogue content steers what an operator approves, so an automated edit path
would defeat informed consent without touching the adapter ceiling. This is the
same reasoning that keeps the catalogue embedded rather than installed alongside
the binary. See [MAINTENANCE.md](MAINTENANCE.md).

This tooling lives in the repository and is not part of any shipped artifact. The
released binary contains no model client and makes no network call.
