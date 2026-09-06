# Supply-chain security

## Security objective

Users may grant `privr` administrator privileges. The build, catalogue, update,
and release processes must therefore prevent policy data or dependency changes
from becoming an unexpected privileged execution path.

## Built-in catalogue

Normal releases contain an offline control catalogue. Each definition selects a
compiled adapter ID and semantic desired value. Catalogue data cannot add:

- shell or script execution;
- executable or dynamic-library paths;
- arbitrary Registry, service, task, preference, or file targets;
- a new privileged operation;
- unbounded IPC or journal content.

New privileged adapter types require source review, native tests, and a signed
binary release.

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

macOS mutation releases must use Developer ID signing and notarization. Linux
release archives and packages must carry checksums and provenance.

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
- [ ] Core commands remain offline when no explicit update is requested.
