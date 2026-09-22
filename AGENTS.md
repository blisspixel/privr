# Repository instructions

`privr` is a local-first privacy posture CLI in Rust. It reads which optional
data-sharing settings are actually in effect, explains the evidence, and will
apply and reverse changes in reviewed steps. The product is the gap between a
configured value and the value in effect, so a wrong `pass` is the worst
possible bug.

## Sources of truth

- Product intent: `README.md` and `docs/PRODUCT.md`.
- Binding decisions: `docs/DECISIONS.md`. It overrides older statements in
  other documents until they are updated.
- Planned work and milestone order: `ROADMAP.md`. Planned is not shipped.
- Implemented behavior: `src/` and `tests/`. Code and tests outrank prose. Several
  documents still describe a concept build with fewer controls than exist; fix
  a stale status claim when your change touches it.
- Contribution workflow and control proposals: `CONTRIBUTING.md` and
  `docs/CONTROL_STANDARD.md`.

## Where code belongs

- `src/model/`: shared host, evidence, applicability, and outcome types, shaped
  for all three platforms. Extend these types rather than adding parallel ones.
- `src/engine/`: evaluation as a pure function. It never touches the operating
  system and contains no `cfg`.
- `src/catalog/<platform>.rs`: compiled control definitions. Each binds a
  compiled probe to metadata and cited sources. No path, key, command, or
  target may come from outside the binary.
- `src/platform/<platform>/`: discovery and typed probes. `cfg` belongs here.
  Probes read through a `Context`, so the same control code runs against a live
  host and against recorded evidence.
- `src/app.rs` dispatches commands; `src/report.rs`, `src/explain.rs`,
  `src/manifest.rs`, and `src/ui/` render. Keep one diagnostic vocabulary.
- The crate stays single until the first machine-scope write exists
  (`docs/ARCHITECTURE.md`). The codebase is synchronous: no async runtime.
- `unsafe_code` is forbidden crate-wide. Use the safe platform crates already
  in `Cargo.toml` before adding a dependency.

## Professional standard

- Treat this as a production-quality privacy and security tool.
- Write concise, precise, technically defensible prose.
- No attribution of any kind to an assistant, model, vendor, or tool (for
  example Claude, Codex, Copilot, or ChatGPT). This covers source, comments,
  documentation, generated artifacts, commit messages, PR and issue text,
  release notes, and `Co-Authored-By`, `Generated with`, or similar trailers
  and footers. Commit as the git identity already configured for the
  repository and never change it. Preserve required third-party legal notices.
- Do not use emojis.
- Do not use em dashes or en dashes. Use commas, parentheses, colons, or
  ordinary hyphens.
- Avoid hype, fear-based language, profanity, and unsupported privacy claims.
- Never promise anonymity, zero telemetry, or complete privacy when a platform
  does not provide that guarantee.

## Privacy requirements

- `privr` must collect no product telemetry.
- Normal check, plan, apply, rollback, and reporting workflows must work without
  network access.
- Reports and transaction journals must minimize and redact local identifiers,
  usernames, account IDs, paths, command lines, recovery material, and secrets.
- Do not put secrets or sensitive values in process arguments.
- Distinguish optional vendor sharing, required connected services, deliberate
  cloud synchronization, and local-only diagnostics.
- Unknown, unreadable, manual, and unsupported states must never be reported as
  compliant.

## Safety requirements

- Keep checks read-only unless the command explicitly applies or rolls back a
  reviewed control.
- Use typed, allowlisted platform operations. Do not permit arbitrary shell
  commands in profiles or catalogue data.
- Show a deterministic plan before mutation.
- Capture only affected prior values in a fixed, permission-restricted journal.
  Journal before writing; a failed journal write stops the apply.
- Verify every change by re-reading the authoritative effective state.
- Roll back only when current state still equals the recorded postimage.
- Stop on failed verification and report partial state honestly.
- Do not clear audit logs, delete cloud data, disable updates, remove disk
  encryption, unlink accounts, or weaken security controls as ordinary privacy
  remediation.
- Require separate acknowledgement for security, destructive, or major
  functionality tradeoffs.
- Do not override Group Policy, MDM, configuration profiles, or another
  authoritative manager.
- Follow the roadmap's milestone order. Mutation belongs to 0.2.0 and depends on
  its listed prerequisites; do not ship a partial mutation path ahead of them.

## Control research

- Prefer current primary vendor or upstream documentation.
- Every control needs a stable semantic ID, supported-version constraints,
  edition or desktop constraints, scope, source, risk, read method, apply method,
  verification method, rollback behavior, and fixtures.
- Do not add a control solely because it appears in a tweak list, script, forum,
  or undocumented preference database.
- Keep brittle or private platform settings audit-only or exclude them.

## Verification

Work on a topic branch. `main` is protected and receives changes only through a
pull request (`CONTRIBUTING.md`). Before calling work done, run:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets --all-features -- -D warnings
cargo clippy --locked --target aarch64-apple-darwin --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo +1.95.0 check --workspace --all-targets --all-features --locked
cargo llvm-cov --locked --workspace --all-features --fail-under-lines 80
cargo deny check
```

Platform code is compiled out on other hosts, so the cross-target Clippy runs
(`rustup target add` if missing) are the only local check of it. CI runs these
jobs on Windows, macOS, and Linux and remains the authority.

- Never make a check pass by weakening it: no new `allow` attributes, ignored
  tests, lowered thresholds, or loosened `deny.toml` without a stated reason.
- Add tests for new behavior, failure paths, and rollback paths.
- Add a false-pass guard for every state that must never be reported as
  compliant. Coverage is a floor, never evidence that a control is correct: a
  line returning a pass where it should return unknown is fully covered and
  wrong. The current gate is 80 percent lines; decision 23 records the intended
  replacement.
- Tests must not depend on or modify the machine they run on. Use recorded
  evidence through the probe context; live mutation is proven in disposable VMs
  (`docs/TESTING.md`).
- For behavior changes, smoke the real binary (`cargo run -- check`,
  `list`, `explain <id>`) and read the output.
- Preserve stable command, control ID, profile, report, and journal schemas.

## Documentation and project state

- Keep README content concise and link to detailed documents.
- Update the README status section and roadmap checkboxes in the same change
  that makes them true. Mark concept, planned, experimental, and supported
  behavior clearly.
- Explain privacy benefits together with security and functionality tradeoffs.
- Use examples that contain no real user, machine, tenant, or account data.
- Put temporary agent state (scratch notes, indexes, plans) in the gitignored
  `.agents/` directory. Promote anything durable into tracked docs or tests.
  Never store secrets there.
