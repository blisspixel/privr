# Contributing

Thank you for helping make privacy controls more understandable and trustworthy.

Read these documents before proposing code or a control:

- [Design decisions](docs/DECISIONS.md), which constrains everything below
- [Product definition](docs/PRODUCT.md)
- [Control standard](docs/CONTROL_STANDARD.md)
- [Policy model](docs/POLICY.md)
- [Result model](docs/RESULTS.md)
- [Safety model](docs/SAFETY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Agent interface](docs/AGENT_INTERFACE.md)
- [Platform control matrix](docs/PLATFORM_SUPPORT.md)
- [Testing strategy](docs/TESTING.md)
- [Maintenance policy](docs/MAINTENANCE.md)
- [Supply-chain security](docs/SUPPLY_CHAIN.md)
- [Repository instructions](AGENTS.md)

## Before proposing a new control

New controls are the least valuable contribution, not the most.

The catalogue is bounded by what can be re-verified, not by what can be
discovered. When the control budget is full, adding one requires retiring one. A
declined control proposal is a policy outcome, not a judgment about the
contributor or the setting. See [MAINTENANCE.md](docs/MAINTENANCE.md).

In descending order of value:

1. Evidence: primary vendor sources, with the exact claim each supports.
2. Correctness: effective-state logic, precedence resolution, applicability.
3. Fixtures: captured and redacted states, especially denied, malformed,
   managed, and unsupported.
4. False-pass guards and rollback conflict tests.
5. New controls, last, and only within budget.

## Contribution types

Useful contributions include:

- primary-source research for a proposed control;
- applicability and policy-precedence corrections;
- redacted platform fixtures;
- typed platform adapter code;
- failure, verification, and rollback tests;
- documentation and usability improvements;
- release and supply-chain hardening.

## Proposing a control

Open a proposal containing:

1. semantic control ID;
2. user-visible behavior;
3. data types and destination;
4. desired state per profile in the ladder;
5. supported versions, editions, distributions, or desktops;
6. authoritative read interface;
7. authoritative write interface, if any;
8. management precedence;
9. security and functionality tradeoffs;
10. verification and rollback behavior;
11. primary source links;
12. fixture plan.

A community tweak list may motivate research but is not sufficient evidence.

## Branch and merge

`main` is protected and always green. Nothing is pushed to it directly, not even
a one-line fix, and not by the maintainer.

```bash
git switch -c topic/short-description
# work, commit
git push -u origin topic/short-description
gh pr create --fill
```

Merging requires every check to pass on all three platforms: formatting, lints,
tests, minimum supported Rust, dependency policy, and coverage. History is
linear, force pushes are refused, and the branch must be up to date with `main`
before it merges.

The lint and minimum-supported-Rust jobs run on Linux, Windows, and macOS
deliberately. Platform-gated code is compiled out elsewhere, so a
single-platform job cannot see an unused import or a dead branch behind a `cfg`
it did not enable. That has already caught failures in both directions.

Run the checks locally before pushing, but do not rely on local results alone:
the toolchain and the host both differ from CI.

## Development checks

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo llvm-cov --workspace --all-features --fail-under-lines 80
cargo deny check
```

Changes that affect the minimum supported Rust version must also pass the MSRV
job documented in CI.

## Pull request expectations

- Keep each change focused.
- Add tests for success and failure paths.
- Preserve stable semantic IDs and schemas.
- Explain user-visible privacy and security impact.
- Include only synthetic and redacted fixtures.
- Do not add arbitrary shell execution.
- Do not weaken the default security posture.
- Keep all platform CI jobs passing.
- Keep normal workflows offline and all reports, journals, logs, and fixtures
  free of unreviewed identifiers or secrets.
- Follow the professional writing rules in `AGENTS.md`.

## Security issues

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
