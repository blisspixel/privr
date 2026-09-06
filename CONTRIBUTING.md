# Contributing

Thank you for helping make privacy controls more understandable and trustworthy.

Read these documents before proposing code or a control:

- [Product definition](docs/PRODUCT.md)
- [Control standard](docs/CONTROL_STANDARD.md)
- [Policy model](docs/POLICY.md)
- [Result model](docs/RESULTS.md)
- [Safety model](docs/SAFETY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Platform control matrix](docs/PLATFORM_SUPPORT.md)
- [Testing strategy](docs/TESTING.md)
- [Supply-chain security](docs/SUPPLY_CHAIN.md)
- [Repository instructions](AGENTS.md)

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
4. privacy-first desired state;
5. supported versions, editions, distributions, or desktops;
6. authoritative read interface;
7. authoritative write interface, if any;
8. management precedence;
9. security and functionality tradeoffs;
10. verification and rollback behavior;
11. primary source links;
12. fixture plan.

A community tweak list may motivate research but is not sufficient evidence.

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
