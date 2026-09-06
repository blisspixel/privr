# privr

Privacy settings you can verify.

`privr` is a local-first privacy posture CLI. It checks which optional
data-sharing settings are enabled, explains the evidence and tradeoffs, safely
applies a policy, and detects drift.

Windows is the first implementation target. macOS and named Linux environments
are planned behind the same policy and reporting model.

```text
privr check
privr explain windows.error-reporting.transmission
privr plan
privr apply
privr rollback <transaction-id>
```

## Current status

This repository is a researched concept with a compiling Rust CLI skeleton. It
does not yet inspect or change operating-system settings.

The skeleton deliberately returns exit code `3` for incomplete commands and
sets `complete: false` in JSON. It must not imply that a machine passed before
real platform probes exist.

The current work establishes:

- the product and CLI contract;
- a Windows-first control candidate matrix;
- macOS and Linux support boundaries;
- a typed, allowlisted privilege architecture;
- exact rollback and drift semantics;
- threat, testing, and supply-chain requirements;
- cross-platform CI, an MSRV check, dependency policy, and an 80 percent
  coverage gate.

See [ROADMAP.md](ROADMAP.md) for implementation milestones.

## Why this exists

Operating systems expose meaningful privacy choices, but those choices are
often spread across settings pages, policy stores, services, and application
preferences. Their behavior can vary by release, edition, management state,
desktop environment, and account type.

Modern platforms frequently bundle helpful user features with continuous
background data collection. What documentation frames as quality improvement
or personalization often functions as persistent observation.

| Platform | Vendor framing | Technical mechanism |
|---|---|---|
| Windows | "Personalized inking and typing dictionary to give you better suggestions" | Extracts local address book contacts (`HarvestContacts`) and streams typing telemetry to cloud endpoints. |
| Windows | "Search the web and Windows from your taskbar" | Transmits local Start Menu keystrokes and search queries in real time to Bing (`api.bing.com`). |
| Windows | "Diagnostic data to keep Windows secure, up to date, and working" | Streams event traces, process crash data, hardware identifiers, and optional memory heaps via `DiagTrack`. |
| macOS | "Help Apple improve products by sending diagnostic and usage data" | Transmits crash logs, loaded dynamic libraries, and system traces via `diagnosticd` and `SubmitDiagInfo`. |
| macOS | "Location Services to gather and use information based on current location" | Scans nearby Wi-Fi router BSSIDs and transmits them to Apple servers to resolve coordinates without hardware GPS. |
| Linux | "Help improve Ubuntu by sending system information once" | Generates system hardware profiles via `ubuntu-report` and uploads crash core dumps via `whoopsie` and `apport`. |

Your workstation should work exclusively for you. In an era where developers
and power users execute local language models, autonomous coding agents, and
sensitive source code on their machines, unmonitored background telemetry
represents an unmanaged operational risk.

`privr` establishes a deterministic, auditable baseline by answering four
practical questions:

1. What is this machine configured to share?
2. Which settings differ from my selected policy?
3. What privacy, security, and functionality tradeoffs does each choice have?
4. Can a supported change be applied and reversed without guessing?

The project is not trying to have the largest tweak list. It is trying to make
a smaller supported catalogue verifiable, automatable, and safe to maintain
over time.

## Canonical workflow

```text
check -> explain -> plan -> apply -> verify -> rollback -> check again
```

- `check` reads effective state and compares it with a policy. `audit` is an
  alias.
- `explain` shows evidence, applicability, management source, and tradeoffs.
- `plan` is read-only and shows the exact eligible change set.
- `apply` recomputes the plan, confirms it, captures prior state, applies typed
  operations, and verifies each result.
- `rollback` accepts an internal transaction ID and restores exact preimages
  only when conflict checks pass. `restore` is an alias.

The proposed complete CLI and exit-code contract are in
[docs/CLI.md](docs/CLI.md).

## Privacy-first policy

The initial built-in policy is `privacy-first`. It minimizes optional vendor
collection and personalization while preserving updates, encryption, malware
protection, reputation services, local crash diagnosis, and core recovery.

Low-breakage choices can use `enforce` mode. Contextual choices such as
location, cloud sync, sensitive app permissions, and security sample submission
default to `review`. Unsupported or deliberately excluded controls use
`ignore`.

Security-reducing, destructive, and major functionality changes do not belong
in the default policy. They may later live in separately reviewed experimental
packs with explicit risk acceptance.

See [docs/POLICY.md](docs/POLICY.md).

## Safety promises

`privr` is designed around these boundaries:

- no product telemetry or background network activity;
- normal check, plan, apply, rollback, and report workflows work offline;
- no arbitrary shell commands in profiles or downloaded catalogue data;
- no user-supplied registry paths, service names, executable paths, or elevated
  file targets;
- no elevated background service;
- no mutation without a fresh plan and immediate compare-before-write check;
- no rollback that silently overwrites a later external change;
- no unknown, unreadable, unsupported, or manual result reported as a pass;
- no ordinary remediation that clears logs, deletes cloud data, disables
  updates, removes encryption, or unlinks accounts;
- no promise of anonymity or of eliminating traffic the operating system
  requires for enabled services.

Windows machine-scope changes will be handled by a short-lived elevated helper
with a compiled operation allowlist. User-scope and machine-scope plans remain
separate because an elevation prompt can run under a different administrator
account.

See [docs/SAFETY.md](docs/SAFETY.md),
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Planned platform scope

| Platform | Initial credible scope | Important boundary |
|---|---|---|
| Windows | Diagnostic data, crash reporting, advertising, personalization, activity, cloud search, clipboard sync, and peer delivery | Respect build, edition, Registry view, Group Policy, and MDM behavior |
| macOS | Analytics, personalized advertising, Siri and Dictation sharing, location, and protected app permissions | Use guided checks when unmanaged settings lack a documented stable API |
| Linux | GNOME privacy settings, Ubuntu Insights, Fedora ABRT, Debian popularity-contest, and KDE UserFeedback | Detect the distribution, desktop, schema, session, and management state first |

The detailed candidates, exclusions, version notes, and primary vendor sources
are in [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md). Every entry is
planned, not implemented, until it passes the control maturity gates.

## Result model

Results keep separate facts separate. A control has an evaluation outcome such
as `pass`, `drift`, `review`, `unknown`, `not_applicable`, or `error`. Independent
fields record support, remediation mode, management source, pending effect, and
policy exceptions.

This prevents misleading states such as treating `managed` as an alternative to
either compliant or drifting. Reports also include a `complete` flag, catalogue
and policy digests, and no stable machine identifier.

See [docs/RESULTS.md](docs/RESULTS.md).

## Rust and architecture

Rust is a strong fit for a small native cross-platform CLI, typed operations,
explicit error handling, constrained process execution, and separately
testable platform adapters. Rust does not make operating-system policy portable,
so correctness still depends on version-gated platform research and native VM
tests.

The planned Windows design separates an unprivileged CLI from a short-lived
elevated helper. Catalogue data selects compiled adapter IDs and semantic desired
states. It cannot introduce new privileged behavior.

## Automation and agent readiness

`privr` is designed to be consumed by human operators, automated scripts, and
local autonomous AI agents alike.

- **Structured output:** All commands support machine-readable JSON via
  `--format json` with versioned schemas and deterministic exit codes.
- **Verification before mutation:** Agents can inspect effective state (`check`)
  and verify proposals (`plan`) without risking unverified modifications.
- **Model Context Protocol (MCP):** A native stdio MCP server interface
  allows desktop agents and coding assistants to query and remediate system
  privacy posture safely. The five canonical stages (`privr_check`,
  `privr_explain`, `privr_plan`, `privr_apply`, `privr_rollback`) map directly
  to typed agent tool calls.
- **Separation of concerns:** `privr` core handles deterministic operating-system
  verification and rollback. Higher-level agent plugins and skills (such as
  developer-tool telemetry audits, package update tracking, and storage
  reclamation) coordinate on top of `privr` without diluting its safety model.

## Build the concept

Rust 1.85 or later is required.

```bash
cargo build --locked
cargo run -- check
cargo run -- plan
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

`check` and `plan` currently print the concept notice and exit `3`. Use
`cargo run -- --help` to inspect the current command surface.

## Project documents

- [Product definition](docs/PRODUCT.md)
- [CLI contract](docs/CLI.md)
- [Policy model](docs/POLICY.md)
- [Result and drift model](docs/RESULTS.md)
- [Control contribution standard](docs/CONTROL_STANDARD.md)
- [Platform findings](docs/PLATFORM_SUPPORT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Safety model](docs/SAFETY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Privacy behavior](docs/PRIVACY.md)
- [Testing strategy](docs/TESTING.md)
- [Supply-chain security](docs/SUPPLY_CHAIN.md)
- [Research notes](docs/RESEARCH.md)
- [Contribution guide](CONTRIBUTING.md)

## Contributing

Early contributions should improve evidence and correctness: primary vendor
sources, compatibility findings, redacted fixtures, effective-state logic,
failure tests, and rollback tests. A setting does not become mutable merely
because it appears in a tweak script.

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the repository instructions before
making changes.

## License

Apache-2.0. See [LICENSE](LICENSE).
