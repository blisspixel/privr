# privr roadmap

## North star

`privr` should become a trustworthy local-first privacy posture CLI:

- one command to see which optional sharing settings are active;
- one semantic policy model across supported operating systems;
- exact explanations instead of an opaque privacy score;
- verified remediation with conflict-aware rollback;
- stable output for people, scripts, and later fleet integrations;
- no product telemetry and no network requirement for normal operation.

The canonical workflow is `check -> plan -> apply -> rollback`.

## Current milestone: researched concept

Status: in progress

Completed foundations:

- [x] Rust CLI skeleton with `check`, `plan`, `apply`, and `rollback`.
- [x] Honest incomplete-report behavior for the concept build.
- [x] Product, CLI, policy, result, safety, threat, and architecture contracts.
- [x] Windows-first and cross-platform control research.
- [x] Control contribution and maturity standard.
- [x] Cross-platform tests, lint, dependency policy, MSRV, and 80 percent line
  coverage gates.
- [x] Repository-wide professional writing and attribution rules.

Required before the first useful release:

- [ ] Convert the Windows candidate matrix into versioned control definitions.
- [ ] Validate the first controls on supported Windows VM fixtures.
- [ ] Implement platform and management discovery without stable identifiers.
- [ ] Implement one real read-only control end to end.
- [ ] Define versioned policy and result schemas as Rust types and fixtures.
- [x] Pin CI actions to reviewed full commit identifiers.

Exit criterion: one documented Windows control produces truthful text and JSON
results across compliant, drift, managed, denied, malformed, and unsupported
fixtures.

## 0.1.0: Windows read-only release

A standard user can:

1. run `privr check` without elevation or network access;
2. receive accurate results for at least 15 documented Windows controls;
3. inspect sources, supported builds, management source, risk, and remediation
   mode for every result;
4. use stable text and versioned JSON output;
5. distinguish drift, review items, unknown state, and non-applicability;
6. select exact control IDs or documented prefixes;
7. run the full test suite with at least 80 percent line coverage.

Engineering work:

- [ ] Discover Windows version, build, edition, architecture, and Registry view.
- [ ] Detect local policy, Group Policy, MDM, and relevant conflicts without
  collecting tenant or account identifiers.
- [ ] Implement typed, read-only registry and policy adapters.
- [ ] Resolve effective state per control instead of assuming one universal
  policy precedence rule.
- [ ] Add the first low-breakage diagnostic, personalization, activity, search,
  clipboard, and delivery controls.
- [ ] Add `explain`, catalogue listing, and stable report fixtures.
- [ ] Fail closed on unknown builds, denied reads, malformed values, and partial
  reports.

Exit criterion: `privr check` is useful and safe even if mutation never ships.

## 0.2.0: Windows plan, apply, and rollback

Product requirements:

- [ ] Define the minimum custom-policy schema before mutation ships.
- [ ] Produce a deterministic, read-only plan with fresh observations.
- [ ] Show risks, privilege, dependencies, and pending restart effects.
- [ ] Prompt interactively; reserve `--yes` for noninteractive standard-risk
  plans.
- [ ] Store mutation transactions by ID in fixed, permission-restricted roots.
- [ ] Restore exact preimages only when current state still equals the recorded
  postimage.
- [ ] Implement Model Context Protocol (MCP) server support (`privr mcp`) over
  stdio for local agent tool calling.

Privilege and transaction requirements:

- [ ] Split user-scope and machine-scope subplans.
- [ ] Add a short-lived Windows elevated helper, not a service.
- [ ] Keep privileged adapter behavior compiled into the signed binary.
- [ ] Use a bounded, local-only named-pipe protocol with explicit access control.
- [ ] Rebuild the machine plan inside the helper from fresh state.
- [ ] Compare immediately before every write and verify immediately afterward.
- [ ] Journal `prepared`, `applied`, `failed`, and rollback states durably.
- [ ] Reject caller-selected journal paths, reparse points, generic registry
  writes, arbitrary commands, and unknown operation IDs.
- [ ] Stop on the first conflict or failed verification and report partial state.

Release trust requirements:

- [ ] Sign and timestamp Windows binaries before any public release that asks
  for elevation.
- [ ] Publish checksums, an SBOM, provenance, and artifact attestations.
- [ ] Use protected release credentials and two-person approval for privileged
  component changes.

Exit criterion: disposable VM tests prove apply, idempotence, reboot,
conflict-aware rollback, crash recovery, and over-the-shoulder elevation safety.

## 0.3.0: macOS read-only release

- [ ] Support the current and two prior supported macOS releases.
- [ ] Detect architecture, enrollment, supervision, and profile management
  without exposing identifiers.
- [ ] Check analytics, personalized advertising, Siri and Dictation sharing,
  location, and relevant protected permissions.
- [ ] Use `review` or `unknown` when an unmanaged setting lacks a stable public
  read interface.
- [ ] Never infer compliance from a private preference key or write the TCC
  database.
- [ ] Sign and notarize public binaries before mutating support is introduced.

Exit criterion: no control claims a pass from a preference that no longer
governs the visible setting.

## 0.4.0: named Linux environments

Initial targets:

- Ubuntu LTS and current Ubuntu with GNOME;
- Fedora Workstation with GNOME;
- Debian with optional popularity-contest;
- KDE Plasma where KUserFeedback is present.

Requirements:

- [ ] Detect distribution, release, init system, desktop, schema, and live user
  session before evaluating a control.
- [ ] Check GNOME usage and history settings, Ubuntu Insights, Fedora ABRT,
  Debian popularity-contest, and KDE UserFeedback.
- [ ] Distinguish local diagnostics from remote submission.
- [ ] Preserve file bytes and metadata where practical.
- [ ] Apply GSettings in the intended user's live session, never a root session
  created only for elevation.
- [ ] Report unsupported environments truthfully.

Exit criterion: a generic or unsupported Linux environment never receives a
false pass.

## 0.5.0: cross-platform remediation

- [ ] Promote only controls with verified audit maturity and exact rollback.
- [ ] Add macOS managed-profile remediation where Apple documents it.
- [ ] Add named Linux adapters with version-specific fixtures.
- [ ] Add custom policy inheritance, explicit exceptions, and expiration dates.
- [ ] Add local transaction history and machine-change comparison.
- [ ] Package through WinGet, a Homebrew tap, and selected Linux formats after
  their platform support is stable.
- [ ] Publish an Agent Skill and plugin specification (`agent-plugins.org`) for
  coordinating system privacy with developer tool hygiene.

## 1.0.0: stable contracts

- [ ] Stable control ID, policy, report, and transaction schemas.
- [ ] Documented support matrix with release and deprecation policy.
- [ ] Signed non-executable catalogue update format with rollback protection.
- [ ] Reproducible builds where practical, release provenance, and SBOMs.
- [ ] Platform ownership and two-review gates for new elevated operation types.
- [ ] Compatibility testing tied to supported operating-system lifecycles.

## Deferred and explicit non-goals

- Mobile operating systems.
- Remote administration or a hosted control plane.
- A resident privileged service.
- Browser-extension management.
- VPN, DNS, firewall, or hosts-file blocklists.
- Debloating, application removal, or generic hardening.
- Erasing security, audit, forensic, crash, shell-history, or cloud data.
- Disabling updates, encryption, or core malware protection in the default
  policy.
- Direct TCC database writes, undocumented Windows state, or raw dconf edits.
- Saved executable plans in the MVP.
- A self-updater.
- A single privacy score.
- A claim that a compliant operating-system configuration proves every
  application is private.

## Open research questions

1. Which Windows controls remain reliable on Home when policy UI and effective
   enforcement differ?
2. Which unmanaged macOS controls can be observed through stable public APIs?
3. Which Ubuntu release transitions require simultaneous legacy and Insights
   consent checks?
4. What is the minimum useful KDE and non-systemd support matrix?
5. Which future high-risk policy packs are useful enough to justify their
   review and support burden?
