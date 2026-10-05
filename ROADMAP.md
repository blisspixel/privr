# privr roadmap

## North star

`privr` should become a trustworthy local-first privacy posture CLI:

- one command to see which optional sharing settings are active;
- one semantic policy model across supported operating systems;
- exact explanations instead of an opaque privacy score;
- verified remediation with conflict-aware rollback;
- stable output for people, scripts, and agent harnesses;
- no product telemetry and no network requirement for normal operation.

The canonical workflow is `check -> plan -> apply -> rollback`.

Milestones are ordered by dependency, not by date. Nothing here carries a
schedule.

The decisions that constrain every milestone are recorded in
[docs/DECISIONS.md](docs/DECISIONS.md).

## Current state

Reviewed 2026-10-03 against `main`. This section is the single statement of
what exists; other documents link here rather than repeating counts.

Terms: **implemented** means the code exists; **tested** means automated tests
cover it; **validated** means it was run and checked on a real machine;
**experimental** means it runs but does not yet meet the requirements of its
milestone and its results should not be trusted.

| Area | State |
|---|---|
| Windows `check`, `explain`, `list` | Implemented and tested with recorded evidence. 28 controls across 5 posture dimensions. Validated on Windows 11 Pro 25H2. `privr explain` includes scoring walkthrough and critical controls. |
| Windows `plan`, `apply`, `rollback` | Implemented and tested. 25 controls carry live, verified apply and rollback routines with pre/postimage validation. Native in-place elevation (-e, --elevate) invokes UAC/sudo with typed CLI argument serialization; interactive plan review and approval prompts run in terminals; noninteractive mode defaults safely to daily-driver with --yes. |
| Posture vectors and personas | Implemented and tested. 5 posture dimensions, 4 friction tiers, 5 workload personas across `check`, `recommend`, `simulate`, `plan`, and `apply`. |
| Linux `check` | Experimental. Discovery and 13 controls (GNOME, Ubuntu, Debian, Fedora, KDE, FreeDesktop, systemd) with elevation metadata. Compiled and tested in CI; never checked against a real desktop. |
| macOS `check` | Experimental. Discovery and 6 controls with elevation metadata. Compiled and tested in CI; never checked against a real Mac. |
| Agent server (`mcp`) | Implemented and tested. Synchronous stdio server with read-only tools and gated mutation. Conforms to Model Context Protocol and Agent Plugins v1.0.0. Supports workload personas and friction budgets. |
| `doctor` | Implemented and tested. Reports non-identifying OS facts, privilege level, platform adapters, storage integrity, reparse-point verification, and schema versions. |
| Profile ladder | Implemented and verified. Baseline <= Strict <= Restrictive ladder partitions controls monotonically. |
| Custom policy files, sections | Not built. Subplan sections and external policy files scheduled for 0.3.0. |
| PowerShell session-only history | Planned research and guided configuration. No PSReadLine history or prediction control is implemented. See [the proposal](#powershell-session-only-history-planned). |
| Fixture files, staleness, signed releases | In progress. |

### Known issues

These are defects in code already on `main`, not future work. Each must be
fixed, or the affected path disabled, before the milestone it belongs to can
exit.

Mutation (blocks 0.2.0):

- [x] `apply` writes before journaling, and a failed journal write only warns
  and continues. (Fixed: transaction journal establishes writability before
  mutation, and failed journal writes immediately halt apply).
- [x] `rollback` receives only the recorded prior value, so it cannot refuse
  when current state no longer equals the recorded postimage. (Fixed: rollback
  takes recorded postimage and refuses with conflict error if state changed
  externally).
- [x] The journal directory comes from environment variables and is not
  permission-restricted. (Fixed: owner-only 0700/0600 permissions enforced on Unix,
  per-user AppData ACLs on Windows, subsecond millisecond transaction IDs, and symlink protection).
- [x] `apply` has no plan review; `--yes` was required even in interactive terminals. (Fixed: interactive terminal execution previews planned changes, highlights elevation requirements, and requests confirmation before applying; native elevation runs child process in-place).
- [x] `rollback` of an unknown transaction prints the old concept-build notice
  and exits `3`, where the contract calls for a clear usage error. (Fixed:
  rollback validates transaction IDs, emits honest stderr guidance, and exits 2).
- [x] A registry test writes to the live `HKEY_CURRENT_USER` hive of whoever
  runs the suite. (Fixed: live registry write test gated behind PRIVR_LIVE_WRITE_TEST=1
  for disposable VMs; unit suite verifies via in-memory recorded context).

Reporting (blocks 0.1.0):

- [x] `plan` prints "machine matches policy" when drift exists that has no
  automatic remediation. (Fixed: `plan` distinguishes unautomated drift from
  full policy compliance and reports honestly).
- [ ] Controls ship without per-control fixture files, so the fixture
  requirements in [CONTROL_STANDARD.md](docs/CONTROL_STANDARD.md) are unmet for
  all of them.
- [ ] The `security` section (LLMNR, WPAD, NCSI active probing) is closer to
  generic hardening, a stated non-goal, than to optional data sharing. Decide
  whether it belongs in the catalogue.

Linux and macOS probes (block 0.3.0 and 0.4.0), each a false-pass risk:

- [ ] macOS analytics searches the raw text of a property list for a key and a
  `false` value anywhere in the file. The 0.3.0 requirements forbid parsing
  preference files directly.
- [ ] Ubuntu Report and Ubuntu Insights report `disabled` when a file is
  absent. Absence of a file is not evidence that submission is off.
- [ ] Fedora ABRT reads `abrt-action-save-package-data.conf` for the
  auto-reporting setting. The governing file has not been verified against
  primary sources.
- [ ] Linux controls run without the ordered environment detection, dconf lock,
  and live-session checks that 0.4.0 requires first.

## Current milestone: researched concept

Status: in progress

Completed foundations:

- [x] Rust CLI skeleton with `check`, `plan`, `apply`, and `rollback`.
- [x] Honest incomplete-report behavior for the concept build.
- [x] Product, CLI, policy, result, safety, threat, and architecture contracts.
- [x] Windows-first and cross-platform control research.
- [x] Control contribution and maturity standard.
- [x] Cross-platform tests, lint, dependency policy, MSRV, and coverage gates.
- [x] Repository-wide professional writing and attribution rules.
- [x] Consolidated design decision record.
- [x] Pin CI actions to reviewed full commit identifiers.
- [x] Raise the minimum supported Rust version to what the platform crates
  require, and adopt the split Windows API crates.
- [x] Fix process exit to flush and unwind, and handle a closed pipe cleanly.
- [x] Define the shared observation, evidence, and host-fact types against the
  hardest case on all three platforms before implementing any adapter.
- [x] Implement tri-state applicability with a closed predicate set.
- [x] Implement the evaluation engine as a pure function.
- [x] Implement Windows discovery without collecting stable identifiers.
- [x] Implement typed read-only registry probing that keeps absent, denied, and
  malformed apart.
- [x] Implement seven read-only Windows controls end to end.
- [x] Grow the Windows catalogue to 23 read-only controls. Fixture files are
  still owed; see Known issues.
- [x] Implement `check`, `explain`, and `list`.
- [x] Implement terminal presentation: colour, progress, wrapping, and explicit
  coverage alongside completeness.
- [x] Prove the edition-gating case on a real machine.
- [x] Type the ways a configured value is not the value in effect.

Required before the first useful release:

- [ ] Implement the catalogue as data rather than Rust constants: three-token
  binding, closed-set predicates, and the compiled adapter registry.
- [ ] Capture redacted fixtures per control and replay them in CI, so
  correctness stops depending on the machine the tests run on.
- [x] Implement the profile ladder, so `baseline`, `strict`, and `restrictive`
  select different control sets rather than all controls being enforced.
- [ ] Implement review staleness against a real reviewed-version range.
- [ ] Implement `doctor` against real discovery.
- [ ] Reach fifteen documented controls. The catalogue exceeds that count;
  what remains is the documentation and fixtures each needs under the control
  standard. See [Current state](#current-state) for counts.
- [ ] Reserve the crate name, or decide on a different one.

## Naming

The name is provisional. `privr.co.uk` hosts a marketing page for an unrelated
business access-management product, and `privr.io` is registered but serves
nothing. The categories barely overlap and no registered mark has been found,
so this is not treated as blocking.

Two options, and the decision is deferred until closer to a stable release:
reserve the crate name and keep it, or rename before 1.0 while the cost is a
find and replace. Reserving costs nothing and prevents the name being taken
meanwhile. Searching the trademark registers is a prerequisite either way.

Exit criterion: every control produces truthful text and JSON results across
compliant, drift, managed, denied, malformed, and unsupported fixtures, without
requiring a particular host to run the tests on.

## 0.1.0: Windows read-only release

The target user is a person on a machine they own, running whichever edition
came with it. A standard user can:

1. run `privr check` without elevation or network access, and get a useful
   answer on Home and Pro, not only on Enterprise;
2. receive accurate results for at least 15 documented Windows controls;
3. inspect sources, supported builds, management source, risk, reversibility,
   and remediation mode for every result;
4. use stable text and versioned JSON output with verbosity tiers;
5. distinguish drift, review, unknown, not applicable, not selected, and not
   checked;
6. select exact control IDs, documented prefixes, or sections;
7. point an agent harness at `privr` and have it inspect the machine safely.

Engineering work:

- [ ] Discover Windows version, build, edition, architecture, and registry view.
- [ ] Detect local policy, Group Policy, and MDM without collecting tenant,
  enrollment, account, or policy object identifiers.
- [ ] Implement typed, read-only registry and policy adapters.
- [ ] Resolve effective state per control rather than assuming one universal
  policy precedence rule.
- [ ] Report a policy value that cannot take effect on this edition as not
  applicable, never as compliant.
- [ ] Add the first low-breakage diagnostic, personalization, activity, search,
  clipboard, and delivery controls, binding the ordinary setting value as the
  primary source and treating the policy form as a secondary source consulted
  for precedence, so a control is not inert on Home and Pro.
- [ ] Prefer user-scope controls, so an unelevated check is already worth
  running on a personal machine.
- [ ] Research PowerShell session-only history with runtime evidence and
  guided review where effective state cannot be observed. See
  [the proposal](#powershell-session-only-history-planned).
- [ ] Add `explain`, `list` as a capability manifest, and stable fixtures.
- [ ] Group results into sections as a reporting structure, with aggregates that
  exclude what could not be evaluated.
- [x] Implement the `baseline`, `strict`, and `restrictive` profile ladder, with
  security tradeoffs held outside it.
- [ ] Implement review staleness so a control past its reviewed platform range
  degrades to unknown and audit-only.
- [ ] Implement the read-only agent server over stdio, with mutating tools
  absent from discovery.
- [ ] Enforce network isolation by dependency allowlist, lint, import-table
  assertion, and runtime proof.
- [ ] Fail closed on unknown builds, denied reads, malformed values, and partial
  reports.

Exit criterion: `privr check` is useful and safe even if mutation never ships,
and an agent can drive it without being able to change anything.

## 0.2.0: Windows plan, apply, and rollback

Apply and rollback are implemented, but release requirements remain unmet;
see [Current state](#current-state) for coverage and resolved defects.

Product requirements:

- [ ] Define the minimum custom-policy schema before mutation ships. This stays
  minimal: a person tuning their own machine selects a profile and adjusts a few
  controls rather than authoring policy files.
- [ ] Produce a deterministic, read-only plan from fresh observations.
- [ ] Show risks, privilege, dependencies, mitigations, and pending restart
  effects.
- [ ] Group the plan into sections and request approval section by section.
- [ ] Treat an intentional stop after approving some sections as success.
- [ ] Split consent into `--yes`, `--force`, and per-control `--accept-risk`.
- [ ] Store mutation transactions by ID in fixed, permission-restricted roots.
- [ ] Restore exact preimages only when current state still equals the recorded
  postimage, at whole-transaction and section granularity.
- [ ] Add `history purge` so an operator can destroy their own record.
- [ ] Enable mutating agent tools only behind an explicit flag, with a
  confirmation token that cannot be obtained through a tool call.
- [ ] After the transaction prerequisites are met, offer reviewed PowerShell
  history configuration, initially guided. Automatic profile edits require
  exact rollback and independent effective-state verification first.

Privilege and transaction requirements:

- [ ] Split user-scope and machine-scope subplans.
- [ ] Add a short-lived Windows elevated helper, not a service.
- [ ] Split the workspace so the helper depends only on the operation and IPC
  crates, and no data-format parser runs elevated.
- [ ] Keep privileged adapter behavior compiled into the signed binary.
- [ ] Use a bounded, local-only named-pipe protocol with explicit access control.
- [ ] Rebuild the machine plan inside the helper from fresh state.
- [ ] Compare immediately before every write and verify immediately afterward.
- [ ] Journal `prepared`, `applied`, `failed`, and rollback states durably, with
  unwinding panics so an interrupted apply can flush.
- [ ] Reject caller-selected journal paths, reparse points, generic registry
  writes, arbitrary commands, and unknown operation IDs.
- [ ] Stop on the first conflict or failed verification and report honestly
  whether anything changed.

Release trust requirements:

- [ ] Sign and timestamp Windows binaries before any public release that asks
  for elevation.
- [ ] Publish checksums, an SBOM, provenance, and artifact attestations.
- [ ] Ship one-line installers and package manager entries. The installer places
  an unprivileged binary and never elevates.
- [ ] Use protected release credentials and two-person approval for privileged
  component changes.

Exit criterion: disposable machine tests prove apply, idempotence, reboot,
conflict-aware rollback, section-granular rollback, crash recovery, and
over-the-shoulder elevation safety.

### PowerShell session-only history (planned)

Recommend session-only history at baseline: keep command recall in the current
shell while stopping persistent PSReadLine history. Local command retention is
a privacy concern even without vendor transmission. Disclose the loss of
cross-session recall in the reviewed plan and let users retain persistence
deliberately. Treat the change as workflow-altering friction, never as zero
workflow disruption. Existing history is not erased by this setting.

- [ ] Research `windows.shell.history-persistence` with semantic states
  `session-only` and `persistent`, under the control standard. Establish the
  supported Windows PowerShell, PowerShell, PSReadLine, and host versions with
  primary sources and fixtures before catalogue inclusion.
- [ ] Observe `Get-PSReadLineOption` in the relevant interactive session. A
  separate child shell cannot attest to its parent; profile text, an absent
  history file, or an unloaded module must never prove a pass. Without session
  evidence, report review or unknown.
- [ ] Guide `HistorySaveStyle = SaveNothing` and verify it before interactive
  input in a fresh shell. Distinguish current-session behavior from startup
  configuration, profile load order, `-NoProfile`, blocked profiles, host-specific
  profiles, Windows PowerShell versus PowerShell, and already-open shells.
- [ ] Keep `PredictionSource = None` an independent optional choice, gated by
  PSReadLine support. Tab completion and PATH command discovery remain usable.
- [ ] Research a bounded-retention alternative for users who want recent
  cross-session recall. Verify the bound on persisted data, not just the recall
  buffer; `MaximumHistoryCount` alone must not be presented as on-disk cleanup.
- [ ] Review the current shell-history erasure exclusion and decision 13 before
  adding cleanup of existing PSReadLine history. Ordinary command recall is
  distinct from security and audit logs. Any supported cleanup must identify
  the documented vendor mechanism, disclose irreversibility, and account for
  open shells rewriting saved entries. Until that review is resolved, cleanup
  remains unimplemented and excluded from ordinary `apply`.
- [ ] Never execute arbitrary profile code to audit it, change execution policy,
  weaken transcription or security logging, or read command history contents
  into evidence. Record only allowlisted settings and non-identifying version
  and host facts.
- [ ] Require exact preimages, conflict-aware rollback, and fresh-session
  verification before automatic configuration. Fixtures must guard against
  startup overrides, unsupported options, denied reads, and ineffective edits.
  Rollback restores configuration only; it cannot recover unsaved commands.

Primary sources, behavior details, and manual configuration are in
[Privacy residue: shell command histories](docs/PRIVACY_RESIDUE.md#shell-command-histories).

## 0.3.0: macOS read-only release

Experimental discovery and controls exist. They do not yet meet the
requirements below; see [Current state](#current-state).

- [ ] Support the current and two prior supported macOS releases.
- [ ] Read through the preferences API, never by shelling to `defaults` and
  never by parsing preference files directly.
- [ ] Use the forced-value API as the management source signal.
- [ ] Detect architecture, enrollment, supervision, and profile management
  without exposing identifiers.
- [ ] Check analytics, personalized advertising, Siri and Dictation sharing,
  location, and relevant protected permissions.
- [ ] Report unmanaged settings that lack a stable public read interface as
  review, and say plainly that unmanaged macOS is largely a guided-review
  product.
- [ ] Never infer compliance from the presence of a management payload, and
  never write the permissions database.
- [ ] Sign and notarize public binaries before mutating support is introduced.

Exit criterion: no control claims a pass from a preference that no longer
governs the visible setting, and no control claims a pass because an enforcing
profile exists.

## 0.4.0: named Linux environments

Experimental discovery and controls exist. They do not yet meet the
requirements below; see [Current state](#current-state).

Initial targets:

- Ubuntu LTS and current Ubuntu with GNOME;
- Fedora Workstation with GNOME;
- Debian with optional popularity-contest;
- KDE Plasma where user feedback is present.

Requirements:

- [ ] Implement the ordered environment detection sequence, where each stage can
  only downgrade confidence, never raise it.
- [ ] Detect distribution, release, write model, init system, desktop, session
  type, schema presence, dconf lock state, and a live user session before
  evaluating a control.
- [ ] Check GNOME usage and history settings, Ubuntu Insights, Fedora ABRT,
  Debian popularity-contest, and KDE user feedback.
- [ ] Distinguish local diagnostics from remote submission everywhere.
- [ ] Apply settings in the intended user's live session, never a root session
  created only for elevation.
- [ ] Verify every write out of band, because a write can report success while
  changing nothing.
- [ ] Ship audit-first, promoting controls to remediation individually on
  evidence rather than by platform.
- [ ] Report unsupported environments truthfully.

Exit criterion: a generic or unsupported Linux environment never receives a
false pass, and no control reports success from an uncommitted write.

## 0.5.0: cross-platform remediation and residue

- [ ] Promote only controls with verified audit maturity and exact rollback.
- [ ] Add macOS managed-profile remediation where Apple documents it.
- [ ] Add named Linux adapters with version-specific fixtures.
- [ ] Add custom policy inheritance, explicit exceptions, and expiry dates.
- [ ] Add `purge` for local privacy residue, invoking documented vendor erasure
  mechanisms only, never deleting files directly, and journaling every
  irreversible action so a later rollback fails loudly.
- [ ] Add local transaction history and machine-change comparison.
- [ ] Add an interactive terminal interface in the same signed binary, adding no
  capability the non-interactive commands lack.
- [ ] Package through WinGet, a Homebrew tap, and selected Linux formats after
  their platform support is stable.
- [ ] Publish an agent skill and plugin specification.

## 1.0.0: stable contracts

- [ ] Stable control ID, policy, report, and transaction schemas.
- [ ] Documented support matrix with release and deprecation policy.
- [ ] Signed non-executable catalogue update format with rollback protection,
  where downloaded content can narrow compiled capability but never widen it.
- [ ] Scheduled maintenance runs that re-verify citations and detect platform
  change, proposing pull requests that a human reviews. Nothing merges
  automatically.
- [ ] A published control budget, so catalogue growth is bounded by what can be
  re-verified.
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
- Generic disk cleanup. Size is computable; whether the operator still wants the
  data is not.
- Erasing security, audit, forensic, crash, shell-history, or cloud data.
  Preventing future shell-history persistence is separate planned work, not
  erasure of existing history or suppression of security logging.
- Disabling updates, encryption, or core malware protection in any profile in
  the default ladder.
- Direct permissions-database writes, undocumented platform state, or raw dconf
  edits.
- Saved executable plans.
- A self-updater.
- A single privacy score.
- A webview, browser engine, or JavaScript runtime in any shipped component.
- A promise to ship three native desktop applications.
- Any paid tier, hosted service, bundled offer, or product telemetry.
- A claim that a compliant operating-system configuration proves every
  application is private, or that a configured machine is unobserved.

## Open research questions

1. Which Windows controls remain reliable on Home when policy UI and effective
   enforcement differ?
2. Which unmanaged macOS controls can be observed through stable public APIs?
3. Which Ubuntu release transitions require simultaneous legacy and Insights
   consent checks?
4. What is the minimum useful KDE and non-systemd support matrix?
5. Where is the boundary between a bounded named predicate and an expression
   language, for controls that need a value rather than a boolean?
6. Which future high-risk policy packs are useful enough to justify their review
   and support burden?
7. Can documented shell-history mechanisms support bounded local retention and
   deliberate cleanup without weakening security logging or collecting command
   contents? The present erasure exclusion needs review before this can ship.
