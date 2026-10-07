# Testing strategy

## Quality is layered

Line coverage is not evidence that a privacy control is correct. Each control
needs pure evaluator tests, captured fixtures, native integration tests, and
compatibility evidence.

The repository requires clean formatting, Clippy warnings denied, dependency
policy checks, the minimum supported Rust version, and Windows, macOS, and Linux
CI.

### On coverage specifically

A line coverage floor is the wrong primary gate here, and the current
configuration demonstrates why:

- It counts test bodies. A large share of covered lines in the concept build are
  the tests themselves.
- It runs on one operating system, so platform-gated code is absent from the
  denominator rather than counted as missed.
- A line that returns `pass` where it should return `unknown` is fully covered
  and wrong. Coverage cannot see the failure this project exists to prevent.

The current CI gate is 80 percent line coverage on Linux, with native tests and
lints on all three platforms. Decision 23 plans its replacement with merged
region coverage across all three operating systems and a per-crate ratchet.
That replacement is not implemented yet.

The metrics that actually track confidence are:

- mutation testing, because it asks whether a test would notice a wrong answer;
- fixture completeness per control against the required state list below;
- false-pass guard completeness, meaning every state that must not become `pass`
  has a test asserting it does not.

## What exists today

Implemented, and not merely designed:

- the evaluation engine as a pure function, with every false-pass rule under a
  test named after the failure it prevents;
- probes reading through a context, so the same control code runs against a live
  host and against recorded evidence of the same type;
- replay coverage for the paths a live machine cannot be made to produce on
  demand, namely denied reads, malformed values, and specific edition
  combinations;
- file-based synthetic observation suites for Windows advertising ID and
  diagnostic data, replayed through the compiled probes and evaluator by the
  ordinary Windows CI test job; the current extent is in
  [ROADMAP.md](../ROADMAP.md#current-state);
- Windows catalogue unit tests use recorded Context observations, including
  explicit edition-gating assertions, rather than requiring the runner's actual
  configuration to be readable or conclusive;
- application and journal tests use private temporary journal directories;
  confirmed apply cases exercise previews, and the application test helper
  rejects live apply. Missing-history rollback cannot select real transactions;
- a registry write test that is disabled in ordinary test runs and requires
  `PRIVR_LIVE_WRITE_TEST=1` in a disposable VM; the resolved defect is recorded in
  [ROADMAP.md](../ROADMAP.md#current-state);
- lints and the minimum-supported-Rust check on all three platforms, which has
  already caught failures in both directions.

Not yet implemented, and described below as the target: complete per-control
fixtures and native capture/redaction tooling, snapshot testing,
property and fuzz testing, virtual machine integration, adversarial and fault
injection, and the enforced network isolation layers beyond the dependency
policy.

## Structure

### Planned residue tests

Purge is not implemented. Its admission criteria, preservation tests, failure
cases, privacy canaries, and performance measurements are specified in the
[privacy cache capability plan](CACHE_PRIVACY_PLAN.md#required-failure-evidence).
Use recorded Context observations for ordinary tests and synthetic data in
disposable VMs for vendor clearing operations. No test may clean a developer's
real caches, temporary files, browser profiles, or history.

### Evaluator and probe tests

The evaluation engine is a pure function from catalogue, policy, host facts, and
observations to a report.

Fixtures are values of the same observation type the real probe produces. There
is no separate fake at that layer, so a fake cannot drift from reality. That
divergence risk moves to the probe layer, where it is handled by capture and
replay rather than hand-written mocks: a recording wrapper captures real probe
output, and a differential test replays recordings on every supported operating
system asserting byte-identical reports.

Structural rules:

- Closed-enum dispatch for host context and probes rather than trait objects, so
  exhaustiveness checking still applies.
- `cfg` appears only inside adapter bodies, never in the engine.
- The operation set is a closed enum, which makes the inverse operation and the
  preview renderer compile errors when a variant is added. Rollback completeness
  is a compile-time property, not a review checklist item.
- A documented read-only root-redirection option, refused by every mutating
  command, gives full-pipeline determinism on any runner.

## Pure engine tests

The core evaluator and planner should run without touching the host. Test:

- applicability by platform, build, edition, architecture, desktop, and
  management mode;
- semantic normalization and documented absent-value defaults;
- outcome, support, management, remediation, effect, and exception dimensions;
- policy inheritance, overrides, expiration, and invalid schemas;
- deterministic plan ordering and canonical digests;
- idempotence and dependency resolution;
- incomplete-report and exit-code precedence;
- redaction and secret-class rejection.

## Minimum fixtures per control

- value or policy absent;
- explicit compliant value;
- explicit drifting value;
- inherited or documented default value;
- conflicting user and machine policy;
- externally managed or locked state;
- malformed type or file;
- unsupported build, edition, distribution, or desktop;
- permission failure;
- successful apply, second apply no-op, and exact rollback;
- current-state conflict before apply and before rollback.

### Fixture format

Most recordings still live in test code. Initial observation files live under
`tests/fixtures/<control-id>/`, with one JSON file per state. They contain a
schema version, a case name, a control ID, synthetic provenance and authorship
date, host facts, observations, and hand-written expectations. They are not
captures or evidence of native platform validation.

The test-only loader in `src/catalog/windows/fixtures.rs` binds `policy` and
`setting` tokens to each control's compiled targets. The files cannot supply a
registry path, command, or write target. Each observation declares the native
registry view and retains the same `Evidence` type and exact raw bytes as the
live reader. An omitted observation remains undetermined; it is not converted
to an absent value. Replay asserts effective state, uncertainty, authority,
ineffectiveness, outcome, support, remediation, and result coherence. It also
guards against an added file being omitted from the suite.

The full capture format below remains the target. Mutation fixtures, native
shape checks, a fixture clock for staleness, and complete control coverage are
not implemented by these initial suites.

One file per state, carrying:

- provenance: what was captured, from which platform version, when, and by whom;
- host facts, including an injected clock so staleness is deterministic;
- observations recorded as exact type plus raw bytes, never a decoded value,
  because a decoded value silently discards the type confusion the tests exist to
  catch;
- hand-written expectations.

Snapshots capture rendering; expectations capture intent. Accepting a snapshot
without reading it still fails the expectation, which is what keeps snapshot
testing from becoming a rubber stamp.

Capture happens downstream of the probe's reduction, so a fixture cannot
physically contain an enrollment, tenant, or security identifier. Redaction
substitutes canaries rather than deleting, which turns the privacy promises into
positive tests: a canary appearing in output is a failing test.

Fixtures contain only synthetic, redacted data. Windows fixtures include exact
Registry value types and views. File fixtures preserve bytes, owner, mode, ACL,
and SELinux context where relevant.

Fixtures are checked for shape drift against real machines, and every control
carries a fixture for a platform beyond its verified range, so staleness handling
is exercised rather than assumed.

## Native VM sequence

Every mutable control must pass this sequence in a disposable snapshot:

```text
check
plan
apply
check
apply again
restart or reboot if required
check
rollback
check
```

The second apply must be a no-op. Rollback must restore exact presence, type,
bytes, scope, and prior value. If current state differs from the recorded
postimage, rollback must stop with a conflict instead of overwriting it.

## Windows matrix

Target current supported combinations, including:

- Windows 11 oldest supported and current releases;
- Windows 10 22H2 while the project claims support for it;
- Home, Pro, Enterprise, and Education where controls differ;
- x64 and ARM64;
- ordinary and Copilot+ hardware where applicable;
- standard users, split-token administrators, over-the-shoulder elevation, and
  Administrator Protection;
- unmanaged, local Group Policy, domain Group Policy, and real MDM enrollment;
- Defender active and a third-party antivirus provider.

Use Hyper-V full VMs and checkpoints for policy, mutation, rollback, domain, and
MDM testing. Windows Sandbox is suitable for parser and smoke tests, not durable
state or reboot workflows.

Microsoft documents [Hyper-V checkpoints](https://learn.microsoft.com/windows-server/virtualization/hyper-v/checkpoints)
and [Windows Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/).

## macOS matrix

- current and two prior supported macOS releases;
- Apple silicon and Intel while supported;
- standard and administrator users;
- unmanaged, enrolled, and supervised systems;
- conflicting configuration profiles;
- relevant TCC and Privacy Preferences Policy Control variations.

Private preference keys are not accepted as proof that a visible unmanaged
setting complies.

## Linux matrix

- Ubuntu 24.04, 25.10, and 26.04, including WSL where relevant;
- Fedora current and previous;
- Debian stable and testing;
- GNOME versions shipped by those distributions;
- KDE Plasma 5 and 6 where still relevant;
- headless sessions, multiple logged-in users, no session D-Bus, locked dconf,
  and missing optional packages;
- systemd and explicitly named non-systemd environments;
- immutable distributions such as Silverblue when claimed as supported.

GSettings tests must prove that the intended desktop user's database is read and
changed. Running as root must never silently target root's database.

## Adversarial tests

- malformed policy, catalogue, report, IPC, and journal payloads;
- parser fuzzing, including UTF-16 and boundary lengths;
- named-pipe squatting and remote connection attempts;
- reparse point, symbolic link, path traversal, and DLL planting attempts;
- hostile current directory, `PATH`, environment, and file associations;
- 32-bit and 64-bit Windows Registry view confusion;
- unknown adapter IDs and attempts to request generic privileged writes;
- concurrent apply, Group Policy refresh, and MDM refresh;
- failure after each prepare, write, verify, journal, and rollback stage;
- process termination, power-loss simulation, disk full, and UAC cancellation;
- helper and journal version mismatch;
- overlapping and out-of-order rollback attempts.

## Sectioned apply and staleness

- A plan groups into sections deterministically.
- Approving a subset of sections and stopping exits `0`, journals only the
  approved work, and records the operation as complete rather than interrupted.
- Section-granular rollback restores one section without disturbing another.
- Dependency edges never cross a section boundary forward, so a partial apply
  cannot leave a dependency pointing into unapplied work.
- A refusal that changes nothing is distinguishable from a failure that changed
  something, by exit code and by journal state.
- Staleness is a pure function of the injected clock. A control past its reviewed
  platform range degrades to `unknown` and `audit_only`, and cannot report
  `pass`. The deterministic portion runs on every change; the time-dependent
  portion runs on a schedule and as a release gate, never on the per-change path,
  so a pull request never fails because the calendar advanced.

## Network isolation

The offline guarantee is enforced, not asserted. A dependency denylist alone is
insufficient because the standard library opens sockets with no crate at all.
Four layers:

1. Dependency allowlisting, with target filtering deliberately left unset so a
   platform-specific network dependency cannot hide from a single-platform job.
2. A lint forbidding the standard networking types outside any permitted module.
3. A golden import-table assertion on **library names**, not symbol names,
   because the relevant Windows socket symbols import by ordinal and a
   symbol-name check passes while sockets work.
4. Runtime proof: network namespaces with syscall tracing, sandbox profiles,
   scoped firewall rules, and virtual machines with no adapter.

## Privacy tests

- Core workflows make no network request.
- Secret values never enter arguments, environment, output, logs, errors, IPC,
  plans, journals, or reports.
- Reports contain no usernames, SIDs, tenant IDs, machine IDs, or unreviewed
  profile paths.
- Debug logging preserves the same redaction rules.
- Audit reports are not retained unless explicitly exported.

## Release gates

A control moves from verified audit to reversible remediation only when:

1. primary-source applicability is current;
2. fixture coverage includes failure and conflict states;
3. native VM apply and rollback pass;
4. exact rollback and redaction are demonstrated;
5. platform owners approve the adapter;
6. elevated operation changes receive two reviews;
7. all repository and release checks pass.
