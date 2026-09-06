# Testing strategy

## Quality is layered

Line coverage is a useful floor, not evidence that a privacy control is correct.
Each control needs pure evaluator tests, captured fixtures, native integration
tests, and compatibility evidence.

The repository requires at least 80 percent line coverage together with clean
formatting, Clippy warnings denied, dependency policy checks, the minimum
supported Rust version, and Windows, macOS, and Linux CI.

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

Fixtures contain only synthetic, redacted data. Windows fixtures include exact
Registry value types and views. File fixtures preserve bytes, owner, mode, ACL,
and SELinux context where relevant.

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
