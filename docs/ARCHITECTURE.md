# Architecture

## Goals

The architecture must make read-only checks easy and privileged mutation hard
to misuse. Core invariants are:

- normal operation is local and offline;
- policy data cannot become executable behavior;
- effective state is resolved per control;
- user-scope and machine-scope work remain separate;
- mutation uses fresh state, typed adapters, and exact rollback journals;
- uncertainty fails closed and remains visible.

The current repository is a small CLI skeleton. The components below are the
target architecture, not an implementation claim.

## Proposed Rust workspace

```text
crates/
  privr-model/             shared policy, result, plan, and journal types
  privr-engine/            applicability, evaluation, planning, and verification
  privr-catalog/           built-in non-executable control definitions
  privr-platform-windows/  Windows discovery, probes, and compiled adapters
  privr-helper-windows/    short-lived machine-scope elevated helper
  privr-cli/               command parsing, presentation, and user interaction
```

macOS and Linux platform crates can be added without putting Windows policy
semantics in the engine.

The workspace should deny unsafe Rust by default. Narrow operating-system FFI
modules may use reviewed `unsafe` blocks only with written safety contracts and
focused tests.

## Core flow

```text
host discovery
      |
      v
applicable controls -> typed observations -> effective-state resolution
                                                |
                                                v
                                      policy evaluation -> report
                                                |
                                                v
                                    deterministic change plan
                                      |                     |
                                      v                     v
                               user-scope apply      machine-scope helper
                                      |                     |
                                      +----------+----------+
                                                 v
                                      verify and journal
```

`check` ends after the report. `plan` ends after producing the intended change
set. No saved executable plan files are part of the MVP. `apply` always observes
and plans again.

## Control definitions

A control definition contains semantic metadata:

```text
id
platform and applicability
policy mode and desired semantic value
compiled adapter ID
scope and privilege
risk and restart behavior
data category and destination
source URLs and last-reviewed platforms
fixture and maturity state
```

It does not contain a command, executable, dynamic library, arbitrary Registry
path, service name, task path, or file target. An adapter ID is valid only if the
installed binary compiled that exact operation.

This rule also applies to future downloaded catalogue data. A catalogue update
may refine metadata or select an existing adapter. It cannot create privileged
behavior.

## Observation and effective state

Platform probes return typed evidence rather than a final pass or fail. Evidence
distinguishes:

- explicit values and documented absence defaults;
- source and scope;
- Windows Registry type and 32-bit or 64-bit view;
- management and writability;
- denied, malformed, unsupported, and unknown states.

The adapter resolves the effective state because precedence is control specific.
Group Policy, MDM, local policy, explicit preferences, and defaults do not have
one universal order. Windows adapters use applicable Resultant Set of Policy or
other documented evidence and expose unresolved conflicts.

Managed hosts are scan-only by default. `privr` reports whether an external
manager's effective value passes or drifts, but does not enter a policy fight.

See Microsoft's [Group Policy processing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
and [`gpresult`](https://learn.microsoft.com/windows-server/administration/windows-commands/gpresult)
documentation.

## Result model

The evaluator combines observation with policy intent. Evaluation outcome is
separate from support, management source, remediation mode, pending effect, and
exceptions. The exact contract is in [RESULTS.md](RESULTS.md).

## Windows privilege boundary

The Windows design uses two executables:

- `privr.exe` runs unelevated, discovers the host, checks state, builds plans,
  handles user-scope operations, and presents results.
- `privr-helper.exe` runs elevated only for one approved machine-scope
  transaction, then exits.

There is no privileged service. The helper never applies the original user's
HKCU plan. Over-the-shoulder elevation can run as a different administrator, so
user and machine subplans must never be merged across that identity boundary.

The helper loads only trusted compiled adapters. It rejects generic operations
such as `RunCommand`, PowerShell, arbitrary Registry writes, arbitrary service
or task mutation, and caller-selected journal paths.

The unprivileged process launches the helper by an absolute verified path using
the Windows elevation mechanism. Process creation uses argument arrays and a
controlled environment, current directory, and DLL search configuration.

## IPC protocol

The proposed helper channel is a one-use local named pipe:

- a high-entropy name generated with the operating-system random source;
- first-instance creation and remote-client rejection;
- an explicit access control list for the expected local principals;
- bounded request size, item count, string length, and protocol version;
- exact enum decoding with unknown fields and operation IDs rejected;
- no secrets or arbitrary paths;
- one request, one response, and immediate teardown.

The pipe and UAC consent UI are not treated as an authentication boundary
against another process on the same desktop. The primary protection is the
helper's compiled allowed-operation ceiling and its fresh re-planning.

Microsoft documents [named-pipe security](https://learn.microsoft.com/windows/win32/ipc/named-pipe-security-and-access-rights)
and the [Windows elevation launch mechanism](https://learn.microsoft.com/windows/win32/shell/launch).

## Plan validation and time-of-check safety

A canonical plan digest identifies what the user reviewed. It is useful for
display, journal correlation, and diagnostics, but it is not authorization.

For machine-scope apply, the helper:

1. validates bounded protocol and policy identifiers;
2. discovers the host again;
3. resolves the selected compiled adapters;
4. rebuilds the plan from fresh effective state;
5. aborts with `replan_required` if the reviewed intent no longer matches;
6. takes an exclusive `privr` apply lock;
7. compares each current value immediately before writing;
8. journals the exact preimage;
9. performs one typed write;
10. verifies the authoritative effective state;
11. stops on conflict or failed verification.

Concurrent Group Policy, MDM, update, or user changes remain possible. These
checks turn races into visible conflicts instead of silent overwrites.

## Transaction journal

Proposed Windows storage roots are:

- `%LocalAppData%\privr\state` for user-scope transactions;
- `%ProgramData%\privr\state` for machine-scope transactions.

The process responsible for a scope creates the fixed root with an explicit
user, Administrators, and SYSTEM access policy as appropriate. It rejects
reparse points, uses exclusive creation, bounded filenames, durable flushes, and
same-volume atomic replacement. The elevated helper never writes to a path from
the caller.

Each operation journal records:

- stable transaction and control IDs;
- adapter, scope, and schema versions;
- exact preimage existence, type, bytes, and Registry view where applicable;
- expected postimage;
- `prepared`, `applied`, `failed`, and rollback transitions;
- verification and restart state;
- catalogue and policy digests.

A hash chain can detect accidental corruption. It cannot prove integrity against
a local administrator who can replace both the journal and program.

## Rollback

Rollback uses an internal transaction ID, never an arbitrary snapshot path. It
restores an exact preimage only when the current state still equals the recorded
verified postimage.

- A formerly absent value is removed by value name only.
- An existing value restores exact type and bytes.
- Registry view, file metadata, and scope are preserved.
- Dependencies roll back in reverse order.
- Recursive deletion is prohibited.
- An older overlapping transaction is refused while a newer transaction exists.
- Conflicts produce a displayed recovery plan, not a force overwrite.
- Versioned decoders preserve compatibility with supported transaction formats.

Irreversible changes, remote deletion, and secret values are ineligible for
ordinary apply.

## Data sensitivity

Typed values carry a sensitivity class:

- `public`: safe semantic state such as enabled or disabled;
- `personal`: local state that needs a reviewed storage and redaction rule;
- `secret`: never allowed in plans, IPC, journals, reports, logs, or errors.

Controls that require secret restoration remain audit-only.

## Platform boundaries

### macOS

Use documented preferences and device-management restrictions. An unmanaged
toggle without a stable public read interface becomes guided review. Do not
write TCC databases or private settings stores.

### Linux

Select adapters only after detecting the distribution, release, init system,
desktop, schema, writability, and live user session. Use GSettings in the target
user's desktop session. Prefer structured atomic file changes that preserve
unrelated content and metadata.

## Updates and releases

Normal commands are offline. Future catalogue updates are explicit, signed,
versioned, non-executable, and rollback protected. Binary signing, provenance,
attestations, and dependency requirements are in
[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).

## Verification

Pure engine tests, redacted fixtures, native platform integration, VM fault
injection, hostile IPC and filesystem tests, and network-isolation tests are all
required. See [TESTING.md](TESTING.md).
