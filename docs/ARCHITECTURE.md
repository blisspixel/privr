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
  privr-model/             shared policy, result, plan, journal, and catalogue types
  privr-engine/            applicability, evaluation, planning, and verification
  privr-ops-windows/       typed Windows operations and their inverses
  privr-ipc/               bounded helper protocol encoding and decoding
  privr-platform-windows/  Windows discovery, probes, and compiled adapters
  privr-helper-windows/    short-lived machine-scope elevated helper
  privr-cli/               command parsing, presentation, and user interaction
```

The catalogue types live in `privr-model` rather than a separate crate; they are
data definitions, not behavior.

The split exists to bound what runs elevated. `privr-helper-windows` depends on
exactly `privr-ops-windows` and `privr-ipc`. It follows that **no data-format
parser ever runs elevated**: the helper receives a bounded binary protocol, not
JSON, TOML, or any other text format.

The repository stays a single crate until the first machine-scope write exists.
Splitting earlier adds friction without buying the property that matters.

macOS and Linux platform crates are added when their adapters are implemented.
The shared model must already express all three platforms before any adapter is
written, or the observation types end up shaped like the Windows registry and
the other platforms become permanently second-class.

The codebase is synchronous. There is no async runtime anywhere, including in
the helper.

Panics unwind. Aborting skips destructors, which would prevent an interrupted
apply from flushing its transaction journal.

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

A plan is grouped into user-facing sections, and `apply` requests approval
section by section. **Stopping partway is a normal terminal state, not a
failure.** An operator who approves two sections and declines the rest has
completed a successful operation in which every approved change was verified and
journaled.

This has structural consequences. Sections are first-class in the plan, the
journal, and rollback. Rollback operates at section granularity as well as
whole-transaction granularity. Dependency edges may only point within a section
or to an earlier-ordered section, because otherwise a partial apply leaves
dependencies pointing into work that was never done.

The exit contract distinguishes an intentional stop, an interrupted or failed
apply, and a clean refusal that changed nothing. See [RESULTS.md](RESULTS.md).

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
path, service name, task path, or file target.

Concretely, a definition binds exactly three tokens: an adapter identifier, a
target key, and a semantic state. All three are strings in the file and all three
resolve to compiled enum variants at load. None can express a path, key, command,
service, file, URI, or pattern.

The target token exists to avoid a false choice. One adapter per control produces
hundreds of adapters and an unreviewable privileged surface. A generic adapter
requires the catalogue to supply a path, which is forbidden. A compiled target
enum gives many controls over one adapter, with every path, value name, type, and
registry view inside reviewed Rust.

Parameters are permitted only as named predicates from a closed compiled set with
typed arguments. A bounded predicate over a known fact is not an expression
language. A free-form parameter is a target in disguise, and that is the exact
mechanism by which non-executable content becomes executable.

This rule also applies to future downloaded catalogue data. A catalogue update
may refine metadata or select an existing adapter. It cannot create privileged
behavior. Stated as an invariant: **catalogue metadata may only narrow compiled
capability, never widen it.**

The catalogue is embedded in the signed binary rather than installed beside it. A
catalogue file next to an executable that requests elevation is writable by
anyone who can write the install directory. The adapter ceiling would still hold,
but an attacker could rewrite risk classes and rationale text to steer approval,
defeating informed consent without breaking the security model. Embedding makes
catalogue integrity identical to binary signature integrity.

Applicability gates the check and the remediation identically, from one
declaration. A remediation must be incapable of running where the control was
never applicable.

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

Management detection reads the policy hives directly as the primary signal, with
the managing authority reduced to a boolean as a secondary signal. Resultant Set
of Policy over management instrumentation is rejected as fragile: it races policy
refresh and has per-extension coverage gaps. Shelling to a policy reporting
command is rejected outright.

A privacy constraint falls out of this and is binding: enrollment identifiers,
security identifiers, and policy object identifiers must never leave the probe
function. Those are exactly the tenant and account identifiers the privacy
requirements forbid collecting, so the reduction happens at the probe boundary
rather than at the reporting boundary.

A policy value that reads back correctly is not evidence of enforcement. Several
documented policies apply only to specific editions, and writing them elsewhere
succeeds while changing nothing. The adapter resolves whether the value can take
effect on this edition and build, and reports a value that cannot as not
applicable, never as compliant. This is the single most common false pass in
comparable tools.

See Microsoft's [Group Policy processing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
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
the Windows elevation mechanism.

Two constraints follow from how that mechanism actually works, and they differ
from what a naive design assumes:

- The elevation call takes a command-line **string**, not an argument array. The
  launcher therefore passes only a single token drawn from a fixed alphabet, the
  helper's one-use pipe name. No path, no operation, and no operator-supplied
  value is ever placed on that command line.
- The DLL search-path hardening call affects only the calling process. The
  launcher cannot configure the helper's search path. The helper therefore
  hardens itself as the first action in its own entry point, before loading
  anything else.

Elevation is requested only after the plan has been displayed. Disclosure
precedes privilege, without exception.

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

An irreversible action still writes a normal journal entry, recording that
rollback is unavailable and why, so a later rollback attempt fails loudly rather
than appearing to succeed. The resulting claim is that every transaction is
recorded and honestly states whether it can be reversed, which is stronger than a
blanket reversibility promise because it survives contact with operations that
genuinely cannot be undone.

The operation set is a closed enum. That makes the inverse operation and the
preview renderer compile errors when a new variant is added, so rollback
completeness is enforced by the compiler rather than by review discipline.

## Diagnostics

`privr` has two distinct failure channels and they must share one vocabulary.

A denied read is not a process error. It is an `unknown` result on one control
while every other control continues to be evaluated. A malformed invocation is a
process error and stops the run.

A single diagnostic type carries a stable code, a severity, help text held
separately from the message, and an optional reference. Text and JSON are two
renderers over that one type. Constructing messages independently in each path
guarantees they eventually disagree about the same fact, which for this product
is a category-level failure.

Messages state what happened, why, and what to do next, and they name the
consequence for the result. A denied read says the control is reported as unknown
rather than as passing. A managed setting reports as skipped with its management
source and states plainly that forcing does not override it. A refused rollback
names the conflicting item, states the invariant, and confirms that nothing was
changed.

## Data sensitivity

Typed values carry a sensitivity class:

- `public`: safe semantic state such as enabled or disabled;
- `personal`: local state that needs a reviewed storage and redaction rule;
- `secret`: never allowed in plans, IPC, journals, reports, logs, or errors.

Controls that require secret restoration remain audit-only.

## Platform boundaries

### macOS

Read through the CoreFoundation preferences API. Do not shell out to the
`defaults` command, and do not parse preference files directly: the preferences
daemon holds values in memory and can overwrite direct file edits, and `defaults`
does not observe managed values at all. The forced-value API supplies the
management source field.

An unmanaged toggle without a stable public read interface becomes guided review.
Unmanaged macOS is largely a guided-review product, and the documentation says so
plainly rather than implying broader coverage.

Do not treat the presence of a management payload as evidence that a setting
holds. Checking that an enforcing profile is installed is not checking the
setting, and conflating the two fails a correctly configured unmanaged machine.

Do not write the permissions database or private settings stores.

### Linux

Run the ordered detection sequence before selecting any adapter. Each stage can
only lower confidence, never raise it: invoking identity, filesystem writability,
operating-system identity and write model, container and virtualization context,
init system, mandatory access control state, the target user's live session,
session type and desktop, schema presence and lock state, and package or unit
state.

Resolve the target user through the invoking-user environment and the account
database, never by assuming a home directory path.

Apply settings inside the target user's live session, never a root session
created only for elevation. **Verify every write out of band.** A settings write
can report success while changing nothing, which is a live false-pass source, and
the same class of failure appears on Windows where writes are silently discarded
under tamper protection.

Per-platform fact tables hold values that differ between distributions and
releases, so no control hard-codes a path or a component name.

Prefer structured atomic file changes that preserve unrelated content and
metadata.

## Updates and releases

Normal commands are offline. Future catalogue updates are explicit, signed,
versioned, non-executable, and rollback protected. Binary signing, provenance,
attestations, and dependency requirements are in
[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).

## Verification

Pure engine tests, redacted fixtures, native platform integration, VM fault
injection, hostile IPC and filesystem tests, and network-isolation tests are all
required. See [TESTING.md](TESTING.md).
