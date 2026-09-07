# Threat model

## Scope

This threat model covers the future `privr` checker, policy catalogue, profile
loader, planner, elevated helper, mutation engine, transaction journals,
reports, catalogue updates, and release artifacts.

The current concept CLI performs no system mutation.

## Security and privacy goals

`privr` should:

- observe settings without collecting unrelated machine data;
- avoid creating new network or telemetry relationships;
- prevent policy or catalogue data from becoming code execution;
- elevate only narrow reviewed operations;
- preserve the integrity of plans, journals, and results;
- avoid leaking identifiers or sensitive values through output or arguments;
- detect conflicts and concurrent changes;
- stop safely on failure;
- restore captured prior state where rollback is supported;
- avoid weakening security under the default profile.

## Assets

| Asset | Why it matters |
|---|---|
| Administrator boundary | Apply operations may modify system-wide policy |
| Control catalogue | Defines what is observed and what operations are allowed |
| User profile | Expresses desired privacy state and exceptions |
| Plan | Binds observed state to approved operations |
| Transaction journal | May contain prior settings needed for recovery |
| Audit report | May reveal software, management, or configuration information |
| Release artifact | Runs locally and may request elevation |
| Signing keys | Establish release and future catalogue authenticity |
| Platform state | Includes privacy, security, synchronization, and diagnostic controls |

## Trust boundaries

### Unprivileged process to operating system

Read-only adapters cross into platform APIs, registry stores, preferences,
services, and files. Data returned by the OS is untrusted input and may be
malformed or unexpectedly large.

### Unprivileged planner to elevated helper

This is the highest-risk boundary. The helper accepts only a bounded versioned
request containing allowlisted control IDs and semantic desired values. It
rebuilds the machine-scope plan from trusted compiled adapters and fresh state.
It never trusts caller-supplied operation targets.

The UAC consent UI and a same-desktop IPC peer are not treated as strong caller
authentication. The helper's main protection is its narrow compiled operation
ceiling.

### Local profile to policy engine

A profile is user-controlled data. It may be malicious, corrupted, or copied
from an untrusted source. It cannot introduce new operations or targets.

### Catalogue update to local catalogue

Future downloaded metadata is untrusted until its signature, digest, schema,
version, and operation constraints are verified. Normal operation does not
perform this update automatically.

### Agent harness to `privr`

An agent driving `privr` is an untrusted caller, and it is untrusted in an
unusual way: its behavior is influenced by text it reads, which may include a
web page, a document, a repository, or a message from a third party. A caller
that can be argued with is not a caller whose intent can be relied on.

The boundary is therefore drawn so that persuasion cannot cross it:

- Mutating tools are absent from tool discovery unless the server is explicitly
  started to expose them. A tool that is not present cannot be invoked, cannot be
  described persuasively, and cannot appear in injected text as an available
  capability.
- The confirmation token required to apply cannot be obtained through any tool
  call. It originates from a terminal on the machine being changed.
- Approval is per section and per named control. There is no blanket approval
  reachable through the agent interface.
- A caller may select from an enumerated plan. It may never synthesize a change,
  supply a target, or widen a selection.

The agent is treated as an assistant to the operator, never as a substitute for
the operator's consent.

### Tool output to terminal or CI

Reports may be copied, uploaded, archived, forwarded to a remote model, or viewed
by other users. Output must be safe without assuming it remains local.

Because a report carries no stable machine identifier, this boundary is closed by
construction rather than by warning people not to share. A privacy tool whose
output is a detailed profile of the machine would defeat its own purpose the
moment a user piped it to a hosted service.

## Threat actors

- malicious author of a custom profile;
- compromised catalogue or release infrastructure;
- local unprivileged process racing or replacing state;
- local user attempting to trick the elevated helper;
- externally managed policy conflicting with local intent;
- compromised administrator or kernel;
- accidental maintainer error in a control mapping;
- curious party reading reports, journals, or process arguments;
- text that reaches an agent driving `privr` and attempts to induce a change the
  operator did not ask for;
- an over-eager or misaligned caller that would approve on the operator's behalf
  if the interface permitted it.

A compromised administrator or kernel is outside the protection boundary, but
the design should still minimize stored sensitive material.

## Threats and mitigations

### Agent-mediated change the operator did not authorize

Threat: text an agent reads, such as a web page, document, repository, or
message, induces it to change privacy settings, approve a security tradeoff,
erase local data, or roll back a transaction the operator wanted kept.

Mitigations:

- mutating tools are absent from tool discovery unless explicitly enabled, so in
  the default configuration there is no capability to induce;
- the confirmation token cannot be obtained through any tool call and originates
  from a terminal on the machine being changed;
- approval is per section and per named control, with no blanket grant reachable
  through the interface;
- security tradeoffs and irreversible erasure require the specific control to be
  named and are never reachable from a general confirmation;
- a caller selects from an enumerated plan and cannot supply a target, widen a
  selection, or synthesize an operation;
- the plan is rebuilt from fresh state at apply time, so an argument made earlier
  in a conversation is not authorization later.

The design assumption is that the caller's judgment may be compromised. Nothing
in the safety model depends on the caller behaving well, on it following
instructions in a tool description, or on it correctly declining.

### Misreporting through caller-side summarization

Threat: an agent summarizes a report and states that a machine is compliant when
results were unknown, denied, not evaluated, or truncated.

Mitigations:

- unknown, denied, unsupported, not-selected, and not-checked never appear as
  passes in the data being summarized;
- aggregates exclude what could not be evaluated, so a summary cannot improve
  because visibility decreased;
- truncation is always reported explicitly rather than silently omitting results;
- `privr` supplies the sentence that must be stated when a result is incomplete,
  rather than relying on the caller to add a caveat;
- reports are deterministic and ordered, so a claim can be checked against a
  rerun.

This threat cannot be fully mitigated, because `privr` does not control what a
caller says. It is reduced by making the honest reading the easy one and by never
emitting a value that would make an optimistic summary defensible.

### Arbitrary code execution through policy data

Threat: a profile or catalogue supplies a program, shell string, script, path,
environment expansion, or dynamic library that runs with user or administrator
privilege.

Mitigations:

- closed typed operation enum;
- reviewed adapter code owns every target and allowed value;
- profiles reference semantic control IDs and desired variants only;
- no shell interpreter;
- no downloaded executable operations;
- strict schema rejection for unknown fields in privileged plans.

### Elevated-helper confused deputy

Threat: an unprivileged caller asks the helper to modify an arbitrary registry
key, file, service, task, or account.

Mitigations:

- helper accepts control ID plus approved semantic variant, not a raw target;
- helper owns the trusted compiled adapter mapping;
- narrow protocol with explicit version;
- random first-instance local named pipe with explicit access control and remote
  clients rejected;
- bounded messages, counts, strings, and exact enum decoding;
- helper exits after the approved transaction;
- no general file write, process launch, or command execution primitive.

### Plan substitution

Threat: the plan shown to the user differs from the plan applied after elevation.

Mitigations:

- canonical plan serialization;
- cryptographic digest displayed before approval;
- digest included in the elevated request and transaction journal for review
  correlation, not authentication;
- helper rebuilds the operation list from trusted adapters and fresh state;
- any applicability or state change invalidates the plan and requires a new
  review.

### Time-of-check to time-of-use race

Threat: a setting changes after the audit but before mutation, causing rollback
to capture or overwrite an unintended state.

Mitigations:

- record expected precondition in the plan;
- take an exclusive scope-specific apply lock;
- re-read immediately before each write;
- capture the actual pre-write value in the journal;
- abort on mismatch unless the user approves a newly generated plan;
- avoid broad multi-setting operations that cannot be checked independently.

### Journal disclosure or redirection

Threat: prior values reveal identifiers, account details, paths, application
state, or security configuration. A caller redirects an elevated write through
a reparse point or symbolic link.

Mitigations:

- store only values needed for rollback;
- reject controls whose safe rollback requires secrets;
- fixed user and machine roots with explicit permissions and no cloud-synced
  default directory;
- elevated helper never accepts a caller-selected path;
- reject reparse points, use exclusive creation, durable flushes, and
  same-volume atomic replacement;
- redact reports separately from journals;
- never include raw command output or unrelated key trees;
- document retention and provide explicit local deletion.

### Process-argument disclosure

Threat: the shell, process monitor, audit policy, event log, or operating system
retains arguments containing sensitive values.

Mitigations:

- do not pass secrets or captured sensitive values through arguments;
- prefer native APIs and inherited handles or protected input channels;
- invoke documented packaged tools directly with static, non-sensitive
  arguments where necessary;
- never interpolate profile data into a shell command.

### Report disclosure

Threat: JSON, SARIF, logs, or terminal output reveals usernames, SIDs, account
IDs, tenant details, recovery keys, command lines, or private paths.

Mitigations:

- structured allowlist of report fields;
- semantic values rather than raw storage;
- deterministic redaction tests;
- no stable machine identifier;
- optional verbose local evidence separated from shareable reports;
- fixtures that contain synthetic data only.

### Managed-policy conflict

Threat: `privr` fights Group Policy, MDM, configuration profiles, or another
manager, causing churn or misleading compliance.

Mitigations:

- management discovery before evaluation;
- report controlling source and conflict;
- externally managed values are not overwritten;
- management source is independent from `pass` or `drift` outcome;
- managed devices are scan-only by default;
- remediation directs the user to the authoritative manager.

### Elevation identity confusion

Threat: over-the-shoulder elevation runs the helper as another administrator,
causing user-scope state to be read or changed under the wrong account.

Mitigations:

- separate user-scope and machine-scope subplans;
- helper handles machine scope only;
- unprivileged process owns the original user's preferences and journal;
- IPC carries no request to reinterpret HKCU under the elevated identity;
- tests cover standard users, split-token administrators, and alternate
  credential elevation.

### DLL or executable search hijack

Threat: a hostile working directory, `PATH`, environment, or DLL search order
causes unintended code to load during elevation.

Mitigations:

- launch the helper by an absolute verified path;
- use controlled environment and working directory;
- call native APIs or absolute packaged tools with argument arrays;
- use safe DLL search configuration and no plugin loading in the helper;
- test hostile current directories, `PATH`, and DLL planting.

### Partial apply or rollback

Threat: process failure, power loss, restart, policy refresh, or access denial
leaves a mixed state.

Mitigations:

- ordered transaction journal flushed before mutation;
- one control mutation followed by immediate verification;
- append-only transaction state transitions;
- rollback in reverse order;
- explicit partial-apply and partial-rollback result states;
- manual recovery instructions generated from the journal;
- fault injection after every transaction stage.

### A setting reads as applied but has no effect

Threat: `privr` reports a machine as compliant when the underlying behavior is
unchanged. This is the project's central threat, because it produces confident
false assurance rather than a visible failure. The operator stops looking.

It is not hypothetical. Four documented instances, on three platforms:

- A Windows policy value written on an edition that does not honor it. The write
  succeeds, the value reads back as written, and the vendor documents the
  effective behavior as unchanged. Every surveyed tool reports a pass.
- A macOS check that verifies an enforcing configuration profile is installed
  rather than verifying the setting, which fails a correctly configured
  unmanaged machine and passes on payload presence alone.
- A Linux settings write performed as root against a user's session, which exits
  zero while the user's value is untouched.
- A configuration file setting overridden per component elsewhere, so a check
  that reads only the main file passes on a stock system.

Mitigations:

- effective state is what is verified, never the presence of an enforcement
  mechanism;
- edition, build, and applicability are resolved per control, and a value that
  cannot take effect is reported as `not_applicable`, never as `pass`;
- every write is verified by re-reading authoritative effective state, out of
  band where the write interface can report success without committing;
- precedence is resolved per control rather than by one universal rule;
- controls bind the value the system actually reads, not the name shown in a
  policy interface;
- no adapter assumes a polarity convention;
- a mandatory fixture per control exercises the beyond-the-ceiling case.

### Privacy change weakens security

Threat: reducing cloud reporting also reduces malware analysis, reputation,
updates, encryption recovery, logging, or incident response.

Mitigations:

- security-tradeoff metadata for every control;
- **no profile in the built-in ladder contains a control that reduces security**,
  so escalating privacy cannot silently escalate exposure;
- security tradeoffs form a separately named opt-in set, selected deliberately;
- separate per-control risk acknowledgement that cannot be granted for a class;
- no blanket service or scheduled-task removal;
- local diagnostics distinguished from vendor uploads;
- audit and remediation recommendations reviewed separately.

### Vendor update changes semantics

Threat: an OS or application update moves a setting, changes its default,
changes policy precedence, or stops honoring an interface.

Mitigations:

- version and edition applicability;
- last-reviewed date and last-reviewed platform range on every control;
- **automatic staleness degradation**: a control past its reviewed range loses
  `verified` support, can no longer report `pass`, and is forced to
  `audit_only`, so a neglected catalogue becomes cautious rather than wrong;
- current and prior release fixtures;
- `unknown` outcome or `unsupported` support on unrecognized builds;
- no optimistic fallback from a missing backing value;
- catalogue deprecation lifecycle that names retired control IDs so stored
  journals remain decodable.

### Catalogue or release supply-chain compromise

Threat: a malicious release or catalogue changes controls or the elevated helper.

Mitigations:

- signed release artifacts;
- reproducible builds where practical;
- source provenance and software bill of materials;
- protected release workflow and hardware-backed signing keys;
- signed, digest-pinned, non-executable catalogue data;
- no automatic catalogue update;
- dependency advisory, license, source, and lockfile checks;
- minimal dependencies for privileged components.

### Catalogue rollback or freeze

Threat: an attacker supplies an old but valid catalogue or blocks updates so
stale platform mappings remain trusted.

Mitigations:

- explicit updates only;
- threshold-signed root and versioned target, snapshot, and timestamp metadata;
- expiration and monotonic version checks;
- locally recorded highest trusted versions;
- unknown newer platform builds fail closed;
- catalogue data cannot add a privileged adapter.

### Resource exhaustion and disk failure

Threat: oversized platform state, IPC input, a full disk, or interrupted durable
write corrupts a transaction or leaves partial state.

Mitigations:

- strict input, item, filename, and allocation bounds;
- journal `prepared` state flushed before mutation;
- one write followed by one verification and state transition;
- fail before mutation when the journal cannot be created durably;
- crash recovery and disk-full fault injection;
- preserve failed and partial records for manual recovery.

## Abuse cases

The design and review process must reject:

- a custom policy that writes an arbitrary file as administrator;
- a control that clears event logs to improve a privacy score;
- a profile that disables updates without a separate named risk action;
- a journal containing an entire registry branch or preference database;
- a report containing a BitLocker recovery key or command line;
- a macOS control that edits the TCC database directly;
- a Linux control that runs `sudo` while intending to change the desktop user's
  GSettings value;
- a Windows control that writes undocumented state because a public tweak script
  does so;
- an update mechanism that downloads and executes a replacement script;
- a `pass` result based only on an unreadable or undocumented absent value;
- a `pass` result derived from the presence of an enforcing policy object or
  management payload rather than from the setting itself;
- a mutating agent tool exposed by default, or a dry-run flag on a mutating tool
  where a separate read tool belongs;
- a confirmation an agent can obtain without the operator touching the machine;
- an aggregate that improves because controls became unreadable;
- an installer that requests elevation or changes a setting;
- a scheduled maintenance job that commits catalogue content, alters a risk or
  reversibility class, or edits rationale or warning text without review;
- an irreversible action reachable from a blanket confirmation flag, or one that
  omits a journal entry recording that rollback is unavailable;
- deleting a file directly where a documented vendor erasure mechanism exists,
  or staging deletions to a location that records what was considered sensitive.

## Security testing

- parser fuzzing for profiles, catalogues, reports, IPC, and journals;
- property tests for canonical plan serialization and digests;
- privilege-boundary protocol tests with unknown and malformed operations;
- named-pipe squatting, path traversal, reparse-point, symbolic-link, and DLL
  search tests;
- redaction tests with synthetic secrets and identifiers;
- concurrent drift tests;
- fault injection after journal, write, verify, and rollback steps;
- disposable VM tests across supported OS versions and editions;
- managed-device conflict fixtures;
- update-signature and rollback-attack tests;
- dependency and release provenance checks;
- proof that core workflows make no network requests, enforced by dependency
  policy, lint, import-table assertion on linked library names, and runtime
  isolation rather than asserted;
- agent-interface tests proving mutating tools are absent from discovery by
  default and that no tool call can yield a confirmation token;
- false-pass guards asserting that every state which must not be reported as
  compliant is not, including edition-gated values, enforcement-mechanism-only
  reads, and writes that report success without committing;
- section-granular apply and rollback tests, including an intentional stop
  partway proving a success result and a clean journal.

The full platform and fault-injection matrix is in [TESTING.md](TESTING.md).

## Residual risks

- Vendors may change undocumented behavior behind a documented setting.
- Some unmanaged macOS controls cannot be observed programmatically.
- Windows Home and consumer editions may not enforce supported management
  policies.
- Linux desktop and distribution diversity limits broad claims.
- A local administrator can modify journals, binaries, or machine policy.
- Rollback cannot reverse remote deletion, cloud-side changes, or every
  operating-system side effect.
- A compliant configuration does not prove that every installed application is
  private.
- Configuring a machine for minimal sharing does not make it unobserved. Platform
  diagnostic schemas can include the current consent state and the authority that
  set it, so the act of hardening is itself reportable.
- Required platform traffic continues. Updates, certificate services, time
  synchronization, and licensing are not optional.
- `privr` cannot constrain what a calling agent says about a report. It can only
  ensure the underlying data does not make an optimistic summary defensible.
- Sustained correctness depends on ongoing re-verification. Staleness degradation
  bounds the damage when that lapses, but a degraded catalogue is a smaller tool,
  not an equally useful one.

These limitations must remain visible in product documentation and output.

Release and catalogue mitigations are detailed in
[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).
