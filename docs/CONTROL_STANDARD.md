# Control standard

## Purpose

A `privr` control is a reviewed statement about one privacy-relevant behavior on
a defined platform range. It includes a reliable observation, semantic desired
states, evidence, risk, and, when supported, typed apply and rollback behavior.

A control is not a copied registry tweak or an arbitrary command.

## Stable identity

Control IDs use lowercase semantic components:

```text
<platform>.<category>.<behavior>
```

Examples:

```text
windows.diagnostics.level
windows.error-reporting.transmission
macos.analytics.share-with-developers
gnome.history.recent-files
ubuntu.insights.consent
```

An ID describes the user-visible behavior, not its current implementation. If a
vendor moves the underlying value, the ID remains stable and its adapter changes.

IDs are never reused for a different behavior. Deprecated IDs remain resolvable
for historical report and transaction-journal compatibility.

## Required metadata

Every control contains:

| Field | Requirement |
|---|---|
| `id` | Stable semantic ID |
| `title` | Short user-facing name |
| `summary` | Plain-language behavior |
| `category` | Diagnostic, crash, advertising, activity, permissions, sync, or another reviewed category |
| `data_types` | Types of data involved, when known |
| `destinations` | Vendor, developer, peer, local-only, user-selected cloud, or unknown |
| `platform` | Platform adapter |
| `applicability` | Version, edition, architecture, distribution, desktop, feature, and management constraints |
| `scope` | User, machine, application, managed, or mixed |
| `desired` | Semantic value for each supported profile |
| `risk` | Standard, sensitive, security-tradeoff, or destructive |
| `remediation` | Automatic, guided, audit-only, or none |
| `read` | Typed observation operation |
| `precedence` | Effective-value resolution rules |
| `apply` | Typed mutation or explicit audit-only marker |
| `verify` | Independent post-change observation |
| `rollback` | Exact prior-state restoration or explicit limitation |
| `restart` | None, application restart, sign-out, restart, or reboot |
| `sources` | Primary documentation URLs |
| `reviewed` | Last review date and verified OS builds |
| `fixtures` | Positive, drift, missing, unsupported, denied, managed, and malformed cases |

## Semantic values

Profiles use understandable values rather than storage details.

Good:

```text
required-only
ask
disabled
local-only
user-control
never-send
```

Avoid:

```text
1
0x3
REG_DWORD
policy-present
```

The platform adapter maps semantic values to documented platform operations.

## Applicability

Applicability is evaluated before observation. It can depend on:

- OS family and build;
- edition or product tier;
- architecture or hardware capability;
- installed application or feature version;
- active desktop or init system;
- device management state;
- user versus machine context;
- required API, schema, or packaged command availability.

An inapplicable control returns outcome `not_applicable` with support metadata
and a reason. It does not return `pass` merely because its backing value is
absent.

## Observation

Observation returns a typed state and evidence sufficient to explain the result
without exposing unrelated local data.

Allowed result classes include:

- effective semantic value;
- missing with a documented default;
- managed with controlling source;
- manual review required;
- unknown or malformed;
- unsupported;
- access denied;
- operational error.

Raw command output, entire registry keys, complete property lists, crash data,
usernames, account IDs, and command lines are not control evidence.

## Precedence

A control defines how its platform resolves effective state. Possible sources
include vendor management policy, local machine policy, local user policy,
explicit user preference, and platform default.

The engine records:

- observed sources;
- effective semantic value;
- controlling source;
- conflicts;
- whether the current state is enforced or driftable.

The engine must not use a universal precedence rule when the vendor documents a
control-specific order.

## Risk classes

### Standard

Low expected breakage and no material reduction in security. Eligible for
default-profile application after normal confirmation.

### Sensitive

May disrupt applications, synchronization, permissions, location, or user
workflow. Audit by default and require explicit selection to apply.

### Security tradeoff

May reduce malware, phishing, update, recovery, encryption, logging, or incident
response protection. Excluded from normal confirmation and requires a named risk
acknowledgement.

### Destructive

Deletes data or causes an irreversible server-side or local effect. Never part
of ordinary profile application. Requires a dedicated command and action-time
confirmation if implemented at all.

## Remediation classes

- `automatic`: documented deterministic write, exact rollback, and verified
  native tests;
- `guided`: documented user action when safe automation is unavailable;
- `audit_only`: observable, but not safely mutable;
- `none`: inapplicable, unsupported, or explicitly excluded.

## Typed operation requirements

The catalogue may select only from a closed set of operations implemented in
reviewed code. Candidate types include:

- Windows registry or effective policy value;
- Windows service or scheduled-task observation;
- dedicated Defender preference adapter;
- Apple managed restriction or supported preference API;
- GNOME GSettings value;
- systemd unit state;
- allowlisted structured configuration key.

The catalogue cannot define:

- a shell command;
- an executable path;
- a script or dynamic library;
- an arbitrary file path;
- command substitution or environment expansion;
- a URL to download and execute.

## Apply requirements

A mutable control must:

1. have a verified known current value or documented absence;
2. support exact prior-state capture;
3. expose a deterministic typed plan;
4. identify privilege and restart requirements;
5. identify security and functionality impact;
6. recheck the current value immediately before writing;
7. perform one narrow mutation;
8. verify the effective state independently;
9. support exact conflict-aware rollback.

Non-reversible controls remain guided or audit-only.

## Rollback requirements

Rollback restores the value captured for the transaction:

- if a value existed, restore its type and data;
- if it did not exist, return it to not configured;
- if an explicit user value overrode a default, preserve that distinction;
- for services, capture enabled, disabled, masked, running, and stopped state
  separately;
- for files, preserve ownership, permissions, security labels, comments, and
  unrelated content.

Rollback accepts an internal transaction ID, verifies that current state still
equals the recorded postimage, and refuses overlapping newer transactions. It
does not consume caller-selected files or silently overwrite external changes.

Rollback verification uses the same authoritative read path as the original
control.

## Evidence standard

At least one current primary source is required. Suitable sources include:

- vendor policy and deployment documentation;
- vendor support documentation describing the user-facing setting;
- official upstream schemas or manuals;
- source code from the owning upstream project when no higher-level contract
  exists.

Community scripts, forums, tweak databases, search summaries, and reverse
engineering can identify research leads but cannot establish supported behavior
alone.

Each source record states:

- URL;
- claim it supports;
- last reviewed date;
- relevant version range;
- any inference made beyond the source.

## Fixture standard

Each control needs redacted fixtures for:

- explicit compliant state;
- explicit drifting state;
- inherited or documented default state;
- missing value with documented default;
- conflicting sources;
- externally managed state;
- unsupported version or edition;
- permission denied;
- malformed value;
- apply success;
- apply failure;
- verification failure;
- rollback success;
- rollback failure.

Fixtures contain no real identifiers, paths, tenant names, command lines,
recovery material, or user content.

## Review checklist

Before merging a control, reviewers confirm:

- [ ] The semantic ID describes behavior, not storage.
- [ ] Primary sources support the behavior and interface.
- [ ] Applicability is explicit.
- [ ] Required platform defaults are documented.
- [ ] Missing and access-denied cases cannot become `pass` accidentally.
- [ ] Management precedence is handled.
- [ ] Reports expose no unnecessary local data.
- [ ] Risk and tradeoffs are accurate.
- [ ] Apply uses a typed operation.
- [ ] Verification reads effective state.
- [ ] Rollback restores captured state.
- [ ] Fixtures cover failure and conflict paths.
- [ ] Documentation contains no unsupported guarantee.

## Lifecycle

Controls move through:

```text
proposed -> researched -> experimental audit-only -> verified audit
         -> reversible remediation -> stable -> deprecated
```

- `proposed`: idea with an initial source.
- `researched`: behavior and interface documented, implementation not complete.
- `experimental audit-only`: opt-in observation not counted as a stable signal.
- `verified audit`: supported observation with compatibility fixtures.
- `reversible remediation`: typed mutation and exact rollback pass native tests.
- `stable`: compatibility range and public contract meet this standard.
- `deprecated`: vendor removed or replaced the interface; historical ID remains.

Executable behavior may be removed after a compatibility window, while report
and journal decoders retain the historical ID meaning.
