# Policy model

## Purpose

A policy states privacy intent. It does not describe operating-system mutation
mechanics.

The engine resolves semantic values such as `required_only`, `disabled`, or
`prompt` through a compiled platform adapter. Policy files cannot contain shell
commands, executable names, Registry paths, service names, arbitrary file paths,
or dynamically loaded code.

## Built-in profiles

Three built-in profiles form an ordered ladder. Each is a strict superset of the
one below, which is what makes moving between them coherent and makes
`check --profile strict` a useful read-only preview of a deeper level.

| Profile | Intent |
|---|---|
| `baseline` | The default and the recommended setting |
| `strict` | Meaningful privacy gains with real, disclosed tradeoffs |
| `restrictive` | Substantial convenience or functionality cost, always review |

`baseline` is deliberately the useful setting rather than the cautious one. The
line that makes it defensible per control is the distinction between collection
and features:

- **Passive continuous collection is disabled in `baseline`.** Data flows that
  occur whether or not the operator uses anything: diagnostic transmission,
  advertising identifiers, activity history upload, tailored experiences, input
  and typing personalization, background usage reporting. These are not features
  an operator invokes, and disabling them costs essentially nothing.
- **Features an operator may actively want default to review.** Cloud clipboard
  sync, location services, cloud search, peer update delivery, and voice
  services are things someone may use on purpose. `baseline` surfaces them with
  their tradeoff and the mitigation, and lets the operator decide.

A control is never held back from `baseline` because it sounds aggressive, only
because the operator might be using the thing.

Every profile in the ladder preserves:

- security and operating-system updates;
- disk encryption and recovery;
- firewalling and real-time malware protection;
- reputation and certificate services;
- local crash diagnosis;
- explicitly selected synchronization features.

## What the ladder never contains

Escalating privacy must not silently escalate exposure. No profile in the ladder
contains a control that reduces security, and choosing `restrictive` can never
disable malware protection, reputation services, sample submission, update
delivery, encryption, or recovery.

Two sets sit outside the ladder and are never reached by selecting a higher
profile:

- **Security tradeoffs.** Clearly named, selected deliberately, and requiring
  per-control risk acceptance.
- **Erasure of local privacy residue.** Irreversible, behind its own verb, never
  part of an ordinary apply.

Profile membership derives from a control's declared risk, breakage, and
reversibility metadata rather than being assigned by hand, so `baseline` cannot
silently accumulate breaking controls as the catalogue grows. Each profile's
disclosure warns at the level of its highest-risk member.

Built-in profiles are generated data, validated at build time, and carry the
same digest treatment as the rest of the catalogue.

## Control modes

| Mode | Meaning |
|---|---|
| `enforce` | Compare with the desired value, report drift, and allow eligible remediation |
| `review` | Report current state and tradeoffs without treating the choice as drift |
| `ignore` | Do not evaluate unless the control is explicitly selected |

Only `enforce` contributes to policy drift.

## Proposed file format

TOML is the initial candidate because it is readable, has a mature Rust parser,
and can be constrained to a small schema.

```toml
schema = 1
extends = "builtin:baseline@0.1"

[controls."windows.defender.sample-submission"]
mode = "review"

[controls."windows.location-services"]
mode = "enforce"
desired = "enabled"

[[exceptions]]
control = "windows.location-services"
accepted = "enabled"
reason = "Needed for device recovery"
expires = "2027-01-01"
```

The schema must reject:

- unknown top-level fields unless an explicit compatibility rule allows them;
- unknown control IDs or semantic values;
- duplicate and contradictory overrides;
- unsupported inheritance cycles;
- executable content and platform operation details;
- exceptions without a control, accepted value, and reason;
- invalid or already expired dates where an active exception is required.

## Exceptions

An exception accepts one named state for one control. It never means "accept
whatever is currently present."

An exception may change the remediation decision and how a control is presented
in an aggregate. **It never changes the finding.** A control that drifts still
reports `drift` while exempted, with its exception state carried as a separate
field. Comparable tools let an exemption suppress the finding itself, which
loses the ability to distinguish an accepted risk from an absent one.

Exceptions require an expiry. `privr` continues to evaluate and display excepted
controls, active exceptions are counted separately, and an expired exception
becomes drift again. Future team metadata may record an approver, but it must
not change the local evaluation semantics.

## Identity and versioning

Every evaluation records:

- policy schema version;
- policy ID and version;
- canonical policy digest;
- catalogue version and digest;
- resolved control modes and desired semantic values.

A built-in policy update is a policy change, not machine drift. Reports keep
these events separate:

- policy drift: effective machine state differs from current enforce-mode
  intent;
- machine change: observed state differs from a selected prior observation;
- policy change: policy content or desired state changed.

## Applicability

Policy intent does not override platform reality. A requested control can still
be unsupported, unverified, externally managed, or unavailable on a particular
build or edition. The result must expose that metadata and never coerce it into
a pass.

## Update behavior

Built-in policy and control metadata ship with the executable. Normal commands
do not fetch updates. A future explicit catalogue update must verify signed,
versioned metadata and cannot add a privileged adapter or executable behavior.

See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).
