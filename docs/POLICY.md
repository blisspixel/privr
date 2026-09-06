# Policy model

## Purpose

A policy states privacy intent. It does not describe operating-system mutation
mechanics.

The engine resolves semantic values such as `required_only`, `disabled`, or
`prompt` through a compiled platform adapter. Policy files cannot contain shell
commands, executable names, Registry paths, service names, arbitrary file paths,
or dynamically loaded code.

## Built-in policy

The first built-in policy is `privacy-first`. It minimizes low-breakage optional
collection and personalization while preserving:

- security and operating-system updates;
- disk encryption and recovery;
- firewalling and real-time malware protection;
- reputation and certificate services;
- local crash diagnosis;
- explicitly selected synchronization features.

Location, cloud sync, sensitive permissions, security sample submission, and
other contextual choices default to review rather than blanket enforcement.

Security-reducing or destructive policy packs are deferred. If introduced,
they must be separately installed or selected, clearly named, and protected by
specific risk acceptance. They are not variants of the default policy.

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
extends = "builtin:privacy-first@0.1"

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

`privr` continues to evaluate and display excepted controls. Active exceptions
are counted separately. An expired exception becomes drift again. Future team
metadata may record an approver, but it must not change the local evaluation
semantics.

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
