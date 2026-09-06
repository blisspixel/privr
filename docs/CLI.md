# CLI contract

## Status

This is the target contract. The current `0.0.x` concept implements only a small
command skeleton and performs no platform checks or changes.

## Design goals

The CLI should be understandable at a terminal and predictable in automation.
Read-only actions are obvious. Mutating actions recompute and show a plan,
capture only needed prior state, verify the result, and report partial failure
honestly.

## Canonical command surface

```text
privr
privr check [--profile <name> | --policy <path>] [--control <id-or-prefix>] [--all]
privr explain <control-id>
privr list [--platform <name>]
privr plan [--profile <name> | --policy <path>] [--control <id-or-prefix>]
privr apply [--profile <name> | --policy <path>] [--control <id-or-prefix>] [--yes]
privr history list
privr history show <transaction-id>
privr history diff <older-id> <newer-id>
privr rollback <transaction-id> [--yes]
privr profiles list
privr profiles show <name>
privr profiles validate <path>
privr doctor
```

`--format text|json` is global. `privr` without a subcommand means
`privr check`. `audit` is an alias for `check`, `restore` is an alias for
`rollback`, and `apply --dry-run` may alias `plan`.

## `check`

`check` observes effective machine state and compares enforce-mode controls with
the selected policy. It does not mutate or request elevation merely to turn an
unreadable result green.

Default text output shows drift, review, unknown, and error results, then counts
passing controls. `--all` includes every passing control.

```text
Profile: privacy-first@0.1
Platform: Windows 11 Pro 24H2
Result: incomplete

14 pass, 3 drift, 2 review, 1 unknown

DRIFT  windows.error-reporting.transmission
       Current: send automatically
       Desired: automatic transmission disabled
       Source: local machine policy
       Fix: automatic, administrator required

REVIEW windows.defender.sample-submission
       Current: send safe samples automatically
       Tradeoff: prompting can delay cloud analysis

UNKNOWN windows.activity-upload
        Reason: effective policy could not be determined
```

This output is illustrative, not a current implementation claim.

## `explain`

An explanation includes:

- current and desired semantic values;
- data involved and likely destination;
- privacy benefit and security or functionality tradeoffs;
- platform, version, edition, architecture, and scope;
- management source and effective-state logic;
- required privilege and restart behavior;
- observation, apply, verification, and rollback support;
- primary source links and last verified platforms.

## `plan`

`plan` is always read-only. It displays the exact eligible changes, dependencies,
scope, privilege boundaries, acknowledgements, and pending effects.

The MVP does not save executable plan files. They create stale-state and local
data risks. `apply` recomputes from fresh observations and compares each target
again immediately before writing.

## `apply`

In an interactive terminal, `apply` displays the fresh plan and prompts for
standard-risk changes. `--yes` is for noninteractive standard-risk use and must
not authorize an unnamed security reduction, destructive operation, logout,
restart, account unlink, or data deletion.

Only controls with verified observation, a compiled typed adapter, exact
rollback, and successful native tests are eligible for automatic remediation.
Externally managed controls are not overwritten.

User-scope and machine-scope subplans are separate. Windows elevation uses a
short-lived allowlisted helper described in [ARCHITECTURE.md](ARCHITECTURE.md).

## `rollback`

`rollback` accepts only an internal transaction ID. It never reads a caller-
selected snapshot file as an elevated mutation request.

Before restoring a value, it confirms that current state still equals the
transaction's verified postimage. It refuses overlapping older transactions and
external changes. Results separate `restored`, `skipped`, `conflict`, `failed`,
and `manual_recovery` items.

Rollback is verified and best-effort, not globally atomic.

## `history`

History stores mutation transactions, not full audit reports. It contains the
minimum state required for conflict detection and rollback. Default output shows
transaction ID, time, policy digest, control IDs, scope, and result.

No command exposes an arbitrary transaction storage path. See
[PRIVACY.md](PRIVACY.md).

## `doctor`

`doctor` reports non-identifying capability information:

- operating-system version, edition, and architecture;
- current privilege and supported elevation path;
- whether relevant external management is present;
- available compiled platform adapters;
- transaction-root permission and reparse-point checks;
- catalogue, policy, report, and journal schema versions.

It does not print tenant IDs, account IDs, usernames, or machine identifiers.

## Selection

`--control` is repeatable. Each value is an exact semantic control ID or a
documented prefix. Dependencies are added automatically and shown in the plan.
The selector never accepts an operation, command, path, or wildcard supplied to
a shell.

`--profile` and `--policy` are mutually exclusive. The built-in default is
`privacy-first`.

## Results

The primary outcome is one of:

- `pass`
- `drift`
- `review`
- `unknown`
- `not_applicable`
- `error`

Separate fields describe management source, remediation, support, pending
effect, and exceptions. See [RESULTS.md](RESULTS.md) for exact definitions and
completeness rules.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Complete check with no enforce-mode drift, or successful informational command |
| `1` | Complete check with enforce-mode drift |
| `2` | Usage, policy parsing, or confirmation failure |
| `3` | Incomplete result caused by unknown state, unsupported scope, missing privilege, or failed observation |
| `4` | Apply or rollback failed or left partial state |

When drift and incomplete results coexist, `3` wins and the JSON report retains
both counts.

## JSON output

Every report includes schema, tool, catalogue, and policy versions and digests;
platform applicability; `complete`; dimensional results; source references;
warnings; and redaction metadata.

Stable machine IDs, usernames, SIDs, tenant IDs, recovery material, raw command
output, and unreviewed paths are excluded. JSON is written to standard output so
the caller controls whether it is retained.

## Terminal behavior

- Color is optional and is never the only state indicator.
- `NO_COLOR` is respected.
- Prompts occur only in an interactive terminal.
- Noninteractive mutation without required confirmation fails closed.
- Sensitive values never appear in arguments, prompts, progress output, or
  errors.
- Normal commands do not use the network.
