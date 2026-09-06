# CLI contract

## Status

This is the target contract. The current `0.0.x` concept implements only a small
command skeleton and performs no platform checks or changes.

## Design goals

The CLI should be understandable at a terminal and predictable in automation.
Read-only actions are obvious. Mutating actions recompute and show a plan,
capture only needed prior state, verify the result, and report honestly what was
and was not changed.

Automation and agent callers are first-class. Output is deterministic, ordered,
and versioned, and every result carries enough context to be explained without a
second call.

## Canonical command surface

```text
privr
privr check [--profile <name> | --policy <path>] [--control <id-or-prefix>]
            [--section <name>] [--all]
privr explain <control-id>
privr list [--platform <name>] [--profile <name>] [--section <name>]
privr plan [--profile <name> | --policy <path>] [--control <id-or-prefix>]
           [--section <name>]
privr apply [--profile <name> | --policy <path>] [--control <id-or-prefix>]
            [--section <name>] [--yes] [--force] [--accept-risk <control-id>]
privr purge [--control <id>] [--preview] [--accept-risk <control-id>]
privr history list
privr history show <transaction-id>
privr history diff <older-id> <newer-id>
privr history purge [--before <date>] [--yes]
privr rollback <transaction-id> [--section <name>] [--yes]
privr profiles list
privr profiles show <name>
privr profiles validate <path>
privr mcp [--allow-apply]
privr doctor
```

`privr` without a subcommand means `privr check`. `audit` is an alias for
`check`, `restore` is an alias for `rollback`.

## Global options

| Option | Behavior |
|---|---|
| `--format text\|json` | Output format. Default `text` on a terminal. |
| `--detail ids\|summary\|full` | Machine-readable verbosity tier. Default `summary`. |
| `--color auto\|always\|never` | Overrides `NO_COLOR` when given explicitly. |
| `-v`, `-vv` | Increase diagnostic verbosity on standard error. |
| `-q` | Suppress non-essential output. Errors still print. |
| `--no-input` | Never prompt. Any operation that would require confirmation fails closed. |
| `--root <path>` | Read platform state from an alternate root. Read-only, and refused by every mutating command. |

`--detail` changes how much of each result is emitted. It never changes which
controls are included and never changes an outcome. Truncation, if any, is
always reported.

`--root` exists for testing and offline analysis of captured state. It is
rejected by `apply`, `purge`, and `rollback` without exception.

## `check`

`check` observes effective machine state and compares enforce-mode controls with
the selected policy. It does not mutate, and it does not request elevation
merely to turn an unreadable result green.

Default text output shows drift, review, unknown, and error results grouped by
section, then counts passing controls. `--all` includes every passing control.

```text
Profile: baseline@0.1
Platform: Windows 11 Pro 24H2
Result: incomplete

14 pass, 3 drift, 2 review, 1 unknown, 2 not evaluated

Diagnostics
  DRIFT   windows.error-reporting.transmission
          Current: send automatically
          Desired: automatic transmission disabled
          Source:  local machine policy
          Fix:     automatic, administrator required

Security tradeoffs
  REVIEW  windows.defender.sample-submission
          Current:  send safe samples automatically
          Tradeoff: prompting can delay cloud analysis

Activity
  UNKNOWN windows.activity-upload
          Reason: effective policy could not be determined
          This control is reported as unknown, not as passing.
```

This output is illustrative, not a current implementation claim.

## `explain`

An explanation includes:

- current and desired semantic values;
- data involved and likely destination;
- privacy benefit, and security or functionality tradeoffs;
- any mitigation that preserves the affected capability;
- platform, version, edition, architecture, and scope;
- management source and effective-state logic;
- required privilege and restart behavior;
- observation, apply, verification, and rollback support;
- reversibility class, and why remediation is unavailable when it is;
- primary source links, last review date, and last verified platforms.

Explanatory prose lives here rather than being inlined into every result, so a
full report stays small enough for a constrained context window.

## `list`

`list` enumerates the catalogue rather than evaluating the host. It is the
capability manifest: every control, its section, risk, reversibility, maturity,
remediation mode, and applicability. It answers "what could this tool do" as a
separate question from "what is true here".

## `plan`

`plan` is always read-only. It displays the exact eligible changes grouped into
sections, with dependencies, scope, privilege boundaries, required
acknowledgements, and pending effects.

Plans are not saved as executable files. They create stale-state and local data
risks. `apply` recomputes from fresh observations and compares each target again
immediately before writing.

## `apply`

In an interactive terminal, `apply` displays the fresh plan and requests
approval section by section. The operator may approve a section, decline it, or
stop entirely.

**Stopping partway is a success.** Approving two sections and declining the rest
is a completed operation with exit code `0`, not a partial failure. Every
approved change is verified and journaled.

Consent is split rather than blanket:

| Flag | Authorizes |
|---|---|
| `--yes` | Standard-risk changes in noninteractive use. Nothing else. |
| `--force` | Proceeding when a non-blocking warning would otherwise stop the run. Never overrides external management, and never substitutes for `--accept-risk`. |
| `--accept-risk <control-id>` | One named control carrying a security tradeoff, destructive effect, or major functionality change. Repeatable. Never accepts a class or a wildcard. |

`--yes` must not authorize an unnamed security reduction, destructive operation,
logout, restart, account unlink, or data deletion. Those require the specific
control to be named.

Only controls with verified observation, a compiled typed adapter, exact
rollback, and successful native tests are eligible for automatic remediation.
Externally managed controls are not overwritten.

User-scope and machine-scope subplans are separate. Windows elevation uses a
short-lived allowlisted helper described in [ARCHITECTURE.md](ARCHITECTURE.md),
and elevation is requested only after the plan has been shown.

## `purge`

`purge` removes local privacy residue by invoking documented vendor erasure
mechanisms. It never deletes files directly.

It is a separate verb precisely because it is irreversible. It is never part of
`apply`, never included in a default profile, and never reachable from `--yes`.
Each target requires `--accept-risk` naming that control.

`--preview` is the default and is contractually free of side effects. It reports
what exists, how much space it occupies, whether the collection that produces it
is still enabled, and whether a supported clear mechanism is available on this
build.

A purge writes a normal transaction journal entry recording that rollback is
unavailable and why, so a later `rollback` on that transaction fails loudly
instead of appearing to succeed.

## `rollback`

`rollback` accepts only an internal transaction ID. It never reads a caller-
selected snapshot file as an elevated mutation request.

Before restoring a value, it confirms that current state still equals the
transaction's verified postimage. It refuses overlapping older transactions and
external changes. `--section` restores one section of a transaction rather than
all of it.

Results separate `restored`, `skipped`, `conflict`, `failed`, and
`manual_recovery` items. A refusal that changes nothing exits `5`. A rollback
that fails partway exits `4`.

Rollback is verified and best-effort, not globally atomic.

## `history`

History stores mutation transactions, not full audit reports. It contains the
minimum state required for conflict detection and rollback. Default output shows
transaction ID, time, policy digest, control IDs, scope, reversibility, and
result.

`history purge` deletes transaction records the operator no longer wants to
keep. It is the operator's own record and they may destroy it. Purging a
transaction record makes its changes unrollbackable, and the command says so
before proceeding.

No command exposes an arbitrary transaction storage path. See
[PRIVACY.md](PRIVACY.md).

## `mcp`

`mcp` runs a stdio server exposing `privr` to an agent harness.

Read-only tools are always available. Mutating tools are **absent from tool
discovery entirely** unless `--allow-apply` is passed. There is no mode flag on
a mutating tool, and no dry-run boolean on apply: a read is a different tool from
a write.

Approval is structural. The confirmation token required to apply cannot be
obtained through any tool call and originates from a terminal on the machine
being changed, so a caller cannot approve on the operator's behalf.

`privr` makes no network requests and never calls a language model. The server
speaks over standard input and output only.

## `doctor`

`doctor` reports non-identifying capability information:

- operating-system version, edition, and architecture;
- current privilege and supported elevation path;
- whether relevant external management is present;
- available compiled platform adapters;
- transaction-root permission and reparse-point checks;
- catalogue staleness summary;
- catalogue, policy, report, and journal schema versions.

It does not print tenant IDs, enrollment IDs, account IDs, security identifiers,
policy object identifiers, usernames, or machine identifiers.

## Selection

`--control` is repeatable. Each value is an exact semantic control ID or a
documented prefix. Dependencies are added automatically and shown in the plan.
The selector never accepts an operation, command, path, or wildcard supplied to
a shell.

`--section` selects a named section from the closed section list.

`--profile` and `--policy` are mutually exclusive. Built-in profiles are ordered:
`baseline` (the default), `strict`, and `restrictive`. Each is a strict superset
of the one below. No profile in that ladder contains a control that reduces
security; those require explicit selection and `--accept-risk`.

## Results

Outcome is one of `pass`, `drift`, `review`, `unknown`, `not_applicable`,
`not_selected`, `not_checked`, or `error`.

Separate fields describe management source, remediation and its reason, support,
reversibility, maturity, section, pending effect, and exceptions. See
[RESULTS.md](RESULTS.md) for exact definitions, aggregate rules, and
completeness rules.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, including an apply the operator intentionally stopped after approving some sections |
| `1` | Complete check with enforce-mode drift |
| `2` | Usage, policy parsing, or confirmation failure |
| `3` | Incomplete result caused by unknown state, unsupported scope, missing privilege, or failed observation |
| `4` | Apply or rollback failed or was interrupted, and state may be partially changed |
| `5` | Operation refused before any change was made, and nothing was changed |

When drift and incomplete results coexist, `3` wins and the JSON report retains
both counts.

## JSON output

Every report includes schema, tool, catalogue, and policy versions and digests;
platform applicability; `complete`; `truncated`; dimensional results; section
membership; source references; warnings; and redaction metadata.

Results are emitted in a stable documented order so two runs can be diffed
without normalization.

Stable machine IDs, usernames, security identifiers, tenant IDs, enrollment IDs,
policy object identifiers, recovery material, raw command output, and unreviewed
paths are excluded. JSON is written to standard output so the caller controls
whether it is retained.

## Terminal behavior

- Color is optional and is never the only state indicator.
- `NO_COLOR` is respected, and an explicit `--color` overrides it.
- Unicode output degrades to ASCII when the terminal cannot render it.
- Standard output carries results. Diagnostics go to standard error.
- A closed pipe is not an error. `privr list | head` exits cleanly.
- Prompts occur only in an interactive terminal. `--no-input` disables them.
- Noninteractive mutation without required confirmation fails closed.
- Sensitive values never appear in arguments, prompts, progress output, or
  errors.
- Normal commands do not use the network.
