# CLI contract

## Status

This is the target contract, not a description of the current build. What
exists today, and where it falls short of this contract, is recorded in
[ROADMAP.md](../ROADMAP.md#current-state).

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
privr explain [<control-id-or-topic>]
privr list [--platform <name>] [--profile <name>] [--section <name>]
privr plan [--profile <name> | --policy <path>] [--control <id-or-prefix>]
           [--section <name>]
privr recommend [--workload <general|developer|creative|mobile|high-assurance>]
                [--max-friction <tier>] [--dimension <dimension>]
privr simulate [--profile <name>] [--control <id-or-prefix>] [--section <name>]
privr apply [--profile <name> | --policy <path>] [--control <id-or-prefix>]
            [--section <name>] [--yes] [--force] [--accept-risk <control-id>]
privr purge [--control <id>] [--polite] [--preview] [--accept-risk <control-id>]
privr history
privr rollback [<transaction-id>] [--section <name>] [--yes] [--elevate]
privr profiles list
privr profiles show <name>
privr profiles validate <path>
privr mcp [--allow-apply]
privr doctor
```

`privr` without a subcommand means `privr check`.
- `check` aliases: `status`, `scan`, `audit`
- `plan` alias: `diff`
- `apply` aliases: `fix`, `harden`
- `rollback` aliases: `restore`, `undo`
- `history` alias: `log`

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

Options:
- `--profile <baseline|strict|restrictive>`: Built-in target profile (default: `baseline`).
- `--policy <path>`: Custom policy file in TOML or JSON format extending a profile with per-control overrides and expiring exceptions.
- `--all`: Include every passing control in text output.
- `--compare <saved-check.json>`: Compare live evaluation against a historical JSON report to detect regression drift and OS platform updates.
- `-s, --section <name>`: Evaluate only the specified posture section(s).
- `-c, --control <id>`: Evaluate only the specified control(s).

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

Running `privr explain` without arguments (or with topic keywords `score`, `posture`, `critical`, `overview`) renders an educational walkthrough explaining:
- exact posture scoring math (`Compliant Controls / Evaluated Controls`);
- the five orthogonal posture dimensions;
- the four operational friction tiers;
- the five most critical Windows privacy and security controls (`llmnr`, `wpad`, `error-reporting`, `inventory-collector`, `delivery-optimization`);
- recommended next commands (`privr diff`, `privr fix`).

Running `privr explain storage` (or aliases `trim`, `wipe`, `sanitization`, `ssd`) details:
- solid-state flash physics vs magnetic platters (why multi-pass overwrites wear out flash and fail to erase data due to FTL wear leveling);
- hardware TRIM and unallocated space deallocation (zero flash wear, active Deterministic Zeroes After TRIM / DZAT);
- high-assurance defense against chip-off physical flash acquisition;
- ATA Secure Erase and NVMe Block Erase standards under NIST SP 800-88 Revision 1.

Running `privr explain shell` (or aliases `history`, `psreadline`, `bash`, `zsh`) details:
- physical retention mechanics of PSReadLine, GNU Readline, and Zsh history;
- accidental credential leakage in CLI flags and multi-line pastes;
- recommended session-only command recall configuration (`Set-PSReadLineOption -HistorySaveStyle SaveNothing` in PowerShell, `HISTCONTROL=ignorespace` or `HISTFILE=/dev/null` in Bash/Zsh);
- operational tradeoffs and the boundary between user command recall and operating system security audit logging.

Running `privr explain residue` (or aliases `clean`, `purge`, `forensics`, `cache`) details:
- local forensic artifact generation across Windows, Linux, and macOS;
- polite retention mode versus aggressive forensic purge;
- safe handling of locks, in-use files, and strict preservation of cookies, passwords, and sessions.

Passing an exact control identifier (e.g. `privr explain windows.security.llmnr`) inspects deep technical evidence:
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

`plan` supports `--workload <persona>` and `--max-friction <tier>` to preview
recommendations tailored to specific operational requirements. Controls that require
administrative elevation are annotated with `[requires elevation]`.

Plans are not saved as executable files. They create stale-state and local data
risks. `apply` recomputes from fresh observations and compares each target again
immediately before writing.

## `apply`

In an interactive terminal, `apply` displays the fresh plan and requests
approval section by section. The operator may approve a section, decline it, or
stop entirely.

`apply` supports `--workload <persona>` and `--max-friction <tier>` to execute
defensive, adaptive hardening without running ad-hoc scripts. By default, running
`privr apply` targets the `general` daily-driver persona and `tier1-cosmetic` friction
ceiling, applying high-impact privacy protections with zero workflow disruption.

**Native and adaptive elevation handling:**
- User-scope and machine-scope subplans are evaluated with elevation awareness.
- When run interactively, `apply` displays the planned changes and prompts for confirmation. If changes require elevation, confirming triggers native elevation in-place (UAC prompt on Windows via `Shell.Application`, or `sudo` on Unix) without requiring terminal hopping.
- Operators can pass `-e, --elevate` to explicitly authorize elevation handoff.
- In non-interactive contexts (scripts, CI) without `--elevate`, unprivileged batch runs defensively defer machine-scope changes, apply user-scope remediations, report `requires_elevation_drift` honestly, and exit with code 0.
- If a user explicitly specifies a machine-scope control via `--control <id>` while
  unelevated and without `--elevate`, `apply` fails closed with clear elevation guidance and exits with code 4.

**Stopping partway is a success.** Approving two sections and declining the rest
is a completed operation with exit code `0`, not a partial failure. Every
approved change is verified and journaled.

Consent is split rather than blanket:

| Flag | Authorizes |
|---|---|
| `--policy <path>` | Load a custom policy file (TOML/JSON) extending a profile with overrides and exceptions. |
| `-e, --elevate` | Request native in-place elevation (UAC on Windows, sudo on Unix) to apply machine-scope changes without switching terminals. |
| `-i, --interactive-sections` | Step through planned changes section by section with interactive approval. |
| `--yes` | Standard-risk changes in noninteractive use. Nothing else. |
| `--workload <persona>` | Tailor candidate remediations to a persona (`general`, `developer`, `creative`, `mobile`, `high-assurance`). |
| `--max-friction <tier>` | Cap remediation candidate friction (`tier0-transparent`, `tier1-cosmetic`, `tier2-workflow-altering`, `tier3-incompatible-or-tradeoff`). |
| `--force` | Proceeding when a non-blocking warning would otherwise stop the run. Never overrides external management, and never substitutes for `--accept-risk`. |
| `--accept-risk <control-id>` | One named control carrying a security tradeoff, destructive effect, or major functionality change. Repeatable. Never accepts a class or a wildcard. |

`--yes` must not authorize an unnamed security reduction, destructive operation,
logout, restart, account unlink, or data deletion. Those require the specific
control to be named.

Only controls with verified observation, a compiled typed adapter, exact
rollback, and successful native tests are eligible for automatic remediation.
Externally managed controls are not overwritten.

## `recommend`

`recommend` generates prioritized, explainable remediation recommendations
based on evaluated machine drift, workload personas, and friction budgets.
It examines the full eligible compiled catalogue across profiles, then applies
the workload, dimension, and friction filters. This differs from `check`, which
defaults to baseline. Only confirmed drift produces a recommendation. An empty
list does not establish compliance: unknown, unchecked, and filtered controls
remain outside that claim. Use `check` for selected-profile completeness.

Instead of reducing complex operational trade-offs to a lossy scalar score,
recommendations are ordered by friction tier (Tier 0 Transparent, Tier 1 Cosmetic,
Tier 2 Workflow-Altering, Tier 3 Incompatible/Tradeoff) and tailored to specific
workload personas:

- `general`: daily-driver workstation with zero workflow disruption;
- `developer`: uses a Windows reporting-specific rationale; other controls keep
  their own platform rationale and diagnostic tradeoffs. Linux core retention
  removal is Tier 3 and is excluded by a lower friction ceiling;
- `creative`: preserves local thumbnail caching for image and video asset curation;
- `mobile`: suppresses broadcast protocols (LLMNR, WPAD) on untrusted Wi-Fi while
  omitting slow pagefile clearing on shutdown;
- `high-assurance`: air-gapped workstation with maximum memory and disk lockdown.

## `simulate`

`simulate` performs an in-memory counterfactual dry run projecting posture
vector transitions, friction tier breakdowns, and pending restart or signout
requirements without modifying machine state.

Options:
- `--profile <baseline|strict|restrictive>`: Target policy profile to simulate (default: `baseline`).
- `--policy <path>`: Simulate applying a custom local policy (TOML/JSON) with overrides and active exceptions.
- `-s, --section <name>`: Simulate changes only in specific posture section(s).
- `-c, --control <id>`: Simulate changes only for specific control(s).

It computes the exact transition from current posture to simulated posture across
all five posture dimensions (`behavioral-commercial`, `forensic-residue`,
`network-exposure`, `diagnostic-crash`, `ambient-sensor`), distinguishing automated
remediation candidates from unautomated drift. Active policy exceptions remain respected
and are excluded from counterfactual remediation.

## `clean` (alias: `purge`)

Status: implemented but experimental; see [known defects](../ROADMAP.md#current-state).

`clean` removes supported local privacy residue. The default includes compiled
cache and temporary-file targets, recent-file lists, and the default PowerShell
ConsoleHost history file. Ordinary history loss and cache rebuilding are expected
consequences, disclosed in the preview. Actual target coverage depends on the
platform. Browser cookies, browser history, and persistent site/session data do
not yet have cleanup adapters. Their absence is a coverage gap, not proof that
those traces are gone.

In a terminal, `clean` displays the selected targets and tradeoffs, then asks for
one confirmation. Without a terminal it previews unless `--yes` is supplied.
`clean --yes` confirms permanent cleanup of the selected scope, including
supported history. Routine activity targets do not require separate
`--accept-risk` flags. That flag remains available for targets explicitly marked
as needing additional acknowledgement.

`--preview` (or `--dry-run`) always prevents deletion, even with `--yes`.
`--polite` reduces selection by retaining convenience-sensitive categories such
as recent activity and thumbnails. `--control` and `--category` narrow scope.
The text preview shows IDs, metadata counts, and tradeoffs. JSON preview and
execution items include an additive `trade_off` string; older items without it
remain readable. Selector validation still has known gaps tracked in issue 53.

Deletion cannot be rolled back. Close affected applications first: open shells
and desktop applications can recreate records. The PowerShell target does not
cover customized history paths, other hosts, or in-memory recall. Cleanup does
not disable future recording or clear cloud copies. It does not establish
physical-media sanitization.

Actual user content, credentials, recovery material, and security/audit logs
remain outside routine cleanup. Do not kill applications or bypass locks. On
Unix, XDG overrides and HOME fallbacks must resolve to absolute roots; selected
cleanup and journal access are refused when the required root is unavailable.

`--trim` requests separate hardware free-space maintenance. It is not evidence
that privacy traces were erased. Cleanup journals currently record the run but
lack per-target totals and interruption state (issue 57); they cannot restore
deleted files.

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
speaks over standard input and output only. `privr_check`, `privr_plan`, `privr_simulate`,
and `privr_apply` accept an optional `policy` argument (file path or inline TOML/JSON) allowing
autonomous agent workflows to audit, plan, and apply settings against enterprise policies.
`privr_apply` and `privr_clean` accept `accept_risk` for explicit authorization of high-friction
or risk-acknowledged actions. `privr_rollback` validates host platform matches the transaction
journal and supports `section` filtering.

## `doctor`

`doctor` reports non-identifying capability information:

- operating-system version, edition, and architecture;
- current privilege and supported elevation path;
- whether relevant external management is present;
- compiled platform adapters, with live capability explicitly unverified;
- transaction-root permission and reparse-point checks;
- catalogue staleness summary;
- catalogue, policy, report, and journal schema versions.

It does not print tenant IDs, enrollment IDs, account IDs, security identifiers,
policy object identifiers, usernames, or machine identifiers.
Windows editions are shown as not applicable on Linux/macOS, distinct from an
unknown edition. Linux privilege uses the effective UID from `/proc/self/status`,
not environment variables. A rolling distribution can have a known ID and no
numeric version; that version remains unknown for applicability. Reported
elevation mechanisms are implemented paths, not proof that the helper is
installed. A successful storage check does not attest other host capabilities.
The fixed Linux discovery interfaces follow the kernel's
[procfs UID ordering](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
and the [os-release specification](https://www.freedesktop.org/software/systemd/man/latest/os-release.html).
`/etc/os-release` exclusively takes precedence over the vendor file; an
unreadable or malformed present file does not permit a lower-priority fallback.

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
