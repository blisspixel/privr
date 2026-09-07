# Product definition

## One-sentence promise

`privr` shows what an operating system is configured to share, explains the
tradeoffs, applies a policy the user controls, and detects when the settings
drift.

Tagline: Privacy settings you can verify.

## Product category

`privr` is a local privacy posture manager. It is narrower than a security
hardening framework and more stateful than a tweak or script collection.

The product loop is:

```text
check -> explain -> plan -> capture -> apply -> verify -> rollback -> check again
```

The key product claim is trustworthy state management, not the number of tweaks
in the catalogue.

## Primary users

### Privacy-conscious individual

This user wants a plain answer to questions such as:

- Is optional diagnostic data enabled?
- Will crash reports be uploaded automatically?
- Is the operating system using activity, typing, location, or advertising data?
- Did an update turn something back on?
- Which settings are required by the platform and cannot be disabled?

The user values understandable language, conservative defaults, and changes that
can be reversed.

### Developer or power user

This user wants:

- a repeatable privacy profile across machines;
- a scriptable command with stable exit codes;
- versioned JSON output;
- exact observed and expected values;
- local history and rollback;
- the ability to document intentional exceptions.

### Who this is not for

`privr` is not a device-management product and does not compete with one. No
fleet console, no remote administration, no compliance attestation, no
enrollment. That is a different product with a different buyer, and building
toward it would distort every other decision here.

The assumed host is a machine the user owns and administers. Where an external
authority does govern a setting, `privr` reports whether its effective value
passes or drifts and stops there. It does not reapply, does not fight a policy
that will simply return, and does not present a policy fight as remediation.

Some controls happen to serve a managed context too, because the underlying
setting is the same one either way. That is a property of the catalogue rather
than a product direction, and it never justifies fleet features.

One consequence worth stating plainly rather than hiding: unmanaged macOS is
largely a guided-review product, and unmanaged is exactly the target here.
Managed Macs are where verification is most possible, and those are the hosts
this product is least aimed at. macOS coverage will therefore be thinner than
Windows coverage for the intended user, for reasons outside this project's
control.

## Jobs to be done

1. Tell me what this machine is configured to share.
2. Separate optional sharing from required platform connectivity.
3. Explain why a setting matters without hiding the tradeoff.
4. Show the exact plan before asking for elevation.
5. Change only the settings I approved.
6. Prove that the change took effect.
7. Restore the values that were actually present before the change.
8. Detect drift after operating-system or application updates.
9. Produce a report that can be reviewed without exposing private machine data.

## Product principles

### Local and quiet

Normal operation requires no network access. `privr` collects no product
telemetry, performs no background update check, and does not upload reports.

### Read-only value first

The first useful release is an accurate checker. Remediation does not justify a
weak or misleading observation model.

### Semantic policy

Profiles state an intent such as `prompt` for Defender samples or `required-only`
for Windows diagnostics. They do not expose registry paths, shell commands, or
opaque numeric values to ordinary users.

### Evidence and applicability

Every control identifies its vendor source, supported versions and editions,
management behavior, last review date, and verification method.

### No false green

Missing, unreadable, unsupported, or ambiguous settings never become `pass`.
Managed settings and effective-but-driftable user choices remain visible.

### Security remains a first-class concern

The default profile retains updates, firewalling, disk encryption, malware
protection, certificate services, and local diagnostic capability. Privacy
choices that reduce a security control require a separate risk acknowledgement.

### Real rollback, modest claims

Rollback uses captured prior values, not vendor defaults. Operating-system
changes are not fully transactional, so `privr` reports partial application and
partial rollback honestly.

## Policy strategy

### The profile ladder

Three built-in profiles, ordered, each a strict superset of the one below:
`baseline` (the default), `strict`, and `restrictive`.

`baseline` is the recommended setting, not a cautious floor. What separates it
from the deeper levels is the distinction between collection and features:

- **Passive continuous collection is disabled.** Data flows that occur whether or
  not the operator uses anything: diagnostic transmission, advertising
  identifiers, activity history upload, tailored experiences, typing
  personalization, background usage reporting. These are not features anyone
  invokes, and disabling them costs essentially nothing.
- **Features the operator may actively want default to review.** Cloud clipboard
  sync, location, cloud search, peer update delivery, and voice services are
  things someone may use on purpose. `baseline` shows the tradeoff and the
  mitigation, then lets the operator decide.

A control is never held back from `baseline` because it sounds aggressive, only
because the operator might be using the thing.

Examples at `baseline`:

- optional diagnostics at the lowest level the edition actually honors;
- automatic crash-report transmission off while local diagnostics remain;
- advertising and tailored experiences off;
- typing-improvement collection off;
- cross-device activity off;
- Defender automatic sample submission changed to prompt, never disabled;
- location, cloud storage, and sensitive permissions reported for review.

No profile in the ladder contains a control that reduces security. Security
tradeoffs and irreversible erasure are selected deliberately, outside the ladder,
with per-control acknowledgement. See [POLICY.md](POLICY.md).

### Custom

A custom profile extends a built-in profile with semantic control overrides and
documented exceptions.

```toml
schema = 1
extends = "builtin:baseline@0.1"

[controls."windows.location-services"]
mode = "enforce"
desired = "enabled"

[[exceptions]]
control = "windows.location-services"
accepted = "enabled"
reason = "Needed for device recovery and automatic time zone"
```

Security-reducing and destructive choices do not belong in a general built-in
profile. If future demand justifies them, they should ship as separately
reviewed experimental packs with specific risk acceptance.

## Differentiation

Useful existing projects prove demand for privacy controls. `privr` should not
compete by copying the largest tweak list.

| Category | Typical strength | `privr` distinction |
|---|---|---|
| Privacy script generators | Transparent changes and broad coverage | Reads effective state, captures actual prior values, verifies and detects drift |
| Windows privacy utilities | Deep Windows UI, profiles, CLI deployment, verification, undo, and broad setting catalogues | Open implementation, named cross-platform support, primary-source metadata, and stable result schemas |
| Security auditors | Broad system and compliance coverage | Focused personal-data-sharing explanations and conservative remediation |
| Generic configuration tools | Powerful desired-state enforcement | Curated vendor-cited privacy controls and guided individual use |

The durable moat is a high-quality control catalogue with applicability data,
fixtures, and safe operations.

[O&O ShutUp10](https://manuals.oo-software.com/ooshutup10/docs/features/overview/)
already documents broad Windows settings, profiles, readback, command-line use,
and undo history. [privacy.sexy](https://github.com/undergroundwires/privacy.sexy)
provides transparent cross-platform script generation. `privr` should
differentiate through conservative typed controls, effective-state evidence,
exact machine-specific rollback, offline normal operation, and durable
automation contracts.

## Product boundaries

`privr` is not:

- an anonymity product;
- a VPN, DNS filter, firewall manager, or traffic interceptor;
- a debloater or application uninstaller;
- an anti-forensics or secure-deletion tool;
- a malware scanner;
- a replacement for Group Policy, MDM, or fleet configuration management;
- proof that an application never sends data;
- a promise of zero telemetry on a platform that does not offer that choice;
- a single privacy score.

## Name and distribution note

`privr` is short but not unique. Unrelated services currently use
[privr.com](https://www.privr.com/) and [privr.nl](https://privr.nl/). This is not
a legal conclusion, but it creates search and domain ambiguity.

Before public branding or package publication, check trademarks, reserve the
crate and package names, and pair the executable with a descriptive phrase such
as "privr privacy CLI." Published crate versions cannot be overwritten, so the
concept remains on `0.0.x` until the Windows checker is useful.

## Success criteria

Early product success should be measured by trust and correctness:

- percentage of results backed by current primary documentation;
- percentage of applicable controls with version and edition fixtures;
- false-positive and false-green rates;
- rollback success under fault injection;
- number of controls that expose security or functionality tradeoffs clearly;
- time required to understand and resolve a drift report;
- cross-platform release and test reproducibility;
- no telemetry emitted by `privr` itself.

Raw control count is not a primary success metric.

## Product decisions

| Decision | Rationale |
|---|---|
| Rust implementation | Native cross-platform binary, typed adapters, controlled process execution |
| Windows-first operational release | Best documented policy surface and immediate user need |
| Cross-platform model from the start | Avoid embedding Windows semantics in the core engine |
| `check` as the primary read-only verb, with `audit` as an alias | Approachable for individuals and familiar to security users |
| `plan` separate from `apply` | Dry-run behavior is important enough to be a first-class workflow |
| `rollback` uses transaction journals | Restores actual prior state instead of guessed defaults |
| No product telemetry | A privacy tool should not create a new telemetry relationship |
| No arbitrary shell policy operations | Prevent policy injection from becoming elevated code execution |
| No single score | Privacy tradeoffs are contextual and cannot be summarized honestly by one number |
| One built-in policy initially | Avoid normalizing security-reducing choices as a routine privacy mode |
| Internal transaction IDs for rollback | Prevent caller-selected snapshot files from crossing the privilege boundary |

## Open product questions

1. Should local scheduled drift checks be configured by `privr schedule` or by
   documented native scheduler examples?
2. Which additional policy packs, if any, justify the review and support burden?
3. Which custom-policy schema features are necessary before remediation without
   creating a general configuration language?
4. How should the product explain a setting that is private now but not enforced
   against future drift?
