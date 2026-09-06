# Results and drift

## Design rule

Evaluation outcome, platform support, management source, remediation ability,
reversibility, pending effect, and policy exception are independent facts. They
must not be compressed into one ambiguous status.

When a new fact appears, it becomes a new dimension rather than a new outcome
value. Adding outcome values that encode two facts at once is how comparable
tools lose the ability to distinguish "we could not check" from "there is
nothing to fix".

## Evaluation outcome

| Outcome | Meaning |
|---|---|
| `pass` | Effective state matches an enforce-mode desired value |
| `drift` | Effective state differs from an enforce-mode desired value |
| `review` | The policy asks the operator to review a contextual choice |
| `unknown` | Effective state cannot be determined confidently |
| `not_applicable` | The control does not apply to this host |
| `not_selected` | The control applies but the selected profile does not include it |
| `not_checked` | The control applies and was selected, but was not evaluated |
| `error` | Observation or evaluation failed |

`not_applicable`, `not_selected`, and `not_checked` are three different facts.
A control that was selected and never evaluated must never be reported as not
applying to the host, and must never be counted as a pass.

Unknown, unreadable, malformed, unsupported, denied, not-selected, and
not-checked states never become `pass`.

Effective state is what is evaluated. The presence of an enforcement mechanism,
such as a policy object or a management payload, is not evidence that the
setting itself holds. Where only the enforcement mechanism is readable, the
outcome is `review`.

## Independent dimensions

### Management source

`user`, `local_policy`, `group_policy`, `mdm`, `configuration_profile`,
`default`, or `unknown`.

A managed control can pass or drift. `privr` reports the authoritative source
and does not fight an external manager.

### Remediation

`automatic`, `guided`, `audit_only`, or `none`.

An automatically readable control may still be guided or audit-only because a
safe write interface, exact rollback, or acceptable tradeoff is unavailable.

When remediation is `none`, a `remediation_reason` is required, drawn from a
closed set: `platform_limitation`, `irreversible_once_set`, `no_safe_write`,
`no_exact_rollback`, `managed_externally`, or `excluded_by_policy`.

This is how a control that is observable, confirmed non-compliant, and not
fixable on this platform is expressed: outcome `drift`, remediation `none`, with
the reason naming why. It is not a separate outcome, because the outcome and the
fixability are two facts.

### Support

`verified`, `unverified`, or `unsupported`.

Verified support is tied to an operating-system version, build, edition,
architecture, management mode, desktop, and adapter revision where relevant.

Support degrades automatically when a control's review has gone stale or the
host has moved beyond its last reviewed platform range. A control whose support
is not `verified` cannot report `pass` and its remediation is forced to
`audit_only`.

### Reversibility

`exact`, `irreversible`, or `remote_effect`.

`exact` means a prior value can be restored byte-for-byte, subject to conflict
checks. `irreversible` means the change cannot be undone by `privr` and the
transaction records that fact. `remote_effect` means the change requests action
outside this machine and cannot be recalled.

### Maturity

`automated`, `partial`, or `manual`.

Maturity is a fact about the control, not about this host. It says whether the
control can be evaluated programmatically at all. Keeping it separate from the
outcome preserves the ability to state that a check is manual and has not been
performed.

### Effect

`active`, `pending_signout`, `pending_restart`, or `pending_reboot`.

The effect field describes when a verified write becomes effective. It does not
replace the evaluation outcome.

### Exception

`none`, `active`, or `expired`.

An exception may change the remediation decision and any aggregate presentation.
It never changes the finding. A control that drifts still reports `drift` while
exempted. Active exceptions name the accepted state, carry an expiry, and remain
visible in reports.

## Sections

Every control belongs to exactly one section. Sections are topical groupings
used for reporting and, once mutation ships, for stepwise approval. Section
membership is part of the result so that text, JSON, and agent output group
identically.

Sections appear in the read-only release as a reporting structure before they
carry any approval semantics.

## Aggregates

Any summary, per section or overall, excludes controls that were not evaluated
rather than counting them.

An aggregate must never improve because visibility decreased. If access is
denied or support degrades, the affected controls move out of the evaluated
denominator and the report says so. A summary that rises when the tool can see
less is the scoring form of a false pass.

`privr` publishes no single privacy score.

## Drift definition

Policy drift means exactly:

> The effective observed value differs from an enforce-mode desired value in
> the selected policy.

History is not required to detect policy drift. A matching but unenforced user
preference can be `pass` with management source `user`; output may warn that it
is more likely to drift.

Machine changes and policy changes are separate comparisons. Neither is silently
relabeled as policy drift.

## Completeness

Every report has `complete: true` or `complete: false`.

A report is incomplete when a selected applicable control cannot be observed
because of denied access, an unknown build, missing required capability,
malformed evidence, adapter failure, or another uncertainty that could hide
drift. Unsupported controls remain visible but only make the report incomplete
when the selected policy expected them to be evaluated on that host.

Truncation for output size is always reported explicitly. Silently omitting
results reads as a pass.

The current concept build always reports `complete: false`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. A complete check with no enforce-mode drift, a successful informational command, or an apply the operator intentionally stopped after approving some sections |
| `1` | Complete check with enforce-mode drift |
| `2` | Usage, policy parsing, or confirmation failure |
| `3` | Incomplete result from unknown state, unsupported scope, missing privilege, or failed observation |
| `4` | Apply or rollback failed or was interrupted, and state may be partially changed |
| `5` | Operation refused before any change was made, and nothing was changed |

Intentionally stopping partway through a sectioned apply is a success. The
operator approved some sections, declined or deferred the rest, and every
approved change was verified. That is not partial failure and does not exit `4`.

Code `5` covers a clean refusal: a conflict detected before writing, a plan that
no longer matches fresh state, or a failed precondition. It exists so that a
caller, human or agent, can distinguish "this stopped and changed nothing" from
"this stopped midway" without parsing prose.

If a check contains both drift and incomplete results, exit code `3` wins. JSON
still carries both counts.

## Output determinism

Results are emitted in a stable, documented order that does not vary between
runs on the same input. Two reports from the same host and catalogue must be
diffable without normalization.

## Verbosity

Machine-readable output supports verbosity tiers so a full report fits a
constrained context window: identifiers only, summary, or full detail.
Explanatory prose lives in `explain`, retrieved one control at a time, rather
than being inlined into every result.

Tier selection changes how much of each result is emitted. It never changes
which controls are included, and it never changes an outcome.

## JSON envelope

A machine-readable report includes:

- report schema and tool version;
- catalogue version and digest;
- policy ID, version, and digest;
- non-identifying platform, build, edition, and management-mode metadata;
- completeness, truncation state, and summary counts;
- result dimensions for each selected control;
- section membership;
- evidence source URLs and last verified platform versions;
- warnings and redaction metadata.

It excludes stable machine identifiers, account identifiers, usernames, tenant
identifiers, enrollment identifiers, security identifiers, policy object
identifiers, recovery material, raw command output, and unreviewed local paths.

Because a report carries no stable machine identifier, it is safe by
construction to pass to an external tool or model. That property is a
requirement, not a side effect.

## Illustrative result

```json
{
  "schema": 1,
  "complete": true,
  "truncated": false,
  "policy": {
    "id": "baseline",
    "version": "0.1",
    "digest": "sha256:example"
  },
  "results": [
    {
      "id": "windows.error-reporting.transmission",
      "section": "diagnostics",
      "outcome": "drift",
      "management_source": "local_policy",
      "remediation": "automatic",
      "support": "verified",
      "reversibility": "exact",
      "maturity": "automated",
      "effect": "active",
      "exception": "none",
      "current": "send_automatically",
      "desired": "disabled"
    }
  ]
}
```

Values, digests, and versions above are illustrative, not current support
claims.
