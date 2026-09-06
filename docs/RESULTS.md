# Results and drift

## Design rule

Evaluation outcome, platform support, management source, remediation ability,
pending effect, and policy exception are independent facts. They must not be
compressed into one ambiguous status.

## Evaluation outcome

| Outcome | Meaning |
|---|---|
| `pass` | Effective state matches an enforce-mode desired value |
| `drift` | Effective state differs from an enforce-mode desired value |
| `review` | The policy asks the user to review a contextual choice |
| `unknown` | Effective state cannot be determined confidently |
| `not_applicable` | The control does not apply to this host |
| `error` | Observation or evaluation failed |

Unknown, unreadable, malformed, unsupported, and denied states never become
`pass`.

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

### Support

`verified`, `unverified`, or `unsupported`.

Verified support is tied to an operating-system version, build, edition,
architecture, management mode, desktop, and adapter revision where relevant.

### Effect

`active`, `pending_signout`, `pending_restart`, or `pending_reboot`.

The effect field describes when a verified write becomes effective. It does not
replace the evaluation outcome.

### Exception

`none`, `active`, or `expired`.

An active exception names the accepted state and remains visible in reports.

## Drift definition

Policy drift means exactly:

> The effective observed value differs from an enforce-mode desired value in
> the selected policy.

History is not required to detect policy drift. A matching but unenforced user
preference can be `pass` with management source `user`; output may warn that it
is more likely to drift.

Machine changes and policy changes are separate comparisons. Neither is
silently relabeled as policy drift.

## Completeness

Every report has `complete: true` or `complete: false`.

A report is incomplete when a selected applicable control cannot be observed
because of denied access, an unknown build, missing required capability,
malformed evidence, adapter failure, or another uncertainty that could hide
drift. Unsupported controls remain visible but only make the report incomplete
when the selected policy expected them to be evaluated on that host.

The current concept build always reports `complete: false`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Complete check with no enforce-mode drift, or successful informational command |
| `1` | Complete check with enforce-mode drift |
| `2` | Usage, policy parsing, or confirmation failure |
| `3` | Incomplete result from unknown state, unsupported scope, missing privilege, or failed observation |
| `4` | Apply or rollback failed or left partial state |

If a check contains both drift and incomplete results, exit code `3` wins. JSON
still carries both counts.

## JSON envelope

A machine-readable report includes:

- report schema and tool version;
- catalogue version and digest;
- policy ID, version, and digest;
- non-identifying platform, build, edition, and management-mode metadata;
- completeness and summary counts;
- result dimensions for each selected control;
- evidence source URLs and last verified platform versions;
- warnings and redaction metadata.

It excludes stable machine identifiers, account identifiers, usernames, tenant
identifiers, recovery material, raw command output, and unreviewed local paths.

## Illustrative result

```json
{
  "schema": 1,
  "complete": true,
  "policy": {
    "id": "privacy-first",
    "version": "0.1",
    "digest": "sha256:example"
  },
  "results": [
    {
      "id": "windows.error-reporting.transmission",
      "outcome": "drift",
      "management_source": "local_policy",
      "remediation": "automatic",
      "support": "verified",
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
