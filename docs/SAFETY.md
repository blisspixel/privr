# Safety model

## Default posture

`privr check`, `explain`, and `plan` are read-only. Normal check, plan, apply,
rollback, and reporting workflows do not require network access and do not emit
product telemetry.

The default `privacy-first` policy preserves updates, encryption, malware
protection, reputation services, local diagnostic capability, and recovery.
Uncertainty fails closed and remains visible.

## Remediation classes

| Class | Meaning |
|---|---|
| `automatic` | Documented interface, deterministic state, exact rollback, and verified native tests |
| `guided` | Supported user choice, but automation is brittle, destructive, context-sensitive, or lacks a stable local API |
| `audit_only` | Evidence can be reported, but `privr` cannot safely change it |
| `none` | Inapplicable, unsupported, or explicitly excluded |

A reliable read does not automatically make a control eligible for write. New
controls mature through audit-only stages before remediation.

## Risk classes

### Standard

Low expected breakage with no material security reduction. Examples include
advertising identifiers, tailored experiences, feedback prompts, and supported
optional diagnostic features.

### Sensitive

May disrupt applications, synchronization, permissions, location, or user
workflow. The default policy normally puts these controls in review mode.

### Security tradeoff

May reduce malware analysis, reputation, phishing protection, update behavior,
recovery, encryption, logging, or incident response. These controls are not
ordinary default-policy remediation and need a separate named risk action if
ever supported.

### Destructive

Deletes local or remote data or creates a side effect that exact rollback cannot
reverse. Examples include clearing history, deleting Recall snapshots, removing
cloud data, or unlinking an account. These operations are guided or excluded,
not part of normal apply.

## Eligibility before mutation

Before a control can enter an apply plan, `privr` must:

1. verify platform, build, edition, architecture, feature, and management
   applicability;
2. resolve the authoritative effective state;
3. reject denied, malformed, unknown, unverified, or externally managed state;
4. select a compiled typed adapter with no caller-supplied target;
5. prove an exact preimage can be stored without retaining a secret;
6. prove post-write verification and conflict-aware rollback;
7. show the current and desired semantic values, scope, privilege, tradeoffs,
   dependencies, and pending effect;
8. receive the required confirmation and any separately named risk acceptance.

The helper and engine re-observe state during apply. A previously displayed plan
is not authority to overwrite a changed value.

## Transaction sequence

For every typed operation:

1. take the scope-specific apply lock;
2. re-read the target and compare it with the planned precondition;
3. record the exact preimage and expected postimage;
4. durably write the `prepared` journal state;
5. apply one mutation;
6. re-read the authoritative effective state;
7. record `applied` only after verification;
8. stop immediately on conflict or failure.

An operating system cannot provide one global transaction across Registry,
preferences, services, profiles, and files. `privr` reports partial state
instead of presenting best-effort work as atomic success.

## Windows elevation

The CLI remains unelevated. A short-lived helper handles only a freshly rebuilt
machine-scope subplan and exits after one transaction. It is not a service.

The helper rejects arbitrary commands, scripts, paths, Registry writes,
services, tasks, environment expansion, unknown adapters, oversized messages,
and caller-selected journal locations. It does not apply user-scope settings
because over-the-shoulder elevation may run under a different account.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the IPC and trust-boundary design.

## Journals and rollback

Transactions live under fixed permission-restricted local roots. They contain
only touched control IDs, exact typed preimages and postimages, digests,
timestamps, and verification states. Secret values are never eligible.

`rollback` accepts an internal transaction ID. It must:

- verify platform, scope, journal schema, and adapter compatibility;
- reject unknown operations and reparse-point or symbolic-link redirection;
- show the rollback plan and require confirmation;
- refuse an older overlapping transaction while a newer one exists;
- compare current state with the verified postimage;
- stop instead of overwriting an external change;
- restore exact existence, type, bytes, view, and metadata in reverse order;
- verify each restored value;
- retain failed or partial transaction evidence for recovery.

An absent preimage means remove only the exact value that `privr` created. It
never authorizes recursive deletion.

## Managed systems

Managed devices are scan-only by default. Group Policy, MDM, and configuration
profiles remain authoritative. A managed value can pass or drift, but `privr`
does not continuously reapply a conflicting local preference.

## Prohibited behavior

The project rejects features that:

- clear security, forensic, crash, or shell-history records as routine privacy
  remediation;
- delete user documents or cloud data;
- disable updates, encryption, firewalling, or real-time malware protection in
  the default policy;
- install certificates or intercept encrypted traffic;
- download and execute privacy scripts;
- allow arbitrary shell commands or privileged paths from policy or catalogue
  data;
- use undocumented Windows, macOS, or Linux settings as stable controls;
- directly write macOS TCC databases or raw dconf when GSettings exists;
- use domain blocklists as proof of privacy;
- hide tradeoffs behind a single score;
- report unknown, denied, manual, or unsupported state as compliant.

## Privacy of the tool

Reports, arguments, errors, IPC, and journals are separate disclosure surfaces.
All use allowlisted fields and sensitivity-aware redaction. Debug logging does
not weaken these rules.

See [PRIVACY.md](PRIVACY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
[TESTING.md](TESTING.md).
