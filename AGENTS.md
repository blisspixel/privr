# Repository instructions

## Professional standard

- Treat this as a production-quality privacy and security tool.
- Write concise, precise, technically defensible prose.
- Do not add authorship, assistant, model, or tool attribution anywhere in the
  repository, generated artifacts, commit messages, trailers, release notes, or
  documentation.
- Do not use emojis.
- Do not use em dashes. Use commas, parentheses, colons, or ordinary hyphens.
- Avoid hype, fear-based language, profanity, and unsupported privacy claims.
- Never promise anonymity, zero telemetry, or complete privacy when a platform
  does not provide that guarantee.

## Privacy requirements

- `privr` must collect no product telemetry.
- Normal check, plan, apply, rollback, and reporting workflows must work without
  network access.
- Reports and transaction journals must minimize and redact local identifiers, usernames,
  account IDs, paths, command lines, recovery material, and secrets.
- Do not put secrets or sensitive values in process arguments.
- Distinguish optional vendor sharing, required connected services, deliberate
  cloud synchronization, and local-only diagnostics.
- Unknown, unreadable, manual, and unsupported states must never be reported as
  compliant.

## Safety requirements

- Keep checks read-only unless the command explicitly applies or rolls back a
  reviewed control.
- Use typed, allowlisted platform operations. Do not permit arbitrary shell
  commands in profiles or catalogue data.
- Show a deterministic plan before mutation.
- Capture only affected prior values in a fixed, permission-restricted journal.
- Verify every change by re-reading the authoritative effective state.
- Stop on failed verification and report partial state honestly.
- Do not clear audit logs, delete cloud data, disable updates, remove disk
  encryption, unlink accounts, or weaken security controls as ordinary privacy
  remediation.
- Require separate acknowledgement for security, destructive, or major
  functionality tradeoffs.
- Do not override Group Policy, MDM, configuration profiles, or another
  authoritative manager.

## Control research

- Prefer current primary vendor or upstream documentation.
- Every control needs a stable semantic ID, supported-version constraints,
  edition or desktop constraints, scope, source, risk, read method, apply method,
  verification method, rollback behavior, and fixtures.
- Do not add a control solely because it appears in a tweak list, script, forum,
  or undocumented preference database.
- Keep brittle or private platform settings audit-only or exclude them.

## Engineering quality

- Keep formatting and Clippy clean with warnings denied.
- Add tests for new behavior, failure paths, and rollback paths.
- Maintain at least 80 percent line coverage. Treat coverage as a floor, not
  evidence that a privacy control is correct.
- Keep Windows, macOS, and Linux CI passing.
- Keep the minimum supported Rust version job passing.
- Run dependency advisory, license, ban, and source checks.
- Preserve stable command, control ID, profile, report, and journal schemas.

## Documentation

- Keep README content concise and link to detailed documents.
- Keep roadmap claims consistent with implemented behavior.
- Mark concept, planned, experimental, and supported behavior clearly.
- Explain privacy benefits together with security and functionality tradeoffs.
- Use examples that contain no real user, machine, tenant, or account data.
