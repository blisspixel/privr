---
name: privr
description: Local-first privacy posture auditing, forensic residue analysis, and verified remediation for Windows, macOS, and Linux. Use when an agent needs to inspect OS privacy settings, detect telemetry drift, explain forensic data residue, preview baseline plans, or interact via Model Context Protocol (MCP).
---

# privr: Privacy posture and residue toolkit

`privr` is a local-first privacy posture CLI and MCP server in Rust. It evaluates whether optional telemetry settings are active in practice, audits local forensic privacy residue, explains findings with citations to primary vendor documentation, and provides verified remediation with conflict-aware rollback.

## Core capabilities

1. **Telemetry in transit:** Audits whether operating system and browser telemetry, advertising identifiers, and crash submission daemons are transmitting data to vendor endpoints.
2. **Privacy residue at rest:** Audits unencrypted local forensic residue (thumbnail caches, push notification databases, memory crash dumps, pattern-of-life databases).
3. **Verified remediation:** Generates deterministic plans before mutation, writes to an exact transaction journal, and rolls back cleanly using recorded preimages.
4. **Honest evaluation:** Never guesses state. Undetermined, denied, and unsupported states are reported truthfully and never collapse into a compliant pass.

## MCP agent tool surface

When `privr` is loaded as an MCP server (`privr mcp`), the following tools are available:

### Read-only tools (always available)

- `privr_status`: Returns host platform, architecture, OS version, and catalogue count. Safe by construction; exposes no user or machine identifiers.
- `privr_doctor`: Evaluates host capability facts, privilege level, platform adapters, storage integrity, and schema versions.
- `privr_catalog`: Queries compiled controls in the catalogue. Accepts optional `query` and `platform` filters.
- `privr_check`: Evaluates host privacy posture against a profile (`baseline`, `strict`, `restrictive`). Accepts `all` boolean to include passing controls, and `control` string to filter by ID or prefix.
- `privr_explain`: Returns full privacy rationale, tradeoff, mitigation, and primary vendor documentation for a specific control identifier (e.g. `windows.storage.thumbnail-cache`).
- `privr_plan`: Returns a dry-run report of proposed changes for drifted controls without modifying the host.

### Mutation tools (gated behind `--allow-apply`)

- `privr_apply`: Applies and verifies supported changes for drifted controls. Requires explicit confirmation parameter (`yes: true`). Records all operations in a transaction journal.
- `privr_rollback`: Restores prior values recorded in a transaction journal. Requires `transaction_id` and explicit confirmation (`yes: true`).

## CLI workflow for agents

When driving `privr` directly via shell commands:

```bash
# Diagnostic capability and health verification
privr doctor --format json

# Non-destructive check with structured JSON output
privr check --format json

# Include passing controls
privr check --all --format json

# Explain a specific control
privr explain windows.storage.thumbnail-cache

# Search the catalogue
privr list --query thumbnail --format json

# Review a dry-run plan
privr plan --format json

# Apply verified baseline changes
privr apply --yes --format json

# Roll back a recorded transaction
privr rollback <tx-id> --yes --format json
```

## Agent rules of engagement

- Never promise zero telemetry or complete anonymity when an operating system does not guarantee it.
- Never report an unverified or unknown state as compliant.
- Do not attempt to bypass confirmation requirements: mutation requires explicit confirmation tokens.
- All JSON outputs are machine-readable, schema-stable, and diffable without normalization.
