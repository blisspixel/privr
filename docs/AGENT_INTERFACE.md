# Agent interface

## Status

Planned. No agent interface exists in the current concept build.

This document describes how `privr` is consumed by an agent harness. For
repository contribution rules, see [AGENTS.md](../AGENTS.md).

## Position

`privr` is designed to be driven by an agent from the first release. The
expected usage is that an operator points a harness at `privr` and it handles
the workflow, rather than the operator running each command.

Three consumer classes matter equally: coding assistants and desktop agents,
hosted models reached through a router, and small local models. The interface is
designed so that the weakest of those is useful and none of them is dangerous.

## Hard constraint

`privr` never calls a language model. It contains no model client, no API key
handling, and no inference network call. The model is always the caller and
never a dependency.

A tool that requires a remote service to be useful cannot make the offline
guarantee the rest of the design depends on. Guidance for callers ships as
documentation, not as code: prefer a local model, and when using a hosted
router, select a no-logging data policy.

## Division of labor

The model performs **routing** and **narration**. `privr` performs **facts** and
**mutation**.

- Routing is bounded selection: mapping a plain-English request to control IDs
  from a candidate set the tool supplied. This is the task small models perform
  most reliably.
- Narration is explaining results, in the operator's words, over facts the tool
  provided.
- A model may select from an enumerated plan. It may never synthesize a change.

Three constraints follow from how small models actually behave:

- Routing must be retrieval-assisted. A bounded catalogue query returns
  candidates rather than expecting a caller to hold every identifier.
- A model cannot be relied on to abstain. Where a result is incomplete, `privr`
  supplies the sentence that must be stated, rather than instructing the model to
  be careful.
- Structured decoding and tool calling should not be enabled together on a local
  model, because tool suppression is a reproduced failure. Below roughly four
  billion parameters, give the model no tools at all and let it narrate piped
  JSON.

## Transport

A stdio server, started with `privr mcp`. No network transport, no session
management, no authorization flow. The protocol is implemented directly rather
than through an SDK, because the available SDK roughly doubles the dependency
count, requires an async runtime, and raises the toolchain floor for features
this tool will never have.

The server must support both the current protocol revision and the revision that
shipping clients still use.

Standard output carries protocol traffic only. Diagnostics go to standard error.
Polluting standard output is the most common way a server of this kind fails.

## Tool surface

Read-only tools, always available:

| Tool | Purpose |
|---|---|
| `privr_status` | Host facts, capability, and catalogue staleness |
| `privr_catalog` | Bounded query over the catalogue, returning candidate controls |
| `privr_check` | Evaluate the host against a profile |
| `privr_explain` | Full detail for one control |
| `privr_plan` | Read-only proposed change set |

All five declare themselves read-only, non-destructive, idempotent, and closed
world.

Mutating tools, **absent from tool discovery entirely** unless the server is
started with `--allow-apply`:

| Tool | Purpose |
|---|---|
| `privr_apply` | Apply approved sections of a plan |
| `privr_rollback` | Restore a recorded transaction |

Design rules:

- Reads may be collapsed behind an enumerated filter. A mutation is never
  collapsed behind a mode flag. There is no dry-run boolean on apply, because a
  read is a different tool from a write.
- A tool that is absent cannot be called by mistake, cannot be described
  persuasively to a model, and cannot appear in a prompt injection as an
  available capability.

## Approval

Confirmation is structural, not instructed.

The token required to apply cannot be obtained through any tool call. It
originates from a terminal on the machine being changed. A caller therefore
cannot approve on the operator's behalf, regardless of what it is told or what
it decides.

Approval is per section and per named control for anything carrying a security
tradeoff, destructive effect, or major functionality change. There is no blanket
approval reachable through the agent interface.

## Token budget

A full report must fit a constrained context window. Measured cost is roughly
10, 35, and 180 tokens per control for the three verbosity tiers, so a
fifty-control report is roughly 500, 1,750, or 9,000 tokens.

Mechanisms:

- A verbosity tier on every read: identifiers, summary, or full.
- Outcome filtering, defaulting to exclude passing controls.
- Explanatory prose only in `privr_explain`, one control at a time.
- Pagination that always reports totals and truncation.
- All tool definitions together stay within a small fixed budget, because they
  occupy context on every turn.

**Truncation is always reported.** Silently omitting results reads as a pass,
which is the same failure the result model exists to prevent.

Self-contained means enough to state one correct sentence and choose the next
tool call. It does not mean the whole explanation.

## Properties the caller can rely on

- **Deterministic ordering.** Two runs on the same host and catalogue produce
  diffable output without normalization.
- **Stable identifiers.** Control IDs carry documented stability guarantees.
- **Self-contained results.** Explaining a finding does not require a second
  call for basic context.
- **Safe to forward.** Reports carry no stable machine identifier, no account or
  tenant identifier, no enrollment or policy object identifier, and no username.
  A report is therefore safe by construction to pass to an external service. This
  is a requirement, not an accident, and it is what keeps the agent integration
  from defeating the tool's purpose.
- **Honest incompleteness.** Unknown, denied, unsupported, not-selected, and
  not-checked never appear as passes, and aggregates exclude what was not
  evaluated.

## Mitigations and declared follow-ups

Some useful follow-up work sits outside what `privr` will ever do. Configuring a
city in a weather application after disabling location services is an
application preference, not an operating-system privacy control: it has no
adapter, no verification method, and no rollback.

`privr` declares such follow-ups without performing them. A mitigation is
machine-readable metadata on a control, so an agent can carry the workflow
further than the tool will.

Constraints:

- A mitigation never affects a result.
- A mitigation has no adapter binding.
- A mitigation may only address a consequence its own control causes.
- Anything the agent does in response is the agent's action, with the agent's
  permissions and its own confirmation. It does not enter a `privr` transaction
  journal, because `privr` did not do it and must not imply it can reverse it.

## Non-agent surfaces

The agent interface is not the only machine surface, and nothing requires it.

`--format json` with `--detail` provides the same information to a script or a
piped model with no protocol involved. `privr list` is the capability manifest.
Exit codes are documented and distinguish "nothing changed" from "stopped
midway". See [CLI.md](CLI.md).
