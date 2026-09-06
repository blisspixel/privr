# Product privacy

## Commitment

`privr` must not create a new telemetry relationship while helping users reduce
existing data sharing.

The product itself collects no usage analytics, crash telemetry, advertising
identifiers, installation identifiers, or remote audit reports. Normal `check`,
`explain`, `list`, `plan`, `apply`, `purge`, `rollback`, `history`, `mcp`, and
`doctor` workflows require no network access.

`privr` never calls a language model. It contains no model client, no API key
handling, and no inference network call. When an agent drives `privr`, the model
is the caller and never a dependency, and the agent server speaks over standard
input and output only. See [AGENT_INTERFACE.md](AGENT_INTERFACE.md).

This commitment applies to `privr`. It is not a claim that a supported operating
system can be configured for zero vendor traffic. Updates, activation,
certificates, security services, licensing, and explicitly chosen cloud features
may still communicate with their providers.

## Local data processed

The tool may need to process:

- operating-system family, version, build, edition, and architecture;
- whether relevant policy management is present, without tenant or account IDs;
- effective values for selected privacy controls;
- explicit policy files supplied by the user;
- exact before and after values for controls that `privr` changes;
- verification, failure, and restart state for a transaction.

Platform adapters must request only the evidence needed for the selected
controls. Broad registry exports, preference database copies, log bundles, and
unrelated configuration trees are prohibited.

## Reports

Default terminal reports minimize local detail. JSON exports intentionally omit:

- usernames, security identifiers, account IDs, tenant IDs, and machine IDs;
- enrollment identifiers and policy object identifiers;
- recovery keys, tokens, cookies, credentials, and encryption material;
- raw process arguments and shell history;
- crash contents, memory dumps, file samples, and document contents;
- paths that expose a user profile name unless a reviewed redaction rule exists;
- raw command output that may contain any of the above.

Identifier reduction happens at the probe boundary, not at the reporting
boundary. Management detection reduces enrollment and policy object identifiers
to a boolean inside the probe function, so they never exist further up the stack
to be leaked by a future code path.

Reports are written only when the user directs output to a file or invokes an
explicit export option. Complete audit reports are not retained automatically.

## Reports are safe to forward

Because a report carries no stable machine identifier, it is safe by construction
to hand to an external tool, a script, or a model. This is a requirement rather
than a side effect, and it exists to close a specific hole.

A privacy tool whose output is a detailed configuration profile of the machine
would defeat its own purpose the moment a user piped that output to a hosted
service. Designing the report so there is nothing in it worth withholding is a
stronger answer than warning people not to share it.

Guidance for callers is documentation, not code: prefer a local model, and when
using a hosted router, select a no-logging data policy.

## Transaction history

Mutation history is retained locally because exact rollback needs a record of
the changed state. A transaction contains only:

- transaction ID and timestamps;
- selected control IDs;
- catalogue and policy digests;
- typed before and after values needed for rollback;
- apply, verification, and rollback results.

Secret-class values are never eligible for ordinary mutation because they
cannot safely enter a plan, journal, report, log, or error. Personal-class values
require an explicit reviewed storage and redaction rule.

Proposed Windows roots are `%LocalAppData%\privr\state` for user transactions
and `%ProgramData%\privr\state` for machine transactions. The elevated helper
chooses the fixed machine path and never accepts a path from the caller.

## Arguments, environment, and logs

Sensitive values must not be placed in process arguments or environment
variables. The shell, operating system, process monitors, event logging, and
terminal history can retain them.

Logs contain semantic control IDs and redacted state only. Debug modes do not
weaken redaction. Errors must not echo raw Registry data, file contents, command
lines, profile secrets, or IPC payloads.

## Network behavior

The executable does not perform an automatic update check. A future explicit
`privr catalog update` command may use the network only after its source,
signature policy, and destination are documented. Downloaded catalogue data is
non-executable and cannot introduce a privileged operation.

Network-isolation tests must prove that core workflows make no requests.

## Retention and deletion

The transaction journal is the one record `privr` keeps, and the promise attached
to it is narrow: **it holds exactly enough to reverse what `privr` did, and
nothing else.** It is local, it is the operator's, it never leaves the machine,
and the operator can read it and destroy it.

`history purge` implements the second half of that. Users can list transaction
records before removing them, and the command must:

- show the exact transaction IDs and paths involved;
- refuse broad or unresolved paths;
- state plainly that purging a record makes its changes unrollbackable;
- distinguish losing rollback ability from deleting ordinary reports;
- avoid deleting operating-system logs or cloud data;
- use recoverable deletion where the platform supports it.

Default retention limits will be chosen before remediation ships and documented
in both CLI help and release notes.

This matters because the project's assurance comes from constrained mechanism
rather than from recording what the operator does. A tool that argued against
ambient observation while building a detailed local history of its user would be
incoherent.
