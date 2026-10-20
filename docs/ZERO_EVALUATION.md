# Reports over an unevaluated scope

Issue 19 is a report correctness repair. A nonempty catalogue containing only
not-applicable and not-selected results has established no policy compliance.
The existing report schema and exit codes already express this: `complete`
must be false and a check must exit 3.

`Summary::is_complete` will require at least one evaluated result and no
concealed state. Evaluated remains pass plus drift plus review. Review is an
observation, not a claim that policy matches. Text, JSON and MCP use this one
aggregate rule, and incomplete takes precedence over drift. Complete text
describes only the selected scope, never certifies the whole machine.

Control and section selectors define the evaluation scope before probes and
aggregation. Explicit control selection preserves CLI enforcement intent;
section selection alone preserves the profile. MCP uses the same builder and
selector semantics. Hiding passing rows is presentation only. `carried` remains
the documented full compiled catalogue count; summary counts describe the
requested scope. Empty selection and empty platform catalogue receive distinct
explanations.

The report builder accepts the existing typed Context internally. Live entry
points still discover the host and construct a live Context. Compiled tests
use synthetic HostFacts and a closed Linux Live/Recorded reader for only the
ten existing file targets. Recordings contain exact bytes or typed read
failures, never outcomes or a pre-labelled Report. Missing observations are
unknown, not absent, and a recorded read never falls back to the machine.
Fixtures cannot choose paths, commands or environment keys. No public fixture
flag or mutating replay mode is added.

The existing evaluator remains the pure outcome authority. The report adapter
uses its existing applicability model before observation, preserving Ignore
before applicability, so excluded, inapplicable and
undetermined scopes do not trigger unnecessary reads. Applicable selected
controls still run their compiled probes and the same pure evaluator.

Linux file transport is bounded and preserves denied, malformed and oversized
inputs as uncertainty. This does not fix systemd drop-in precedence or prove
loaded daemon state. No new parser, resolver, service query, control, privilege,
remediation or distribution channel belongs to this change. Those known risks
remain in the roadmap.

Acceptance includes the reported Arch/Hyprland baseline (7 not applicable,
6 not selected, no evaluated controls), empty and excluded scopes, raw-byte
compiled popcon pass/drift/denied/malformed controls, drift with unknown,
selector and visibility parity, CLI aliases, and actual MCP dispatch. Tests
must prove that the repair neither disables successful probes nor promotes a
failed observation to pass. Native CI and the existing formatting, Clippy,
coverage, and dependency gates remain required.
