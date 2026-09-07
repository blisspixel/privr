# Design decisions

This document records decisions that constrain the rest of the project, with
the reasoning behind each one. It is a decision log, not a specification. Where
a decision contradicts an older statement in another document, this file is
authoritative until that document is updated.

Every decision here is planned unless the status line says otherwise. Nothing
in this file describes implemented behavior.

## 1. Rust, with a current toolchain

Status: decided.

`privr` is written in Rust. The deciding criterion is the product claim itself.
Distinguishing `unknown`, `denied`, `malformed`, `absent`, and `not_applicable`
is the core of what the tool sells, and Rust enums with exhaustive matching make
mishandling those a compile error. Go has no sum types, and its zero value makes
an unset field indistinguishable from a real negative. C# with NativeAOT
produces a single fast binary, but `null` inhabits every reference type, so
`unknown` can always decay into `compliant` at runtime.

The minimum supported Rust version tracks what the platform crates require
rather than a conservative floor. `privr` is an end-user binary, not a library,
so a low MSRV buys little and currently blocks the correct registry crate.

Consequences: MSRV rises when a required platform crate requires it. The MSRV
job pins the declared version and fails when the manifest and the toolchain
disagree.

## 2. No asynchronous runtime

Status: decided.

The codebase is synchronous. Registry reads, preference reads, and a single IPC
round trip gain nothing from an executor. The usual reason a project like this
acquires one is a protocol SDK that requires it, and decision 7 removes that
pressure.

Consequences: no `tokio` or equivalent in the dependency graph, including in the
elevated helper.

## 3. Contract parity across platforms, catalogue depth in sequence

Status: decided.

Two things that earlier drafts blurred are now separate. Contract parity ships
from the first release: the same result model, CLI surface, JSON schema, agent
tools, and honesty rules apply on every platform. Catalogue depth arrives per
platform in sequence, Windows first.

The failure this prevents is a core shaped like the Windows registry. The typed
observation and evidence model is designed against the hardest case on each
platform before any adapter is implemented:

- Windows: Group Policy, MDM, and preference precedence, with no universal
  ordering and edition-dependent enforcement.
- macOS: forced-by-configuration-profile as a state distinct from user-set,
  readable through `CFPreferencesAppValueIsForced`.
- Linux: absent schema, absent live user session, and system-wide dconf lock as
  distinct states.

Consequences: platform crates are added when their adapters are implemented, but
the shared model must already express all three. No release ships a binary for a
platform whose adapters are unimplemented.

## 4. Agent integration is part of the core contract

Status: decided. Supersedes the roadmap placement of Model Context Protocol
support at 0.2.0.

Read-only agent tooling ships with the first release, not after mutation. The
agent surface is a property of the result schema rather than a layer above it,
so it is designed in from the first control:

- Result objects are self-contained. Explaining a finding must not require a
  second call.
- Output ordering is deterministic, so two runs can be diffed.
- Control IDs carry documented stability guarantees.
- Verbosity tiers are part of the schema. Measured cost is roughly 10, 35, and
  180 tokens per control for identifier, summary, and full detail, so a
  fifty-control report is roughly 500, 1,750, or 9,000 tokens. This is the
  difference between usable and unusable in a small context window.
- Truncation is always reported. Silent truncation reads as a pass.
- The catalogue doubles as a capability manifest, and a bounded query returns
  candidate controls rather than requiring a caller to hold every identifier.

## 5. `privr` never calls a language model

Status: decided.

The binary contains no model client, no API key handling, and no network calls
for inference. The model is always the caller and never a dependency. A tool
that needs a remote service to be useful cannot make the offline guarantee that
the rest of the design depends on.

Guidance for callers is shipped as documentation and prompt material rather than
as code: prefer a local model, and when using a hosted router, select a
no-logging data policy.

Reports are already required to carry no stable machine identifier. That makes a
report safe by construction to hand to a model, and that property is now stated
explicitly rather than left implicit, because the alternative is a privacy tool
that leaks through its own agent integration.

## 6. Division of labor between the tool and the model

Status: decided.

The model performs routing and narration. `privr` performs facts and mutation.
A model may select from an enumerated plan; it may never synthesize a change.

Routing is bounded selection from a candidate set, which is the task small local
models perform most reliably. Narration is unconstrained generation over facts
the tool supplied. Three constraints follow from measured small-model behavior:

- Routing must be retrieval-assisted through a bounded catalogue query.
- A model cannot be relied on to abstain, so the tool supplies the sentence that
  must be stated when a result is incomplete.
- Structured decoding and tool calling should not be enabled together locally,
  because tool suppression is a reproduced failure.

## 7. The agent protocol server is implemented directly

Status: decided.

The stdio protocol server is implemented against `serde_json`, which is already
a dependency, rather than by adopting a protocol SDK. The available SDK is
maintained and capable, but it roughly doubles the dependency count, makes an
async runtime mandatory, and raises the required toolchain. Its value is
concentrated in transports, session management, and authorization flows that
`privr` will never have.

Consequences: the server must support both the current protocol revision and the
revision shipping clients still use.

## 8. Mutating tools are absent unless explicitly enabled

Status: decided.

Read-only tools are always present. Mutating tools are absent from tool
discovery entirely unless the server is started with an explicit flag. Reads may
be collapsed behind an enumerated filter; a mutation is never collapsed behind a
mode flag, so there is no dry-run boolean on an apply tool.

Confirmation is structural rather than instructed. The approval token cannot be
obtained through any tool call and originates from a terminal on the machine
being changed. A caller therefore cannot approve on the operator's behalf.

## 9. Catalogue data is non-executable, by construction

Status: decided.

A control definition binds exactly three tokens: an adapter identifier, a target
key, and a semantic state. All three are strings in the file and all three
resolve to compiled enum variants at load. None can express a path, registry
key, command, service name, file, URI, or pattern.

A second rule makes the first survive future downloaded catalogues: catalogue
metadata may only narrow compiled capability, never widen it.

The target token exists to avoid a false choice between one adapter per control,
which produces an unreviewable privileged surface, and a generic adapter that
requires the catalogue to supply a path, which is forbidden. A compiled target
enum gives many controls over one adapter, with every path, value name, type,
and registry view inside reviewed Rust.

Applicability is a flat conjunction of typed constraints over a fixed host-facts
structure. There is no nesting, no disjunction, no negation, no comparison
between facts, and no patterns. Disjunction is expressed as ordered first-match
variants. Applicability is tri-state so that undetermined can never collapse
into not-applicable. An expression language is rejected: a free-form parameter
is a target in disguise, and that is the mechanism by which non-executable
content becomes executable content.

Parameters are permitted only as named predicates drawn from a closed,
compiled set, with typed arguments. A bounded predicate over a known fact is
not an expression language, and the distinction is what lets a control express
an edition or release constraint without the catalogue gaining the ability to
name arbitrary targets. Where a version constraint is available at more than one
level, prefer the operating-system release over a component version, because
distributions backport.

Applicability gates the check and the remediation identically, from the same
declaration. A remediation must be incapable of running where the control was
never applicable. Deriving the two independently is how a tool ends up
remediating a machine it just reported the control did not apply to.

Per-platform fact tables hold values that differ between distributions or
releases, so that no control hard-codes a path or a component name.

## 10. The catalogue is embedded, in canonical JSON, authored in TOML

Status: decided.

Controls are authored as one TOML file each and compiled into canonical JSON
that is committed and embedded in the binary. TOML is better for authoring
because contributors write rationale and tradeoff prose, and comments and
multi-line diffs matter. JSON is better for shipping because it canonicalizes,
which the supply-chain requirements need for digests and signing.

The catalogue is embedded rather than installed alongside the binary. A
catalogue file next to an executable that requests elevation is writable by
anyone who can write the install directory. The adapter ceiling still prevents
new privileged behavior, but an attacker could rewrite risk classes and
rationale text to steer approval, which defeats informed consent without
breaking the security model. Embedding makes catalogue integrity identical to
binary signature integrity and makes the digest a build-time constant.

YAML is rejected on security grounds rather than preference: the common Rust
parser is unmaintained, and anchors with merge keys form a mini-language with a
known amplification denial-of-service.

## 11. Sections, and intentional partial application

Status: decided. Supersedes the treatment of partial state as a failure mode.

A plan is grouped into user-facing sections. The operator approves section by
section and may stop at any point. Stopping after approving some sections is a
normal, successful terminal state, not an interruption and not a warning.

Consequences:

- Sections are a first-class concept in the plan, the journal, and rollback.
- Rollback operates at section granularity as well as whole-transaction
  granularity.
- Dependency edges may only point within a section or to an earlier-ordered
  section. Without that constraint, section-granular rollback is not definable.
- Each section carries a risk ceiling, so a high-risk control cannot appear in a
  section whose disclosure does not warn for it.
- The exit code contract must distinguish an intentional stop from an
  interrupted or failed apply. The current definition of exit code 4 as leaving
  partial state behind is wrong under this model.

Sections ship in the read-only release, as a reporting structure, before they
carry any approval semantics. Grouping findings is useful on its own, it lets
the grouping be validated against real output before consent depends on it, and
it means approval later attaches to a structure operators already recognize. An
aggregate presented per section must exclude controls that could not be
evaluated, rather than counting them as passes.

## 12. Every transaction states whether it can be reversed

Status: decided. Replaces any claim that all changes are reversible.

Reversibility is a first-class control property with three classes: exactly
reversible, irreversible, and remote effect. An irreversible action still writes
a normal transaction journal entry, recording that rollback is unavailable and
why, so that a later rollback attempt fails loudly instead of silently
succeeding.

The resulting claim is that every transaction is recorded and honestly states
whether it can be reversed. That is stronger than a reversibility promise
because it survives contact with operations that genuinely cannot be undone.

The competitive claim is narrowed accordingly. Preimage capture and undo files
already exist in the Windows tooling landscape. What does not exist is
conflict-aware restoration: restoring only when current state still equals the
recorded postimage, refusing rather than overwriting a later external change,
and verifying the result. That, together with cited applicability and precedence
resolution, is the defensible ground.

## 13. Erasure invokes documented vendor mechanisms only

Status: decided.

`privr` does not delete files. It invokes documented vendor erasure actions.
That single rule excludes anti-forensic behavior and undocumented edits without
needing a separate prohibition list, and keeps erasure in the same evidence
class as every check: each action cites a vendor page.

Supporting findings:

- The size case and the privacy case barely overlap. The artifacts that consume
  many gigabytes carry little personal content, and the artifacts that carry
  personal content are usually small. One artifact is both large and highly
  sensitive, and it justifies the feature on its own.
- Documented clear mechanisms correlate inversely with forensic value, so the
  vendor-documentation rule excludes the anti-forensic set automatically.
- Staging to a quarantine area is rejected. The desktop trash specification
  requires a per-item record of original path and deletion date, which
  manufactures an index of exactly what the operator considered sensitive. It
  converts one exposure into two while allowing the tool to report success.

Erasure lives behind its own verb, never in the default profile, never part of
an ordinary apply, and never reachable from a blanket confirmation flag.
Preview is the default and is contractually free of side effects. Warnings are
structured metadata naming the artifact, the capability it supports, that the
action cannot be undone, and the consequence.

Generic disk cleanup is out of scope. It belongs to a separate tool or to the
calling agent, which already holds the context for judgments the tool cannot
make. Size, age, lock state, and whether a supported mechanism exists are
computable. Whether the operator still wants the data is not.

## 14. No webview, and no promise of three native applications

Status: decided.

`privr` will not ship a browser engine, a JavaScript runtime, or a webview-based
front end. Putting an HTTP client and a script engine inside a process that
requests elevation is irreconcilable with both the offline guarantee and the
compiled operation ceiling.

The commitment is stated as a constraint rather than as a promised artifact. The
core remains library-shaped with a clean boundary so a genuinely native front
end is possible on any platform. The project does not promise to build three of
them, because no comparable security product sustains three native desktop front
ends.

Sequencing is deliberate. Agent integration is proven out first, because
pointing an existing agent harness at `privr` and having it handle the whole
workflow is both the more distinctive capability and far cheaper to deliver than
a desktop application. A native application is considered only after that works
well, and only if a real need remains that the command line and the terminal
interface do not already meet.

Interactive use is served by a terminal interface compiled into the same signed
binary, once the underlying data model exists to justify it. It is subject to a
permanent constraint: the interactive interface adds no capability that the
non-interactive commands lack. This keeps the human surface and the agent
surface from diverging and bounds the accessibility cost, since a cell grid
cannot be read by a screen reader.

## 15. Result vocabulary distinguishes not-checked from not-applicable

Status: decided.

Established compliance formats distinguish outcomes that the current result
model collapses. "Not applicable to this host", "not selected by this profile",
and "selected but not evaluated" are three different facts. Reporting the third
as the first is the false-pass shape the entire design exists to prevent.

Independent result dimensions are retained and promoted rather than buried:
evaluation outcome stays separate from support, management source, remediation
mode, pending effect, and policy exception. Surveyed tools collapse these, and
this separation is the property most likely to persuade an administrator.

A case the current model could not express: a setting that is observable,
confirmed non-compliant, and not fixable on this platform. The established macOS
baseline names several variants, separating a limitation inherent to the
platform from one that is permanent once set.

This is expressed through the existing dimensions rather than a new outcome
value. The outcome is `drift`, remediation is `none`, and a required
`remediation_reason` from a closed set names why. Adding an outcome would have
encoded two facts in one field, which is the failure this design rule exists to
prevent. The general rule: a new fact becomes a new dimension, never a new
outcome value.

Exemption semantics are fixed by the same reasoning. An exemption may change the
remediation decision and any aggregate presentation. It may never change the
finding. A control that drifts still reports drift when exempted. Exemptions
carry an expiry, which the prior art omits.

Effective state is what is verified, never the presence of an enforcement
mechanism. Checking that a managing profile or policy object exists is not the
same as checking the setting, and treating the two as equivalent fails a
correctly configured unmanaged machine. Where only the enforcement mechanism is
readable, the honest result is `review`, not a pass.

## 16. One diagnostic vocabulary, two renderers

Status: decided.

`privr` has two distinct failure channels. A denied read is not a process error:
it is an `unknown` result on one control while every other control continues to
be evaluated. A malformed invocation is a process error. Both must speak one
vocabulary.

A single diagnostic type carries a stable code, a severity, help text held
separately from the message, and an optional reference. Text and JSON are two
renderers over that one type. Constructing messages independently in each path
guarantees eventual disagreement between them, which for this product is a
category-level failure.

Messages state what happened, why, and what the operator can do next, and they
name the consequence for the result. A denied read says the control is reported
as unknown rather than as passing. A managed setting is reported as skipped with
its management source, and says plainly that forcing does not override it. A
refused rollback names the conflicting item, states the invariant, and confirms
that nothing was changed.

## 17. Evidence standard, and no folklore

Status: decided.

Every published claim about platform behavior cites current primary vendor
documentation. Claims that circulate widely in tweak tooling but have no vendor
source are excluded, regardless of how plausible they are.

Vendor documentation is generally stronger material than the folklore. Published
field lists describe the collected data directly, and quoting a vendor's own
documentation next to its own product language is both more defensible and more
persuasive than characterizing intent. The project does not assert corporate
motive and does not allege third-party arrangements.

Data-sensitivity analysis, where included, is clearly labeled as analysis,
describes what a data class supports inferentially, and does not speculate about
recipients or purposes.

The project also does not imply that hardening confers invisibility. Platform
telemetry can include the configuration state itself and the authority that set
it, so a machine that has been configured for minimal sharing is not thereby
unobserved. This is stated alongside the existing disclaimers about anonymity
and required service traffic.

## 18. Maintenance load is a design constraint

Status: decided.

The pattern in this space is that rigorous projects are either institutionally
funded or abandoned, and the most thorough independent effort in the category
stopped while holding thousands of users. `privr` proposes a higher per-control
cost than any of them.

Two mechanisms address this directly:

- An explicit control budget. Catalogue growth is bounded by what can be
  re-verified, not by what can be discovered.
- Review staleness. Every control carries a last-reviewed date and a
  last-reviewed platform version. When a review goes stale, or the host has moved
  beyond the reviewed range, the control degrades to `unknown` rather than
  continuing to report a result.

Staleness converts the sustainability risk into a property of the honesty model.
An unmaintained control stops claiming to know things.

## 18a. Agent-assisted maintenance, with review as a hard boundary

Status: decided.

Catalogue upkeep is the dominant long-term cost, and it is largely mechanical:
re-reading vendor documentation, noticing that a page changed, noticing that a
new platform release added or removed a setting, and noticing that a cited claim
no longer says what it said. That work is well suited to scheduled agent runs
and poorly suited to sustained human attention.

Scheduled maintenance runs cover:

- Citation re-verification. Every source entry records a URL, the specific claim
  it supports, the date reviewed, and any inference drawn. An agent can fetch the
  source and check whether the claim still holds, which is the single largest
  recurring cost in the project.
- Staleness triage. The staleness mechanism in decision 18 produces a work
  queue. A control that has aged past its reviewed platform range becomes an item
  to re-verify rather than a silent inaccuracy.
- Platform change watch. New operating-system releases, new settings, renamed or
  deprecated policies, and changed edition applicability.
- Landscape watch. New controls appearing in reputable tooling and published
  guidance, as candidates for proper research rather than as content to import.

The boundary is absolute: **agents propose, humans review, nothing merges
automatically.** Output is a pull request carrying sources and a diff. No
scheduled run may commit to the catalogue, change a risk class, change a
reversibility class, alter rationale or warning text, or promote a control's
maturity. Catalogue content steers what an operator approves, so an automated
edit path would defeat informed consent without touching the adapter ceiling,
which is the same reason the catalogue is embedded rather than installed
alongside the binary (decision 10).

This does not conflict with decision 5. That decision governs the shipped
binary, which contains no model client and makes no network call. Maintenance
runs are repository tooling, not a runtime dependency, and nothing they produce
reaches an operator without review.

## 18b. `privr` as a component in agent workflows

Status: planned.

The expected long-term usage is that an operator points an agent harness at
`privr` and it handles the workflow, rather than the operator driving each
command. That shapes priorities: the agent surface is core contract (decision 4),
and a published skill and plugin specification is a deliverable rather than a
nice-to-have.

The separation of concerns holds. `privr` performs deterministic operating-system
verification, remediation, and rollback. Higher-level plugins and skills
coordinate it with adjacent work such as developer tool hygiene and storage
reclamation, without importing that scope into the catalogue (decision 13).

## 19. Distribution and installation

Status: decided.

Installation is a single command, matching the norm set by current developer
CLIs: one PowerShell command on Windows, one shell command on macOS and Linux.
Quality of life here is a goal, not a concession.

Two properties keep that compatible with the trust model:

- The installer is unprivileged. It places a binary and does nothing else. It
  must never request elevation, and it must never change a system setting.
- Disclosure precedes elevation applies to `privr` itself, not to the installer.
  Elevation happens only at apply time, after a plan has been displayed and
  approved section by section.

The distinction matters because the installers criticized in this category are
the ones that elevate immediately and begin changing the system before the
operator has seen anything. That is a different operation from placing a binary.

Supporting requirements:

- The install script is short and readable, served from this repository so that
  the published URL and the reviewable file are visibly the same artifact, and
  linked directly from the README.
- Package manager paths are listed alongside the one-line installer rather than
  buried, since a signed package flow is preferable for operators who want one.
- No binary is published for a platform whose adapters are unimplemented. A
  download that reports nothing useful is worse than no download.
- Until signed release artifacts exist, the README documents building from
  source. An installer that fetches unsigned binaries would undercut the trust
  position it is meant to support.
- Ordering: build from source, then publish the crate, then signed release
  artifacts with the one-line installer and package manager entries.
- Panic behavior must unwind. Aborting skips destructors, which would prevent an
  interrupted apply from flushing its transaction journal.

## 20. Profiles are an ordered ladder, and tradeoffs are a separate axis

Status: decided. Names are provisional.

How far an operator wants to go is a different question from what topic a
control belongs to. Sections are topical (diagnostics, personalization,
location, search). Profiles express depth. A control belongs to exactly one
section and is included at one profile level.

Three ordered profiles, each a strict superset of the one below:

- `baseline`: the default, and the recommended setting. Not a timid floor.
- `strict`: meaningful privacy gains with real, disclosed tradeoffs, such as
  losing cloud clipboard sync or tailored suggestions. Contains controls that
  default to review.
- `restrictive`: substantial convenience or functionality cost. Always review,
  never enforced without per-control acknowledgement.

The default is deliberately the useful setting rather than the cautious one, and
the line that makes it defensible per control is the distinction between
collection and features:

- **Passive continuous collection is off in `baseline`.** Data flows that occur
  whether or not the operator uses anything: diagnostic transmission,
  advertising identifiers, activity history upload, tailored experiences, input
  and typing personalization, background usage reporting. These are not features
  an operator invokes. They run. Turning them off costs essentially nothing and
  is the whole point of the tool.
- **Features an operator may actively want default to review.** Cloud clipboard
  sync, location services, cloud search, peer update delivery, and voice
  services are things someone may use on purpose. `baseline` surfaces them with
  their tradeoff and lets the operator decide, rather than deciding for them.

That rule is what keeps `baseline` both strong and safe: it removes ambient
observation without removing capability. A control is not held back from the
default because it sounds aggressive, only because the operator might actually
be using the thing.

The superset property is what makes moving between levels coherent, and it makes
`check --profile strict` a useful read-only preview of what a deeper level would
flag before anything is committed.

The critical constraint: **the ladder never includes controls that reduce
security.** Escalating privacy must not silently escalate exposure. A control
that weakens malware protection, reputation services, sample submission, update
delivery, encryption, or recovery is not a deeper rung on the same ladder. It
belongs to a separately named opt-in set that must be selected deliberately and
acknowledged on its own terms. The clearest prior art in the surveyed landscape
makes this a named top-level category rather than an implicit consequence of
choosing a stronger setting, and that framing is adopted here.

Two sets sit outside the ladder entirely and are never reached by choosing a
higher profile:

- Security tradeoffs, as above.
- Erasure of local privacy residue, which is irreversible and governed by
  decision 13.

Supporting requirements:

- Profile membership derives from a control's declared risk, breakage, and
  reversibility metadata rather than being assigned by hand. Otherwise a
  `baseline` profile silently accumulates breaking controls over time.
- Each profile's disclosure warns at the level of its highest-risk member.
- Tradeoff text appears at the decision point, not only in reference
  documentation. An operator approving a section should see the one-line cost of
  each control there.
- Built-in profiles are generated data, validated at build time, and carry the
  same digest treatment as the rest of the catalogue.
- The existing `privacy-first` name maps onto this ladder rather than sitting
  beside it.

## 21. Tradeoffs carry mitigations, and follow-ups are declared, not performed

Status: decided.

A tradeoff stated without a remedy is less useful than it looks. Turning off
location services is the right recommendation for most operators, and the cost
is concrete: the built-in weather experience stops resolving a location on its
own. The useful form of that finding names the cost and the workaround
together, so the operator is choosing between "lose weather" and "set your city
manually once", not between privacy and an unspecified breakage.

Every control that declares a functional cost should, where one exists, declare
the mitigation alongside it. This is a `review` control's most important field,
because review exists precisely to hand the operator a decision, and a decision
without the workaround is worse informed than it needs to be.

Separately, some genuinely useful follow-up work sits outside what `privr` will
ever do. Configuring a city in a weather application is an application
preference, not a documented operating-system privacy control, and it has no
adapter, no verification method, and no rollback. `privr` must not grow a
shadow catalogue of unverified application tweaks in pursuit of a nicer
narrative.

The resolution is that `privr` declares such follow-ups without performing them.
A mitigation is machine-readable metadata attached to a control, so an agent
driving the tool can carry the workflow further than the tool itself will,
which is exactly the division of labor in decisions 6 and 18b. The operator gets
the complete picture; the catalogue stays bounded.

Constraints that keep this from becoming scope creep:

- A mitigation never affects a result. The finding for a control is determined
  by effective state alone. Mitigation text is advisory and is never evaluated.
- A mitigation has no adapter binding. If `privr` could perform it as a typed,
  verifiable, reversible operation, it would be a control instead.
- A mitigation may only address a consequence the control itself causes. It
  cannot be a general recommendation attached to a loosely related control.
- Mitigations are cited to vendor documentation on the same standard as every
  other claim, or they are marked as unverified guidance.
- Anything an agent does in response is the agent's action, performed with its
  own permissions and its own confirmation, and is not recorded in a `privr`
  transaction journal. `privr` did not do it and must not imply that it can
  reverse it.

## 21a. The user is a person on their own machine

Status: decided.

`privr` is for individuals and power users on machines they own and administer.
Developers, security-minded people, anyone running sensitive work or local
models on their own hardware.

It is not a device-management product and does not compete with one. No fleet
console, no remote administration, no compliance attestation, no enrollment.
Those are a different product with a different buyer, and building toward them
would distort every decision in this document.

Consequences that follow, and that resolve real design questions:

- **The default host is unmanaged.** Host-level management detection is
  therefore not load-bearing, which is why reporting it as unknown costs almost
  nothing. What matters is per-control: whether this specific setting is governed
  by an authority, observed directly rather than inferred about the host.
- **Managed hosts are supported by being honest about them, not by managing
  them.** Where an external authority governs a value, `privr` reports whether
  its effective value passes or drifts and stops there. It does not reapply, does
  not fight, and does not pretend a policy fight is remediation.
- **Some controls serve both contexts,** because the underlying setting is the
  same one either way. That is a happy accident of the catalogue, not a product
  direction, and it never justifies fleet features.
- **Output is designed for one machine and one person.** No aggregation across
  hosts, no scoring for comparison, no dashboard.

This makes one platform limitation more painful and it should be stated rather
than hidden: unmanaged macOS is largely a guided-review product, and unmanaged is
exactly the target. Managed Macs are where verification is genuinely possible,
and those are the hosts this product is least aimed at. The honest framing is
that macOS coverage will be thinner than Windows coverage for the intended user,
for reasons outside this project's control.

## 22. Control maturity is per control, and risk metadata is enforced

Status: decided.

Whether a control can be remediated is a property of that control, not of its
platform. Linux ships audit-first, but as the aggregate consequence of
per-control maturity rather than as a platform-wide rule, with a named
allowlist of machine-scope settings that have documented defaults and trivial
preimages promoted to remediation first. That keeps the door open for a control
to be promoted on evidence instead of on a platform-wide decision.

Catalogue maturity is recorded separately from the scan result. Whether a
control is automatable, partially automatable, or manual is a fact about the
control; whether this host passes is a fact about the host. Collapsing them
loses the ability to say "this is a manual check and you have not done it."

Risk, breakage, and disruption metadata are enforced by the engine, not
advisory. The most mature comparable project has carried disruption and
complexity fields described as informative only for a decade, and they never
became load-bearing. Metadata that nothing checks decays. Here, risk class
determines section eligibility, profile membership, and whether blanket
confirmation is accepted, so it cannot rot without failing a test.

An aggregate must never improve because visibility decreased. A surveyed tool's
hardening index rises when it can see less, which is the scoring form of a false
pass. Any per-section summary excludes controls that could not be evaluated
rather than counting them.

## 23. Verification strategy

Status: decided.

The evaluation engine is a pure function from catalogue, policy, host facts, and
observations to a report. Fixtures are values of the same observation type the
real probe produces, so there is no separate fake at that layer and no
opportunity for a fake to drift from reality.

Divergence risk moves to the probe layer and is handled by capture and replay
rather than hand-written mocks. A recording wrapper captures real probe output,
and a differential test replays recordings on every supported operating system
asserting byte-identical reports.

Structural choices:

- Closed-enum dispatch for host context and probes rather than trait objects.
  No mature Rust project of this kind abstracts the platform behind a vtable,
  and enum dispatch keeps exhaustiveness checking.
- `cfg` appears only inside adapter bodies, never in the engine.
- The operation set is a closed enum, which makes the inverse operation and the
  preview renderer compile errors when a variant is added. Rollback completeness
  becomes a compile-time property rather than a review checklist item.
- A documented read-only root-redirection capability, refused by every mutation
  path, gives full-pipeline determinism on any runner.

Fixtures are one file per state carrying provenance, host facts including an
injected clock, observations recorded as exact type plus raw bytes rather than
decoded values, and hand-written expectations. Snapshots capture rendering;
expectations capture intent, so rubber-stamping a snapshot still fails the
assertion. Capture happens downstream of the probe's reduction, so a fixture
cannot physically contain a tenant or enrollment identifier. Redaction
substitutes canaries rather than deleting, which turns the privacy promises into
positive tests.

Network isolation is enforced in four layers rather than asserted. A dependency
denylist is insufficient because the standard library needs no crate to open a
socket. The mechanism is dependency allowlisting with target filtering
deliberately left unset so platform-specific dependencies cannot hide from a
single-platform job, a lint forbidding the standard networking types, a golden
import-table assertion on library names rather than symbol names because the
relevant Windows symbols import by ordinal, and runtime proof under network
namespaces, sandboxes, scoped firewall rules, and adapterless virtual machines.

Staleness is a pure function of an injected clock, so the deterministic portion
runs on every change and the time-dependent portion runs on a schedule and as a
release gate, never on the per-change path.

The 80 percent line coverage floor is the wrong bar and currently produces false
confidence: it counts test bodies, it runs on one operating system so
platform-gated code is absent rather than missed, and a line that returns a pass
where it should return unknown is fully covered and wrong. Coverage moves to
merged region coverage across all three operating systems with a ratchet, and
the metrics that actually track confidence are mutation testing, fixture
completeness per control, and false-pass guard completeness.

## 24. No monetization

Status: decided.

No paid tier, no hosted service, no bundled offers, no product telemetry. The
reputational fault line in this category is the business model, and every new
entrant inherits that suspicion. Stating the position explicitly is cheap and
addresses the assumption directly.
