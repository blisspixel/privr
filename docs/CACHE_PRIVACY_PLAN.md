# Privacy cache capability plan

Status: proposed, researched 2026-10-06. This plan adds no runtime capability.
Implemented behavior and release blockers remain in
[the roadmap Current state](../ROADMAP.md#current-state).

Build selective residue inspection, documented clearing, and retention guidance.
Prioritize data that reveals activity or contains private content. Keep disk
space estimates separate from privacy findings, and pair each clearing action
with an explanation of what will recreate the data.

The planned purge defaults to thorough clearing of supported disposable caches
and temporary files. Aggressive describes completeness within that safe scope.
Both modes preserve login state, ordinary history, and persistent site data
unless separately selected and approved. OS operation and recovery remain
protected. `--polite` additionally retains caches whose rebuilding would disrupt
convenience or application workflows. An unconfirmed call
previews the plan, while named approval authorizes its execution.

## What cleanup tools offer

CCleaner has a free edition with browser privacy cleaning and temporary-file
cleanup. Its documentation distinguishes those functions from Professional
features, so a paid cleaner is not a prerequisite for this work.
Source: [CCleaner Health Check](https://support.ccleaner.com/articles/en_US/Master_Article/what-is-health-check).

Custom Clean offers analysis before execution, application and category
selection, and counts and sizes in results. These are useful interaction
patterns for a deterministic residue preview.
Source: [CCleaner analysis and results](https://support.ccleaner.com/articles/en_US/Master_Article/custom-clean-s-analysis-and-results-function).

Cookie exceptions preserve selected sites rather than clearing every login.
Support user-selected exceptions and show their retained exposure explicitly.
The default cleanup preserves cookies. If the user separately selects cookie
clearing, honor only explicit exceptions and disclose sign-outs. A cookie count
alone cannot establish which cookies track the user or which are necessary for
a workflow.
Source: [CCleaner cookie selection](https://support.ccleaner.com/articles/en_US/Master_Article/select-cookies-to-clean-with-ccleaner-for-windows).

BleachBit is a free, open-source cleaner with per-application options, preview,
and a command-line interface. Its cleaner contribution guidance requires
accurate category descriptions and checking options individually. Use those
ideas for target isolation and fixtures.
Sources: [BleachBit documentation](https://docs.bleachbit.org/index.html),
[CLI](https://docs.bleachbit.org/doc/command-line-interface/), and
[cleaner contribution guidance](https://docs.bleachbit.org/cml/contributing/).

Implement adapters independently from primary platform documentation. Do not
bundle a cleaner, invoke saved cleaner presets, or import executable cleaning
rules. CCleaner's `/AUTO` uses saved Custom Clean options; that does not bind
execution to a fresh privr plan. A third-party cleaner documenting its own file
deletion is also insufficient evidence of a documented platform erasure API.
Source: [CCleaner command-line parameters](https://support.ccleaner.com/articles/en_US/Master_Article/command-line-parameters-for-ccleaner-for-windows).

## Candidate priorities

These are research priorities, not supported controls. Each candidate still
needs the full [control standard](CONTROL_STANDARD.md), version constraints,
management handling, an authoritative observation, and recorded fixtures.

| Candidate | Privacy relevance | Proposed first delivery | Consequence and boundary |
|---|---|---|---|
| Browser HTTP cache | Copies of page text, images, and resources | Guided cache-only clearing for Edge, Chrome, and Firefox, then metadata preview where reliable | Pages reload resources; do not include cookies, history, or site storage implicitly |
| Disposable temporary files | Temporary copies can retain document or application content | Guided vendor cleanup categories first, then isolated typed operations where verified | Respect vendor eligibility and in-use rules; preserve autosave, recovery data, active work, and durable files |
| Browser cookies and site storage | Session state, identifiers, preferences, and locally stored web-app data | Separate guided review with site exceptions where the browser supports them | Can sign users out and remove offline application data or unsynced work; a site exception retains exposure |
| Browser and download history | Visited addresses and download records | Separate guided review after resolving sync scope | Address suggestions are lost; download history is distinct from downloaded files; exclude cloud deletion |
| Windows thumbnail cache | Visual previews of documents and media | Guided selection of Thumbnails in Disk Cleanup; research a narrowly scoped adapter for 0.5.0 | Previews regenerate; retain creative-workload exceptions; verify the existing prevention control independently |
| Ordinary recent-file lists | Records of opened documents and locations | Research documented application or desktop clear interfaces and retention choices | May lose useful recent items or pinned entries; exclude ShellBags and private databases |
| PowerShell command recall | Commands can retain sensitive arguments | Continue the existing session-only history proposal | Cross-session recall is lost; existing-history erasure stays excluded pending the existing scope review |
| Application and local model caches | May contain document extracts or retained prompts, depending on the application | Later research of a small named application set using vendor retention and reset interfaces | Separate rebuildable indexes from conversations, model weights, downloaded assets, projects, and unsynced documents |

Google documents separate cache, cookies/site data, history, download history,
autofill, and site permissions. It also warns that deleting account-backed data
can remove it from other devices and the account. Microsoft explicitly tells
users to turn off Edge sync before clearing only the current device. Automated
local clearing must therefore establish scope; unknown sync or remote effects
block execution for affected categories. Guidance must disclose the same
condition without signing the user out or unlinking an account automatically.
Sources: [Chrome data categories and sync](https://support.google.com/chrome/answer/2392709?co=GENIE.Platform%3DDesktop&hl=en),
[Edge data categories and sync](https://support.microsoft.com/en-us/edge/view-and-delete-browser-history-in-microsoft-edge).

Firefox documents clearing only temporary cached files and pages, including a
cache-only choice at browser close. That is a useful prevention candidate,
initially guided. Cookie and site-data clearing has its own documented flow.
Configuration rollback can restore a setting, but cannot recover data already
cleared while the setting was enabled. Browser-close behavior needs separate
verification, including abnormal exit and background processes.
Sources: [Firefox cache clearing](https://support.mozilla.org/en-US/kb/how-clear-firefox-cache),
[Firefox cookies and site data](https://support.mozilla.org/en-US/kb/clear-cookies-and-site-data-firefox).

Windows already offers a Thumbnails category in Disk Cleanup. This supports
guidance, not a claim that `cleanmgr` exposes a standalone thumbnail-cache
parameter. `/sagerun` consumes a stored selection and enumerates all drives;
`/sageset` changes persistent settings. Neither is a read-only preview or an
acceptable way to execute an unverified saved selection.
Sources: [Windows Disk Cleanup categories](https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/free-up-drive-space-in-windows),
[cleanmgr command contract](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cleanmgr).

Include documented disposable temporary-file categories in purge research,
initially guided through Windows Storage settings or Disk Cleanup. A temporary
directory or filename is not enough to establish disposability. Microsoft
documents an age condition for its Temporary Files category; aggressive mode
must retain vendor eligibility conditions rather than delete every file in a
temporary directory. Autosave, recovery, active work, and installer or update
rollback data are separate categories and remain protected.
Source: [Disk Cleanup temporary-file eligibility](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cleanmgr).

Storage Sense can also delete Recycle Bin or Downloads items and make cloud
files online-only, depending on configuration. Those effects require their own
review and cannot be packaged as a privacy cache fix.
Source: [Storage Sense behavior](https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/manage-drive-space-with-storage-sense).

For Linux thumbnail research, respect the XDG cache directory rather than
assuming `~/.cache`. The thumbnail standard documents storage layout; it does
not by itself establish a supported clearing service. macOS Quick Look needs a
version-reviewed clearing reference and native fixtures before automation.
Source: [FreeDesktop thumbnail directory specification](https://specifications.freedesktop.org/thumbnail/latest/directory.html).

## Product and execution contract

### Aggressive and polite clearing

Aggressive is the default clearing mode for reviewed disposable caches and
temporary files. With no control filter, preview those categories for the current
user and supported local application profiles. Cookies, persistent site data,
history, and recent-file lists are separate opt-in targets and are never added
by mode selection. A control filter narrows default selection or explicitly
selects one of those reviewed optional targets. Each category remains separately
visible and requires its own named acknowledgement before execution. Unsupported
and blocked targets remain visible with their reasons.

| Category | Aggressive default | Polite option |
|---|---|---|
| Browser HTTP cache | Clear the selected disposable category through the documented mechanism | Clear the selected disposable category through the documented mechanism |
| Supported thumbnail and application caches | Clear only reviewed rebuildable caches with proven isolation | Retain caches classified as costly or disruptive to rebuild |
| Supported disposable temporary files | Clear all vendor-eligible files in the selected category | Clear vendor-eligible disposable files with the same active-work and recovery protections |
| Cookies and login-related site state | Preserve unless separately selected and approved | Preserve unless separately selected and approved |
| Persistent site storage and offline web-app data | Preserve unless separately selected and approved with its data-loss warning | Preserve unless separately selected and approved with its data-loss warning |
| Browser and download history | Preserve unless separately selected and approved | Preserve unless separately selected and approved |
| Ordinary recent-file lists | Preserve unless separately selected and approved | Preserve unless separately selected and approved |
| Explicit user exceptions | Honor them and report retained categories or scope | Honor them and report retained categories or scope |

Aggressive mode applies no extra recency cutoff to disposable caches. Vendor age
limits, in-use protections, and eligibility conditions apply in both modes.
Neither mode can exceed the selected target's documented scope. If the vendor
provides only a narrower clear operation, show that limit. Polite retention uses
reviewed per-target workflow/friction metadata; unavailable classification keeps
the target guided or unselected. Report retained residue instead of claiming
that all activity records were cleared.

Both modes preserve passwords, passkeys, bookmarks, downloaded files, projects,
and other durable user content. Exclude OS components, registry cleanup,
installer state, update rollback files, restore points, package databases,
application settings, autosave, and recovery data from ordinary purge. An
application cache containing unsynced user data is not disposable. Do not
stop services, kill applications, or bypass locks to make cleanup succeed.
If a vendor action mixes disposable caches with protected data and cannot
isolate them, keep it guided or unsupported. Pinned entries require a clear
mechanism that preserves them or a separately reviewed target naming their loss.
Both modes retain the exclusions and execution safeguards below. They do not
widen scope to other users, cloud data, security logs, or undocumented storage.

Keep reversible posture configuration in the existing check, plan, apply, and
rollback workflow. Pair it with residue observations without inferring that
disabling future retention removed existing data. Workflow-altering retention
choices require review and the existing friction metadata.

Use the already specified separate verb for deliberate clearing. The following
syntax is planned in [CLI.md](CLI.md#purge), not implemented:

```text
privr purge
privr purge --polite
privr purge --preview --control <id>
privr purge --control <id> --accept-risk <id>
privr purge --polite --control <id> --accept-risk <id>
```

The first two forms preview aggressive and polite selection respectively.
`--preview` always forbids mutation, even when acknowledgement flags are supplied.
`--control` and `--accept-risk` are repeatable for individually named targets.
Exact selection and named acknowledgement can opt into a reviewed category
omitted by the selected mode; its tradeoffs still appear in the plan. Unknown
control IDs and mismatched acknowledgements are usage errors, never a reason to
broaden selection. No blanket cookie, history, or site-storage selection follows
from an aggressive default.

Preserve existing control IDs, including `windows.storage.thumbnail-cache`.
Review any new target IDs before catalogue inclusion. Avoid a second positional
target syntax or an unrelated generic `clean` command.

A preview should show aggressive or polite mode, selected and retained categories,
the target category, bounded scope, supported versions,
presence or uncertainty, aggregate size or unavailable estimate, retention
behavior, prerequisite application state, documented clear mechanism, risk,
and verification limits. Display human-readable tradeoffs next to the action.
Identify applications and profiles using temporary local labels rather than
account names or personalized paths. Discovery must cover multiple profiles
and distinguish inaccessible or unsupported profiles from empty ones.

Metadata inspection must not open an application to measure it or read browsing
history, cookie values, thumbnail images, document contents, or prompts into
evidence. Bound enumeration, do not hydrate online files, and reject scope that
escapes the reviewed local storage root. A denied, partial, missing, locked,
malformed, or unfamiliar layout is not proof of compliance. A cache directory
that is absent establishes only absence at that location and observation time.

Execution must:

1. Recompute scope and prerequisites immediately before acting. Reject changed
   application versions, stale plans, external management, and unknown remote
   effects. Never terminate an application or discard unsaved work silently.
2. Dispatch a compiled, typed vendor operation with fixed arguments and verified
   executable resolution where a process is required. No caller-supplied paths,
   shell code, broad wildcards, or inherited cleaner presets.
3. Require named destructive acknowledgement independently of `--yes` and any
   ordinary apply approval. Do not add purge to agent mutation discovery until
   equivalent approval and scope protections are proven.
4. Durably journal intent before erasure and stop if the journal cannot be
   secured or written. Store IDs, operation states, aggregate results, and the
   mode and reason rollback is unavailable. Do not copy erased contents, record
   file inventories, or stage them in a second sensitive cache.
5. Re-read authoritative state after the action. A successful process exit or
   reduced byte count alone cannot prove clearing. Distinguish completion,
   partial change, unverifiable state, and regeneration using the shared
   diagnostic vocabulary and a versioned result contract.
6. Stop on conflict or failed verification. Recovery after interruption reports
   uncertainty and re-observes; it must not silently replay an irreversible
   operation.

Report only the reviewed local category and observation time. Do not claim
secure erasure, removal from backups or snapshots, deletion from memory or
cloud services, or lasting absence while an application can regenerate data.
Cache presence does not prove vendor transmission, and clearing does not prove
that an application stops sharing. Keep footprint and clearing results separate
from existing posture scores so freed bytes cannot improve a privacy score.

In this CLI, purge means verified removal of selected unwanted local residue.
It does not claim the media-sanitization meaning of purge defined by NIST.
Deleting files or overwriting their currently addressable blocks cannot by
itself establish sanitization on flash storage, whose physical copies may be
outside those addresses. Record the documented mechanism and observed removal;
never label a result securely erased without an independently proven guarantee.
Device sanitization and cryptographic erasure are separate destructive workflows
outside routine cache cleanup.
Source: [NIST media sanitization guidance](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf).

## Implementation sequence

Milestone order remains unchanged. Research and guidance can proceed while
release prerequisites are completed; automated clearing stays in 0.5.0.

### Target admission criteria

A target can enter automatic default selection only when all of these are
proven for its reviewed platform and application range:

1. The vendor identifies the category as disposable or rebuildable. A path,
   extension, size, age, or successful past deletion is insufficient by itself.
2. Discovery resolves only the current user's intended local scope through a
   typed Context observation. Unknown locations, links, inaccessible profiles,
   and storage layout changes remain visible and block affected execution.
3. The documented operation isolates the category from settings, documents,
   credentials, unsynced app data, OS components, and recovery material. A broad
   cleanup preset does not qualify.
4. The adapter establishes prerequisites and handles in-use data without
   terminating processes, stopping services, or weakening permissions.
5. A separate authoritative observation can distinguish successful clearing,
   retained entries, regeneration, and unavailable verification. Empty state
   proves only the reviewed scope at that observation time.
6. Native disposable VM evidence shows preserved unrelated data, idempotent
   repeat execution, conflict handling, interruption behavior, no network
   requirement, and a truthful irreversible journal record.

Document the decision under the control standard with supported versions,
source claims, scope, risk, verification limits, default selection eligibility,
polite selection eligibility, and fixture provenance. Keep targets guided,
audit-only, or excluded until their own evidence satisfies admission; a
successful adapter for another application or build is not transferable proof.

### Milestone deliverables

| Stage | Work | Completion evidence |
|---|---|---|
| Documentation and research | Reconcile residue candidates with decision 13, the CLI contract, and roadmap exclusions; review existing thumbnail prevention evidence; prepare browser guidance | Sources support each precise claim; unsupported operations are marked audit-only or excluded |
| 0.1.0 evidence foundations | Finish existing fixtures, version staleness, and false-pass guards; design metadata observations through Context | Recorded evidence covers empty, denied, locked, unfamiliar, partial, and multiple-profile cases; preview causes no mutation or network traffic |
| 0.2.0 transaction foundations | Finish section approval, fixed restricted journals, helper isolation, and crash recovery; continue guided PowerShell prevention | Required release checks and disposable VM proofs pass; configuration rollback and irreversible effects are represented honestly |
| 0.3.0 and 0.4.0 platform foundations | Validate macOS and named Linux environments before extending residue adapters | Native fixtures and effective-state proofs on each supported platform; no universal cache-directory deletion |
| 0.5.0 residue preview | Add the planned purge verb with aggressive default selection, a polite option, read-only preview first, and guided targets where automation is unavailable | Stable text and JSON, selected and retained categories, scope checks, redaction, named consent, and honest verification limits |
| 0.5.0 first automated target | Research Windows thumbnails first; ship only if an isolated documented mechanism and authoritative post-check are proven | VM evidence of target isolation, interruption handling, locked/regenerated state, and preservation of unrelated data; otherwise remain guided |
| Later target expansion | Add browser automation only after a stable local interface, profile boundaries, and sync safeguards are proven | Cache-only operation demonstrably preserves unrelated categories; named consent, false-pass guards, and offline execution pass |

### Required failure evidence

| Scenario | Required behavior |
|---|---|
| Unknown build, layout, management, or local scope | No affected mutation; uncertainty remains visible |
| Linked or replaced root, profile, or target | Reject the changed scope; do not follow it into unrelated data |
| Locked data or a background writer | Respect the lock or defer the target; no forced close; report retained or regenerated state |
| Journal denied, unavailable, or full | Stop before mutation |
| Vendor error, partial completion, or failed verification | Stop remaining targets, record observed partial state, and report failure honestly |
| Cancellation before mutation | No target data change |
| Cancellation or interruption after mutation starts | Complete the bounded current operation if safe, then stop; uncertain results remain unverified and are not silently replayed |
| Attempted rollback | State that erased data cannot be restored; never fabricate a preimage |
| Polite mode or explicit exception | Retained categories remain intact and appear in the result |
| Privacy canaries in synthetic data | Neither text nor JSON, errors, journals, or progress output exposes the canaries |

Fixtures must also cover reparse points and symbolic links, replaced storage
roots, app restarts between preview and execution, background writers, managed
settings, unknown sync scope, disk-full or denied journal writes, partial vendor
failure, interruption, and attempted rollback of an irreversible action. Native
VM tests must prove that unrelated categories and profiles remain intact.
Test that aggressive default selection includes only reviewed disposable caches
and temp files, both modes preserve cookies/history/site data unless separately
selected, polite retains disruptive caches, and protected OS/recovery data is
untouched. Cover full-range eligible clearing, explicit exceptions, and refusal
to execute without each target's consent.
Neither mode may turn denied or unsupported evidence into an empty-cache pass.

### Performance and user experience

There is no measured purge duration yet. Duration estimates remain unvalidated
and must not become product claims. The provisional design
goal is a routine supported cache/temp pass within one minute on a documented
reference SSD desktop; publish measurements before adopting a release promise.
Slow or large targets must remain understandable while running.

Measure discovery, preview, vendor execution, and independent verification
separately. Use a monotonic timer and local aggregate timings; collect no product
telemetry. Report elapsed time by category and use indeterminate progress when
the vendor supplies no reliable completion count. Do not manufacture a percent
complete or an exact finish time from byte estimates.

Benchmark synthetic small, medium, and large workloads, including 1,000,
10,000, and 100,000 entries where the reviewed mechanism supports them. Include
many small files, larger files, warm and cold filesystem caches, locked entries,
and immediate regeneration. Record hardware, storage, OS/application versions,
sample count, median and tail latency, and scope coverage without personal data.
Measure polite and default modes independently and repeat after adapter changes.

Bound enumeration, prerequisite checks, and child-process waiting. Set timeout
behavior per vendor operation after reviewing its cancellation semantics. A
timeout while mutation may still be running is uncertain state, not successful
cleanup or restored data. Stop further operations and require reconciliation;
never restart or kill the operation blindly. Cancellation is cooperative at
safe boundaries, with the journal preserving any already-started operation.

Separate logical bytes inspected or removed from actual disk space reclaimed.
Compression, shared storage, and concurrent writers can make them differ. Report
space reclamation as an estimate or unavailable unless the adapter can measure
and attribute it. Do not retain file inventories to obtain a more precise count.

Extend shared host, evidence, applicability, and outcome types under `src/model/`.
Keep eligibility evaluation pure under `src/engine/`; implement typed discovery,
observations, and vendor operations under `src/platform/` through Context.
Bind reviewed metadata in `src/catalog/`, reuse `src/journal.rs`, and render
through the existing app and report layers. Follow the existing workspace split
prerequisite for privileged operations; add no resident service or async runtime.

Create small reviewable changes in this order: documentation reconciliation,
target research and fixtures, read-only observations, purge preview, then one
proven vendor operation. Complete existing release blockers before promoting
new capabilities. Each behavior change needs the required lint, native tests,
cross-target Clippy, MSRV, dependency checks, at least 80 percent line coverage,
and all platform CI jobs.

## Exclusions and unresolved scope

Keep registry cleaning, disk optimization, free-space wiping, generic file
shredding, update-cache removal, Downloads deletion, security-log clearing,
ShellBags, SRUM, quarantine/provenance databases, crash-dump erasure, and cloud
deletion outside this plan. DNS-cache flushing is a low-priority transient-state
operation, not a substitute for stored-activity cleanup. Disk encryption and
application access controls remain necessary for local exposure.

Existing shell-history erasure and assistant-session cleanup require a separate
scope review and exact vendor documentation. Do not implement them as age-based
file deletion. Pagefile configuration and TRIM configuration are separate
posture/storage behaviors, not cache-purge operations or secure-erasure proofs.

The useful first increment is accurate browser cache guidance, reviewed
thumbnail-cache handling, and retention recommendations, followed by an honest
read-only residue preview. Broader automation depends on proving the mechanism,
scope, and result for each target.
