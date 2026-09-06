# Maintenance policy

## Why this document exists

The failure mode for a project like this is not a bug. It is abandonment.

Every rigorous effort in this space is either institutionally funded or dead.
The most thorough independent project of its kind carried thousands of users,
cited primary sources throughout, supported reversion, and stopped anyway. Its
issue asking whether the project is still alive has gone unanswered for months.

`privr` proposes a higher per-control cost than any of them: cited sources with
recorded review dates, edition and build applicability, fixtures across six
states, and verified rollback. Nothing about good intentions makes that
sustainable. The mechanisms below are what make it survivable, and they are
designed so that falling behind degrades honesty gracefully rather than silently.

## The control budget

Catalogue growth is bounded by what can be re-verified, not by what can be
discovered.

A control is not added because it exists, because a tweak list mentions it, or
because it would make a comparison table look better. It is added when there is
capacity to keep verifying it.

When the budget is full, adding a control requires retiring one or expanding
capacity. This is stated publicly so that a rejected contribution is a policy
outcome and not a judgment about the contributor.

## Review staleness

Every control records a last-reviewed date and the platform versions it was last
verified against.

When a review goes stale, or the host has moved beyond the reviewed range,
support degrades automatically:

- support becomes `unverified` or `unsupported`;
- the control can no longer report `pass`;
- remediation is forced to `audit_only`.

The control stays visible and explains why it is degraded. It stops claiming to
know things.

This converts the sustainability risk into a property of the honesty model. A
neglected catalogue produces an increasingly cautious tool rather than an
increasingly wrong one, which is the correct direction to fail in.

Staleness is evaluated as a pure function of an injected clock. The
deterministic portion runs on every change; the time-dependent portion runs on a
schedule and as a release gate, never on the per-change path, so a pull request
does not fail because the calendar advanced.

## Deprecation

A control is deprecated rather than deleted when its mechanism disappears.

The changelog names the retired control ID explicitly, because stored transaction
journals reference control IDs and must remain decodable. A superseded control
names its successor.

Retiring a control never breaks the ability to roll back a transaction that used
it.

## Agent-assisted maintenance

Most of the recurring work is mechanical: re-reading vendor documentation,
noticing a page changed, noticing a release added or removed a setting, noticing
that a cited claim no longer says what it said. That suits scheduled agent runs
and does not suit sustained human attention.

Scheduled runs cover:

- **Citation re-verification.** Every source entry records a URL, the specific
  claim it supports, the date reviewed, and any inference drawn. Checking whether
  the source still supports the claim is the single largest recurring cost, and
  it is automatable.
- **Staleness triage.** The staleness mechanism produces a work queue rather than
  a silent inaccuracy.
- **Platform change watch.** New releases, new settings, renamed or deprecated
  policies, changed edition applicability.
- **Landscape watch.** Controls appearing in reputable tooling and published
  guidance, as candidates for proper research rather than content to import.

### The boundary

**Agents propose. Humans review. Nothing merges automatically.**

Output is a pull request carrying sources and a diff. No scheduled run may:

- commit to the catalogue;
- change a risk class or a reversibility class;
- alter rationale, tradeoff, mitigation, or warning text;
- promote a control's maturity or support state.

Catalogue content steers what an operator approves. An automated edit path would
defeat informed consent without ever touching the compiled adapter ceiling, which
is the same reason the catalogue is embedded in the signed binary rather than
installed beside it.

This does not conflict with the rule that `privr` never calls a language model.
That rule governs the shipped binary, which contains no model client and makes no
network call. Maintenance tooling lives in the repository, and nothing it
produces reaches an operator without review.

## Contribution priorities

In descending order of value:

1. Evidence: primary vendor sources, with the exact claim each supports.
2. Correctness: effective-state logic, precedence resolution, applicability.
3. Fixtures: captured and redacted states, especially denied, malformed,
   managed, and unsupported.
4. Failure tests: false-pass guards, and rollback conflict cases.
5. New controls, last, and only within budget.

A setting does not become supported because it appears in a tweak script, a
forum post, or an undocumented preference store. See
[CONTROL_STANDARD.md](CONTROL_STANDARD.md).

## Ownership

Each supported platform needs a named owner before its controls can be promoted
beyond audit-only. New elevated operation types require two reviews.

A platform without an owner ships audit-first and says so, rather than shipping
remediation nobody can maintain.
