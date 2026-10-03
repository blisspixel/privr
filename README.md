# privr

Privacy settings you can verify.

`privr` is a local-first privacy posture CLI. It reads which optional
data-sharing settings are actually in effect, explains the evidence and the
tradeoffs, applies a policy in reviewable steps, and can reverse what it
changed.

It is built for individuals and power users on machines they own: developers,
security-minded people, anyone running sensitive work or local models on their
own hardware. It is not a device-management product and does not compete with
one.

Every command produces stable text and versioned JSON, works offline, and is
designed to be driven by an agent harness as readily as by a person.

## Status

- **Windows `check`, `explain`, `list`, `doctor`, `recommend`, `simulate`, `plan`, `apply`, and `rollback` work**, with 28 controls across five posture dimensions, verified rollback journaling, and adaptive elevation handling.
- **Defensive and adaptive application**: `plan` and `apply` accept `--workload` (`general`, `developer`, `creative`, `mobile`, `high-assurance`) and `--max-friction`. When run unprivileged, batch operations apply eligible user-scope controls and report deferred machine-scope controls without failure.
- **Linux (13 controls) and macOS (6 controls) `check` are experimental** with typed elevation metadata, tested in CI across multiple platforms.
- **Agent integration (`privr mcp`) is implemented**, providing a stdio Model Context Protocol (MCP) server exposing `privr_check`, `privr_plan`, `privr_apply`, `privr_recommend`, `privr_simulate`, `privr_explain`, and `privr_doctor` with Agent Plugins v1.0.0 packaging.

The full state, including known defects, is in
[ROADMAP.md](ROADMAP.md#current-state).

![privr check on Windows 11 showing 28 controls](docs/assets/check-windows.svg)
![privr doctor on Windows 11 showing capability facts and storage integrity](docs/assets/doctor-windows.svg)


On the machine this was developed on, one control found something real:

```text
diagnostics
  pass      Diagnostic data level
            windows.diagnostics.level
            A level of 0 is configured, but this Windows edition does not honor it.
            Microsoft documents value 0 as applying only to Enterprise, Education,
            and Server, and as equivalent to 1 elsewhere. This machine sends
            required diagnostic data.
```

Something had set `AllowTelemetry = 0` on a Windows Professional machine. Every
tool that checks that value reports telemetry as disabled. It is not.

What is designed but not built: profiles that select different controls,
sectioned approval, fixture files, and signed releases.

## Where it is going

`plan` exists today only as a flat list. This is the intended shape: changes
grouped into sections you approve one at a time, every tradeoff paired with a
way to keep the capability, and a plan that changes nothing.

![privr plan, showing changes grouped into sections, a tradeoff paired with a mitigation, and confirmation that nothing has been changed](docs/assets/plan-linux.svg)

The image is a mockup of unimplemented behaviour, unlike the output above it.

## Why this exists

Consider a setting that many Windows privacy tools change.

`AllowTelemetry = 0` is documented by Microsoft as applying only to Enterprise,
Education, and Server editions. On Home and Pro, Microsoft states that using it
is "equivalent to setting the value of 1"
([Policy CSP - System](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system)).

So on the most common editions of Windows the write succeeds, the value reads
back as `0`, every tool that checks it reports success, and the effective
behavior is unchanged. The machine audits as hardened and is not.

That is not an unusual case. Several widely applied policy values are silently
inert outside Enterprise and Education, and comparable traps exist on the other
platforms: a macOS preference read without the right permission can return a
value from a stale file rather than failing, and a Fedora setting written in the
main configuration file is overridden per repository.

`privr` exists to answer four questions without guessing:

1. What is this machine configured to share?
2. Which settings differ from the policy I selected?
3. What does each choice cost me in privacy, security, and functionality?
4. Can a change be applied and reversed without surprises?

The goal is not the longest list of tweaks. It is a smaller catalogue that is
cited, version-aware, and honest about what it does not know.

## Install

Building from source is currently the only path. Rust 1.95 or later:

```bash
git clone https://github.com/blisspixel/privr
cd privr
cargo build --locked --release
```

One-line installers and package manager entries ship with the first signed
release. The installer will place an unprivileged binary and nothing else;
`privr` requests elevation only at apply time, after showing you the plan.

## Workflow

```text
check -> explain -> recommend -> simulate -> plan -> apply -> verify -> rollback
```

This is the canonical workflow. On Windows, all commands in the lifecycle are implemented,
tested, and verified against real hosts:

```text
privr check
privr explain windows.advertising.id
privr recommend --workload developer
privr simulate --profile baseline
privr plan
privr apply
privr rollback <transaction-id> --yes
```

- `doctor` reports capability facts, elevation paths, platform adapters, storage integrity, and schema versions.
- `check` reads effective state and compares it against a policy across five posture dimensions (behavioral-commercial, forensic-residue, network-exposure, diagnostic-crash, ambient-sensor).
- `explain` shows evidence, applicability, management source, and tradeoffs.
- `recommend` computes deterministic change recommendations ordered by friction tier (Tier 0 transparent to Tier 3 incompatible/tradeoff), workload persona, or friction budget.
- `simulate` performs a dry-run counterfactual posture vector projection without mutating host state, reporting transition deltas, friction counts, and reboot or signout requirements.
- `plan` is read-only and shows the exact eligible change set. Running `privr plan` without arguments defaults to the daily-driver general persona and cosmetic friction ceiling.
- `apply` executes safe, verified remediation with transaction journaling, interactive plan review, and native in-place elevation (`-e, --elevate`). Running `privr apply` without arguments applies recommended daily-driver controls with zero workflow disruption.
- `rollback` restores exact prior values, and only when current state still matches what was recorded.

The full command and exit-code contract is in [docs/CLI.md](docs/CLI.md).

## Agents
 
`privr` is designed to be driven by an agent harness from the first release,
whether that is a coding assistant, a hosted model, or a local one. A direct
stdio server is implemented at `privr mcp`, alongside packaging for the open
[Agent Plugins](https://agent-plugins.org/) standard (`plugin.json`, `mcp.json`,
and `skills/privr/SKILL.md`).

- Read-only tool access (`privr_status`, `privr_doctor`, `privr_catalog`,
  `privr_check`, `privr_explain`, `privr_plan`, `privr_recommend`, `privr_simulate`)
  over stdio, so an agent can inspect, simulate, and propose without being able
  to change anything.
- Mutating tools (`privr_apply`, `privr_rollback`) are absent from discovery
  unless explicitly enabled via `--allow-apply`, and approval cannot be granted
  through an unconfirmed tool call.
- Result objects are self-contained and ordered deterministically, with
  verbosity tiers so a full report fits a small context window.
- Reports carry no stable machine identifier, so a report is safe to hand to a
  model.

![Agent MCP session showing structured posture evidence](docs/assets/mcp-agent.svg)

`privr` never calls a language model itself. The model is always the caller,

never a dependency, and normal operation stays offline.

## Safety

These are the release requirements. The experimental `apply` and `rollback` do
not yet meet all of them; see [ROADMAP.md](ROADMAP.md#current-state).

- No product telemetry, and no network requirement for normal operation.
- No arbitrary shell commands in profiles or catalogue data.
- No mutation without a fresh plan and a check immediately before each write.
- No rollback that silently overwrites a later external change.
- No unknown, unreadable, or unsupported result reported as a pass.
- No clearing of logs, deleting of cloud data, disabling of updates, or removal
  of encryption as ordinary remediation.
- No promise of anonymity. Configuring a machine for minimal sharing does not
  make it unobserved, and on some platforms the configuration state itself is
  reported.

See [docs/SAFETY.md](docs/SAFETY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Documentation

- [Design decisions](docs/DECISIONS.md)
- [Product definition](docs/PRODUCT.md)
- [CLI contract](docs/CLI.md)
- [Agent interface](docs/AGENT_INTERFACE.md)
- [Policy model](docs/POLICY.md)
- [Result and drift model](docs/RESULTS.md)
- [Control contribution standard](docs/CONTROL_STANDARD.md)
- [Platform findings](docs/PLATFORM_SUPPORT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Maintenance policy](docs/MAINTENANCE.md)
- [Safety model](docs/SAFETY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Privacy behavior](docs/PRIVACY.md)
- [Privacy residue and erasure](docs/PRIVACY_RESIDUE.md)
- [Testing strategy](docs/TESTING.md)
- [Supply-chain security](docs/SUPPLY_CHAIN.md)
- [Research notes](docs/RESEARCH.md)
- [Contribution guide](CONTRIBUTING.md)

## Contributing

Early contributions should improve evidence and correctness: primary vendor
sources, compatibility findings, redacted fixtures, effective-state logic,
failure tests, and rollback tests. A setting does not become supported because
it appears in a tweak script.

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) before making
changes.

## License

Apache-2.0. See [LICENSE](LICENSE).
