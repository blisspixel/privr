# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub Security
Advisories for this repository, using the "Report a vulnerability" button on the
Security tab.

If private advisories are unavailable to you, email `nick@pueo.io` instead.
Do not open a public issue for a vulnerability that could enable code execution,
privilege escalation, policy injection, journal disclosure, unsafe rollback, or
destructive system changes.

Expect an acknowledgement within seven days. Please allow ninety days for a fix
before public disclosure, and tell us if you intend to disclose sooner so we can
coordinate.

Include:

- affected version or commit;
- operating system and version;
- reproduction steps;
- expected and observed behavior;
- whether elevated privileges are required;
- any suggested mitigation.

## Security-sensitive design areas

The following areas require additional review:

- parsing custom policies;
- crossing from an unprivileged check into elevated remediation;
- validating registry, preference, service, and file targets;
- transaction-journal permissions and contents;
- command argument construction;
- update and policy-signature verification;
- apply, verification, and rollback ordering.

The project does not currently provide operational remediation. The concept CLI
changes zero system settings.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the security model and
[docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) for release and catalogue controls.
