# Research notes

These notes capture decisions from the initial product and platform research.
They are inputs to the roadmap, not an implementation guarantee. A control only
becomes supported after it has applicability metadata, fixtures, verification,
and rollback tests.

Research reviewed: 2026-08-30.

## Product findings

The strongest product position is not a larger tweak collection. It is a local
state-management loop:

```text
check -> explain -> plan -> capture -> apply -> verify -> rollback -> check again
```

The initial users are privacy-conscious individuals and developers who want a
repeatable machine setup. Small-team and fleet workflows can build on stable
JSON and policy schemas later.

Important decisions:

- Ship Windows first, but keep the core model platform-neutral.
- Make read-only checks useful before shipping remediation.
- Keep normal operation offline and collect no product telemetry.
- Do not collapse findings into an unexplained privacy score.
- Treat OS edition, version, management source, and privilege as part of every
  result.
- Keep security tradeoffs outside the default apply path.
- Never allow arbitrary shell commands in profiles or downloaded catalog data.

Related tools validate the need but have different centers of gravity:

| Project | Useful precedent | `privr` focus |
|---|---|---|
| [privacy.sexy](https://github.com/undergroundwires/privacy.sexy) | Transparent cross-platform script generation | Observed state, typed policy, captured prior values, verification, drift |
| [O&O ShutUp10](https://manuals.oo-software.com/ooshutup10/docs/features/overview/) | Broad Windows coverage, profiles, CLI deployment, verification, undo history, and drift reapplication | Open implementation, named cross-platform support, primary-source metadata, and stable result schemas |
| [Lynis](https://github.com/CISOfy/lynis) | Mature Unix auditing | Narrow personal-data-sharing focus and approachable remediation |
| [osquery](https://osquery.readthedocs.io/en/stable/) | Scheduled state observation | Curated explanations, desired privacy state, and rollback |
| [InSpec](https://github.com/inspec/inspec) | General compliance as code | Small native binary and vendor-cited privacy catalogue |

## Rust assessment

Rust is a good implementation choice for a native, portable CLI with a typed
operation model and limited runtime dependencies. Rust supports conditional
compilation and first-class Windows, macOS, and Linux targets:

- [Rust conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html)
- [Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html)
- [`std::process::Command`](https://doc.rust-lang.org/std/process/struct.Command.html)

Rust does not solve OS-interface stability. The project should prefer native
APIs or documented packaged commands, pass arguments without a shell, and avoid
putting sensitive values in process arguments.

## Windows findings

Windows should be the first operational adapter. It has the broadest documented
policy surface, but support varies by edition, build, scope, and management
state. Windows Pro cannot reach diagnostic-data value `0`; on typical consumer
editions the privacy-first floor is required diagnostic data, value `1`.

The MVP must detect Windows build and edition, elevation, domain or Entra join,
MDM enrollment, and policy precedence before evaluating a control. A missing
policy value is not automatically drift because the corresponding effective
user setting may already be private.

Primary catalogue references:

- [Windows Privacy Compliance Guide](https://learn.microsoft.com/windows/privacy/windows-privacy-compliance-guide)
- [Configure Windows diagnostic data](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization)
- [Privacy policy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy)
- [System policy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system)

### Safe MVP remediation candidates

| Control | Privacy-first state | Source |
|---|---|---|
| Diagnostic data | Required-only, plus diagnostic-log and dump limits where supported | [Diagnostic configuration](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization) |
| Advertising ID | Disabled through supported policy | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| Input personalization | Cloud input personalization and linguistic collection off | [TextInput CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-textinput) |
| Tailored experiences and feedback | Tailored experiences off, feedback prompts suppressed | [Experience CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience) |
| Activity and clipboard sync | Cross-device activity and clipboard sync off, local clipboard retained | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| Search | Cloud content, highlights, and location-aware search off; local search retained | [Search CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search) |
| Delivery Optimization | HTTP-only mode `0`, which disables peer uploads | [Delivery Optimization CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-deliveryoptimization) |
| Windows Error Reporting | Disable automatic transmission while retaining local diagnostics | [ErrorReporting CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting) |
| Edge | Required diagnostics only, personalization and URL diagnostics off | [Edge DiagnosticData](https://learn.microsoft.com/deployedge/microsoft-edge-policies/diagnosticdata) |
| Website language sharing | Opt out of exposing the Windows language list | [Windows connection management](https://learn.microsoft.com/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services) |

Policy CSP documentation defines semantics and support. It is not a generic
local API. `privr` should use a local registry mapping only where Microsoft
documents that mapping for the applicable edition and build.

### Consent-gated or audit-only controls

- Windows Backup and settings synchronization can include remembered passwords,
  personalization, and application settings.
- OneDrive policy can disable sync but does not delete cloud copies or undo
  known-folder moves.
- Location and Find My Device affect navigation, time zone, weather, and theft
  recovery.
- Camera, microphone, contacts, and other app-permission denials can break
  applications. Undocumented `ConsentStore` writes are excluded.
- Disabling Recall can delete existing snapshots and require a restart, so
  ordinary profile application cannot treat it as reversible:
  [Manage Recall](https://learn.microsoft.com/windows/client-management/manage-recall).
- Defender sample submission should default to `AlwaysPrompt` while preserving
  cloud protection. `NeverSend` can disable block-at-first-sight analysis:
  [Microsoft Defender sample submission](https://learn.microsoft.com/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).
- Clearing stored Windows diagnostic data is a remote deletion request, not a
  drift-remediation setting.
- Command-line, PowerShell, Sysmon, and forwarded logs can retain sensitive
  arguments, but disabling them weakens incident response. Report their exposure
  separately from optional vendor telemetry.
- BitLocker recovery-key handling must never print or remove recovery material,
  and privacy work must not disable disk encryption.

### Explicit exclusions

The MVP should not delete or disable DiagTrack, Windows Error Reporting,
Delivery Optimization, Windows Update, Defender, SmartScreen, certificate
services, or diagnostic scheduled tasks. It should not use hosts-file or
firewall blocklists, package removal, ownership or ACL hacks, private
`CloudStore` or `ContentDeliveryManager` writes, or an MDM bridge as an
enrollment bypass.

## macOS findings

Apple documents distinct settings for:

- Share Mac Analytics;
- Share with app developers;
- Share iCloud Analytics;
- Improve Siri and Dictation;
- Improve Assistive Voice Features where available;
- personalized Apple advertising.

Sources:

- [Mac Privacy and Security settings](https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac)
- [Improve Siri and Dictation](https://support.apple.com/en-us/127070)
- [Apple device-management restrictions](https://developer.apple.com/documentation/devicemanagement/restrictions)
- [Privacy Preferences Policy Control](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-settings-dep38df53c2a/web)

Product implications:

- There is no supported public CLI for reliably reading and changing every
  unmanaged Mac toggle.
- Private `defaults` keys and direct TCC database edits are not an acceptable
  foundation.
- Unmanaged settings without a supported interface should use outcome `review`
  and remediation `guided` with an exact System Settings path.
- Managed Macs can be evaluated through documented restrictions and profiles.
- TCC permissions, location, and cloud synchronization are audit or guided
  review controls by default.
- Deleting Siri history is a separate networked and irreversible action. It must
  never be bundled into normal profile application.

## Linux findings

Linux support must discover `/etc/os-release`, the active desktop, available
GSettings schemas, installed packages, and service manager before choosing
checks. Unsupported environments must not receive a false `pass`.

### GNOME

Stable upstream privacy keys include recent-file history, application-usage
history, software-usage statistics, technical-problem reporting, and location.
The authoritative schemas are:

- [GNOME desktop privacy schema](https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.desktop.privacy.gschema.xml.in)
- [GNOME location schema](https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.system.location.gschema.xml.in)
- [GSettings explicit user values](https://docs.gtk.org/gio/method.Settings.get_user_value.html)

Rollback must distinguish an explicit user value from an inherited default.
Disabling history does not delete existing history. Deletion is a separate,
confirmed operation.

### Ubuntu

Ubuntu 25.10 and later are moving from Ubuntu Report to Ubuntu Insights. Version
detection must support both during the transition.

- [Ubuntu Insights client](https://github.com/ubuntu/ubuntu-insights/blob/main/insights/README.md)
- [Ubuntu Report](https://github.com/ubuntu/ubuntu-report)
- [Ubuntu Apport](https://documentation.ubuntu.com/project/contributors/debugging/apport/)

Apport collection, prompt display, and Whoopsie upload are distinct states. A
setting that hides crash prompts is not proof that capture or upload is disabled.

### Fedora, Debian, and KDE

- Fedora ABRT automatic reporting should use the packaged
  `abrt-auto-reporting` interface where installed:
  [ABRT configuration](https://github.com/abrt/doc/blob/master/conf.rst).
- Debian `popularity-contest` is optional and explicit opt-in, but participation
  is privacy-relevant when installed:
  [Debian privacy policy](https://www.debian.org/legal/privacy) and
  [popularity-contest manual](https://manpages.debian.org/testing/popularity-contest/popularity-contest.8.en.html).
- KDE provides a documented global user-feedback policy:
  [KDE Kiosk telemetry policy](https://develop.kde.org/docs/administration/kiosk/keys/).

### Local diagnostics are not automatically telemetry

systemd journals and core dumps are normally local data. Remote forwarding and
network submission must be checked separately. Disabling local diagnostics by
default can weaken incident response. Core dumps can still contain command lines,
environment data, file paths, and memory, so retention deserves a clearly
labeled audit:
[systemd-coredump](https://www.freedesktop.org/software/systemd/man/systemd-coredump.html).

## Research rules for adding a check

A proposed check should answer:

1. What data leaves the machine, if any?
2. Where does it go?
3. Is the behavior optional, required, local-only, or user-initiated?
4. What is the authoritative read interface?
5. What is the authoritative write interface?
6. Which OS versions, editions, desktops, and management modes support it?
7. What functionality or security protection is lost?
8. Can the exact prior state be restored?
9. Can the effective value be verified after writing?
10. What primary documentation supports the claim?

The consolidated control candidates, unsupported techniques, and compatibility
requirements are in [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md). Architecture,
testing, and release findings are in [ARCHITECTURE.md](ARCHITECTURE.md),
[TESTING.md](TESTING.md), and [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).
