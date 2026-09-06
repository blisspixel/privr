# Platform control matrix

## Status

This is a research-backed candidate matrix. The concept build implements none of
these controls yet. A control becomes supported only after meeting
[CONTROL_STANDARD.md](CONTROL_STANDARD.md).

Research reviewed: 2026-08-30.

## Capability labels

| Label | Meaning |
|---|---|
| `check` | Reliable programmatic observation is a credible MVP target |
| `apply` | Typed remediation and exact rollback are credible MVP targets |
| `guided` | Documented user control without a stable unmanaged programmatic interface |
| `managed` | Documented organization-management interface only |
| `review` | Report tradeoffs without default enforcement |
| `exclude` | Too brittle, unsafe, destructive, or misleading for ordinary remediation |

All rows are planned research until their implementation and fixture status say
otherwise.

## Windows

### The edition-gating rule

A policy value that reads back correctly is not evidence that it took effect.

Many documented policies apply only to specific editions. Home appears in no
policy applicability table, and several policies exclude Pro as well. Writing
such a value on an unsupported edition succeeds, reads back as written, and
changes nothing. The most widely copied example is the lowest diagnostic data
value, which Microsoft documents as equivalent to the next level up outside
Enterprise, Education, and Server.

Every surveyed tool reports a pass in that situation. It is the most common false
pass in this category and the clearest reason this project exists.

The rule every Windows control follows: resolve whether the value can take effect
on this edition and build, and report a value that cannot as `not_applicable`,
never as `pass`. In general, non-policy setting values take effect on Home while
values under the policy branches do not.

Three related traps are encoded as catalogue rules:

- Value names differ from policy names, so a control binds the value name the
  system actually reads, not the name in the policy user interface.
- Polarity is inconsistent. Some security-related values use `1` to mean the
  protective state, so no adapter may assume zero means private.
- Some writes are silently discarded, notably under anti-tampering protection.
  Every write is verified by re-reading effective state.

### Privacy-first MVP candidates

| Control ID | Desired behavior | Capability | Scope and constraints | Primary source |
|---|---|---|---|---|
| `windows.diagnostics.level` | Lowest edition-supported level | check, apply | Value `0` only honored on Enterprise, Education, and Server; Pro uses Required; Home remains unverified or guided until build evidence exists | [Diagnostic data configuration](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization) |
| `windows.diagnostics.log-collection` | Limit diagnostic logs | check, apply | Gate by build and installed policy definitions | [Diagnostic data configuration](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization) |
| `windows.diagnostics.dump-collection` | Limit dump collection | check, apply | Gate by build and installed policy definitions | [Diagnostic data configuration](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization) |
| `windows.advertising.id` | Disabled | check, apply | Supported policy editions, administrator | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.input.personalization` | Cloud input personalization off | check, apply | Supported policy editions, administrator | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.input.linguistic-data` | Optional linguistic collection off | check, apply | Supported policy editions, administrator | [TextInput CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-textinput) |
| `windows.experience.tailored` | Tailored experiences off | check, apply | Per user where documented | [Experience CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience) |
| `windows.feedback.prompts` | Feedback prompts suppressed | check, apply | Device policy, administrator | [Experience CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience) |
| `windows.activity.upload` | Activity upload off | check, apply | Windows 10 1803 or later on documented business editions | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.activity.publish` | Activity publishing off | check, apply | Windows 10 1709 or later on documented business editions | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.apps.diagnostic-info` | Windows apps denied diagnostic information | check, apply | Does not govern every desktop program; app restart may be needed | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.clipboard.cross-device` | Cloud clipboard off, local clipboard retained | check, apply | Pro or higher, administrator | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.search.cloud-content` | Cloud content off | check, apply | OneDrive and SharePoint search results removed | [Search CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search) |
| `windows.search.highlights` | Dynamic highlights off | check, apply | Support varies by build and edition | [Search CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search) |
| `windows.search.location` | Location-aware search off | check, apply | Local search retained | [Search CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search) |
| `windows.delivery-optimization.peers` | HTTP-only mode `0` | check, apply | Disables peer upload, retains Microsoft HTTP delivery | [Delivery Optimization workflow](https://learn.microsoft.com/en-ca/windows/deployment/do/delivery-optimization-workflow) |
| `windows.error-reporting.transmission` | Automatic Windows Error Reporting transmission off | check, apply | Reduces Microsoft solution lookup and remote crash diagnosis; preserve local diagnostics | [ErrorReporting CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting) |
| `windows.error-reporting.additional-data` | Do not send second-level data automatically | check, apply | Administrator | [WER settings](https://learn.microsoft.com/windows/win32/wer/wer-settings) |
| `windows.edge.diagnostic-data` | Required-only | check, apply | Edge 122 or later; browser restart | [Edge DiagnosticData](https://learn.microsoft.com/deployedge/microsoft-edge-policies/diagnosticdata) |
| `windows.edge.personalization` | Personalization reporting off | check, apply | Browser policy | [Edge PersonalizationReportingEnabled](https://learn.microsoft.com/deployedge/microsoft-edge-policies/personalizationreportingenabled) |
| `windows.edge.url-diagnostics` | URL diagnostic data off | check, apply | Browser policy | [Edge UrlDiagnosticDataEnabled](https://learn.microsoft.com/deployedge/microsoft-edge-policies/urldiagnosticdataenabled) |
| `windows.web.language-list` | Website language-list sharing opted out | check, apply | Per user, low impact | [Windows connection management](https://learn.microsoft.com/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services) |

### Review-first or guided Windows controls

| Control ID | Privacy question | Capability | Reason for gating | Primary source |
|---|---|---|---|---|
| `windows.defender.sample-submission` | Are samples sent automatically? | check, review | Prompting can delay cloud analysis; metadata still leaves the machine | [Defender sample submission](https://learn.microsoft.com/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission) |
| `windows.sync.settings` | Are passwords and settings synchronized? | check, review | Windows 11 21H2 or qualified Windows 10 builds; disabling removes backup and convenience features | [SettingSync CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-settingsync) |
| `windows.sync.onedrive` | Is file synchronization active? | check, review | Disabling breaks sync and does not remove cloud copies | [OneDrive policy reference](https://learn.microsoft.com/sharepoint/use-group-policy) |
| `windows.location.services` | Is device and app location available? | check, review | Affects time zone, weather, navigation, and recovery | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.find-my-device` | Can device location support recovery? | check, guided | Privacy benefit conflicts with theft recovery | [Windows Privacy Compliance Guide](https://learn.microsoft.com/en-gb/windows/privacy/windows-privacy-compliance-guide) |
| `windows.permissions.*` | Which apps can access sensitive capabilities? | check, guided | Blanket denial breaks applications; undocumented ConsentStore writes excluded | [Privacy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) |
| `windows.recall.snapshots` | Is Recall enabled and storing snapshots? | check, guided | Copilot+ Windows 11 24H2, qualified build and Pro or higher; applying disable can delete snapshots, so it is not ordinary reversible remediation | [WindowsAI CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai) |
| `windows.logging.command-lines` | Are arguments retained in audit or shell logs? | check, audit-only | Disabling weakens incident response | [Command-line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing) |
| `windows.bitlocker.cloud-recovery` | May recovery keys exist in a cloud account? | check, guided | Never print or remove a recovery key; do not weaken encryption | [BitLocker recovery](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/recovery-process) |
| `windows.diagnostics.remote-deletion` | Should stored vendor-side diagnostics be deleted? | exclude from profile apply | Remote destructive request, not desired-state remediation | [Clear-WindowsDiagnosticData](https://learn.microsoft.com/powershell/module/windowsdiagnosticdata/clear-windowsdiagnosticdata) |

### Excluded Windows techniques

- deleting or disabling DiagTrack, Windows Error Reporting, Delivery
  Optimization, Windows Update, Defender, SmartScreen, certificate services, or
  diagnostic scheduled tasks;
- hosts-file and firewall blocklists for broad Microsoft domains;
- component-package removal, ownership changes, or ACL hacks;
- undocumented `CloudStore`, `ContentDeliveryManager`, or `ConsentStore` writes;
- deprecated Delivery Optimization bypass modes;
- using an MDM bridge as an enrollment or policy-support bypass;
- clearing security, PowerShell, Sysmon, or event-forwarding logs.

## macOS

Apple exposes important privacy choices in System Settings and managed
restrictions, but no supported public CLI covers every unmanaged toggle. Private
preference keys and direct TCC database writes are excluded.

| Control ID | Desired behavior | Capability | Constraints | Primary source |
|---|---|---|---|---|
| `macos.analytics.share-mac` | Off | guided, managed | Managed restriction available on macOS 10.13 or later; unmanaged UI review | [Apple Mac restrictions](https://support.apple.com/guide/deployment/restrictions-for-mac-depba790e53/web) |
| `macos.analytics.share-with-developers` | Off | guided | Do not disable local crash generation | [Mac analytics](https://support.apple.com/guide/mac-help/mh27990/mac) |
| `macos.analytics.icloud` | Off | guided | User-facing UI unless a documented managed interface applies | [Mac Privacy and Security](https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac) |
| `macos.siri.improvement` | Off | guided | Prevents optional storage and review of samples | [Improve Siri and Dictation](https://support.apple.com/en-us/127070) |
| `macos.voice-features.improvement` | Off | guided | Available only on supporting releases | [Mac Privacy and Security](https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac) |
| `macos.advertising.personalized` | Off | guided, managed | Managed restriction available on macOS 12.0.1 or later | [Apple Mac restrictions](https://support.apple.com/guide/deployment/restrictions-for-mac-depba790e53/web) |
| `macos.dictation.on-device` | Prefer on-device where supported | managed | macOS 14 or later on Apple silicon | [Apple Mac restrictions](https://support.apple.com/guide/deployment/restrictions-for-mac-depba790e53/web) |
| `macos.intelligence.external-integrations` | External intelligence integrations off | managed, review | macOS 15.2 or later on supervised devices; disables integrations such as ChatGPT and Google Lens | [Apple Mac restrictions](https://support.apple.com/guide/deployment/restrictions-for-mac-depba790e53/web) |
| `macos.permissions.*` | Review sensitive app grants | guided, managed | Never write TCC database directly | [Privacy Preferences Policy Control](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-settings-dep38df53c2a/web) |
| `macos.siri.history` | Separate user-selected deletion | exclude from profile apply | Networked and irreversible; does not change consent | [Delete Siri and Dictation history](https://support.apple.com/guide/mac-help/delete-siri-and-dictation-history-mchlf55961c0/mac) |

### macOS readability tiers

How a setting is read determines what `privr` can honestly report. Four tiers:

| Tier | Meaning | Outcome available |
|---|---|---|
| Unprivileged effective state | Readable without elevation through a documented interface | `pass` or `drift` |
| Privileged effective state | Readable, but requires elevation or a granted permission | `pass` or `drift` when granted, otherwise `unknown` |
| Managed payload only | Observable only where a management payload exists | `review` on unmanaged Macs |
| Not readable | No supported read interface, such as per-application permission grants | `review`, never `pass` |

Consequences for the roadmap: **unmanaged macOS is largely a guided-review
product**, and the documentation says so rather than implying broader coverage.
Managed Macs are where verification is genuinely possible.

### macOS reading rules

- Read through the CoreFoundation preferences API. Do not shell out to the
  `defaults` command, which does not observe managed values, and do not parse
  preference files directly, because the preferences daemon holds values in
  memory and can overwrite direct edits.
- Use the forced-value API for the management source field.
- **The presence of an enforcing profile is not evidence that a setting holds.**
  The most credible macOS baseline in existence checks for an installed payload
  in roughly forty percent of its rules, which fails a user who has correctly
  configured every option by hand. Where only the enforcement mechanism is
  readable, report `review`.
- Many widely circulated `defaults` commands are inert, deprecated, or apply to a
  different operating system entirely. A command appearing in a hardening guide
  is not evidence that it does anything.

The initial macOS release should be useful as a guided checker even if it applies
few unmanaged settings.

## Linux platform discovery

Linux is where a naive check most easily produces a false pass. Discovery runs as
an ordered sequence, and **each stage can only lower confidence, never raise
it.**

1. Invoking identity. Resolve the target user through the elevation environment
   and the account database, never by assuming a home directory path.
2. Filesystem writability, including an actual write-and-rename probe rather than
   inferring from mount flags alone.
3. Operating-system identity and write model: mutable, image-based, declarative,
   or transactional. A declarative system cannot be remediated by editing files.
4. Container and virtualization context.
5. Service manager presence.
6. Mandatory access control state, where an indeterminate result is `unknown`
   rather than absent.
7. The target user's live session, and ownership of their configuration
   directory.
8. Session type and desktop environment, read from the session rather than from
   an ambient variable alone.
9. Schema presence, backend sanity, and lock state.
10. Package and unit state.

Only then is a control read, in the target user's context.

**Every write is verified out of band.** A settings write can report success while
changing nothing, most notably when performed as root against a user's session.
Of the tools surveyed, none acts correctly on a user session from root and two
silently report success.

A setting that stops local collection is distinguished from one that stops remote
submission, everywhere. Preserving local crash capture while disabling upload is
usually the correct default.

An unsupported combination returns `not_applicable` with support metadata, not
`pass`. An undetermined stage returns `unknown`.

Linux ships audit-first. That is the aggregate consequence of per-control
maturity rather than a platform-wide rule, so an individual control can be
promoted to remediation on evidence. The first candidates for promotion are plain
machine-scope settings with documented defaults and trivial prior values.

## GNOME

| Control ID | Desired behavior | Capability | Notes | Primary source |
|---|---|---|---|---|
| `gnome.history.recent-files` | Do not remember new recent files | check, apply | Does not clear existing history | [GNOME privacy schema](https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.desktop.privacy.gschema.xml.in) |
| `gnome.history.application-usage` | Do not remember app usage | check, apply | User setting | [GNOME privacy schema](https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.desktop.privacy.gschema.xml.in) |
| `gnome.telemetry.software-usage` | Off | check, apply | Check schema presence and writability | [GNOME privacy schema](https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.desktop.privacy.gschema.xml.in) |
| `gnome.crash-reporting.technical-problems` | Off | check, apply | Desktop setting, not proof that all distro uploaders are disabled | [GNOME privacy schema](https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.desktop.privacy.gschema.xml.in) |
| `gnome.location.services` | Review current location behavior | check, review | Applications may infer location independently | [GNOME location schema](https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.system.location.gschema.xml.in) |
| `gnome.history.clear-existing` | Separate confirmed deletion | exclude from profile apply | Destructive and distinct from disabling history | [GNOME recent files](https://help.gnome.org/gnome-help/privacy-history-recent-off.html) |

GSettings writes run as the logged-in desktop user. Running through ordinary
`sudo` would change root's preferences and produce a false result.

## Ubuntu

| Control ID | Desired behavior | Capability | Constraints | Primary source |
|---|---|---|---|---|
| `ubuntu.insights.consent` | System opt-out where supported | check, apply | Ubuntu 25.10 transition and 26.04 interface detection required | [Ubuntu Insights](https://github.com/ubuntu/ubuntu-insights/blob/main/insights/README.md) |
| `ubuntu.report.consent` | Opt out | check, apply | Legacy component may coexist during transition | [Ubuntu Report](https://github.com/ubuntu/ubuntu-report) |
| `ubuntu.apport.capture` | Observe separately from upload | check, audit-only | Version-specific; local collection is not vendor submission | [Ubuntu Apport](https://documentation.ubuntu.com/project/contributors/debugging/apport/) |
| `ubuntu.whoopsie.upload` | Automatic upload off | check, audit-only | Service behavior varies by release | [Ubuntu Apport](https://documentation.ubuntu.com/project/contributors/debugging/apport/) |

An opt-out notification may itself contact the Ubuntu service. Reports must
disclose this difference from a strict zero-egress configuration.

## Fedora, Debian, and KDE

| Control ID | Desired behavior | Capability | Notes | Primary source |
|---|---|---|---|---|
| `fedora.abrt.auto-reporting` | Disabled, user-triggered reports retained | check, apply | Use packaged `abrt-auto-reporting` interface | [ABRT configuration](https://github.com/abrt/doc/blob/master/conf.rst) |
| `debian.popularity-contest.participation` | `PARTICIPATE=no` | check, apply | Only when package is installed; preserve file metadata and comments | [popularity-contest manual](https://manpages.debian.org/testing/popularity-contest/popularity-contest.8.en.html) |
| `kde.user-feedback.global` | Disabled | check, apply | Atomically preserve unrelated configuration | [KDE Kiosk policy](https://develop.kde.org/docs/administration/kiosk/keys/) |

## Linux audit-only expansion

- NetworkManager connectivity checks, because disabling them affects captive
  portals and route selection;
- systemd core-dump retention, because it is local diagnostics rather than
  vendor telemetry and can support incident response;
- systemd journal upload and remote syslog destinations;
- GNOME Remote Desktop and file sharing;
- online accounts;
- Flatpak permissions and Snap connections.

Update checks, certificate updates, NTP, and package repositories are not
classified as telemetry merely because they contact a server.

## Compatibility test expectations

Each supported platform family needs:

- current release and at least two prior supported versions where practical;
- relevant editions or product tiers;
- unmanaged and managed fixtures;
- explicit-value and inherited-default fixtures;
- missing feature, package, schema, or command fixtures;
- access-denied and malformed-value fixtures;
- apply, verification, restart, and rollback fixtures;
- disposable VM or image tests for actual platform behavior;
- an `unknown` fallback for newer unverified releases.

The release support table should name verified builds rather than saying only
"Windows 11," "macOS," or "Linux."
