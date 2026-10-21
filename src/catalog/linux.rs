//! Linux control definitions.
//!
//! Evaluates privacy and telemetry controls for Linux desktop environments
//! (GNOME, KDE) and distribution services (Ubuntu, Fedora, Debian).

use super::{Context, Control, Source};
use crate::engine::evaluate::{ControlSpec, Resolution, SemanticState, Uncertainty};
use crate::model::applicability::{Applicability, Predicate, Variant};
use crate::model::host::ManagementSource;
use crate::model::outcome::{Maturity, Remediation, Reversibility};
use crate::model::posture::{FrictionTier, PostureDimension};
use crate::model::profile::Profile;
use crate::platform::linux::evidence::Target;
use crate::platform::linux::systemd::ConfigurationFamily;

fn enabled() -> SemanticState {
    SemanticState::new("enabled")
}

fn disabled() -> SemanticState {
    SemanticState::new("disabled")
}

const GNOME_PRIVACY_SCHEMA: &str = "https://github.com/GNOME/gsettings-desktop-schemas/blob/main/schemas/org.gnome.desktop.privacy.gschema.xml.in";
const UBUNTU_REPORT_URL: &str = "https://github.com/ubuntu/ubuntu-report";
const UBUNTU_INSIGHTS_URL: &str = "https://github.com/ubuntu/ubuntu-insights";
const DEBIAN_POPCON_URL: &str =
    "https://manpages.debian.org/testing/popularity-contest/popularity-contest.8.en.html";
const DEBIAN_POPCON_CRON_URL: &str =
    "https://sources.debian.org/src/popularity-contest/1.79/debian/cron.daily/";
const SYSTEMD_UNIT_URL: &str =
    "https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html";
const SYSTEMD_SYSTEMCTL_URL: &str =
    "https://www.freedesktop.org/software/systemd/man/latest/systemctl.html";
const FEDORA_ABRT_URL: &str = "https://abrt.readthedocs.io/en/latest/conf.html";
const KDE_USERFEEDBACK_URL: &str = "https://develop.kde.org/docs/administration/kiosk/keys/";
const PLASMA_FEEDBACK_KCFG_URL: &str = "https://invent.kde.org/plasma/plasma-workspace/-/blob/master/kcms/feedback/feedbacksettings.kcfg";
const SYSTEMD_COREDUMP_URL: &str =
    "https://github.com/systemd/systemd/blob/v262/man/coredump.conf.xml";
const FREEDESKTOP_THUMBNAIL_URL: &str =
    "https://specifications.freedesktop.org/thumbnail-spec/thumbnail-spec-latest.html";
const FSTRIM_DOCS_URL: &str = "https://manpages.debian.org/testing/util-linux/fstrim.8.en.html";
const SYSTEMD_JOURNALD_URL: &str =
    "https://github.com/systemd/systemd/blob/v262/man/journald.conf.xml";
const NETWORKMANAGER_CONF_URL: &str =
    "https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html";
const AVAHI_CONF_URL: &str =
    "https://manpages.debian.org/testing/avahi-daemon/avahi-daemon.conf.5.en.html";
const RESOLVED_DBUS_URL: &str =
    "https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html";

/// The daily job merges more than this one file.
///
/// popularity-contest 1.79 exits when its command is absent. Otherwise it
/// unsets participation, sources the package default, then this etc file,
/// then each drop-in. Submission runs unless the merged value is `no` or
/// empty. A later drop-in can turn submission on after this file says no,
/// and off after it says yes. The package default says a missing option
/// defaults to no, but that default is not in the file this probe reads.
fn probe_debian_popcon(ctx: &Context) -> Resolution {
    match ctx.linux.text(Target::DebianPopcon) {
        Ok(_) => popcon_not_established(),
        Err(reason) => Resolution::uncertain(reason, ManagementSource::User),
    }
}

fn popcon_not_established() -> Resolution {
    let mut resolution =
        Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::Unknown);
    resolution.note = Some(
        "The package default, the drop-in directory, and the package command were not read. This file alone does not establish whether submission is off."
            .to_owned(),
    );
    resolution
}

/// The opt-in file is not the documented consent state.
fn probe_ubuntu_insights(ctx: &Context) -> Resolution {
    file_presence_is_not_consent(
        ctx.linux.exists(Target::UbuntuInsights),
        "The opt-in file is not the Ubuntu Insights consent state. Its absence is not an opt-out.",
    )
}

/// A metrics cache is not the documented opt-out.
fn probe_ubuntu_report(ctx: &Context) -> Resolution {
    file_presence_is_not_consent(
        ctx.linux.exists(Target::UbuntuReport),
        "A metrics cache file is not the Ubuntu Report opt-out. Its absence is not evidence that submission is off.",
    )
}

fn file_presence_is_not_consent(read: Result<bool, Uncertainty>, note: &str) -> Resolution {
    match read {
        Ok(_) => {
            let mut resolution =
                Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::Unknown);
            resolution.note = Some(note.to_owned());
            resolution
        }
        Err(reason) => Resolution::uncertain(reason, ManagementSource::User),
    }
}

/// System autoreporting is `AutoreportingEnabled` in `/etc/abrt/abrt.conf`.
///
/// An explicit `yes` is upload enabled. `no`, a missing key, and a missing
/// file do not establish that upload is off: the desktop session has its own
/// setting, and the package-data file does not govern this switch.
fn probe_fedora_abrt(ctx: &Context) -> Resolution {
    match ctx.linux.text(Target::FedoraAbrt) {
        Ok(Some(content)) => match autoreporting_enabled(&content) {
            Some(true) => Resolution::determined(enabled(), ManagementSource::LocalPolicy),
            Some(false) => abrt_not_established(
                "System AutoreportingEnabled is no. The desktop session setting was not read, so this does not establish that upload is off.",
            ),
            None => abrt_not_established(
                "abrt.conf does not set AutoreportingEnabled to yes. That is not evidence that crash upload is off.",
            ),
        },
        Ok(None) => abrt_not_established(
            "abrt.conf is absent. That is not evidence that crash upload is off.",
        ),
        Err(reason) => Resolution::uncertain(reason, ManagementSource::LocalPolicy),
    }
}

fn abrt_not_established(note: &str) -> Resolution {
    let mut resolution =
        Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::LocalPolicy);
    resolution.note = Some(note.to_owned());
    resolution
}

/// `Some(true)` is an explicit yes. `Some(false)` is an explicit no.
/// `None` means the setting was not present.
fn autoreporting_enabled(content: &str) -> Option<bool> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("autoreportingenabled") else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
        let token = rest.split_whitespace().next().unwrap_or("");
        if token == "yes" {
            return Some(true);
        }
        if token == "no" {
            return Some(false);
        }
    }
    None
}

/// Probe GNOME desktop settings.
///
/// In headless or non-GNOME environments without a live session bus,
/// reports undetermined rather than guessing the state.
fn probe_gnome_desktop_setting(ctx: &Context) -> Resolution {
    if ctx
        .host
        .session
        .desktop
        .known()
        .is_some_and(|desktop| !desktop.contains("gnome"))
    {
        return Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User);
    }
    Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User)
}

/// Plasma's feedback level and the administrator force-off are different files.
///
/// The file this target names is neither `PlasmaUserFeedback` nor
/// `/etc/xdg/KDE/UserFeedback.conf`. A missing file, and `FeedbackLevel=0` in
/// the wrong file, used to pass. Telemetry is off by default, and a user can
/// still enable it inside applications, so this reading stays unknown.
fn probe_kde_feedback(ctx: &Context) -> Resolution {
    // Keep the typed read so a denied or malformed access stays that reason.
    // The bytes are not a consent state, including an explicit level of 0.
    match ctx.linux.text(Target::KdeFeedback) {
        Ok(_) => {
            let mut resolution =
                Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::Unknown);
            resolution.note = Some(
                "This file is not PlasmaUserFeedback, and it is not the administrator force-off. Neither setting was read, so this does not establish that telemetry is off."
                    .to_owned(),
            );
            resolution
        }
        Err(reason) => Resolution::uncertain(reason, ManagementSource::User),
    }
}

/// Probe systemd core dump persistence.
fn probe_systemd_coredump(ctx: &Context) -> Resolution {
    ctx.linux.configuration(ConfigurationFamily::Coredump)
}

/// Probe FreeDesktop thumbnail caching.
fn probe_freedesktop_thumbnails(ctx: &Context) -> Resolution {
    crate::platform::linux::exposure::thumbnails(ctx.linux)
}

fn probe_networkmanager_connectivity(ctx: &Context) -> Resolution {
    crate::platform::linux::exposure::network_manager(ctx.linux)
}

fn probe_avahi_publishing(ctx: &Context) -> Resolution {
    crate::platform::linux::exposure::avahi(ctx.linux)
}

fn probe_resolved_llmnr(ctx: &Context) -> Resolution {
    crate::platform::linux::exposure::resolved_llmnr(ctx.linux)
}

fn probe_resolved_mdns(ctx: &Context) -> Resolution {
    crate::platform::linux::exposure::resolved_mdns(ctx.linux)
}

/// Whether `fstrim.timer` is enabled, after the unit file systemd would load.
///
/// A wants symlink is the documented enabled state. It is not sufficient:
/// an empty unit file, including a link to the null device, is masked and
/// cannot start. Search the unit paths before the wants symlinks. An unread
/// or unreadable path stops the conclusion.
fn probe_systemd_fstrim(ctx: &Context) -> Resolution {
    match fstrim_fragment(ctx) {
        Err(reason) => Resolution::uncertain(reason, ManagementSource::LocalPolicy),
        Ok(FstrimFragment::Masked) => noted(
            Resolution::determined(disabled(), ManagementSource::LocalPolicy),
            "The unit file systemd would load is empty. An empty unit file, including one linked to the null device, is masked and cannot start. A wants symlink does not show that the timer runs.",
        ),
        Ok(FstrimFragment::Missing) => noted(
            Resolution::determined(disabled(), ManagementSource::Default),
            "No fstrim unit file was found in the standard unit directories. The timer is not running.",
        ),
        Ok(FstrimFragment::Loadable) => fstrim_wants(ctx),
    }
}

enum FstrimFragment {
    Loadable,
    Masked,
    Missing,
}

fn fstrim_fragment(ctx: &Context) -> Result<FstrimFragment, Uncertainty> {
    for target in [
        Target::FstrimUnitEtc,
        Target::FstrimUnitRun,
        Target::FstrimUnitLocal,
        Target::FstrimUnitUsr,
        Target::FstrimUnitLib,
    ] {
        match ctx.linux.text(target) {
            Ok(None) => {}
            Ok(Some(content)) => {
                return Ok(if content.is_empty() {
                    FstrimFragment::Masked
                } else {
                    FstrimFragment::Loadable
                });
            }
            Err(reason) => return Err(reason),
        }
    }
    Ok(FstrimFragment::Missing)
}

fn fstrim_wants(ctx: &Context) -> Resolution {
    for target in [Target::FstrimAdmin, Target::FstrimLib, Target::FstrimVendor] {
        match ctx.linux.exists(target) {
            Ok(true) => return Resolution::determined(enabled(), ManagementSource::LocalPolicy),
            Ok(false) => {}
            Err(reason) => return Resolution::uncertain(reason, ManagementSource::LocalPolicy),
        }
    }
    Resolution::determined(disabled(), ManagementSource::Default)
}

fn noted(mut resolution: Resolution, note: &str) -> Resolution {
    resolution.note = Some(note.to_owned());
    resolution
}

/// Probe systemd-journald volatile storage.
fn probe_systemd_journald(ctx: &Context) -> Resolution {
    ctx.linux.configuration(ConfigurationFamily::Journald)
}

/// Return all Linux controls, sorted by identifier.
pub fn controls() -> Vec<Control> {
    let mut controls = vec![
        Control {
            spec: ControlSpec {
                id: "debian.popularity-contest.participation".to_owned(),
                title: "Package popularity survey".to_owned(),
                section: "debian".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-debian",
                    vec![Predicate::DistributionIn(vec![
                        "debian".to_owned(),
                        "ubuntu".to_owned(),
                    ])],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: true,
            },
            title: "Package popularity survey",
            summary: "Debian popularity-contest transmits lists of installed and accessed packages.",
            rationale: "Submitting package installation and access timestamps reveals application inventory to survey collectors.",
            tradeoff: Some(
                "Distribution maintainers receive fewer statistics for ranking popular packages.",
            ),
            mitigation: Some(
                "Package installation, updates, and package management are completely unaffected.",
            ),
            sources: &[
                Source {
                    url: DEBIAN_POPCON_URL,
                    claim: "The daily job follows the etc configuration and the package default.",
                    reviewed: "2026-10-20",
                },
                Source {
                    url: DEBIAN_POPCON_CRON_URL,
                    claim: "The 1.79 daily job exits when the package command is absent. Otherwise it unsets participation, sources the package default, then the etc file, then each popularity-contest.d drop-in, and skips submission when the merged value is no or empty.",
                    reviewed: "2026-10-20",
                },
            ],
            probe: probe_debian_popcon,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "fedora.abrt.auto-reporting".to_owned(),
                title: "Automated crash reporting".to_owned(),
                section: "fedora".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-fedora",
                    vec![Predicate::DistributionIn(vec![
                        "fedora".to_owned(),
                        "rhel".to_owned(),
                        "centos".to_owned(),
                    ])],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: true,
            },
            title: "Automated crash reporting",
            summary: "Fedora ABRT uploads application crash dumps and backtraces automatically.",
            rationale: "Automatic crash uploads can capture sensitive in-memory strings, environment variables, and user data.",
            tradeoff: Some(
                "Upstream maintainers do not receive automated bug filings for system crashes.",
            ),
            mitigation: Some(
                "Crashes are preserved locally in /var/spool/abrt and can be reviewed before manual submission.",
            ),
            sources: &[Source {
                url: FEDORA_ABRT_URL,
                claim: "System autoreporting is AutoreportingEnabled in abrt.conf. The desktop session setting is separate, and abrt-action-save-package-data.conf does not govern upload.",
                reviewed: "2026-10-20",
            }],
            probe: probe_fedora_abrt,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "freedesktop.thumbnails.caching".to_owned(),
                title: "FreeDesktop thumbnail caching".to_owned(),
                section: "freedesktop".to_owned(),
                dimension: PostureDimension::ForensicResidue,
                friction: FrictionTier::Tier2WorkflowAltering,
                applicability: Applicability::new(vec![Variant::new("linux", vec![])]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
                requires_elevation: false,
            },
            title: "FreeDesktop thumbnail caching",
            summary: "Linux desktop environments generate and retain unencrypted file thumbnails when browsing folders.",
            rationale: "FreeDesktop thumbnail management caches high-resolution previews in ~/.cache/thumbnails/ with MD5 URI mapping to original file paths, persisting after files are deleted.",
            tradeoff: Some(
                "Desktop file managers display generic file icons instead of visual media previews.",
            ),
            mitigation: Some(
                "Media files can be opened and viewed directly in default applications.",
            ),
            sources: &[Source {
                url: FREEDESKTOP_THUMBNAIL_URL,
                claim: "Generated previews are stored in the XDG cache thumbnails directory. That directory is storage, not a switch that turns generation off.",
                reviewed: "2026-10-20",
            }],
            probe: probe_freedesktop_thumbnails,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "gnome.crash-reporting.technical-problems".to_owned(),
                title: "Technical problem reporting".to_owned(),
                section: "gnome".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-gnome",
                    vec![
                        Predicate::DesktopIn(vec!["gnome".to_owned()]),
                        Predicate::LiveSession(true),
                    ],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: false,
            },

            title: "Technical problem reporting",
            summary: "GNOME automatically transmits technical error reports when applications crash.",
            rationale: "Automated crash reports transmit application memory state and environment metadata to distribution aggregators.",
            tradeoff: Some("Developers receive fewer automated crash reports."),
            mitigation: Some(
                "Local system logs and coredumpctl remain fully available for offline debugging.",
            ),
            sources: &[Source {
                url: GNOME_PRIVACY_SCHEMA,
                claim: "Documents technical problems reporting schema.",
                reviewed: "2026-09-21",
            }],
            probe: probe_gnome_desktop_setting,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "gnome.history.application-usage".to_owned(),
                title: "Application usage history".to_owned(),
                section: "gnome".to_owned(),
                dimension: PostureDimension::ForensicResidue,
                friction: FrictionTier::Tier1Cosmetic,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-gnome",
                    vec![
                        Predicate::DesktopIn(vec!["gnome".to_owned()]),
                        Predicate::LiveSession(true),
                    ],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
                requires_elevation: false,
            },
            title: "Application usage history",
            summary: "GNOME tracks application launch frequency to sort applications in the overview.",
            rationale: "Tracking application execution frequency maintains a persistent profile of user habits.",
            tradeoff: Some("Applications in the overview are not sorted by launch frequency."),
            mitigation: Some("Pin favorite applications directly to the dash."),
            sources: &[Source {
                url: GNOME_PRIVACY_SCHEMA,
                claim: "Documents application usage tracking schema.",
                reviewed: "2026-09-21",
            }],
            probe: probe_gnome_desktop_setting,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "gnome.history.recent-files".to_owned(),
                title: "Recent files history".to_owned(),
                section: "gnome".to_owned(),
                dimension: PostureDimension::ForensicResidue,
                friction: FrictionTier::Tier1Cosmetic,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-gnome",
                    vec![
                        Predicate::DesktopIn(vec!["gnome".to_owned()]),
                        Predicate::LiveSession(true),
                    ],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
                requires_elevation: false,
            },
            title: "Recent files history",
            summary: "GNOME records recently opened files in a persistent access list.",
            rationale: "Recording recent files preserves file paths and access timestamps across all applications.",
            tradeoff: Some(
                "File pickers and GNOME Files do not display recently opened documents.",
            ),
            mitigation: Some("Add frequently accessed directories to Nautilus bookmarks."),
            sources: &[Source {
                url: GNOME_PRIVACY_SCHEMA,
                claim: "Documents recent files retention schema.",
                reviewed: "2026-09-21",
            }],
            probe: probe_gnome_desktop_setting,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "gnome.telemetry.software-usage".to_owned(),
                title: "Software usage statistics".to_owned(),
                section: "gnome".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-gnome",
                    vec![
                        Predicate::DesktopIn(vec!["gnome".to_owned()]),
                        Predicate::LiveSession(true),
                    ],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: false,
            },
            title: "Software usage statistics",
            summary: "GNOME Software transmits application search and installation statistics.",
            rationale: "Transmitting software usage uploads application install events and catalog navigation metrics.",
            tradeoff: Some(
                "Distribution maintainers receive less popularity data for software catalog curation.",
            ),
            mitigation: Some("Software installation, updates, and reviews function normally."),
            sources: &[Source {
                url: GNOME_PRIVACY_SCHEMA,
                claim: "Documents software usage statistics reporting schema.",
                reviewed: "2026-09-21",
            }],
            probe: probe_gnome_desktop_setting,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "kde.user-feedback.global".to_owned(),
                title: "KDE Plasma user feedback".to_owned(),
                section: "kde".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-kde",
                    vec![
                        Predicate::DesktopIn(vec!["kde".to_owned()]),
                        Predicate::LiveSession(true),
                    ],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: false,
            },

            title: "KDE Plasma user feedback",
            summary: "KDE applications collect software usage and system telemetry.",
            rationale: "KDE UserFeedback periodically uploads telemetry from desktop applications.",
            tradeoff: Some("KDE developers receive less telemetry on desktop component usage."),
            mitigation: Some(
                "KDE Plasma desktop and applications function identically without feedback.",
            ),
            sources: &[
                Source {
                    url: KDE_USERFEEDBACK_URL,
                    claim: "Telemetry is disabled by default, but a user can enable it in applications. Global force-off is Enabled=false in the administrator UserFeedback file, which this control does not read.",
                    reviewed: "2026-10-20",
                },
                Source {
                    url: PLASMA_FEEDBACK_KCFG_URL,
                    claim: "Plasma stores FeedbackLevel in PlasmaUserFeedback, group Global, default NoTelemetry.",
                    reviewed: "2026-10-20",
                },
            ],
            probe: probe_kde_feedback,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "systemd.coredump.storage".to_owned(),
                title: "Systemd core dump persistence".to_owned(),
                section: "systemd".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier3IncompatibleOrTradeoff,
                applicability: Applicability::new(vec![Variant::new("linux-systemd", vec![])]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
                requires_elevation: true,
            },
            title: "Systemd core dump persistence",
            summary: "systemd-coredump can retain process core dumps when applications crash.",
            rationale: "Crash dumps store full process memory contents, which can expose passwords, encryption keys, decrypted tokens, and sensitive document text.",
            tradeoff: Some(
                "Developers and administrators cannot inspect post-crash core dumps for offline debugging.",
            ),
            mitigation: Some(
                "Backtraces may remain available when processing permits; Storage=none alone does not prevent temporary disk writes.",
            ),
            sources: &[Source {
                url: SYSTEMD_COREDUMP_URL,
                claim: "Documents v262 configured core retention, including temporary-write and backtrace limits.",
                reviewed: "2026-10-11",
            }],
            probe: probe_systemd_coredump,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "systemd.fstrim.timer".to_owned(),
                title: "Periodic SSD TRIM timer".to_owned(),
                section: "systemd".to_owned(),
                dimension: PostureDimension::ForensicResidue,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new("linux-systemd", vec![])]),
                desired: enabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
                requires_elevation: true,
            },
            title: "Periodic SSD TRIM timer",
            summary: "systemd provides fstrim.timer to periodically discard unused filesystem blocks on solid-state drives.",
            rationale: "Periodic TRIM informs solid-state drives of deleted and unallocated filesystem blocks, enabling wear leveling and physical data erasure.",
            tradeoff: Some(
                "fstrim executes a periodic storage discard scan across mounted filesystems.",
            ),
            mitigation: Some(
                "The timer executes once per week during system idle time with negligible I/O impact.",
            ),
            sources: &[
                Source {
                    url: FSTRIM_DOCS_URL,
                    claim: "Documents fstrim discard operations started by the systemd timer.",
                    reviewed: "2026-10-20",
                },
                Source {
                    url: SYSTEMD_UNIT_URL,
                    claim: "An empty unit file, or a unit file linked to /dev/null, is masked and cannot be activated.",
                    reviewed: "2026-10-20",
                },
                Source {
                    url: SYSTEMD_SYSTEMCTL_URL,
                    claim: "Enabled means a wants, requires, or alias symlink. mask links the unit to /dev/null under /etc/systemd/system or /run/systemd/system and prevents activation, including enablement.",
                    reviewed: "2026-10-20",
                },
            ],
            probe: probe_systemd_fstrim,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "systemd.journald.storage".to_owned(),
                title: "Systemd journal memory storage".to_owned(),
                section: "systemd".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier1Cosmetic,
                applicability: Applicability::new(vec![Variant::new("linux-systemd", vec![])]),
                desired: enabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Restrictive,
                requires_elevation: true,
            },
            title: "Systemd journal memory storage",
            summary: "systemd-journald supports volatile storage for the default journal instance.",
            rationale: "Persistent journal logs record command execution traces, process crashes, and user session metadata to disk, surviving across system shutdowns.",
            tradeoff: Some(
                "Volatile journal files do not survive reboot; existing persistent files or forwarded logs may remain.",
            ),
            mitigation: Some(
                "The running journal may remain queryable while available; forwarding, namespaces and other logging inputs require separate verification.",
            ),
            sources: &[Source {
                url: SYSTEMD_JOURNALD_URL,
                claim: "Documents v262 journal configuration and command-line overrides; files do not attest loaded state.",
                reviewed: "2026-10-11",
            }],
            probe: probe_systemd_journald,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "ubuntu.insights.consent".to_owned(),
                title: "Ubuntu Insights telemetry".to_owned(),
                section: "ubuntu".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-ubuntu",
                    vec![Predicate::DistributionIn(vec!["ubuntu".to_owned()])],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: true,
            },
            title: "Ubuntu Insights telemetry",
            summary: "Ubuntu Insights collects telemetry on packages, services, and hardware configuration.",
            rationale: "Structured configuration metrics are gathered and uploaded periodically to Canonical.",
            tradeoff: Some(
                "Canonical receives fewer fleet metrics on package and service utilization.",
            ),
            mitigation: Some(
                "Package installation, updates, and system operation are completely unaffected.",
            ),
            sources: &[Source {
                url: UBUNTU_INSIGHTS_URL,
                claim: "Consent lives in the insights consent state and system opt-out, not in a single opt-in file.",
                reviewed: "2026-10-20",
            }],
            probe: probe_ubuntu_insights,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "ubuntu.report.consent".to_owned(),
                title: "Ubuntu system metrics report".to_owned(),
                section: "ubuntu".to_owned(),
                dimension: PostureDimension::DiagnosticCrash,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new(
                    "linux-ubuntu",
                    vec![Predicate::DistributionIn(vec!["ubuntu".to_owned()])],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: true,
            },

            title: "Ubuntu system metrics report",
            summary: "Ubuntu transmits hardware metrics, installer performance, and system configuration.",
            rationale: "Ubuntu Report collects system specs, partition layouts, and machine attributes upon installation.",
            tradeoff: Some(
                "Canonical does not receive aggregate machine hardware distribution statistics.",
            ),
            mitigation: Some(
                "All package updates, repositories, and applications function normally.",
            ),
            sources: &[Source {
                url: UBUNTU_REPORT_URL,
                claim: "Documents Ubuntu Report. A metrics cache file is not the opt-out control.",
                reviewed: "2026-10-20",
            }],
            probe: probe_ubuntu_report,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "networkmanager.connectivity.check".to_owned(),
                title: "Network connectivity check".to_owned(),
                section: "networkmanager".to_owned(),
                dimension: PostureDimension::NetworkExposure,
                friction: FrictionTier::Tier1Cosmetic,
                applicability: Applicability::new(vec![Variant::new("linux", vec![])]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: false,
            },
            title: "Network connectivity check",
            summary: "NetworkManager can request a web page to decide whether a connection reaches the internet.",
            rationale: "An enabled connectivity URI is requested on network changes and reveals this machine's address and activity times to that server.",
            tradeoff: Some(
                "Captive-portal helpers and per-device route penalties lose NetworkManager's connectivity signal.",
            ),
            mitigation: Some(
                "Open a browser to the network sign-in page, or set connectivity.uri to a server you operate.",
            ),
            sources: &[Source {
                url: NETWORKMANAGER_CONF_URL,
                claim: "Documents connectivity.enabled, connectivity.uri, and conf.d precedence: /usr/lib, then /run, then NetworkManager.conf, then /etc/NetworkManager/conf.d, with same-name files shadowed by the higher directory. NetworkManager-intern.conf is read last.",
                reviewed: "2026-10-12",
            }],
            probe: probe_networkmanager_connectivity,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "avahi.mdns.publishing".to_owned(),
                title: "mDNS address publishing".to_owned(),
                section: "avahi".to_owned(),
                dimension: PostureDimension::NetworkExposure,
                friction: FrictionTier::Tier2WorkflowAltering,
                applicability: Applicability::new(vec![Variant::new("linux", vec![])]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
                requires_elevation: false,
            },
            title: "mDNS address publishing",
            summary: "avahi-daemon can announce this machine's hostname and addresses to the local network.",
            rationale: "Published mDNS records expose the hostname and addresses to every device on the link, including shared wireless networks.",
            tradeoff: Some(
                "Local service discovery and address records from this host stop being announced.",
            ),
            mitigation: Some(
                "Browse services from a client that already knows the host, or keep publishing limited to a trusted interface.",
            ),
            sources: &[Source {
                url: AVAHI_CONF_URL,
                claim: "Documents disable-publishing, publish-addresses, publish-hinfo, and publish-workstation in avahi-daemon.conf. Drop-ins under avahi-daemon.conf.d use the same /usr/lib, /run, then /etc shadowing order.",
                reviewed: "2026-10-12",
            }],
            probe: probe_avahi_publishing,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "systemd.resolved.llmnr".to_owned(),
                title: "LLMNR name resolution".to_owned(),
                section: "systemd".to_owned(),
                dimension: PostureDimension::NetworkExposure,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new("linux", vec![])]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: false,
            },
            title: "LLMNR name resolution",
            summary: "systemd-resolved can send and answer Link-Local Multicast Name Resolution on each link.",
            rationale: "LLMNR queries and responses broadcast names on the local network and can be answered by any peer.",
            tradeoff: Some("Single-label names that depend on LLMNR stop resolving."),
            mitigation: Some("Use DNS or an explicit host entry for names that must resolve."),
            sources: &[Source {
                url: RESOLVED_DBUS_URL,
                claim: "Documents the org.freedesktop.resolve1 Manager and Link LLMNR properties read from the system bus.",
                reviewed: "2026-10-12",
            }],
            probe: probe_resolved_llmnr,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "systemd.resolved.mdns".to_owned(),
                title: "Multicast DNS resolution".to_owned(),
                section: "systemd".to_owned(),
                dimension: PostureDimension::NetworkExposure,
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new("linux", vec![])]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: false,
            },
            title: "Multicast DNS resolution",
            summary: "systemd-resolved can resolve and answer multicast DNS on each link.",
            rationale: "mDNS queries leave the machine and responses identify it to other devices on the link.",
            tradeoff: Some(
                ".local names that depend on systemd-resolved multicast DNS stop resolving.",
            ),
            mitigation: Some(
                "Use unicast DNS, or a separate mDNS client whose publishing is reviewed on its own.",
            ),
            sources: &[Source {
                url: RESOLVED_DBUS_URL,
                claim: "Documents the org.freedesktop.resolve1 Manager and Link MulticastDNS properties read from the system bus.",
                reviewed: "2026-10-12",
            }],
            probe: probe_resolved_mdns,
            apply: None,
            rollback: None,
        },
    ];

    controls.sort_by(|a, b| {
        (a.spec.section.clone(), a.spec.id.clone())
            .cmp(&(b.spec.section.clone(), b.spec.id.clone()))
    });
    controls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_catalogue_is_sorted_by_section_then_identifier() {
        let controls = controls();
        let keys: Vec<(String, String)> = controls
            .iter()
            .map(|c| (c.spec.section.clone(), c.spec.id.clone()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn coredump_has_a_shared_tradeoff_tier_and_file_intent_never_becomes_a_recommendation() {
        use crate::model::posture::WorkloadPersona;
        use crate::platform::linux::systemd::ConfigurationFamily;
        let host = crate::test_context::host("arch", "hyprland");
        let reader = crate::test_context::configuration_reader(
            ConfigurationFamily::Coredump,
            b"[Coredump]\nStorage=external\n",
        );
        let context = crate::test_context::context(&host, &reader);
        let controls = controls();
        assert_eq!(controls.len(), 17);
        for (id, citation) in [
            ("networkmanager.connectivity.check", "networkmanager.dev"),
            ("avahi.mdns.publishing", "avahi-daemon.conf"),
            ("systemd.resolved.llmnr", "org.freedesktop.resolve1"),
            ("systemd.resolved.mdns", "org.freedesktop.resolve1"),
            ("freedesktop.thumbnails.caching", "thumbnail-spec"),
        ] {
            let control = controls
                .iter()
                .find(|control| control.spec.id == id)
                .unwrap();
            assert!(
                control
                    .sources
                    .iter()
                    .any(|source| source.url.contains(citation)),
                "{id}"
            );
        }
        let coredump = controls
            .iter()
            .find(|control| control.spec.id == "systemd.coredump.storage")
            .expect("compiled control");
        assert_eq!(
            coredump.spec.friction,
            FrictionTier::Tier3IncompatibleOrTradeoff
        );
        assert_eq!(coredump.observe(&context).state, None);
        for workload in [
            WorkloadPersona::General,
            WorkloadPersona::Developer,
            WorkloadPersona::HighAssurance,
        ] {
            assert!(
                !crate::engine::recommend::is_control_recommended_for_workload(
                    &coredump.spec,
                    workload,
                    Some(FrictionTier::Tier2WorkflowAltering),
                )
            );
            assert!(
                crate::engine::recommend::generate_recommendations(
                    std::slice::from_ref(coredump),
                    &context,
                    &host,
                    workload,
                    None,
                    None,
                )
                .is_empty()
            );
        }
    }
}
