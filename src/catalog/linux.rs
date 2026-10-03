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
const FEDORA_ABRT_URL: &str = "https://github.com/abrt/doc/blob/master/conf.rst";
const KDE_USERFEEDBACK_URL: &str = "https://develop.kde.org/docs/administration/kiosk/keys/";
const SYSTEMD_COREDUMP_URL: &str =
    "https://manpages.debian.org/testing/systemd-coredump/systemd-coredump.conf.5.en.html";
const FREEDESKTOP_THUMBNAIL_URL: &str =
    "https://specifications.freedesktop.org/thumbnail-spec/thumbnail-spec-latest.html";
const FSTRIM_DOCS_URL: &str = "https://manpages.debian.org/testing/util-linux/fstrim.8.en.html";
const SYSTEMD_JOURNALD_URL: &str =
    "https://manpages.debian.org/testing/systemd/journald.conf.5.en.html";

/// Probe Debian popularity-contest configuration.
fn probe_debian_popcon(_ctx: &Context) -> Resolution {
    let path = std::path::Path::new("/etc/popularity-contest.conf");
    if !path.exists() {
        // When not installed or absent, the package does not participate.
        return Resolution::determined(disabled(), ManagementSource::Default);
    }
    match std::fs::read_to_string(path) {
        Ok(content) => {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("PARTICIPATE=") {
                    let val = trimmed.trim_start_matches("PARTICIPATE=").trim_matches('"');
                    if val.eq_ignore_ascii_case("no") {
                        return Resolution::determined(disabled(), ManagementSource::User);
                    }
                    return Resolution::determined(enabled(), ManagementSource::User);
                }
            }
            Resolution::determined(disabled(), ManagementSource::Default)
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Resolution::uncertain(Uncertainty::Denied, ManagementSource::User)
            } else {
                Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User)
            }
        }
    }
}

/// Probe Ubuntu Insights opt-in status.
fn probe_ubuntu_insights(_ctx: &Context) -> Resolution {
    let opt_in = std::path::Path::new("/etc/ubuntu-insights/opt-in");
    if opt_in.exists() {
        Resolution::determined(enabled(), ManagementSource::User)
    } else {
        Resolution::determined(disabled(), ManagementSource::Default)
    }
}

/// Probe Ubuntu Report telemetry status.
fn probe_ubuntu_report(_ctx: &Context) -> Resolution {
    if let Ok(home) = std::env::var("HOME") {
        let metrics = std::path::PathBuf::from(home).join(".cache/ubuntu-report/metrics.json");
        if metrics.exists() {
            return Resolution::determined(enabled(), ManagementSource::User);
        }
    }
    Resolution::determined(disabled(), ManagementSource::Default)
}

/// Probe Fedora ABRT automated reporting status.
fn probe_fedora_abrt(_ctx: &Context) -> Resolution {
    let conf = std::path::Path::new("/etc/abrt/abrt-action-save-package-data.conf");
    if !conf.exists() {
        return Resolution::determined(disabled(), ManagementSource::Default);
    }
    match std::fs::read_to_string(conf) {
        Ok(content) => {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("AutoreportingEvent") && trimmed.contains("none") {
                    return Resolution::determined(disabled(), ManagementSource::LocalPolicy);
                }
            }
            Resolution::determined(enabled(), ManagementSource::LocalPolicy)
        }
        Err(_) => Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::LocalPolicy),
    }
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

/// Probe KDE UserFeedback telemetry level.
fn probe_kde_feedback(_ctx: &Context) -> Resolution {
    if let Ok(home) = std::env::var("HOME") {
        let conf = std::path::PathBuf::from(home).join(".config/KDE/UserFeedback.conf");
        if let Ok(content) = std::fs::read_to_string(&conf) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("FeedbackLevel=") {
                    let level = trimmed.trim_start_matches("FeedbackLevel=");
                    if level == "0" {
                        return Resolution::determined(disabled(), ManagementSource::User);
                    }
                    return Resolution::determined(enabled(), ManagementSource::User);
                }
            }
        }
    }
    Resolution::determined(disabled(), ManagementSource::Default)
}

/// Probe systemd core dump persistence.
fn probe_systemd_coredump(_ctx: &Context) -> Resolution {
    let conf = std::path::Path::new("/etc/systemd/coredump.conf");
    if !conf.exists() {
        return Resolution::determined(enabled(), ManagementSource::Default);
    }
    match std::fs::read_to_string(conf) {
        Ok(content) => {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Storage=") {
                    let val = trimmed.trim_start_matches("Storage=").trim();
                    if val.eq_ignore_ascii_case("none") {
                        return Resolution::determined(disabled(), ManagementSource::LocalPolicy);
                    }
                    return Resolution::determined(enabled(), ManagementSource::LocalPolicy);
                }
            }
            Resolution::determined(enabled(), ManagementSource::Default)
        }
        Err(_) => Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::LocalPolicy),
    }
}

/// Probe FreeDesktop thumbnail caching.
fn probe_freedesktop_thumbnails(_ctx: &Context) -> Resolution {
    Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User)
}

/// Probe systemd fstrim timer status.
fn probe_systemd_fstrim(_ctx: &Context) -> Resolution {
    for path in [
        "/etc/systemd/system/timers.target.wants/fstrim.timer",
        "/lib/systemd/system/timers.target.wants/fstrim.timer",
        "/usr/lib/systemd/system/timers.target.wants/fstrim.timer",
    ] {
        if std::path::Path::new(path).exists() {
            return Resolution::determined(enabled(), ManagementSource::LocalPolicy);
        }
    }
    Resolution::determined(disabled(), ManagementSource::Default)
}

/// Probe systemd-journald volatile storage.
fn probe_systemd_journald(_ctx: &Context) -> Resolution {
    let conf = std::path::Path::new("/etc/systemd/journald.conf");
    if !conf.exists() {
        return Resolution::determined(disabled(), ManagementSource::Default);
    }
    match std::fs::read_to_string(conf) {
        Ok(content) => {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Storage=") {
                    let val = trimmed.trim_start_matches("Storage=").trim();
                    if val.eq_ignore_ascii_case("volatile") {
                        return Resolution::determined(enabled(), ManagementSource::LocalPolicy);
                    }
                    return Resolution::determined(disabled(), ManagementSource::LocalPolicy);
                }
            }
            Resolution::determined(disabled(), ManagementSource::Default)
        }
        Err(_) => Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::LocalPolicy),
    }
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
            sources: &[Source {
                url: DEBIAN_POPCON_URL,
                claim: "Documents popularity-contest survey participation.",
                reviewed: "2026-09-21",
            }],
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
                claim: "Documents ABRT automated crash reporting configuration.",
                reviewed: "2026-09-21",
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
                applicability: Applicability::new(vec![Variant::new(
                    "linux-desktop",
                    vec![Predicate::LiveSession(true)],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
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
                claim: "Documents FreeDesktop Thumbnail Management Standard.",
                reviewed: "2026-10-01",
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
            },

            title: "KDE Plasma user feedback",
            summary: "KDE applications collect software usage and system telemetry.",
            rationale: "KDE UserFeedback periodically uploads telemetry from desktop applications.",
            tradeoff: Some("KDE developers receive less telemetry on desktop component usage."),
            mitigation: Some(
                "KDE Plasma desktop and applications function identically without feedback.",
            ),
            sources: &[Source {
                url: KDE_USERFEEDBACK_URL,
                claim: "Documents KDE UserFeedback configuration keys.",
                reviewed: "2026-09-21",
            }],
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
                friction: FrictionTier::Tier0Transparent,
                applicability: Applicability::new(vec![Variant::new("linux-systemd", vec![])]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
                min_profile: Profile::Strict,
            },
            title: "Systemd core dump persistence",
            summary: "systemd-coredump records process memory dumps to disk when applications crash.",
            rationale: "Crash dumps store full process memory contents, which can expose passwords, encryption keys, decrypted tokens, and sensitive document text.",
            tradeoff: Some(
                "Developers and administrators cannot inspect post-crash core dumps for offline debugging.",
            ),
            mitigation: Some(
                "Crash stack traces and backtraces remain logged in systemd-journald.",
            ),
            sources: &[Source {
                url: SYSTEMD_COREDUMP_URL,
                claim: "Documents systemd-coredump storage configuration.",
                reviewed: "2026-10-01",
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
            sources: &[Source {
                url: FSTRIM_DOCS_URL,
                claim: "Documents systemd fstrim service and timer discard operations.",
                reviewed: "2026-10-01",
            }],
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
            },
            title: "Systemd journal memory storage",
            summary: "systemd-journald stores system event logs in volatile memory instead of persistent disk files.",
            rationale: "Persistent journal logs record command execution traces, process crashes, and user session metadata to disk, surviving across system shutdowns.",
            tradeoff: Some("System logs are lost when the system is rebooted or powered down."),
            mitigation: Some(
                "Real-time system logging and journalctl query commands remain fully functional during the active session.",
            ),
            sources: &[Source {
                url: SYSTEMD_JOURNALD_URL,
                claim: "Documents systemd-journald volatile storage configuration.",
                reviewed: "2026-10-01",
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
                claim: "Documents Ubuntu Insights opt-in mechanism.",
                reviewed: "2026-09-21",
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
                claim: "Documents Ubuntu Report opt-out mechanism.",
                reviewed: "2026-09-21",
            }],
            probe: probe_ubuntu_report,
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
}
