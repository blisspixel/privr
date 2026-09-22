//! macOS control definitions.
//!
//! Evaluates privacy and security controls for macOS (analytics,
//! advertising, and Siri data retention).

use super::{Context, Control, Source};
use crate::engine::evaluate::{ControlSpec, Resolution, SemanticState, Uncertainty};
use crate::model::applicability::{Applicability, Predicate, Variant};
use crate::model::host::{ManagementSource, Platform};
use crate::model::outcome::{Maturity, Remediation, Reversibility};

fn disabled() -> SemanticState {
    SemanticState::new("disabled")
}

const APPLE_RESTRICTIONS_URL: &str =
    "https://support.apple.com/guide/deployment/restrictions-for-mac-depba790e53/web";
const MAC_ANALYTICS_URL: &str = "https://support.apple.com/guide/mac-help/mh27990/mac";
const SIRI_PRIVACY_URL: &str = "https://support.apple.com/en-us/127070";

fn probe_macos_analytics(_ctx: &Context) -> Resolution {
    let path = std::path::Path::new(
        "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist",
    );
    if let Ok(content) = std::fs::read_to_string(path)
        && content.contains("<key>AutoSubmit</key>")
        && content.contains("<false/>")
    {
        return Resolution::determined(disabled(), ManagementSource::LocalPolicy);
    }
    Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User)
}

fn probe_macos_unmanaged_guided(_ctx: &Context) -> Resolution {
    Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User)
}

/// Return all macOS controls, sorted by identifier.
pub fn controls() -> Vec<Control> {
    let mut controls = vec![
        Control {
            spec: ControlSpec {
                id: "macos.advertising.personalized".to_owned(),
                title: "Personalized advertising".to_owned(),
                section: "advertising".to_owned(),
                applicability: Applicability::new(vec![Variant::new(
                    "macos",
                    vec![Predicate::Platform(Platform::Macos)],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
            },
            title: "Personalized advertising",
            summary: "Apple personalizes ads in the App Store, Apple News, and Stocks.",
            rationale: "Personalized advertising targets ads using device activity, downloads, and interest segments.",
            tradeoff: Some(
                "Ads displayed in Apple apps become contextual rather than personalized.",
            ),
            mitigation: Some(
                "The volume of ads is unchanged; ads are simply not targeted to your device history.",
            ),
            sources: &[Source {
                url: APPLE_RESTRICTIONS_URL,
                claim: "Documents personalized advertising restriction.",
                reviewed: "2026-09-21",
            }],
            probe: probe_macos_unmanaged_guided,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "macos.analytics.share-mac".to_owned(),
                title: "Mac analytics and diagnostics".to_owned(),
                section: "analytics".to_owned(),
                applicability: Applicability::new(vec![Variant::new(
                    "macos",
                    vec![Predicate::Platform(Platform::Macos)],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
            },
            title: "Mac analytics and diagnostics",
            summary: "macOS automatically uploads diagnostic, performance, and usage data to Apple.",
            rationale: "Diagnostic submission transmits daily usage telemetry, system events, and crash traces to Apple.",
            tradeoff: Some(
                "Apple receives fewer automatic diagnostic reports for proactive fault triage.",
            ),
            mitigation: Some(
                "Local crash reports remain accessible in Console.app and /Library/Logs/DiagnosticReports/.",
            ),
            sources: &[Source {
                url: MAC_ANALYTICS_URL,
                claim: "Documents Mac analytics and usage data sharing.",
                reviewed: "2026-09-21",
            }],
            probe: probe_macos_analytics,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "macos.analytics.share-with-developers".to_owned(),
                title: "Third-party developer analytics".to_owned(),
                section: "analytics".to_owned(),
                applicability: Applicability::new(vec![Variant::new(
                    "macos",
                    vec![Predicate::Platform(Platform::Macos)],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
            },
            title: "Third-party developer analytics",
            summary: "macOS shares application usage and crash metrics with third-party software developers.",
            rationale: "Sharing developer analytics transmits crash dumps and usage statistics through App Store Connect.",
            tradeoff: Some("Application developers do not receive automated crash metrics."),
            mitigation: Some(
                "You can share crash logs directly with developers when troubleshooting issues.",
            ),
            sources: &[Source {
                url: MAC_ANALYTICS_URL,
                claim: "Documents developer analytics sharing.",
                reviewed: "2026-09-21",
            }],
            probe: probe_macos_unmanaged_guided,
            apply: None,
            rollback: None,
        },
        Control {
            spec: ControlSpec {
                id: "macos.siri.improvement".to_owned(),
                title: "Improve Siri and Dictation".to_owned(),
                section: "siri".to_owned(),
                applicability: Applicability::new(vec![Variant::new(
                    "macos",
                    vec![Predicate::Platform(Platform::Macos)],
                )]),
                desired: disabled(),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: Remediation::AuditOnly,
                remediation_reason: None,
            },
            title: "Improve Siri and Dictation",
            summary: "Apple retains and human-reviews audio samples of interactions with Siri.",
            rationale: "Siri improvement stores voice recordings and query transcripts for human grading.",
            tradeoff: Some("Voice samples are excluded from Apple's model improvement pipelines."),
            mitigation: Some(
                "Siri and speech dictation continue to operate normally on-device and in cloud processing.",
            ),
            sources: &[Source {
                url: SIRI_PRIVACY_URL,
                claim: "Documents Siri and Dictation data sharing opt-out.",
                reviewed: "2026-09-21",
            }],
            probe: probe_macos_unmanaged_guided,
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
    fn macos_catalogue_is_sorted_by_section_then_identifier() {
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
