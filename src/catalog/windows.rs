//! Windows control definitions.
//!
//! Each probe owns its own registry targets. Nothing outside this module can
//! name a path, a value, or a view.
//!
//! Binding rule: the ordinary setting value is the primary source and the
//! policy form is a secondary source consulted for precedence. Doing it the
//! other way round produces a control that is inert on the editions people
//! actually run, because many documented policies apply only to Enterprise,
//! Education, and Server.

use super::{Control, Source};
use crate::engine::evaluate::{ControlSpec, Resolution, SemanticState, Uncertainty};
use crate::model::applicability::{Applicability, Predicate, Variant};
use crate::model::evidence::{Evidence, Observation, RawValue};
use crate::model::host::{HostFacts, ManagementSource, Platform};
use crate::model::outcome::{Maturity, Remediation, Reversibility};
use crate::platform::windows::registry::{self, Hive, Target, View};

fn enabled() -> SemanticState {
    SemanticState::new("enabled")
}

fn disabled() -> SemanticState {
    SemanticState::new("disabled")
}

/// The per-user advertising identifier setting.
///
/// Zero means the identifier is off. Absent means on, because Windows enables
/// it by default.
const ADVERTISING_USER: Target = Target::new(
    Hive::CurrentUser,
    r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
    "Enabled",
    View::Native,
);

/// The policy form of the same setting.
///
/// Note the inverted polarity against the user setting above: here one means
/// the identifier is off, whereas in the user setting zero means off. Two value
/// names for one semantic state, with opposite senses, is exactly the trap that
/// makes a naive "zero is private" assumption wrong. Each source is decoded by
/// its own function rather than a shared convention.
const ADVERTISING_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
    "DisabledByGroupPolicy",
    View::Native,
);

fn decode_user_setting(value: &RawValue) -> Option<SemanticState> {
    match value.as_u32()? {
        0 => Some(disabled()),
        1 => Some(enabled()),
        // A value outside the documented set is not evidence of either state.
        _ => None,
    }
}

fn decode_policy(value: &RawValue) -> Option<SemanticState> {
    match value.as_u32()? {
        1 => Some(disabled()),
        0 => Some(enabled()),
        _ => None,
    }
}

/// Resolve the advertising identifier state.
///
/// The policy form is consulted first because it overrides the user setting
/// where it is present, then the user setting, which is the source that
/// actually governs on an unmanaged machine.
fn probe_advertising_id(_host: &HostFacts) -> Resolution {
    let policy = registry::read(&ADVERTISING_POLICY, ManagementSource::GroupPolicy);

    // A present policy value governs. Absent policy is not a finding: it simply
    // means the user setting decides.
    if let Evidence::Present { value, .. } = &policy {
        return match decode_policy(value) {
            Some(state) => Resolution::determined(state, ManagementSource::GroupPolicy),
            None => Resolution::uncertain(Uncertainty::Malformed, ManagementSource::GroupPolicy),
        };
    }
    // A policy we were not allowed to read might be governing this value, so we
    // cannot fall through to the user setting and claim to know the answer.
    if !policy.is_conclusive() {
        return Resolution::uncertain(Uncertainty::Denied, ManagementSource::GroupPolicy);
    }

    let user = registry::read(&ADVERTISING_USER, ManagementSource::User);
    let observation = Observation::new(vec![user]);
    Resolution::from_observation(
        &observation,
        &[ManagementSource::User],
        decode_user_setting,
        // Windows enables the advertising identifier by default, so an absent
        // value means on, not off.
        &enabled(),
    )
}

// Diagnostic data.
//
// The value zero is documented as applying only to Enterprise, Education, and
// Server. Microsoft states that using it elsewhere is "equivalent to setting
// the value of 1". On every other edition the write succeeds, the value reads
// back as zero, and the machine sends required diagnostic data regardless.
//
// This is the single most common false pass in this category, and this control
// exists as much to demonstrate it as to check it.

/// Editions that honor the lowest diagnostic level.
///
/// Enumerated rather than negated, so a future edition is treated as not
/// honoring it until someone checks, which is the safe direction.
const EDITIONS_HONORING_SECURITY_LEVEL: &[&str] = &[
    "Enterprise",
    "EnterpriseS",
    "EnterpriseG",
    "IoTEnterprise",
    "Education",
    "EnterpriseSN",
    "ServerStandard",
    "ServerDatacenter",
];

/// The policy form, which an administrator or management sets.
const DIAGNOSTICS_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "AllowTelemetry",
    View::Native,
);

/// The form the settings interface and most tools write.
const DIAGNOSTICS_SETTING: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    "AllowTelemetry",
    View::Native,
);

fn diagnostics_state(level: u32) -> Option<SemanticState> {
    match level {
        0 => Some(SemanticState::new("security")),
        1 => Some(SemanticState::new("required")),
        2 => Some(SemanticState::new("enhanced")),
        3 => Some(SemanticState::new("optional")),
        _ => None,
    }
}

fn honors_security_level(host: &HostFacts) -> Option<bool> {
    host.edition.known().map(|edition| {
        EDITIONS_HONORING_SECURITY_LEVEL
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(edition))
    })
}

/// Resolve the effective diagnostic level, accounting for edition gating.
fn probe_diagnostics_level(host: &HostFacts) -> Resolution {
    let mut configured: Option<(u32, ManagementSource)> = None;

    for (target, source) in [
        (&DIAGNOSTICS_POLICY, ManagementSource::GroupPolicy),
        (&DIAGNOSTICS_SETTING, ManagementSource::LocalPolicy),
    ] {
        match registry::read(target, source) {
            Evidence::Present { value, .. } => match value.as_u32() {
                Some(level) => {
                    configured = Some((level, source));
                    break;
                }
                None => return Resolution::uncertain(Uncertainty::Malformed, source),
            },
            Evidence::Absent { .. } => {}
            // A source we could not read might be the one governing this value.
            _ => return Resolution::uncertain(Uncertainty::Denied, source),
        }
    }

    // Absent everywhere means the platform default governs, which is the full
    // optional level on consumer editions.
    let Some((level, source)) = configured else {
        return Resolution::determined(SemanticState::new("optional"), ManagementSource::Default);
    };

    let Some(state) = diagnostics_state(level) else {
        return Resolution::uncertain(Uncertainty::Malformed, source);
    };

    if level != 0 {
        return Resolution::determined(state, source);
    }

    // The gated case. What is configured and what the platform acts on differ.
    match honors_security_level(host) {
        Some(true) => Resolution::determined(state, source),
        Some(false) => Resolution::determined(SemanticState::new("required"), source).with_note(
            "A level of 0 is configured, but this Windows edition does not honor it.              Microsoft documents value 0 as applying only to Enterprise, Education, and              Server, and as equivalent to 1 elsewhere. This machine sends required              diagnostic data.",
        ),
        // Without knowing the edition we cannot say which of two different
        // states is in effect, and guessing either way would be a false claim.
        None => Resolution::uncertain(Uncertainty::Undetermined, source),
    }
}

fn diagnostics_level() -> Control {
    Control {
        spec: ControlSpec {
            id: "windows.diagnostics.level".to_owned(),
            title: "Diagnostic data level".to_owned(),
            section: "diagnostics".to_owned(),
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            // The lowest level ordinary editions actually honor. Asking for
            // less would mean reporting drift no operator could ever clear.
            desired: SemanticState::new("required"),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            verified_through: None,
            remediation: Remediation::AuditOnly,
            remediation_reason: None,
        },
        title: "Diagnostic data level",
        summary: "Windows sends diagnostic data about how the machine and its apps                   behave. The optional level adds browsing and typing activity,                   inventory, and memory captured when something crashes.",
        rationale: "Microsoft's own field lists for the optional level include text                     typed in the address bar and search box, available network names,                     the device serial number, files identified as a possible cause of a                     crash, and memory dumps that can contain everything in use at the                     time. The required level is the floor on ordinary editions.",
        tradeoff: Some(
            "Microsoft receives less information about faults you encounter, which              can mean a problem specific to your setup takes longer to be noticed.",
        ),
        mitigation: Some(
            "Local crash diagnosis is unaffected. Reliability history and the event              log continue to work, and you can still report a problem deliberately.",
        ),
        sources: &[
            Source {
                url: "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system",
                claim: "States that value 0 applies only to Enterprise, Education, and                         Server, and is equivalent to 1 on other editions.",
                reviewed: "2026-09-07",
            },
            Source {
                url: "https://learn.microsoft.com/windows/privacy/windows-diagnostic-data",
                claim: "Enumerates the data types collected at the optional level.",
                reviewed: "2026-09-07",
            },
        ],
        probe: probe_diagnostics_level,
    }
}

fn advertising_id() -> Control {
    Control {
        spec: ControlSpec {
            id: "windows.advertising.id".to_owned(),
            title: "Advertising identifier".to_owned(),
            section: "advertising".to_owned(),
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            desired: disabled(),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            // Read-only for now. Remediation arrives with the transaction
            // journal, not before.
            verified_through: None,
            remediation: Remediation::AuditOnly,
            remediation_reason: None,
        },
        title: "Advertising identifier",
        summary: "Windows gives apps a per-user identifier so advertising you see \
                  can be linked across different apps.",
        rationale: "The identifier lets separate applications correlate what you do \
                    into one profile. Turning it off does not reduce the number of \
                    ads, it removes the shared key that links them together.",
        tradeoff: Some("Advertising becomes less relevant to you."),
        mitigation: Some(
            "Nothing else depends on this identifier. Apps continue to work \
             normally and you can turn it back on at any time.",
        ),
        sources: &[Source {
            url: "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy",
            claim: "Documents the advertising identifier setting and its policy form.",
            reviewed: "2026-09-07",
        }],
        probe: probe_advertising_id,
    }
}

/// Every Windows control, in stable sorted order by identifier.
pub fn controls() -> Vec<Control> {
    vec![advertising_id(), diagnostics_level()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::evaluate::{Mode, evaluate};
    use crate::model::host::{
        Architecture, ContainerKind, Fact, OsVersion, SessionFacts, WriteModel,
    };
    use crate::model::outcome::{Exception, Outcome};
    use crate::platform;

    fn windows_host() -> HostFacts {
        HostFacts {
            platform: Platform::Windows,
            version: Fact::Known(OsVersion::new(vec![10, 0, 26100], "10.0.26100")),
            architecture: Fact::Known(Architecture::X86_64),
            edition: Fact::Known("Professional".to_owned()),
            distribution: Fact::NotPresent,
            managed: Fact::Unknown,
            write_model: Fact::Known(WriteModel::Mutable),
            container: Fact::Known(ContainerKind::None),
            session: SessionFacts::not_present(),
            elevated: Fact::Known(false),
        }
    }

    #[test]
    fn the_lowest_diagnostic_level_is_gated_by_edition() {
        // The case this project exists for. Microsoft documents value 0 as
        // applying only to Enterprise, Education, and Server, and as equivalent
        // to 1 elsewhere. Reporting it as the security level on any other
        // edition is the most common false pass in this category.
        let mut host = windows_host();

        host.edition = Fact::Known("Enterprise".to_owned());
        assert_eq!(honors_security_level(&host), Some(true));

        for ordinary in [
            "Professional",
            "Core",
            "CoreSingleLanguage",
            "ProfessionalN",
        ] {
            host.edition = Fact::Known(ordinary.to_owned());
            assert_eq!(
                honors_security_level(&host),
                Some(false),
                "{ordinary} must not be treated as honoring level 0"
            );
        }
    }

    #[test]
    fn an_unrecognised_edition_is_assumed_not_to_honor_the_lowest_level() {
        // Enumerated rather than negated, so an edition nobody has checked is
        // treated as not honoring it until someone does.
        let mut host = windows_host();
        host.edition = Fact::Known("SomeFutureEdition".to_owned());
        assert_eq!(honors_security_level(&host), Some(false));
    }

    #[test]
    fn an_unknown_edition_leaves_the_level_undetermined() {
        // Without the edition, two different states are possible and neither
        // may be claimed.
        let mut host = windows_host();
        host.edition = Fact::Unknown;
        assert_eq!(honors_security_level(&host), None);
    }

    #[test]
    fn diagnostic_levels_map_to_documented_states_only() {
        assert_eq!(diagnostics_state(0), Some(SemanticState::new("security")));
        assert_eq!(diagnostics_state(1), Some(SemanticState::new("required")));
        assert_eq!(diagnostics_state(2), Some(SemanticState::new("enhanced")));
        assert_eq!(diagnostics_state(3), Some(SemanticState::new("optional")));
        // A value outside the documented set is not evidence of any level.
        assert_eq!(diagnostics_state(4), None);
        assert_eq!(diagnostics_state(99), None);
    }

    #[test]
    fn the_two_sources_use_opposite_polarity() {
        // The trap this control exists to demonstrate. The same semantic state
        // is one value in the policy and the other in the user setting, so a
        // shared decoder would invert one of them.
        assert_eq!(decode_user_setting(&RawValue::u32(0)), Some(disabled()));
        assert_eq!(decode_policy(&RawValue::u32(0)), Some(enabled()));

        assert_eq!(decode_user_setting(&RawValue::u32(1)), Some(enabled()));
        assert_eq!(decode_policy(&RawValue::u32(1)), Some(disabled()));
    }

    #[test]
    fn an_undocumented_value_decodes_to_nothing() {
        // Neither state, so the caller reports malformed rather than guessing.
        assert_eq!(decode_user_setting(&RawValue::u32(7)), None);
        assert_eq!(decode_policy(&RawValue::u32(7)), None);
    }

    #[test]
    fn a_value_of_the_wrong_type_decodes_to_nothing() {
        use crate::model::evidence::ValueKind;
        let text = RawValue::new(ValueKind::String, b"0\0".to_vec());
        assert_eq!(decode_user_setting(&text), None);
    }

    #[test]
    fn probing_diagnostics_on_this_machine_is_conclusive() {
        let host = platform::discover();
        let resolution = probe_diagnostics_level(&host);
        assert!(
            resolution.state.is_some(),
            "diagnostic level was not determined: {resolution:?}"
        );
    }

    #[test]
    fn a_gated_level_reports_what_the_platform_does_and_says_so() {
        // If this machine has the gated value configured, the reported state
        // must be what the platform acts on, and the discrepancy must be
        // stated rather than left for the operator to discover.
        let host = platform::discover();
        let resolution = probe_diagnostics_level(&host);

        if resolution.note.is_some() {
            assert_eq!(
                resolution.state,
                Some(SemanticState::new("required")),
                "a gated level must report the level actually in effect"
            );
            let note = resolution.note.as_deref().unwrap_or_default();
            assert!(note.contains("does not honor"), "note does not explain");
        }
    }

    #[test]
    fn probing_this_machine_produces_a_determined_state() {
        // An integration check against the real registry. Whatever this machine
        // holds, the answer must be conclusive rather than an error, because
        // both the present and absent cases are documented.
        let host = platform::discover();
        let resolution = probe_advertising_id(&host);

        assert!(
            resolution.state.is_some(),
            "advertising identifier state was not determined: {resolution:?}"
        );
        assert!(resolution.honored);
    }

    #[test]
    fn the_control_evaluates_end_to_end_on_this_machine() {
        let host = platform::discover();
        let control = advertising_id();
        let resolution = control.observe(&host);
        let result = evaluate(
            &control.spec,
            Mode::Enforce,
            &resolution,
            &host,
            Exception::None,
        );

        assert_eq!(result.id, "windows.advertising.id");
        assert_eq!(result.section, "advertising");
        // The state is known, so this must be a real finding rather than an
        // unknown, and it must be one of the two evaluated outcomes.
        assert!(
            matches!(result.outcome, Outcome::Pass | Outcome::Drift),
            "expected a finding, got {:?}",
            result.outcome
        );
        assert!(result.is_coherent());
    }
}
