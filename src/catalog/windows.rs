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
    vec![advertising_id()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::evaluate::{Mode, evaluate};
    use crate::model::outcome::{Exception, Outcome};
    use crate::platform;

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
