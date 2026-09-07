//! Evaluation: a pure function from a control, a resolution, and host facts to
//! a result.
//!
//! Nothing here touches the operating system. Adapters produce [`Resolution`]
//! values from raw evidence, and fixtures produce the same type, so there is no
//! separate fake that can drift from the real probe.
//!
//! Every rule in this module exists to stop one specific way of reporting a
//! machine as compliant when it is not.

use serde::{Deserialize, Serialize};

use crate::model::applicability::{Applicability, Applies};
use crate::model::evidence::Observation;
use crate::model::host::{HostFacts, ManagementSource, OsVersion};
use crate::model::outcome::{
    ControlResult, Effect, Exception, Ineffective, Maturity, Outcome, Remediation,
    RemediationReason, Reversibility, Support,
};

/// A semantic state, such as `disabled` or `required_only`.
///
/// Adapters own the mapping between raw platform values and these names, so the
/// engine compares intent rather than encodings.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SemanticState(pub String);

impl SemanticState {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// Why an effective state could not be determined.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Uncertainty {
    /// A source refused access.
    Denied,
    /// A value was present but of an unexpected type.
    Malformed,
    /// The reading interface is absent on this host.
    Unsupported,
    /// The probe could not conclude.
    Undetermined,
    /// Only the enforcement mechanism was readable, not the setting itself.
    ///
    /// Checking that a policy object or management payload exists is not
    /// checking the setting. Treating the two as equivalent fails a correctly
    /// configured unmanaged machine.
    EnforcementMechanismOnly,
}

/// What an adapter concluded from an observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Resolution {
    /// The effective semantic state, when it could be determined.
    pub state: Option<SemanticState>,
    /// Which authority governs the effective value.
    pub source: ManagementSource,
    /// Why the state is not determined. Present exactly when `state` is absent.
    pub uncertainty: Option<Uncertainty>,
    /// Whether the platform actually acts on this setting here.
    ///
    /// A policy value that writes and reads back on an edition that ignores it
    /// is the most common false pass in this category.
    pub honored: bool,
    /// When a verified change would take effect.
    pub effect: Effect,
    /// Why what is configured is not what the platform acts on.
    pub ineffective: Option<Ineffective>,
    /// A fact about this reading the operator must be told.
    ///
    /// Used where the state is determined but a naive reading of the
    /// configuration would mislead, most importantly where a configured value
    /// is not the value the platform acts on. The tool supplies the sentence
    /// rather than relying on a caller to notice and add a caveat.
    pub note: Option<String>,
}

impl Resolution {
    pub fn determined(state: SemanticState, source: ManagementSource) -> Self {
        Self {
            state: Some(state),
            source,
            uncertainty: None,
            honored: true,
            effect: Effect::Active,
            note: None,
            ineffective: None,
        }
    }

    /// Record that the configured value is not the value in effect.
    ///
    /// Takes both the typed reason and the sentence, because a caller needs to
    /// branch on one and an operator needs to read the other.
    #[must_use]
    pub fn configured_but_ineffective(
        mut self,
        reason: Ineffective,
        note: impl Into<String>,
    ) -> Self {
        self.ineffective = Some(reason);
        self.note = Some(note.into());
        self
    }

    pub fn uncertain(uncertainty: Uncertainty, source: ManagementSource) -> Self {
        Self {
            state: None,
            source,
            uncertainty: Some(uncertainty),
            honored: true,
            effect: Effect::Active,
            note: None,
            ineffective: None,
        }
    }

    /// A state that reads back correctly but that the platform ignores here.
    pub fn inert(state: SemanticState, source: ManagementSource) -> Self {
        Self {
            state: Some(state),
            source,
            uncertainty: None,
            honored: false,
            effect: Effect::Active,
            note: None,
            ineffective: None,
        }
    }

    /// Build a resolution from an observation using a control's source order.
    ///
    /// Precedence is per control. There is no universal ordering across policy,
    /// management, and preference sources, so the control declares which
    /// authorities it consults and in what order.
    pub fn from_observation(
        observation: &Observation,
        precedence: &[ManagementSource],
        decode: impl Fn(&crate::model::evidence::RawValue) -> Option<SemanticState>,
        absent_means: &SemanticState,
    ) -> Self {
        use crate::model::evidence::Evidence;

        for wanted in precedence {
            let Some(evidence) = observation
                .evidence
                .iter()
                .find(|item| item.source() == *wanted)
            else {
                continue;
            };

            let resolved = match evidence {
                Evidence::Present { source, value } => match decode(value) {
                    Some(state) => Self {
                        state: Some(state),
                        source: *source,
                        uncertainty: None,
                        honored: observation.honored_by_platform,
                        effect: Effect::Active,
                        note: None,
                        ineffective: None,
                    },
                    // A value we cannot interpret is malformed evidence, never
                    // a fallback to the documented default.
                    None => Self::uncertain(Uncertainty::Malformed, *source),
                },
                Evidence::Absent { source } => Self {
                    state: Some(absent_means.clone()),
                    source: *source,
                    uncertainty: None,
                    honored: observation.honored_by_platform,
                    effect: Effect::Active,
                    note: None,
                    ineffective: None,
                },
                Evidence::Denied { source, .. } => Self::uncertain(Uncertainty::Denied, *source),
                Evidence::Malformed { source, .. } => {
                    Self::uncertain(Uncertainty::Malformed, *source)
                }
                Evidence::Unsupported { source } => {
                    Self::uncertain(Uncertainty::Unsupported, *source)
                }
                Evidence::Undetermined { source, .. } => {
                    Self::uncertain(Uncertainty::Undetermined, *source)
                }
            };

            return Self {
                honored: observation.honored_by_platform,
                ..resolved
            };
        }

        Self::uncertain(Uncertainty::Undetermined, ManagementSource::Unknown)
    }
}

/// What the policy asks of a control.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Compare against the desired value and report drift.
    Enforce,
    /// Report current state and tradeoffs without treating the choice as drift.
    Review,
    /// Do not evaluate unless explicitly selected.
    Ignore,
}

/// The subset of a control definition the evaluator needs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlSpec {
    pub id: String,
    pub title: String,
    pub section: String,
    pub applicability: Applicability,
    pub desired: SemanticState,
    pub reversibility: Reversibility,
    pub maturity: Maturity,
    /// The newest platform version this control was verified against.
    ///
    /// A host beyond this range degrades support rather than reporting a
    /// result, so a neglected catalogue becomes cautious instead of wrong.
    pub verified_through: Option<OsVersion>,
    /// Remediation when everything is verified and the control is eligible.
    pub remediation: Remediation,
    /// Required when `remediation` is `None`.
    pub remediation_reason: Option<RemediationReason>,
}

/// Evaluate one control.
pub fn evaluate(
    spec: &ControlSpec,
    mode: Mode,
    resolution: &Resolution,
    host: &HostFacts,
    exception: Exception,
) -> ControlResult {
    let build =
        |outcome: Outcome, support: Support, remediation: Remediation, reason| ControlResult {
            id: spec.id.clone(),
            title: spec.title.clone(),
            section: spec.section.clone(),
            outcome,
            management_source: resolution.source,
            remediation,
            remediation_reason: reason,
            support,
            reversibility: spec.reversibility,
            maturity: spec.maturity,
            effect: resolution.effect,
            exception,
            note: resolution.note.clone(),
            ineffective: resolution.ineffective,
        };

    // A control the profile does not select is reported, not omitted. Silence
    // and exclusion are different facts, and only one of them is honest.
    if mode == Mode::Ignore {
        return build(
            Outcome::NotSelected,
            Support::Verified,
            Remediation::None,
            Some(RemediationReason::ExcludedByPolicy),
        );
    }

    match spec.applicability.resolve(host).applies {
        Applies::No => {
            return build(
                Outcome::NotApplicable,
                Support::Unsupported,
                Remediation::None,
                Some(RemediationReason::PlatformLimitation),
            );
        }
        // Undetermined applicability is never not-applicable. The operator
        // would believe the control had been checked.
        Applies::Undetermined => {
            return build(
                Outcome::Unknown,
                Support::Unverified,
                Remediation::AuditOnly,
                None,
            );
        }
        Applies::Yes => {}
    }

    // Staleness. A host past the reviewed range loses verified support, so it
    // can no longer report a pass and cannot be remediated automatically.
    let stale = match (&spec.verified_through, host.version.known()) {
        (Some(ceiling), Some(actual)) => actual.at_least(ceiling) && actual != ceiling,
        // A host whose version is unknown is not assumed to be in range.
        (Some(_), None) => true,
        (None, _) => false,
    };

    // The edition-gating case. The value is present, reads back exactly as
    // written, and the platform does not act on it. Reporting this as
    // compliant is the most common false pass in this category.
    if !resolution.honored {
        return build(
            Outcome::NotApplicable,
            Support::Unsupported,
            Remediation::None,
            Some(RemediationReason::PlatformLimitation),
        );
    }

    let support = if stale {
        Support::Unverified
    } else {
        Support::Verified
    };

    // Anything short of a determined state is unknown. It is never a pass, and
    // it is never silently treated as the documented default.
    let Some(state) = resolution.state.as_ref() else {
        return build(Outcome::Unknown, support, Remediation::AuditOnly, None);
    };

    // A manual control cannot produce a machine-derived finding, so it reports
    // for review regardless of what was observed.
    if spec.maturity == Maturity::Manual {
        return build(Outcome::Review, support, Remediation::Guided, None);
    }

    if mode == Mode::Review {
        return build(Outcome::Review, support, Remediation::Guided, None);
    }

    // An external authority governs this value. `privr` reports whether its
    // effective value passes or drifts, and does not enter a policy fight.
    let (remediation, reason) = if resolution.source.is_external() {
        (
            Remediation::None,
            Some(RemediationReason::ManagedExternally),
        )
    } else if stale || spec.reversibility != Reversibility::Exact {
        // Degraded support and irreversible changes both fall back to
        // audit-only rather than offering a write that cannot be trusted or
        // undone.
        (Remediation::AuditOnly, None)
    } else {
        (spec.remediation, spec.remediation_reason)
    };

    let outcome = if *state == spec.desired {
        Outcome::Pass
    } else {
        Outcome::Drift
    };

    // Support that is not verified cannot carry a pass. The state matched, but
    // the reading was not trustworthy enough to say so.
    let outcome = if outcome == Outcome::Pass && support != Support::Verified {
        Outcome::Unknown
    } else {
        outcome
    };

    build(outcome, support, remediation, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::applicability::{Predicate, Variant};
    use crate::model::evidence::{DenialReason, Evidence, RawValue, ValueKind};
    use crate::model::host::{
        Architecture, ContainerKind, Fact, Platform, SessionFacts, WriteModel,
    };

    fn host() -> HostFacts {
        HostFacts {
            platform: Platform::Windows,
            version: Fact::Known(OsVersion::new(vec![10, 0, 26100], "10.0.26100")),
            architecture: Fact::Known(Architecture::X86_64),
            edition: Fact::Known("Professional".to_owned()),
            distribution: Fact::NotPresent,
            managed: Fact::Known(false),
            write_model: Fact::Known(WriteModel::Mutable),
            container: Fact::Known(ContainerKind::None),
            session: SessionFacts::not_present(),
            elevated: Fact::Known(false),
        }
    }

    fn spec() -> ControlSpec {
        ControlSpec {
            id: "windows.advertising.id".to_owned(),
            title: "Advertising identifier".to_owned(),
            section: "advertising".to_owned(),
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            desired: SemanticState::new("disabled"),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            verified_through: None,
            remediation: Remediation::Automatic,
            remediation_reason: None,
        }
    }

    fn evaluate_with(resolution: &Resolution) -> ControlResult {
        evaluate(&spec(), Mode::Enforce, resolution, &host(), Exception::None)
    }

    #[test]
    fn matching_state_passes_and_stays_coherent() {
        let result = evaluate_with(&Resolution::determined(
            SemanticState::new("disabled"),
            ManagementSource::User,
        ));
        assert_eq!(result.outcome, Outcome::Pass);
        assert_eq!(result.support, Support::Verified);
        assert!(result.is_coherent());
    }

    #[test]
    fn differing_state_drifts() {
        let result = evaluate_with(&Resolution::determined(
            SemanticState::new("enabled"),
            ManagementSource::User,
        ));
        assert_eq!(result.outcome, Outcome::Drift);
        assert_eq!(result.remediation, Remediation::Automatic);
        assert!(result.is_coherent());
    }

    #[test]
    fn a_value_the_platform_ignores_is_not_applicable_not_compliant() {
        // The Windows edition-gating case. The write succeeded, the value reads
        // back exactly as desired, and the platform does not act on it. Every
        // surveyed tool reports a pass here.
        let result = evaluate_with(&Resolution::inert(
            SemanticState::new("disabled"),
            ManagementSource::LocalPolicy,
        ));
        assert_eq!(result.outcome, Outcome::NotApplicable);
        assert_ne!(result.outcome, Outcome::Pass);
        assert!(result.is_coherent());
    }

    #[test]
    fn every_inconclusive_reading_becomes_unknown_never_pass() {
        for uncertainty in [
            Uncertainty::Denied,
            Uncertainty::Malformed,
            Uncertainty::Unsupported,
            Uncertainty::Undetermined,
            Uncertainty::EnforcementMechanismOnly,
        ] {
            let result = evaluate_with(&Resolution::uncertain(uncertainty, ManagementSource::User));
            assert_eq!(result.outcome, Outcome::Unknown, "{uncertainty:?}");
            assert!(result.outcome.conceals_state(), "{uncertainty:?}");
            assert!(result.is_coherent(), "{uncertainty:?}");
        }
    }

    #[test]
    fn undetermined_applicability_is_unknown_not_excluded() {
        let mut host = host();
        host.edition = Fact::Unknown;

        let mut spec = spec();
        spec.applicability = Applicability::new(vec![Variant::new(
            "enterprise",
            vec![Predicate::EditionIn(vec!["Enterprise".to_owned()])],
        )]);

        let result = evaluate(
            &spec,
            Mode::Enforce,
            &Resolution::determined(SemanticState::new("disabled"), ManagementSource::User),
            &host,
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::Unknown);
        assert_ne!(result.outcome, Outcome::NotApplicable);
    }

    #[test]
    fn a_wrong_platform_is_definitely_not_applicable() {
        let mut spec = spec();
        spec.applicability = Applicability::new(vec![Variant::new(
            "linux",
            vec![Predicate::Platform(Platform::Linux)],
        )]);

        let result = evaluate(
            &spec,
            Mode::Enforce,
            &Resolution::determined(SemanticState::new("disabled"), ManagementSource::User),
            &host(),
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::NotApplicable);
    }

    #[test]
    fn a_stale_control_cannot_report_a_pass() {
        let mut spec = spec();
        spec.verified_through = Some(OsVersion::new(vec![10, 0, 22631], "10.0.22631"));

        let result = evaluate(
            &spec,
            Mode::Enforce,
            &Resolution::determined(SemanticState::new("disabled"), ManagementSource::User),
            &host(),
            Exception::None,
        );

        // The state matches, but the reading is no longer trustworthy here.
        assert_eq!(result.outcome, Outcome::Unknown);
        assert_eq!(result.support, Support::Unverified);
        assert_eq!(result.remediation, Remediation::AuditOnly);
        assert!(result.is_coherent());
    }

    #[test]
    fn a_stale_control_still_reports_drift() {
        // Degrading support must not hide a finding. Drift is still drift.
        let mut spec = spec();
        spec.verified_through = Some(OsVersion::new(vec![10, 0, 22631], "10.0.22631"));

        let result = evaluate(
            &spec,
            Mode::Enforce,
            &Resolution::determined(SemanticState::new("enabled"), ManagementSource::User),
            &host(),
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::Drift);
        assert_eq!(result.remediation, Remediation::AuditOnly);
        assert!(result.is_coherent());
    }

    #[test]
    fn an_unknown_host_version_is_treated_as_out_of_range() {
        let mut host = host();
        host.version = Fact::Unknown;

        let mut spec = spec();
        spec.verified_through = Some(OsVersion::new(vec![10, 0, 26100], "10.0.26100"));

        let result = evaluate(
            &spec,
            Mode::Enforce,
            &Resolution::determined(SemanticState::new("disabled"), ManagementSource::User),
            &host,
            Exception::None,
        );
        assert_eq!(result.support, Support::Unverified);
        assert_ne!(result.outcome, Outcome::Pass);
    }

    #[test]
    fn an_externally_managed_value_is_reported_not_overwritten() {
        let result = evaluate_with(&Resolution::determined(
            SemanticState::new("enabled"),
            ManagementSource::GroupPolicy,
        ));
        assert_eq!(result.outcome, Outcome::Drift);
        assert_eq!(result.remediation, Remediation::None);
        assert_eq!(
            result.remediation_reason,
            Some(RemediationReason::ManagedExternally)
        );
        assert!(result.is_coherent());
    }

    #[test]
    fn an_ignored_control_is_reported_as_not_selected() {
        let result = evaluate(
            &spec(),
            Mode::Ignore,
            &Resolution::determined(SemanticState::new("enabled"), ManagementSource::User),
            &host(),
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::NotSelected);
        assert!(!result.outcome.conceals_state());
        assert!(result.is_coherent());
    }

    #[test]
    fn review_mode_never_reports_drift() {
        let result = evaluate(
            &spec(),
            Mode::Review,
            &Resolution::determined(SemanticState::new("enabled"), ManagementSource::User),
            &host(),
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::Review);
        assert!(result.is_coherent());
    }

    #[test]
    fn an_irreversible_control_is_never_offered_for_automatic_apply() {
        let mut spec = spec();
        spec.reversibility = Reversibility::Irreversible;

        let result = evaluate(
            &spec,
            Mode::Enforce,
            &Resolution::determined(SemanticState::new("enabled"), ManagementSource::User),
            &host(),
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::Drift);
        assert_ne!(result.remediation, Remediation::Automatic);
        assert!(result.is_coherent());
    }

    #[test]
    fn an_exception_changes_remediation_but_never_the_finding() {
        let result = evaluate(
            &spec(),
            Mode::Enforce,
            &Resolution::determined(SemanticState::new("enabled"), ManagementSource::User),
            &host(),
            Exception::Active,
        );
        // Still drift. An exempted control that reports a pass loses the
        // ability to distinguish an accepted risk from an absent one.
        assert_eq!(result.outcome, Outcome::Drift);
        assert_eq!(result.exception, Exception::Active);
    }

    #[test]
    fn precedence_consults_sources_in_the_control_declared_order() {
        let observation = Observation::new(vec![
            Evidence::Present {
                source: ManagementSource::User,
                value: RawValue::u32(1),
            },
            Evidence::Present {
                source: ManagementSource::GroupPolicy,
                value: RawValue::u32(0),
            },
        ]);

        let decode = |value: &RawValue| {
            value
                .as_u32()
                .map(|raw| SemanticState::new(if raw == 0 { "disabled" } else { "enabled" }))
        };

        let policy_first = Resolution::from_observation(
            &observation,
            &[ManagementSource::GroupPolicy, ManagementSource::User],
            decode,
            &SemanticState::new("enabled"),
        );
        assert_eq!(policy_first.state, Some(SemanticState::new("disabled")));
        assert_eq!(policy_first.source, ManagementSource::GroupPolicy);

        let user_first = Resolution::from_observation(
            &observation,
            &[ManagementSource::User, ManagementSource::GroupPolicy],
            decode,
            &SemanticState::new("enabled"),
        );
        assert_eq!(user_first.state, Some(SemanticState::new("enabled")));
        assert_eq!(user_first.source, ManagementSource::User);
    }

    #[test]
    fn an_absent_value_resolves_to_the_documented_default() {
        let observation = Observation::new(vec![Evidence::Absent {
            source: ManagementSource::Default,
        }]);

        let resolution = Resolution::from_observation(
            &observation,
            &[ManagementSource::Default],
            |_| None,
            &SemanticState::new("enabled"),
        );
        assert_eq!(resolution.state, Some(SemanticState::new("enabled")));
        assert!(resolution.uncertainty.is_none());
    }

    #[test]
    fn a_denied_read_never_falls_back_to_the_default() {
        let observation = Observation::new(vec![Evidence::Denied {
            source: ManagementSource::LocalPolicy,
            reason: DenialReason::Permission,
        }]);

        let resolution = Resolution::from_observation(
            &observation,
            &[ManagementSource::LocalPolicy],
            |_| None,
            &SemanticState::new("disabled"),
        );
        assert_eq!(resolution.state, None);
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Denied));
    }

    #[test]
    fn an_undecodable_value_is_malformed_not_defaulted() {
        let observation = Observation::new(vec![Evidence::Present {
            source: ManagementSource::User,
            value: RawValue::new(ValueKind::String, b"unexpected".to_vec()),
        }]);

        let resolution = Resolution::from_observation(
            &observation,
            &[ManagementSource::User],
            |value| value.as_u32().map(|_| SemanticState::new("disabled")),
            &SemanticState::new("disabled"),
        );
        assert_eq!(resolution.state, None);
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Malformed));
    }

    #[test]
    fn no_consulted_source_present_is_undetermined() {
        let observation = Observation::new(vec![Evidence::Absent {
            source: ManagementSource::User,
        }]);

        let resolution = Resolution::from_observation(
            &observation,
            &[ManagementSource::GroupPolicy],
            |_| None,
            &SemanticState::new("disabled"),
        );
        assert_eq!(resolution.state, None);
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Undetermined));
    }

    #[test]
    fn inertness_survives_precedence_resolution() {
        let observation = Observation::inert(vec![Evidence::Present {
            source: ManagementSource::LocalPolicy,
            value: RawValue::u32(0),
        }]);

        let resolution = Resolution::from_observation(
            &observation,
            &[ManagementSource::LocalPolicy],
            |value| value.as_u32().map(|_| SemanticState::new("disabled")),
            &SemanticState::new("enabled"),
        );
        assert!(!resolution.honored);
    }
}
