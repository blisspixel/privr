//! Result dimensions.
//!
//! Evaluation outcome, support, management source, remediation, reversibility,
//! maturity, pending effect, and policy exception are independent facts. They
//! are never compressed into one status.
//!
//! When a new fact appears it becomes a new dimension, never a new outcome
//! value. Outcome values that encode two facts at once are how comparable tools
//! lose the ability to distinguish "we could not check" from "there is nothing
//! to fix".

use serde::{Deserialize, Serialize};

use super::host::ManagementSource;

/// The evaluation outcome for one control on one host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Effective state matches an enforce-mode desired value.
    Pass,
    /// Effective state differs from an enforce-mode desired value.
    Drift,
    /// The policy asks the operator to review a contextual choice.
    Review,
    /// Effective state could not be determined confidently.
    Unknown,
    /// The control does not apply to this host.
    NotApplicable,
    /// The control applies, but the selected profile does not include it.
    NotSelected,
    /// The control applies and was selected, but was not evaluated.
    NotChecked,
    /// Observation or evaluation failed.
    Error,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Drift => "drift",
            Self::Review => "review",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not_applicable",
            Self::NotSelected => "not_selected",
            Self::NotChecked => "not_checked",
            Self::Error => "error",
        }
    }

    /// Whether this outcome represents a completed evaluation of the host.
    ///
    /// Only evaluated outcomes belong in an aggregate denominator. An aggregate
    /// that counts unevaluated controls can improve when visibility decreases,
    /// which is the scoring form of a false pass.
    pub const fn is_evaluated(self) -> bool {
        matches!(self, Self::Pass | Self::Drift | Self::Review)
    }

    /// Whether this outcome hides a state that could differ from the policy.
    ///
    /// These make a report incomplete. The machine might be sharing data the
    /// operator believes is disabled.
    pub const fn conceals_state(self) -> bool {
        matches!(self, Self::Unknown | Self::NotChecked | Self::Error)
    }
}

/// Whether `privr` can change this control here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Remediation {
    Automatic,
    Guided,
    AuditOnly,
    None,
}

/// Why remediation is unavailable. Required whenever remediation is `None`.
///
/// This is how "observable, confirmed non-compliant, and not fixable here" is
/// expressed: outcome `Drift`, remediation `None`, with the reason naming why.
/// It is not a separate outcome, because the finding and the fixability are two
/// different facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationReason {
    /// The platform provides no way to change this.
    PlatformLimitation,
    /// The setting cannot be returned to its previous state once changed.
    IrreversibleOnceSet,
    /// No documented, verifiable write interface exists.
    NoSafeWrite,
    /// The prior value cannot be captured exactly, so rollback is impossible.
    NoExactRollback,
    /// An external authority governs this value.
    ManagedExternally,
    /// The selected policy deliberately excludes remediation.
    ExcludedByPolicy,
}

/// How well this control is verified on this host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// Verified against this platform version, with fixtures.
    Verified,
    /// The interface is believed to work here but has not been verified.
    Unverified,
    /// Not supported on this host.
    Unsupported,
}

/// Whether a change can be undone.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The prior value can be restored byte for byte, subject to conflict
    /// checks.
    Exact,
    /// The change cannot be undone by `privr`.
    Irreversible,
    /// The change requests action beyond this machine and cannot be recalled.
    RemoteEffect,
}

/// Whether the control can be evaluated programmatically at all.
///
/// This is a fact about the control, not about this host. Keeping it separate
/// from the outcome preserves the ability to say that a check is manual and has
/// not been performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Maturity {
    Automated,
    Partial,
    Manual,
}

/// When a verified write becomes effective.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Active,
    PendingSignout,
    PendingRestart,
    PendingReboot,
}

/// Policy exception state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exception {
    None,
    Active,
    Expired,
}

/// Why a configured value is not the value the platform acts on.
///
/// The gap between "I turned this off" and "it stopped" is the product. A tool
/// that reads a setting and reports what it finds is answering the wrong
/// question, because the setting can read back exactly as written while the
/// behaviour continues.
///
/// These are the documented ways that happens. Each is a distinct failure with
/// a distinct remedy, so they are typed rather than described in prose: a
/// caller can branch on them, and a control cannot invent a new one without
/// review.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ineffective {
    /// Accepted and stored, but this edition or product tier does not act on
    /// it. The write succeeds and reads back unchanged.
    EditionGated,
    /// The write is discarded by a protection mechanism without an error.
    SilentlyDiscarded,
    /// A different setting takes precedence and re-enables the behaviour.
    SupersededBySetting,
    /// The platform restores its own value on update or on a schedule.
    RevertedByPlatform,
    /// The setting governs one path to the behaviour but not all of them.
    ScopeIncomplete,
    /// The write reported success but the backing store never committed it.
    WriteNotCommitted,
}

impl Ineffective {
    /// A short phrase naming the failure, for output that has no room for the
    /// full explanation.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::EditionGated => "not honored on this edition",
            Self::SilentlyDiscarded => "the write is discarded without an error",
            Self::SupersededBySetting => "another setting overrides it",
            Self::RevertedByPlatform => "the platform restores its own value",
            Self::ScopeIncomplete => "it does not cover every path to this behaviour",
            Self::WriteNotCommitted => "the write was reported as successful but not stored",
        }
    }
}

/// The complete result for one control.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlResult {
    pub id: String,
    /// Human-readable name. Results are self-contained by contract, so
    /// explaining a finding never requires a second lookup.
    pub title: String,
    pub section: String,
    pub outcome: Outcome,
    pub management_source: ManagementSource,
    pub remediation: Remediation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_reason: Option<RemediationReason>,
    pub support: Support,
    pub reversibility: Reversibility,
    pub maturity: Maturity,
    pub effect: Effect,
    pub exception: Exception,
    /// A fact about this finding the operator must be told.
    ///
    /// Carried in the result rather than left to the renderer, because the
    /// contract is that a result is self-contained and that the tool supplies
    /// the sentence which must be stated. A caller cannot be relied upon to
    /// notice a caveat and add one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Why what is configured is not what the platform acts on.
    ///
    /// Typed alongside the prose note so a caller can branch on the failure
    /// rather than parse a sentence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ineffective: Option<Ineffective>,
}

impl ControlResult {
    /// Whether this result is internally consistent.
    ///
    /// These invariants are checked rather than assumed, because each one is a
    /// way a report could quietly claim more than it knows.
    pub fn is_coherent(&self) -> bool {
        // Remediation `None` must always say why.
        if self.remediation == Remediation::None && self.remediation_reason.is_none() {
            return false;
        }
        // A reason without `None` remediation is contradictory.
        if self.remediation != Remediation::None && self.remediation_reason.is_some() {
            return false;
        }
        // Support that is not verified cannot support a pass, and cannot offer
        // automatic remediation.
        if self.support != Support::Verified {
            if self.outcome == Outcome::Pass {
                return false;
            }
            if self.remediation == Remediation::Automatic {
                return false;
            }
        }
        // An irreversible control is never automatically remediable, because
        // ordinary apply is built on being able to undo what it did.
        if self.reversibility != Reversibility::Exact && self.remediation == Remediation::Automatic
        {
            return false;
        }
        // A manual control cannot report a machine-derived pass or drift.
        if self.maturity == Maturity::Manual
            && matches!(self.outcome, Outcome::Pass | Outcome::Drift)
        {
            return false;
        }
        true
    }
}

/// Counts for a set of results.
///
/// The denominator deliberately excludes anything that was not evaluated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub pass: usize,
    pub drift: usize,
    pub review: usize,
    pub unknown: usize,
    pub not_applicable: usize,
    pub not_selected: usize,
    pub not_checked: usize,
    pub error: usize,
}

impl Summary {
    pub fn of<'a>(results: impl IntoIterator<Item = &'a ControlResult>) -> Self {
        let mut summary = Self::default();
        for result in results {
            let slot = match result.outcome {
                Outcome::Pass => &mut summary.pass,
                Outcome::Drift => &mut summary.drift,
                Outcome::Review => &mut summary.review,
                Outcome::Unknown => &mut summary.unknown,
                Outcome::NotApplicable => &mut summary.not_applicable,
                Outcome::NotSelected => &mut summary.not_selected,
                Outcome::NotChecked => &mut summary.not_checked,
                Outcome::Error => &mut summary.error,
            };
            *slot += 1;
        }
        summary
    }

    /// How many controls were actually evaluated against this host.
    pub const fn evaluated(&self) -> usize {
        self.pass + self.drift + self.review
    }

    /// How many results conceal state that could differ from the policy.
    pub const fn concealed(&self) -> usize {
        self.unknown + self.not_checked + self.error
    }

    /// A report is complete only when nothing conceals state.
    pub const fn is_complete(&self) -> bool {
        self.concealed() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_result() -> ControlResult {
        ControlResult {
            id: "windows.example".to_owned(),
            title: "Example control".to_owned(),
            section: "diagnostics".to_owned(),
            outcome: Outcome::Pass,
            management_source: ManagementSource::User,
            remediation: Remediation::Automatic,
            remediation_reason: None,
            support: Support::Verified,
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            effect: Effect::Active,
            exception: Exception::None,
            note: None,
            ineffective: None,
        }
    }

    #[test]
    fn only_evaluated_outcomes_enter_the_denominator() {
        assert!(Outcome::Pass.is_evaluated());
        assert!(Outcome::Drift.is_evaluated());
        assert!(Outcome::Review.is_evaluated());

        assert!(!Outcome::Unknown.is_evaluated());
        assert!(!Outcome::NotApplicable.is_evaluated());
        assert!(!Outcome::NotSelected.is_evaluated());
        assert!(!Outcome::NotChecked.is_evaluated());
        assert!(!Outcome::Error.is_evaluated());
    }

    #[test]
    fn the_three_negative_outcomes_are_distinct() {
        // Not applicable to this host, not selected by this profile, and
        // selected but not evaluated are three different facts. Reporting the
        // third as the first is the false pass this model exists to prevent.
        assert_ne!(Outcome::NotApplicable, Outcome::NotSelected);
        assert_ne!(Outcome::NotSelected, Outcome::NotChecked);
        assert_ne!(Outcome::NotApplicable, Outcome::NotChecked);

        assert!(!Outcome::NotApplicable.conceals_state());
        assert!(!Outcome::NotSelected.conceals_state());
        assert!(Outcome::NotChecked.conceals_state());
    }

    #[test]
    fn an_aggregate_cannot_improve_when_visibility_decreases() {
        let visible = [
            ControlResult {
                outcome: Outcome::Pass,
                ..base_result()
            },
            ControlResult {
                outcome: Outcome::Drift,
                ..base_result()
            },
        ];
        let obscured = [
            ControlResult {
                outcome: Outcome::Pass,
                ..base_result()
            },
            ControlResult {
                outcome: Outcome::Unknown,
                support: Support::Unverified,
                remediation: Remediation::AuditOnly,
                ..base_result()
            },
        ];

        let visible = Summary::of(&visible);
        let obscured = Summary::of(&obscured);

        // Losing sight of the drifting control must not raise the evaluated
        // count, and must not let the report claim completeness.
        assert_eq!(visible.evaluated(), 2);
        assert_eq!(obscured.evaluated(), 1);
        assert!(visible.is_complete());
        assert!(!obscured.is_complete());
        assert_eq!(obscured.concealed(), 1);
    }

    #[test]
    fn unverified_support_cannot_report_a_pass() {
        let result = ControlResult {
            outcome: Outcome::Pass,
            support: Support::Unverified,
            remediation: Remediation::AuditOnly,
            ..base_result()
        };
        assert!(!result.is_coherent());
    }

    #[test]
    fn unverified_support_cannot_offer_automatic_remediation() {
        let result = ControlResult {
            outcome: Outcome::Drift,
            support: Support::Unverified,
            remediation: Remediation::Automatic,
            ..base_result()
        };
        assert!(!result.is_coherent());
    }

    #[test]
    fn no_remediation_must_state_a_reason() {
        let missing = ControlResult {
            outcome: Outcome::Drift,
            remediation: Remediation::None,
            remediation_reason: None,
            ..base_result()
        };
        assert!(!missing.is_coherent());

        let stated = ControlResult {
            remediation_reason: Some(RemediationReason::PlatformLimitation),
            ..missing
        };
        assert!(stated.is_coherent());
    }

    #[test]
    fn a_reason_without_none_remediation_is_contradictory() {
        let result = ControlResult {
            remediation: Remediation::Automatic,
            remediation_reason: Some(RemediationReason::PlatformLimitation),
            ..base_result()
        };
        assert!(!result.is_coherent());
    }

    #[test]
    fn an_irreversible_control_is_never_automatically_remediated() {
        let result = ControlResult {
            outcome: Outcome::Drift,
            reversibility: Reversibility::Irreversible,
            remediation: Remediation::Automatic,
            ..base_result()
        };
        assert!(!result.is_coherent());
    }

    #[test]
    fn a_manual_control_cannot_claim_a_machine_derived_finding() {
        let result = ControlResult {
            outcome: Outcome::Pass,
            maturity: Maturity::Manual,
            ..base_result()
        };
        assert!(!result.is_coherent());

        let reviewed = ControlResult {
            outcome: Outcome::Review,
            maturity: Maturity::Manual,
            ..base_result()
        };
        assert!(reviewed.is_coherent());
    }

    #[test]
    fn observable_non_compliant_and_unfixable_is_expressible() {
        // The macOS case: the state was read successfully, it does not match,
        // and the platform offers no way to change it. Outcome and fixability
        // stay separate facts.
        let result = ControlResult {
            outcome: Outcome::Drift,
            remediation: Remediation::None,
            remediation_reason: Some(RemediationReason::PlatformLimitation),
            ..base_result()
        };
        assert!(result.is_coherent());
        assert!(result.outcome.is_evaluated());
    }
}
