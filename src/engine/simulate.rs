//! Counterfactual dry-run and simulation engine.
//!
//! Evaluates the projected privacy posture delta, aggregate friction vector,
//! and pending restart/signout requirements of candidate changes in-memory
//! without modifying machine state.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::catalog::{Context, Control};
use crate::engine::evaluate::{Mode, evaluate};
use crate::model::host::HostFacts;
use crate::model::outcome::{Effect, Exception, Outcome, Remediation};
use crate::model::posture::PostureVector;
use crate::model::profile::Profile;

#[derive(Clone, Debug, Serialize)]
pub struct SimulationOutcome {
    pub profile: String,
    pub simulated_changes: usize,
    pub unautomated_drift: usize,
    pub current_posture: PostureVector,
    pub simulated_posture: PostureVector,
    pub friction_breakdown: BTreeMap<String, usize>,
    pub pending_restart_required: bool,
    pub pending_signout_required: bool,
    pub simulated_control_ids: Vec<String>,
}

pub fn simulate_profile(
    controls: &[Control],
    context: &Context,
    host: &HostFacts,
    profile: Profile,
    control_filter: &[String],
    section_filter: &[String],
) -> SimulationOutcome {
    let mut current_posture = PostureVector::new();
    let mut simulated_posture = PostureVector::new();
    let mut friction_breakdown = BTreeMap::new();
    let mut pending_restart_required = false;
    let mut pending_signout_required = false;
    let mut simulated_control_ids = Vec::new();
    let mut simulated_changes = 0;
    let mut unautomated_drift = 0;

    for control in controls {
        let spec = &control.spec;
        let resolution = control.observe(context);
        let mode = if spec.min_profile <= profile {
            Mode::Enforce
        } else {
            Mode::Ignore
        };
        let eval = evaluate(spec, mode, &resolution, host, Exception::None);

        current_posture.record(spec.dimension, eval.outcome);

        let matches_control = control_filter.is_empty()
            || control_filter
                .iter()
                .any(|c| spec.id == *c || spec.id.starts_with(c));
        let matches_section = section_filter.is_empty()
            || section_filter.iter().any(|s| {
                spec.section.eq_ignore_ascii_case(s)
                    || spec
                        .section
                        .to_ascii_lowercase()
                        .starts_with(&s.to_ascii_lowercase())
            });

        if eval.outcome == Outcome::Drift && matches_control && matches_section {
            if eval.remediation == Remediation::Automatic && control.apply.is_some() {
                simulated_changes += 1;
                simulated_control_ids.push(spec.id.clone());
                simulated_posture.record(spec.dimension, Outcome::Pass);

                let tier_str = spec.friction.as_str().to_owned();
                *friction_breakdown.entry(tier_str).or_insert(0) += 1;

                match eval.effect {
                    Effect::PendingRestart | Effect::PendingReboot => {
                        pending_restart_required = true
                    }
                    Effect::PendingSignout => pending_signout_required = true,
                    Effect::Active => {}
                }
            } else {
                unautomated_drift += 1;
                simulated_posture.record(spec.dimension, eval.outcome);
            }
        } else {
            simulated_posture.record(spec.dimension, eval.outcome);
        }
    }

    SimulationOutcome {
        profile: profile.as_str().to_owned(),
        simulated_changes,
        unautomated_drift,
        current_posture,
        simulated_posture,
        friction_breakdown,
        pending_restart_required,
        pending_signout_required,
        simulated_control_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::applicability::Applicability;
    use crate::model::host::Platform;
    use crate::model::outcome::{Maturity, Reversibility};
    use crate::model::posture::{FrictionTier, PostureDimension};

    fn make_test_control(
        id: &str,
        dimension: PostureDimension,
        friction: FrictionTier,
        probe: fn(&Context) -> crate::engine::evaluate::Resolution,
        can_apply: bool,
    ) -> Control {
        Control {
            spec: crate::engine::evaluate::ControlSpec {
                id: id.to_owned(),
                title: format!("Test {id}"),
                section: "test".to_owned(),
                dimension,
                friction,
                applicability: Applicability::default(),
                desired: crate::engine::evaluate::SemanticState::new("disabled"),
                reversibility: Reversibility::Exact,
                maturity: Maturity::Automated,
                verified_through: None,
                remediation: if can_apply {
                    Remediation::Automatic
                } else {
                    Remediation::AuditOnly
                },
                remediation_reason: None,
                min_profile: Profile::Baseline,
                requires_elevation: false,
            },
            title: "Test Control",
            summary: "Test Summary",
            rationale: "Test Rationale",
            tradeoff: None,
            mitigation: None,
            sources: &[],
            probe,
            apply: if can_apply {
                Some(|_| {
                    Ok(crate::catalog::AppliedOp {
                        target_key: "test".to_owned(),
                        preimage: None,
                        postimage: crate::model::evidence::RawValue::u32(0),
                    })
                })
            } else {
                None
            },
            rollback: None,
        }
    }

    #[test]
    fn simulate_projects_compliant_delta_in_memory() {
        let host = HostFacts::unknown(Platform::Windows);
        let ctx = Context::live(&host);

        let c = make_test_control(
            "test.drift",
            PostureDimension::BehavioralCommercial,
            FrictionTier::Tier0Transparent,
            |_| {
                crate::engine::evaluate::Resolution::determined(
                    crate::engine::evaluate::SemanticState::new("enabled"),
                    crate::model::host::ManagementSource::User,
                )
            },
            true,
        );

        let outcome = simulate_profile(&[c], &ctx, &host, Profile::Baseline, &[], &[]);

        assert_eq!(outcome.simulated_changes, 1);
        let cur_m = outcome
            .current_posture
            .dimensions
            .get(&PostureDimension::BehavioralCommercial)
            .unwrap();
        assert_eq!(cur_m.drift, 1);
        assert_eq!(cur_m.compliant, 0);

        let sim_m = outcome
            .simulated_posture
            .dimensions
            .get(&PostureDimension::BehavioralCommercial)
            .unwrap();
        assert_eq!(sim_m.compliant, 1);
        assert_eq!(sim_m.drift, 0);
    }
}
