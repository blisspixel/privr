//! Deterministic recommendation engine.
//!
//! Generates prioritized, explainable remediation recommendations based on
//! evaluated host drift, workload personas, and friction budgets.

use crate::catalog::{Context, Control};
use crate::engine::evaluate::{Mode, evaluate};
use crate::model::host::HostFacts;
use crate::model::outcome::{Exception, Outcome};
use crate::model::posture::{FrictionTier, PostureDimension, Recommendation, WorkloadPersona};

/// Generate deterministic recommendations for a host given a workload persona and budget.
pub fn generate_recommendations(
    controls: &[Control],
    context: &Context,
    host: &HostFacts,
    workload: WorkloadPersona,
    max_friction: Option<FrictionTier>,
    dimension_filter: Option<PostureDimension>,
) -> Vec<Recommendation> {
    let mut recs = Vec::new();

    for control in controls {
        let spec = &control.spec;

        // Apply dimension filter early if requested.
        if let Some(dim) = dimension_filter
            && spec.dimension != dim
        {
            continue;
        }

        // Apply friction budget filter.
        if let Some(budget) = max_friction
            && spec.friction > budget
        {
            continue;
        }

        let resolution = control.observe(context);
        // Evaluate in Enforce mode to detect drift across the full catalogue.
        let eval = evaluate(spec, Mode::Enforce, &resolution, host, Exception::None);

        if eval.outcome != Outcome::Drift {
            continue;
        }

        // Check persona-specific policy rules:
        // 1. Creative Persona:
        //    Must preserve thumbnail caching for visual asset curation.
        if workload == WorkloadPersona::Creative
            && (spec.id == "windows.storage.thumbnail-cache"
                || spec.id == "freedesktop.thumbnails.caching"
                || spec.id == "macos.storage.quicklook-cache")
        {
            // Omit thumbnail caching disablement from creative workflow recommendations.
            continue;
        }

        // 2. Developer Persona:
        //    Preserve local crash minidumps for debugging.
        let custom_rationale = if workload == WorkloadPersona::Developer
            && (spec.id == "windows.diagnostics.error-reporting"
                || spec.id == "systemd.coredump.storage"
                || spec.id == "macos.analytics.share-with-developers")
        {
            Some(
                "Suppresses remote vendor crash telemetry while preserving local crash dumps for debugger symbol inspection.",
            )
        } else if workload == WorkloadPersona::Mobile
            && (spec.id == "windows.security.llmnr" || spec.id == "windows.security.wpad")
        {
            Some(
                "Essential on mobile laptops to prevent credential harvesting and proxy poisoning on public Wi-Fi.",
            )
        } else if workload == WorkloadPersona::Mobile && spec.id == "windows.storage.pagefile-clear"
        {
            // Do not recommend pagefile clear on mobile laptops: BitLocker protects disk, and
            // pagefile zeroing drains battery and causes overheating when the lid is closed.
            continue;
        } else {
            None
        };

        let current_str = resolution
            .state
            .as_ref()
            .map(|s| s.0.clone())
            .unwrap_or_else(|| "drift".to_owned());

        recs.push(Recommendation {
            control_id: spec.id.clone(),
            title: control.title.to_owned(),
            section: spec.section.clone(),
            dimension: spec.dimension,
            friction_tier: spec.friction,
            remediation: eval.remediation,
            reversibility: spec.reversibility,
            support: eval.support,
            current_state: current_str,
            desired_state: spec.desired.0.clone(),
            rationale: custom_rationale
                .map(str::to_owned)
                .unwrap_or_else(|| control.rationale.to_owned()),
            tradeoff: control.tradeoff.map(str::to_owned),
        });
    }

    // Deterministic total ordering: lowest friction first, then dimension, then control ID.
    recs.sort();
    recs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::applicability::Applicability;
    use crate::model::host::Platform;
    use crate::model::outcome::{Maturity, Reversibility};
    use crate::model::profile::Profile;

    fn make_test_control(
        id: &str,
        dimension: PostureDimension,
        friction: FrictionTier,
        probe: fn(&Context) -> crate::engine::evaluate::Resolution,
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
                remediation: crate::model::outcome::Remediation::Automatic,
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
            apply: None,
            rollback: None,
        }
    }

    #[test]
    fn recommendations_sort_by_friction_tier_first() {
        let host = HostFacts::unknown(Platform::Windows);
        let ctx = Context::live(&host);

        let c1 = make_test_control(
            "test.high_friction",
            PostureDimension::ForensicResidue,
            FrictionTier::Tier2WorkflowAltering,
            |_| {
                crate::engine::evaluate::Resolution::determined(
                    crate::engine::evaluate::SemanticState::new("enabled"),
                    crate::model::host::ManagementSource::User,
                )
            },
        );
        let c2 = make_test_control(
            "test.zero_friction",
            PostureDimension::BehavioralCommercial,
            FrictionTier::Tier0Transparent,
            |_| {
                crate::engine::evaluate::Resolution::determined(
                    crate::engine::evaluate::SemanticState::new("enabled"),
                    crate::model::host::ManagementSource::User,
                )
            },
        );

        let recs =
            generate_recommendations(&[c1, c2], &ctx, &host, WorkloadPersona::General, None, None);

        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].control_id, "test.zero_friction");
        assert_eq!(recs[1].control_id, "test.high_friction");
    }

    #[test]
    fn creative_persona_filters_out_thumbnail_caching() {
        let host = HostFacts::unknown(Platform::Windows);
        let ctx = Context::live(&host);

        let c = make_test_control(
            "windows.storage.thumbnail-cache",
            PostureDimension::ForensicResidue,
            FrictionTier::Tier2WorkflowAltering,
            |_| {
                crate::engine::evaluate::Resolution::determined(
                    crate::engine::evaluate::SemanticState::new("enabled"),
                    crate::model::host::ManagementSource::User,
                )
            },
        );

        let recs =
            generate_recommendations(&[c], &ctx, &host, WorkloadPersona::Creative, None, None);

        assert!(
            recs.is_empty(),
            "thumbnail cache should be excluded for creative persona"
        );
    }
}
