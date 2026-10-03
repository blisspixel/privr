//! Multi-dimensional privacy posture and operational friction models.
//!
//! Replaces lossy scalar scoring (e.g. 0-100 or letter grades) with
//! orthogonal posture dimensions and academically grounded friction tiers
//! (Saltzer-Schroeder, NIST, SOUPS).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::outcome::{Outcome, Remediation, Reversibility, Support};

/// Orthogonal threat and privacy domains.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum PostureDimension {
    /// Advertising ID, consumer telemetry, tailored suggestions, search highlights.
    BehavioralCommercial,
    /// Shell MRU, Jump Lists, TypedPaths, thumbnail caches, clipboard sync.
    ForensicResidue,
    /// NCSI active probing, LLMNR, NetBIOS broadcast, WPAD, captive portal checks.
    NetworkExposure,
    /// Windows Error Reporting dumps, diagnostic data level, inventory collection.
    DiagnosticCrash,
    /// Geolocation, microphone/camera background permissions, inking/typing dictionaries.
    AmbientSensor,
}

impl PostureDimension {
    pub const ALL: [Self; 5] = [
        Self::BehavioralCommercial,
        Self::ForensicResidue,
        Self::NetworkExposure,
        Self::DiagnosticCrash,
        Self::AmbientSensor,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BehavioralCommercial => "behavioral_commercial",
            Self::ForensicResidue => "forensic_residue",
            Self::NetworkExposure => "network_exposure",
            Self::DiagnosticCrash => "diagnostic_crash",
            Self::AmbientSensor => "ambient_sensor",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::BehavioralCommercial => "Behavioral & Commercial",
            Self::ForensicResidue => "Forensic Residue",
            Self::NetworkExposure => "Network Exposure",
            Self::DiagnosticCrash => "Diagnostic & Crash",
            Self::AmbientSensor => "Sensor & Perimeter",
        }
    }
}

impl fmt::Display for PostureDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operational friction and workflow disruption tier for a given control.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum FrictionTier {
    /// Completely transparent. No functional degradation, latency, or visible UI changes.
    Tier0Transparent,
    /// Cosmetic UI changes. No productivity or workflow interruptions.
    Tier1Cosmetic,
    /// Disables user-facing conveniences, cloud sync, or visual thumbnails.
    Tier2WorkflowAltering,
    /// Incompatible with specific software, anti-forensic, or introduces security trade-offs.
    Tier3IncompatibleOrTradeoff,
}

impl FrictionTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tier0Transparent => "tier0_transparent",
            Self::Tier1Cosmetic => "tier1_cosmetic",
            Self::Tier2WorkflowAltering => "tier2_workflow_altering",
            Self::Tier3IncompatibleOrTradeoff => "tier3_incompatible_or_tradeoff",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Tier0Transparent => "Tier 0 (Transparent)",
            Self::Tier1Cosmetic => "Tier 1 (Cosmetic)",
            Self::Tier2WorkflowAltering => "Tier 2 (Workflow-Altering)",
            Self::Tier3IncompatibleOrTradeoff => "Tier 3 (Incompatible / Tradeoff)",
        }
    }

    pub const fn is_unattended_safe(self) -> bool {
        matches!(self, Self::Tier0Transparent)
    }

    pub const fn badge(self) -> &'static str {
        match self {
            Self::Tier0Transparent => "[Safe: Zero Breakage]",
            Self::Tier1Cosmetic => "[Cosmetic: Minor Indicator]",
            Self::Tier2WorkflowAltering => "[Workflow: Disables Feature]",
            Self::Tier3IncompatibleOrTradeoff => "[Tradeoff: Compatibility Risk]",
        }
    }
}

impl fmt::Display for FrictionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Evaluation metrics for a single posture dimension.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DimensionMetrics {
    /// Controls matching desired policy.
    pub compliant: usize,
    /// Controls confirmed drifting from desired policy.
    pub drift: usize,
    /// Controls requiring manual user review.
    pub review: usize,
    /// Controls that could not be evaluated (Unknown, NotChecked, Error).
    pub concealed: usize,
    /// Controls not applicable to this host edition or hardware.
    pub not_applicable: usize,
    /// Controls not selected by the evaluated profile.
    pub not_selected: usize,
}

impl DimensionMetrics {
    /// Total evaluated controls in this dimension.
    pub const fn evaluated(&self) -> usize {
        self.compliant + self.drift + self.review
    }

    /// Total applicable controls in this dimension on this host.
    pub const fn applicable(&self) -> usize {
        self.evaluated() + self.concealed
    }

    /// True if there are zero concealed controls in this dimension.
    pub const fn is_complete(&self) -> bool {
        self.concealed == 0
    }

    /// Compliance percentage expressed in basis points (0 to 10,000 = 0.00% to 100.00%).
    pub fn compliance_basis_points(&self) -> Option<u16> {
        let denom = self.evaluated();
        if denom == 0 {
            None
        } else {
            let bpos = (self.compliant as u64 * 10_000) / (denom as u64);
            Some(bpos as u16)
        }
    }
}

/// Multi-dimensional posture vector.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PostureVector {
    pub dimensions: BTreeMap<PostureDimension, DimensionMetrics>,
}

impl PostureVector {
    pub fn new() -> Self {
        let mut dimensions = BTreeMap::new();
        for dim in PostureDimension::ALL {
            dimensions.insert(dim, DimensionMetrics::default());
        }
        Self { dimensions }
    }

    pub fn record(&mut self, dimension: PostureDimension, outcome: Outcome) {
        let entry = self.dimensions.entry(dimension).or_default();
        match outcome {
            Outcome::Pass => entry.compliant += 1,
            Outcome::Drift => entry.drift += 1,
            Outcome::Review => entry.review += 1,
            Outcome::Unknown | Outcome::NotChecked | Outcome::Error => entry.concealed += 1,
            Outcome::NotApplicable => entry.not_applicable += 1,
            Outcome::NotSelected => entry.not_selected += 1,
        }
    }

    /// Complete if every individual dimension has zero concealed controls.
    pub fn is_complete(&self) -> bool {
        self.dimensions.values().all(|m| m.is_complete())
    }

    /// Check Pareto dominance against another posture vector.
    pub fn pareto_compare(&self, other: &Self) -> Option<Ordering> {
        let mut greater_count = 0;
        let mut less_count = 0;

        for dim in PostureDimension::ALL {
            let m_self = self.dimensions.get(&dim).copied().unwrap_or_default();
            let m_other = other.dimensions.get(&dim).copied().unwrap_or_default();

            let score_self = m_self.compliance_basis_points().unwrap_or(0);
            let score_other = m_other.compliance_basis_points().unwrap_or(0);

            if score_self > score_other {
                greater_count += 1;
            } else if score_self < score_other {
                less_count += 1;
            }
        }

        if greater_count > 0 && less_count == 0 {
            Some(Ordering::Greater)
        } else if less_count > 0 && greater_count == 0 {
            Some(Ordering::Less)
        } else if greater_count == 0 && less_count == 0 {
            Some(Ordering::Equal)
        } else {
            None // Incomparable trade-off across dimensions
        }
    }
}

/// Workload personas for contextual policy tuning.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadPersona {
    /// General daily-driver workstation: zero workflow disruption.
    #[default]
    General,
    /// Software developer: preserves local crash minidumps for debugging.
    Developer,
    /// Creative & media producer: preserves local thumbnail caching for image/video curation.
    Creative,
    /// Mobile traveler on untrusted Wi-Fi: aggressive broadcast suppression, no shutdown delay.
    Mobile,
    /// High-assurance air-gapped workstation: maximum disk and memory lockdown.
    HighAssurance,
}

impl WorkloadPersona {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Developer => "developer",
            Self::Creative => "creative",
            Self::Mobile => "mobile",
            Self::HighAssurance => "high_assurance",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::General => "General Daily Driver",
            Self::Developer => "Software Developer",
            Self::Creative => "Creative & Media Producer",
            Self::Mobile => "Mobile Traveler",
            Self::HighAssurance => "High Assurance / Air-Gapped",
        }
    }
}

impl fmt::Display for WorkloadPersona {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A deterministic recommendation for improving posture within a friction budget.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub control_id: String,
    pub title: String,
    pub section: String,
    pub dimension: PostureDimension,
    pub friction_tier: FrictionTier,
    pub remediation: Remediation,
    pub reversibility: Reversibility,
    pub support: Support,
    pub current_state: String,
    pub desired_state: String,
    pub rationale: String,
    pub tradeoff: Option<String>,
}

impl Ord for Recommendation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.friction_tier
            .cmp(&other.friction_tier)
            .then_with(|| self.dimension.cmp(&other.dimension))
            .then_with(|| self.control_id.cmp(&other.control_id))
    }
}

impl PartialOrd for Recommendation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_vector_records_and_calculates_dimensions() {
        let mut pv = PostureVector::new();
        pv.record(PostureDimension::BehavioralCommercial, Outcome::Pass);
        pv.record(PostureDimension::BehavioralCommercial, Outcome::Pass);
        pv.record(PostureDimension::BehavioralCommercial, Outcome::Drift);

        let m = pv
            .dimensions
            .get(&PostureDimension::BehavioralCommercial)
            .unwrap();
        assert_eq!(m.compliant, 2);
        assert_eq!(m.drift, 1);
        assert_eq!(m.evaluated(), 3);
        assert_eq!(m.compliance_basis_points(), Some(6666));
        assert!(pv.is_complete());
    }

    #[test]
    fn posture_pareto_dominance() {
        let mut pv1 = PostureVector::new();
        let mut pv2 = PostureVector::new();

        pv1.record(PostureDimension::BehavioralCommercial, Outcome::Pass);
        pv2.record(PostureDimension::BehavioralCommercial, Outcome::Drift);

        assert_eq!(pv1.pareto_compare(&pv2), Some(Ordering::Greater));
        assert_eq!(pv2.pareto_compare(&pv1), Some(Ordering::Less));
    }

    #[test]
    fn friction_tiers_ordering() {
        assert!(FrictionTier::Tier0Transparent < FrictionTier::Tier1Cosmetic);
        assert!(FrictionTier::Tier1Cosmetic < FrictionTier::Tier2WorkflowAltering);
        assert!(FrictionTier::Tier2WorkflowAltering < FrictionTier::Tier3IncompatibleOrTradeoff);
    }

    #[test]
    fn posture_dimension_display_and_helpers() {
        for dim in PostureDimension::ALL {
            assert!(!dim.as_str().is_empty());
            assert!(!dim.display_name().is_empty());
            assert_eq!(format!("{dim}"), dim.as_str());
        }
    }

    #[test]
    fn friction_tier_display_and_helpers() {
        for tier in [
            FrictionTier::Tier0Transparent,
            FrictionTier::Tier1Cosmetic,
            FrictionTier::Tier2WorkflowAltering,
            FrictionTier::Tier3IncompatibleOrTradeoff,
        ] {
            assert!(!tier.as_str().is_empty());
            assert!(!tier.display_name().is_empty());
            assert_eq!(format!("{tier}"), tier.as_str());
        }
        assert!(FrictionTier::Tier0Transparent.is_unattended_safe());
        assert!(!FrictionTier::Tier1Cosmetic.is_unattended_safe());
        assert_eq!(
            FrictionTier::Tier0Transparent.badge(),
            "[Safe: Zero Breakage]"
        );
        assert_eq!(
            FrictionTier::Tier1Cosmetic.badge(),
            "[Cosmetic: Minor Indicator]"
        );
        assert_eq!(
            FrictionTier::Tier2WorkflowAltering.badge(),
            "[Workflow: Disables Feature]"
        );
        assert_eq!(
            FrictionTier::Tier3IncompatibleOrTradeoff.badge(),
            "[Tradeoff: Compatibility Risk]"
        );
    }

    #[test]
    fn workload_persona_display_and_helpers() {
        for persona in [
            WorkloadPersona::General,
            WorkloadPersona::Developer,
            WorkloadPersona::Creative,
            WorkloadPersona::Mobile,
            WorkloadPersona::HighAssurance,
        ] {
            assert!(!persona.as_str().is_empty());
            assert!(!persona.display_name().is_empty());
            assert_eq!(format!("{persona}"), persona.as_str());
        }
        assert_eq!(WorkloadPersona::default(), WorkloadPersona::General);
    }

    #[test]
    fn dimension_metrics_applicable_and_zero_denom() {
        let mut m = DimensionMetrics::default();
        assert_eq!(m.evaluated(), 0);
        assert_eq!(m.compliance_basis_points(), None);
        assert!(m.is_complete());

        m.concealed = 1;
        assert!(!m.is_complete());
        assert_eq!(m.applicable(), 1);
    }

    #[test]
    fn recommendation_ordering() {
        let r1 = Recommendation {
            control_id: "a".to_owned(),
            title: "A".to_owned(),
            section: "sec".to_owned(),
            dimension: PostureDimension::BehavioralCommercial,
            friction_tier: FrictionTier::Tier0Transparent,
            remediation: Remediation::Automatic,
            reversibility: Reversibility::Exact,
            support: Support::Verified,
            current_state: "drift".to_owned(),
            desired_state: "pass".to_owned(),
            rationale: "rat".to_owned(),
            tradeoff: None,
        };
        let mut r2 = r1.clone();
        r2.control_id = "b".to_owned();
        r2.friction_tier = FrictionTier::Tier2WorkflowAltering;

        assert!(r1 < r2);
    }

    #[test]
    fn pareto_compare_tradeoff_incomparable() {
        let mut pv1 = PostureVector::new();
        let mut pv2 = PostureVector::new();

        pv1.record(PostureDimension::BehavioralCommercial, Outcome::Pass);
        pv1.record(PostureDimension::ForensicResidue, Outcome::Drift);

        pv2.record(PostureDimension::BehavioralCommercial, Outcome::Drift);
        pv2.record(PostureDimension::ForensicResidue, Outcome::Pass);

        // Trade-off across dimensions: neither Pareto dominates the other
        assert_eq!(pv1.pareto_compare(&pv2), None);
        assert_eq!(pv1.pareto_compare(&pv1), Some(Ordering::Equal));
    }
}
