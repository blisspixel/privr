//! Declarative applicability, without a mini programming language.
//!
//! Applicability is a flat conjunction of typed predicates over [`HostFacts`].
//! There is no nesting, no disjunction, no negation, no comparison between two
//! facts, and no pattern matching. Disjunction is expressed as ordered
//! first-match variants, each carrying its own conjunction.
//!
//! The restriction is deliberate. An expression language in catalogue data is
//! the mechanism by which non-executable content becomes executable content: a
//! free-form parameter is a target in disguise. Predicates are drawn from a
//! closed compiled set with typed arguments, so a catalogue can narrow what a
//! compiled adapter does but can never describe something new.

use serde::{Deserialize, Serialize};

use super::host::{Architecture, ContainerKind, Fact, HostFacts, OsVersion, Platform, WriteModel};

/// Whether a control applies to a host.
///
/// Tri-state, because "we could not tell" must never collapse into "does not
/// apply". A control silently excluded on an undetermined fact is a control the
/// operator believes was checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Applies {
    Yes,
    No,
    Undetermined,
}

impl Applies {
    /// Combine two results in a conjunction.
    ///
    /// A definite `No` wins over `Undetermined`: if the platform is Linux, a
    /// Windows-only control does not apply regardless of what else is unknown.
    /// Otherwise any uncertainty propagates.
    pub const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Undetermined, _) | (_, Self::Undetermined) => Self::Undetermined,
            (Self::Yes, Self::Yes) => Self::Yes,
        }
    }
}

/// Evaluate a fact against a test, preserving undeterminedness.
fn check<T>(fact: &Fact<T>, test: impl FnOnce(&T) -> bool) -> Applies {
    match fact {
        Fact::Known(value) => {
            if test(value) {
                Applies::Yes
            } else {
                Applies::No
            }
        }
        // The fact does not exist on this platform, so a predicate about it
        // cannot be satisfied. That is a definite answer, not uncertainty.
        Fact::NotPresent => Applies::No,
        Fact::Unknown => Applies::Undetermined,
    }
}

/// Case-insensitive membership, used for identifiers the platform reports as
/// free text such as editions, distributions, and desktop names.
fn contains_ignoring_case(haystack: &[String], needle: &str) -> bool {
    haystack
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(needle))
}

/// One typed predicate from the closed set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "predicate", content = "value")]
pub enum Predicate {
    Platform(Platform),
    /// Host version is at or above this version.
    VersionAtLeast(OsVersion),
    /// Host version is strictly below this version, for controls that a later
    /// release removed or replaced.
    VersionBelow(OsVersion),
    ArchitectureIn(Vec<Architecture>),
    /// Windows edition, or the distribution variant elsewhere.
    ///
    /// Membership is enumerated rather than negated. Listing the editions a
    /// control works on forces the author to know them, whereas excluding one
    /// silently assumes every future edition behaves like today's.
    EditionIn(Vec<String>),
    DistributionIn(Vec<String>),
    DesktopIn(Vec<String>),
    SessionTypeIn(Vec<String>),
    WriteModelIn(Vec<WriteModel>),
    ContainerIn(Vec<ContainerKind>),
    /// A live session for the intended user is required. User-scope settings
    /// written without one can report success while changing nothing.
    LiveSession(bool),
    /// The process must be able to act as the intended user.
    CanActAsUser(bool),
    Elevated(bool),
    /// An external management authority is present.
    Managed(bool),
}

impl Predicate {
    pub fn evaluate(&self, host: &HostFacts) -> Applies {
        match self {
            Self::Platform(expected) => {
                if host.platform == *expected {
                    Applies::Yes
                } else {
                    Applies::No
                }
            }
            Self::VersionAtLeast(minimum) => {
                check(&host.version, |actual| actual.at_least(minimum))
            }
            Self::VersionBelow(ceiling) => check(&host.version, |actual| !actual.at_least(ceiling)),
            Self::ArchitectureIn(allowed) => {
                check(&host.architecture, |actual| allowed.contains(actual))
            }
            Self::EditionIn(allowed) => check(&host.edition, |actual| {
                contains_ignoring_case(allowed, actual)
            }),
            Self::DistributionIn(allowed) => check(&host.distribution, |actual| {
                contains_ignoring_case(allowed, actual)
            }),
            Self::DesktopIn(allowed) => check(&host.session.desktop, |actual| {
                contains_ignoring_case(allowed, actual)
            }),
            Self::SessionTypeIn(allowed) => check(&host.session.session_type, |actual| {
                contains_ignoring_case(allowed, actual)
            }),
            Self::WriteModelIn(allowed) => {
                check(&host.write_model, |actual| allowed.contains(actual))
            }
            Self::ContainerIn(allowed) => check(&host.container, |actual| allowed.contains(actual)),
            Self::LiveSession(expected) => {
                check(&host.session.live_session, |actual| actual == expected)
            }
            Self::CanActAsUser(expected) => {
                check(&host.session.can_act_as_user, |actual| actual == expected)
            }
            Self::Elevated(expected) => check(&host.elevated, |actual| actual == expected),
            Self::Managed(expected) => check(&host.managed, |actual| actual == expected),
        }
    }
}

/// One applicability case: a conjunction of predicates.
///
/// A control carries an ordered list of these. The first that applies wins, and
/// each may narrow the control's risk, privilege, or restart behavior. It may
/// never widen them.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Variant {
    /// A stable name, so a result can say which case matched.
    pub name: String,
    pub predicates: Vec<Predicate>,
}

impl Variant {
    pub fn new(name: impl Into<String>, predicates: Vec<Predicate>) -> Self {
        Self {
            name: name.into(),
            predicates,
        }
    }

    pub fn evaluate(&self, host: &HostFacts) -> Applies {
        self.predicates.iter().fold(Applies::Yes, |acc, predicate| {
            acc.and(predicate.evaluate(host))
        })
    }
}

/// The full applicability of a control: ordered first-match variants.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Applicability {
    pub variants: Vec<Variant>,
}

/// Which variant matched, if any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Match<'a> {
    pub applies: Applies,
    pub variant: Option<&'a Variant>,
}

impl Applicability {
    pub fn new(variants: Vec<Variant>) -> Self {
        Self { variants }
    }

    /// Resolve applicability against a host.
    ///
    /// Returns the first variant that definitely applies. If none does but one
    /// could not be resolved, the result is undetermined rather than negative.
    pub fn resolve<'a>(&'a self, host: &HostFacts) -> Match<'a> {
        // An empty applicability applies everywhere. A control that never
        // constrains itself is a catalogue error, caught at load rather than
        // silently excluded here.
        if self.variants.is_empty() {
            return Match {
                applies: Applies::Yes,
                variant: None,
            };
        }

        let mut saw_undetermined = false;
        for variant in &self.variants {
            match variant.evaluate(host) {
                Applies::Yes => {
                    return Match {
                        applies: Applies::Yes,
                        variant: Some(variant),
                    };
                }
                Applies::Undetermined => saw_undetermined = true,
                Applies::No => {}
            }
        }

        Match {
            applies: if saw_undetermined {
                Applies::Undetermined
            } else {
                Applies::No
            },
            variant: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::host::SessionFacts;

    fn windows_host() -> HostFacts {
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

    #[test]
    fn conjunction_lets_a_definite_no_beat_uncertainty() {
        // Wrong platform settles it, whatever else is unknown.
        assert_eq!(Applies::No.and(Applies::Undetermined), Applies::No);
        assert_eq!(Applies::Undetermined.and(Applies::No), Applies::No);
    }

    #[test]
    fn conjunction_propagates_uncertainty_over_success() {
        assert_eq!(
            Applies::Yes.and(Applies::Undetermined),
            Applies::Undetermined
        );
        assert_eq!(
            Applies::Undetermined.and(Applies::Yes),
            Applies::Undetermined
        );
        assert_eq!(Applies::Yes.and(Applies::Yes), Applies::Yes);
    }

    #[test]
    fn an_unknown_fact_never_collapses_into_not_applicable() {
        // This is the property the whole tri-state exists for. A host whose
        // edition could not be read must not silently drop an edition-gated
        // control, because the operator would believe it was checked.
        let mut host = windows_host();
        host.edition = Fact::Unknown;

        let applicability = Applicability::new(vec![Variant::new(
            "enterprise",
            vec![Predicate::EditionIn(vec!["Enterprise".to_owned()])],
        )]);

        assert_eq!(applicability.resolve(&host).applies, Applies::Undetermined);
    }

    #[test]
    fn a_fact_absent_from_the_platform_is_a_definite_no() {
        // Desktop environment does not exist on Windows, so a desktop-gated
        // control genuinely does not apply. That is not uncertainty.
        let host = windows_host();
        let predicate = Predicate::DesktopIn(vec!["gnome".to_owned()]);
        assert_eq!(predicate.evaluate(&host), Applies::No);
    }

    #[test]
    fn edition_matching_ignores_case() {
        let host = windows_host();
        let predicate = Predicate::EditionIn(vec!["professional".to_owned()]);
        assert_eq!(predicate.evaluate(&host), Applies::Yes);
    }

    #[test]
    fn version_predicates_bound_from_both_ends() {
        let host = windows_host();

        let at_least = Predicate::VersionAtLeast(OsVersion::new(vec![10, 0, 22000], "10.0.22000"));
        assert_eq!(at_least.evaluate(&host), Applies::Yes);

        let too_new = Predicate::VersionAtLeast(OsVersion::new(vec![10, 0, 99999], "10.0.99999"));
        assert_eq!(too_new.evaluate(&host), Applies::No);

        let below = Predicate::VersionBelow(OsVersion::new(vec![10, 0, 99999], "10.0.99999"));
        assert_eq!(below.evaluate(&host), Applies::Yes);
    }

    #[test]
    fn first_matching_variant_wins_in_order() {
        let applicability = Applicability::new(vec![
            Variant::new(
                "enterprise",
                vec![Predicate::EditionIn(vec!["Enterprise".to_owned()])],
            ),
            Variant::new(
                "professional",
                vec![Predicate::EditionIn(vec!["Professional".to_owned()])],
            ),
        ]);

        let resolved = applicability.resolve(&windows_host());
        assert_eq!(resolved.applies, Applies::Yes);
        assert_eq!(
            resolved.variant.map(|v| v.name.as_str()),
            Some("professional")
        );
    }

    #[test]
    fn all_variants_failing_definitely_yields_not_applicable() {
        let applicability = Applicability::new(vec![Variant::new(
            "linux-only",
            vec![Predicate::Platform(Platform::Linux)],
        )]);

        let resolved = applicability.resolve(&windows_host());
        assert_eq!(resolved.applies, Applies::No);
        assert!(resolved.variant.is_none());
    }

    #[test]
    fn one_undetermined_variant_taints_an_otherwise_negative_result() {
        let mut host = windows_host();
        host.edition = Fact::Unknown;

        let applicability = Applicability::new(vec![
            // Definitely does not apply.
            Variant::new("linux-only", vec![Predicate::Platform(Platform::Linux)]),
            // Cannot be resolved, so the whole result must stay uncertain.
            Variant::new(
                "enterprise",
                vec![Predicate::EditionIn(vec!["Enterprise".to_owned()])],
            ),
        ]);

        assert_eq!(applicability.resolve(&host).applies, Applies::Undetermined);
    }

    #[test]
    fn a_totally_unknown_host_leaves_everything_undetermined() {
        let host = HostFacts::unknown(Platform::Windows);
        let applicability = Applicability::new(vec![Variant::new(
            "any-windows",
            vec![
                Predicate::Platform(Platform::Windows),
                Predicate::VersionAtLeast(OsVersion::new(vec![10], "10")),
            ],
        )]);

        assert_eq!(applicability.resolve(&host).applies, Applies::Undetermined);
    }

    #[test]
    fn a_live_session_requirement_is_gated_not_assumed() {
        let mut host = windows_host();
        host.session = SessionFacts {
            live_session: Fact::Unknown,
            desktop: Fact::Known("gnome".to_owned()),
            session_type: Fact::Known("wayland".to_owned()),
            can_act_as_user: Fact::Known(true),
        };

        let predicate = Predicate::LiveSession(true);
        assert_eq!(predicate.evaluate(&host), Applies::Undetermined);
    }
}
