//! The control catalogue.
//!
//! Controls are compiled definitions. Each binds a compiled probe, a set of
//! semantic states, and metadata. Nothing here accepts a path, key, command, or
//! target from outside the binary, which is what keeps catalogue content from
//! being able to describe a new privileged operation.
//!
//! Definitions are Rust constants for now. When they move to a shipped data
//! format they will name a compiled adapter and a compiled target rather than
//! carrying either, so the ceiling this module establishes does not move.

#[cfg(windows)]
mod windows;

use crate::engine::evaluate::{ControlSpec, Resolution};
use crate::model::host::HostFacts;

/// What a probe is allowed to look at.
///
/// A probe never reaches for the machine directly. It reads through this, so
/// the same control code runs against a live host and against recorded
/// evidence, and there is no separate implementation that can drift.
pub struct Context<'a> {
    pub host: &'a HostFacts,
    #[cfg(windows)]
    pub registry: &'a crate::platform::windows::registry::Registry,
}

impl<'a> Context<'a> {
    /// A context reading the machine this process is running on.
    #[cfg(windows)]
    pub fn live(host: &'a HostFacts) -> Self {
        use crate::platform::windows::registry::Registry;
        // A borrow of a constant with a static lifetime, so callers do not have
        // to hold a live registry value themselves.
        static LIVE: Registry = Registry::Live;
        Self {
            host,
            registry: &LIVE,
        }
    }

    #[cfg(not(windows))]
    pub fn live(host: &'a HostFacts) -> Self {
        Self { host }
    }
}

/// A primary source supporting a claim this control makes.
///
/// The claim is recorded alongside the link, because a bare URL does not say
/// what it was cited for, and a page that changes underneath a citation is the
/// most common way a catalogue quietly becomes wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source {
    pub url: &'static str,
    pub claim: &'static str,
    pub reviewed: &'static str,
}

/// A compiled control definition.
pub struct Control {
    pub spec: ControlSpec,
    /// Short user-facing name.
    pub title: &'static str,
    /// What the machine does, in the operator's language rather than the name
    /// of the underlying value.
    pub summary: &'static str,
    /// Why this matters for privacy.
    pub rationale: &'static str,
    /// What the operator loses by changing it, if anything.
    pub tradeoff: Option<&'static str>,
    /// How to keep the affected capability. The most valuable field on a review
    /// control: a tradeoff stated without a remedy is less useful than it looks.
    pub mitigation: Option<&'static str>,
    pub sources: &'static [Source],
    /// The compiled adapter. Owns every path, value name, type, and view.
    pub probe: fn(&Context) -> Resolution,
}

impl Control {
    pub fn observe(&self, context: &Context) -> Resolution {
        (self.probe)(context)
    }
}

/// Every control this build carries, in a stable documented order.
pub fn all() -> Vec<Control> {
    #[cfg(windows)]
    {
        windows::controls()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_identifiers_are_unique_and_ordered() {
        let controls = all();
        let ids: Vec<&str> = controls.iter().map(|c| c.spec.id.as_str()).collect();

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate control identifier");

        // Stable ordering matters: two runs must be diffable without
        // normalisation, and an agent compares reports across time.
        let mut expected = ids.clone();
        expected.sort_unstable();
        assert_eq!(ids, expected, "controls are not in sorted order");
    }

    #[test]
    fn every_control_carries_a_reviewed_source() {
        for control in all() {
            assert!(
                !control.sources.is_empty(),
                "{} has no source",
                control.spec.id
            );
            for source in control.sources {
                assert!(source.url.starts_with("https://"), "{}", control.spec.id);
                assert!(!source.claim.is_empty(), "{}", control.spec.id);
                assert!(!source.reviewed.is_empty(), "{}", control.spec.id);
            }
        }
    }

    #[test]
    fn every_control_explains_itself_without_naming_a_registry_path() {
        // The explanation belongs in the operator's language. The value name is
        // evidence, not description.
        for control in all() {
            assert!(!control.title.is_empty(), "{}", control.spec.id);
            assert!(!control.summary.is_empty(), "{}", control.spec.id);
            assert!(!control.rationale.is_empty(), "{}", control.spec.id);

            for text in [control.title, control.summary, control.rationale] {
                assert!(
                    !text.contains("HKEY_") && !text.contains("HKCU") && !text.contains("HKLM"),
                    "{} leaks a registry path into its explanation",
                    control.spec.id
                );
            }
        }
    }

    #[test]
    fn a_control_declaring_a_tradeoff_offers_a_mitigation() {
        for control in all() {
            if control.tradeoff.is_some() {
                assert!(
                    control.mitigation.is_some(),
                    "{} states a cost with no way to keep the capability",
                    control.spec.id
                );
            }
        }
    }
}
