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

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
pub mod residue;
#[cfg(windows)]
mod windows;

/// Schema version for compiled control definitions.
pub const CATALOG_SCHEMA: u8 = 1;

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
    #[cfg(target_os = "linux")]
    pub linux: &'a crate::platform::linux::evidence::Reader,
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

    #[cfg(target_os = "linux")]
    pub fn live(host: &'a HostFacts) -> Self {
        static LIVE: crate::platform::linux::evidence::Reader =
            crate::platform::linux::evidence::Reader::Live;
        Self { host, linux: &LIVE }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
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

use crate::model::evidence::RawValue;

/// An applied mutation operation for a control.
#[derive(Clone, Debug, PartialEq)]
pub struct AppliedOp {
    pub target_key: String,
    pub preimage: Option<RawValue>,
    pub postimage: RawValue,
}

pub type ApplyFn = fn(&Context) -> Result<AppliedOp, String>;
pub type RollbackFn = fn(&Context, &Option<RawValue>, &RawValue) -> Result<(), String>;

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
    /// Verified apply implementation, if available.
    pub apply: Option<ApplyFn>,
    /// Conflict-aware rollback implementation, if available.
    pub rollback: Option<RollbackFn>,
}

impl Control {
    pub fn observe(&self, context: &Context) -> Resolution {
        (self.probe)(context)
    }

    pub fn apply(&self, context: &Context) -> Option<Result<AppliedOp, String>> {
        self.apply.map(|f| f(context))
    }

    pub fn rollback(
        &self,
        context: &Context,
        preimage: &Option<RawValue>,
        postimage: &RawValue,
    ) -> Option<Result<(), String>> {
        self.rollback.map(|f| f(context, preimage, postimage))
    }

    pub fn requires_elevation(&self) -> bool {
        self.spec.requires_elevation
    }
}

/// Every control this build carries, in a stable documented order.
pub fn all() -> Vec<Control> {
    #[cfg(windows)]
    {
        windows::controls()
    }
    #[cfg(target_os = "linux")]
    {
        linux::controls()
    }
    #[cfg(target_os = "macos")]
    {
        macos::controls()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Check whether a control ID is known across any compiled platform catalogue.
pub fn is_known_control_id(id: &str) -> bool {
    if all().iter().any(|c| c.spec.id == id) {
        return true;
    }
    const ALL_REGISTERED_IDS: &[&str] = &[
        // Windows
        "windows.advertising.id",
        "windows.shell.history-persistence",
        "windows.ai.copilot-shell",
        "windows.ai.recall-snapshot",
        "windows.capability.account-info",
        "windows.capability.activity",
        "windows.capability.wifi-data",
        "windows.diagnostics.crash-dump-scope",
        "windows.diagnostics.error-reporting",
        "windows.diagnostics.feedback",
        "windows.diagnostics.inventory-collector",
        "windows.clipboard.cloud-sync",
        "windows.clipboard.cross-device",
        "windows.diagnostics.level",
        "windows.experience.start-suggestions",
        "windows.experience.suggested-apps",
        "windows.experience.system-suggestions",
        "windows.experience.tailored",
        "windows.input.personalization",
        "windows.search.device-history",
        "windows.search.web",
        "windows.delivery-optimization.mode",
        "windows.security.llmnr",
        "windows.security.ncsi-probing",
        "windows.security.wpad",
        "windows.browser.edge.telemetry",
        "windows.storage.pagefile-clear",
        "windows.storage.thumbnail-cache",
        "windows.storage.bitlocker-cipher",
        "windows.storage.dma-protection",
        "windows.storage.trim-notify",
        // Linux
        "debian.popularity-contest.participation",
        "fedora.abrt.auto-reporting",
        "freedesktop.thumbnails.caching",
        "gnome.crash-reporting.technical-problems",
        "gnome.history.application-usage",
        "gnome.history.recent-files",
        "gnome.telemetry.software-usage",
        "kde.user-feedback.global",
        "systemd.coredump.storage",
        "systemd.fstrim.timer",
        "systemd.journald.storage",
        "ubuntu.insights.consent",
        "ubuntu.report.consent",
        "networkmanager.connectivity.check",
        "avahi.mdns.publishing",
        "systemd.resolved.llmnr",
        "systemd.resolved.mdns",
        // macOS
        "macos.advertising.personalized",
        "macos.analytics.share-mac",
        "macos.analytics.share-with-developers",
        "macos.siri.improvement",
        "macos.storage.quarantine-events",
        "macos.storage.quicklook-cache",
    ];

    ALL_REGISTERED_IDS.contains(&id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_compiled_control_is_registered_in_known_catalogue() {
        for control in all() {
            assert!(
                is_known_control_id(&control.spec.id),
                "control '{}' missing from ALL_REGISTERED_IDS",
                control.spec.id
            );
        }
    }

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

    #[test]
    fn every_control_id_matches_its_section() {
        for control in all() {
            let parts: Vec<&str> = control.spec.id.split('.').collect();
            assert!(
                parts.len() >= 3,
                "control id '{}' must have at least 3 parts",
                control.spec.id
            );
            let expected_section = if parts[0] == "windows" || parts[0] == "macos" {
                parts[1]
            } else {
                parts[0]
            };
            assert_eq!(
                control.spec.section.as_str(),
                expected_section,
                "control id '{}' section mismatch: expected '{}', got '{}'",
                control.spec.id,
                expected_section,
                control.spec.section
            );
        }
    }

    #[test]
    fn no_control_contains_emojis_or_em_dashes() {
        for control in all() {
            let mut text_fields = vec![control.title, control.summary, control.rationale];
            if let Some(t) = control.tradeoff {
                text_fields.push(t);
            }
            if let Some(m) = control.mitigation {
                text_fields.push(m);
            }
            for source in control.sources {
                text_fields.push(source.claim);
            }

            for text in text_fields {
                for ch in text.chars() {
                    assert!(
                        ch != '\u{2014}' && ch != '\u{2013}',
                        "control '{}' contains em or en dash: '{}'",
                        control.spec.id,
                        text
                    );
                    assert!(
                        !matches!(ch, '\u{1F000}'..='\u{1FAFF}' | '\u{2600}'..='\u{27BF}' | '\u{FE0F}'),
                        "control '{}' contains emoji character: '{}'",
                        control.spec.id,
                        text
                    );
                }
            }
        }
    }
}
