//! The capability manifest.
//!
//! `list` answers a different question from `check`. Check asks what is true on
//! this machine; list asks what this build is able to examine at all. Keeping
//! them separate is what lets coverage be stated honestly, because the
//! denominator comes from here rather than from whatever happened to be
//! evaluated.
//!
//! This is also the surface an agent routes against. A caller maps a plain
//! request to control identifiers by querying this rather than by holding every
//! identifier in context.

use serde::Serialize;

use crate::catalog;
use crate::model::outcome::{Maturity, Remediation, Reversibility};
use crate::ui::{Ui, style};

/// One control as it appears in the manifest.
#[derive(Debug, Serialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub section: String,
    pub summary: String,
    /// The state this control aims for.
    pub desired: String,
    pub reversibility: Reversibility,
    pub maturity: Maturity,
    pub remediation: Remediation,
    /// Whether changing this costs the operator something.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tradeoff: Option<String>,
    /// How to keep the affected capability, where a way exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<String>,
    pub sources: Vec<String>,
}

/// The manifest for this build.
#[derive(Debug, Serialize)]
pub struct Manifest {
    pub schema: u8,
    /// The platform these controls target, which is the platform this binary
    /// was built for. A build ships no control it cannot evaluate.
    pub platform: String,
    pub total: usize,
    pub entries: Vec<Entry>,
}

impl Manifest {
    pub fn build(query: Option<&str>) -> Self {
        let needle = query.map(str::to_ascii_lowercase);

        let mut entries: Vec<Entry> = catalog::all()
            .into_iter()
            .filter(|control| {
                needle.as_ref().is_none_or(|needle| {
                    // Matched across identifier, title, section, and summary,
                    // so a caller can find a control by what it does rather
                    // than by knowing what it is called.
                    let haystack = format!(
                        "{} {} {} {}",
                        control.spec.id, control.title, control.spec.section, control.summary
                    )
                    .to_ascii_lowercase();
                    haystack.contains(needle)
                })
            })
            .map(|control| Entry {
                id: control.spec.id.clone(),
                title: control.title.to_owned(),
                section: control.spec.section.clone(),
                summary: control.summary.to_owned(),
                desired: control.spec.desired.0.clone(),
                reversibility: control.spec.reversibility,
                maturity: control.spec.maturity,
                remediation: control.spec.remediation,
                tradeoff: control.tradeoff.map(str::to_owned),
                mitigation: control.mitigation.map(str::to_owned),
                sources: control.sources.iter().map(|s| s.url.to_owned()).collect(),
            })
            .collect();

        entries.sort_by(|a, b| (&a.section, &a.id).cmp(&(&b.section, &b.id)));

        Self {
            schema: 1,
            platform: crate::model::host::Platform::current().as_str().to_owned(),
            total: entries.len(),
            entries,
        }
    }

    pub fn to_text(&self, ui: &Ui) -> String {
        let mut out = String::new();

        if self.entries.is_empty() {
            out.push_str(&ui.wrap("No controls are implemented for this platform yet.", 0));
            out.push('\n');
            return out;
        }

        let mut current_section = "";
        for entry in &self.entries {
            if entry.section != current_section {
                current_section = &entry.section;
                out.push_str(&format!(
                    "\n{}\n",
                    ui.paint(style::HEADING, current_section)
                ));
            }
            out.push_str(&format!("  {}\n", ui.paint(style::IDENT, &entry.id)));
            out.push_str(&ui.wrap(&entry.summary, 4));
            out.push('\n');

            // Say up front whether this is something privr will change, so a
            // reader is never surprised later by an audit-only control.
            let capability = match entry.remediation {
                Remediation::Automatic => "reversible change available",
                Remediation::Guided => "guided, privr will not change it",
                Remediation::AuditOnly => "reported only",
                Remediation::None => "not changeable",
            };
            out.push_str(&ui.paint(style::MUTED, &format!("    {capability}")));
            out.push('\n');
        }

        out.push_str(&format!(
            "\n{}\n",
            ui.paint(
                style::MUTED,
                &format!(
                    "{} control{} in this build. Run privr explain <id> for evidence.",
                    self.total,
                    if self.total == 1 { "" } else { "s" }
                )
            )
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_counts_what_it_lists() {
        let manifest = Manifest::build(None);
        assert_eq!(manifest.total, manifest.entries.len());
    }

    #[test]
    fn entries_are_ordered_deterministically() {
        let first = Manifest::build(None);
        let second = Manifest::build(None);
        let ids =
            |m: &Manifest| -> Vec<String> { m.entries.iter().map(|e| e.id.clone()).collect() };
        assert_eq!(ids(&first), ids(&second));
    }

    #[cfg(windows)]
    #[test]
    fn a_query_matches_on_what_a_control_does_not_only_its_name() {
        // The routing property an agent depends on: find a control from a plain
        // description rather than from knowing its identifier.
        let by_word = Manifest::build(Some("advertising"));
        assert_eq!(by_word.total, 1);

        let by_behaviour = Manifest::build(Some("linked across"));
        assert_eq!(by_behaviour.total, 1, "summary text is not searchable");
    }

    #[cfg(windows)]
    #[test]
    fn a_query_that_matches_nothing_returns_nothing_not_everything() {
        // An empty result must never widen into the full catalogue, which
        // would silently answer a different question.
        let manifest = Manifest::build(Some("zzzz-no-such-control"));
        assert_eq!(manifest.total, 0);
        assert!(manifest.entries.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn every_entry_carries_what_a_caller_needs_to_route() {
        for entry in Manifest::build(None).entries {
            assert!(!entry.id.is_empty());
            assert!(!entry.title.is_empty());
            assert!(!entry.summary.is_empty());
            assert!(!entry.desired.is_empty());
            assert!(!entry.sources.is_empty(), "{} has no source", entry.id);
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_listing_states_whether_privr_will_change_each_control() {
        // A reader must not have to run apply to discover a control is
        // audit-only.
        let text = Manifest::build(None).to_text(&Ui::plain());
        assert!(text.contains("reported only") || text.contains("reversible change"));
    }

    #[test]
    fn plain_output_contains_no_escape_sequences() {
        let text = Manifest::build(None).to_text(&Ui::plain());
        assert!(!text.contains('\u{1b}'));
    }
}
