//! Building and rendering a check report.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::catalog;
use crate::engine::evaluate::{Mode, evaluate};
use crate::model::host::HostFacts;
use crate::model::outcome::{ControlResult, Exception, Outcome, Summary};
use crate::ui::{Ui, style};

/// Capitalise a lowercase platform identifier for display.
fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

/// The report schema version. Any change to the shape of this output is a
/// change to a published contract and must bump this.
pub const SCHEMA: u8 = 1;

#[derive(Serialize)]
pub struct Report {
    pub schema: u8,
    pub complete: bool,
    pub truncated: bool,
    pub profile: String,
    pub platform: String,
    /// The vendor's own version string. Carries no machine identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// How many controls this build carries.
    ///
    /// Emitted alongside the summary because completeness and coverage are
    /// different claims, and a consumer that sees only the first will overstate
    /// what the report established.
    pub carried: usize,
    pub summary: Summary,
    pub results: Vec<ControlResult>,
}

impl Report {
    /// Evaluate every applicable control against this host.
    pub fn build(host: &HostFacts, profile: &str) -> Self {
        let context = catalog::Context::live(host);
        let mut results: Vec<ControlResult> = catalog::all()
            .iter()
            .map(|control| {
                evaluate(
                    &control.spec,
                    Mode::Enforce,
                    &control.observe(&context),
                    host,
                    Exception::None,
                )
            })
            .collect();

        // Deterministic order, so two runs are diffable without normalisation.
        results.sort_by(|a, b| (&a.section, &a.id).cmp(&(&b.section, &b.id)));

        let summary = Summary::of(&results);

        Self {
            schema: SCHEMA,
            // A build with no controls has observed nothing, so it cannot claim
            // to be complete however clean the summary looks.
            complete: summary.is_complete() && !results.is_empty(),
            truncated: false,
            profile: profile.to_owned(),
            platform: host.platform.as_str().to_owned(),
            os_version: host.version.known().map(|v| v.display.clone()),
            edition: host.edition.known().cloned(),
            carried: results.len(),
            summary,
            results,
        }
    }

    /// The process exit code this report implies.
    pub fn exit_code(&self) -> i32 {
        // Incomplete wins over drift: something is hidden, and reporting a
        // clean drift count would overstate what was actually established.
        if !self.complete {
            return 3;
        }
        if self.summary.drift > 0 {
            return 1;
        }
        0
    }

    pub fn to_text(&self, ui: &Ui, show_all: bool) -> String {
        let mut out = String::new();
        let field = |name: &str| ui.paint(style::MUTED, &format!("{name:<9}"));

        out.push_str(&format!("{}{}\n", field("Profile"), self.profile));

        let platform = match (&self.edition, &self.os_version) {
            (Some(edition), Some(version)) => {
                format!("{} {edition}, {version}", capitalise(&self.platform))
            }
            _ => capitalise(&self.platform),
        };
        out.push_str(&format!("{}{platform}\n", field("Platform")));

        // Completeness and coverage are separate claims, and only showing the
        // first lets a thin catalogue read as a clean machine.
        let evaluated = self.summary.evaluated();
        let coverage = if self.complete {
            format!("{evaluated} of {} controls in this build", self.carried)
        } else {
            format!(
                "{evaluated} of {} controls, {} could not be established",
                self.carried,
                self.summary.concealed()
            )
        };
        out.push_str(&format!("{}{coverage}\n\n", field("Coverage")));

        out.push_str(&self.count_line(ui));

        let mut sections: BTreeMap<&str, Vec<&ControlResult>> = BTreeMap::new();
        for result in &self.results {
            if show_all || result.outcome != Outcome::Pass {
                sections.entry(&result.section).or_default().push(result);
            }
        }

        for (section, results) in sections {
            out.push_str(&format!("\n{}\n", ui.paint(style::HEADING, section)));
            for result in results {
                let label = ui.paint(
                    style::outcome_style(result.outcome),
                    style::outcome_label(result.outcome),
                );
                out.push_str(&format!("  {label}  {}\n", result.title));
                out.push_str(&ui.paint(style::MUTED, &format!("            {}", result.id)));
                out.push('\n');

                // A note is printed even on a pass, because the case it exists
                // for is precisely a finding that looks fine and is not what
                // the operator configured.
                if let Some(note) = &result.note {
                    out.push_str(&ui.paint(style::CAVEAT, &ui.wrap(note, 12)));
                    out.push('\n');
                }

                // Uncertainty is stated in words at the point of the finding,
                // never left to be inferred from a colour.
                if result.outcome.conceals_state() {
                    out.push_str(&ui.paint(
                        style::CAVEAT,
                        "            Reported as unknown, not as passing.",
                    ));
                    out.push('\n');
                }
            }
        }

        out.push('\n');
        if self.results.is_empty() {
            out.push_str(&ui.wrap(
                "No controls are implemented for this platform yet, so this says nothing \
                 about the machine.",
                0,
            ));
        } else {
            // Permanent, not a placeholder for a thin catalogue. A report can
            // only ever speak for the settings it carries, and saying so keeps a
            // clean summary from reading as a clean machine.
            let note = format!(
                "This build carries {} control{}. It is not a full picture of this machine.",
                self.carried,
                if self.carried == 1 { "" } else { "s" }
            );
            out.push_str(&ui.paint(style::MUTED, &ui.wrap(&note, 0)));
        }
        out.push('\n');

        out
    }

    /// The count line.
    ///
    /// Empty categories are omitted as noise, except any category that hides
    /// state, which is always shown so it cannot be missed.
    fn count_line(&self, ui: &Ui) -> String {
        let s = &self.summary;
        let paint = |outcome: Outcome, count: usize, word: &str| {
            ui.paint(style::outcome_style(outcome), &format!("{count} {word}"))
        };

        let mut parts = vec![
            paint(Outcome::Pass, s.pass, "pass"),
            paint(Outcome::Drift, s.drift, "drift"),
        ];
        if s.review > 0 {
            parts.push(paint(Outcome::Review, s.review, "review"));
        }
        if s.unknown > 0 {
            parts.push(paint(Outcome::Unknown, s.unknown, "unknown"));
        }
        if s.not_checked > 0 {
            parts.push(paint(Outcome::NotChecked, s.not_checked, "not checked"));
        }
        if s.error > 0 {
            parts.push(paint(Outcome::Error, s.error, "error"));
        }
        if s.not_applicable > 0 {
            parts.push(paint(
                Outcome::NotApplicable,
                s.not_applicable,
                "not applicable",
            ));
        }
        format!("{}\n", parts.join("    "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::host::Platform;
    use crate::platform;

    fn empty_report() -> Report {
        Report {
            schema: SCHEMA,
            complete: true,
            truncated: false,
            profile: "baseline".to_owned(),
            platform: "linux".to_owned(),
            os_version: None,
            edition: None,
            carried: 0,
            summary: Summary::default(),
            results: Vec::new(),
        }
    }

    #[test]
    fn a_report_with_no_controls_is_never_complete() {
        // Observing nothing is not the same as finding nothing wrong. A clean
        // summary over an empty result set would be the emptiest possible false
        // pass, so completeness requires that something was evaluated.
        assert!(Summary::default().is_complete());

        let host = HostFacts::unknown(Platform::Linux);
        let built = Report::build(&host, "baseline");
        if built.results.is_empty() {
            assert!(!built.complete);
            assert_eq!(built.exit_code(), 3);
        }
    }

    /// Collapse whitespace so an assertion is not coupled to wrapping or
    /// column padding, which are presentation choices that may change.
    fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn an_empty_report_says_it_establishes_nothing() {
        let text = empty_report().to_text(&Ui::plain(), true);
        assert!(flat(&text).contains("says nothing about the machine"));
    }

    #[test]
    fn coverage_is_reported_alongside_completeness() {
        // The failure this prevents: a one-control build reporting "complete"
        // and reading as a clean bill of health for the whole machine.
        let host = platform::discover();
        let report = Report::build(&host, "baseline");
        let text = report.to_text(&Ui::plain(), true);

        assert!(text.contains("Coverage"), "coverage line missing");
        if !report.results.is_empty() {
            assert!(
                flat(&text).contains("not a full picture of this machine"),
                "report does not disclaim its own coverage"
            );
        }
    }

    #[test]
    fn incomplete_outranks_drift_in_the_exit_code() {
        let host = platform::discover();
        let mut report = Report::build(&host, "baseline");

        report.complete = false;
        report.summary.drift = 1;
        assert_eq!(report.exit_code(), 3);

        report.complete = true;
        assert_eq!(report.exit_code(), 1);

        report.summary.drift = 0;
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn results_are_ordered_deterministically() {
        let host = platform::discover();
        let first = Report::build(&host, "baseline");
        let second = Report::build(&host, "baseline");

        let ids = |r: &Report| -> Vec<String> { r.results.iter().map(|x| x.id.clone()).collect() };
        assert_eq!(ids(&first), ids(&second));
    }

    #[test]
    fn plain_output_contains_no_escape_sequences() {
        // The property that keeps a pipe, a log, and an agent parse clean.
        let host = platform::discover();
        let text = Report::build(&host, "baseline").to_text(&Ui::plain(), true);
        assert!(!text.contains('\u{1b}'), "escape sequence in plain output");
    }

    #[test]
    fn the_report_carries_no_machine_identifier() {
        let host = platform::discover();
        let report = Report::build(&host, "baseline");
        let rendered = serde_json::to_string(&report).expect("report serialises");

        for forbidden in ["S-1-5", "-1-5-21", "EnrollmentState"] {
            assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        }
        assert!(!rendered.contains("Users\\"), "leaked a profile path");
    }

    #[cfg(windows)]
    #[test]
    fn this_machine_produces_real_findings() {
        // Deliberately host-independent. What must hold on any Windows host is
        // that controls are evaluated, results are coherent, and completeness
        // agrees with whether anything was concealed. What this particular
        // machine holds is not asserted, because a test that depends on the
        // developer's registry state is a test that fails on someone else's.
        let host = platform::discover();
        let report = Report::build(&host, "baseline");

        assert!(!report.results.is_empty(), "no controls evaluated");
        for result in &report.results {
            assert!(result.is_coherent(), "incoherent result: {result:?}");
        }
        assert_eq!(report.complete, report.summary.concealed() == 0);

        let text = report.to_text(&Ui::plain(), true);
        assert!(text.contains("windows.advertising.id"));
        assert!(text.contains("Advertising identifier"));
        assert!(flat(&text).contains("Profile baseline"));
        assert!(flat(&text).contains("Coverage"));
    }
}
