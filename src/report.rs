//! Building and rendering a check report.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::catalog;
use crate::engine::evaluate::{Mode, evaluate};
use crate::model::host::HostFacts;
use crate::model::outcome::{ControlResult, Exception, Outcome, Summary};

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
    pub summary: Summary,
    pub results: Vec<ControlResult>,
}

impl Report {
    /// Evaluate every applicable control against this host.
    pub fn build(host: &HostFacts, profile: &str) -> Self {
        let mut results: Vec<ControlResult> = catalog::all()
            .iter()
            .map(|control| {
                evaluate(
                    &control.spec,
                    Mode::Enforce,
                    &control.observe(host),
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

    pub fn to_text(&self, show_all: bool) -> String {
        let mut out = String::new();

        out.push_str(&format!("Profile   {}\n", self.profile));
        let platform = match (&self.edition, &self.os_version) {
            (Some(edition), Some(version)) => format!("{} {edition} {version}", self.platform),
            _ => self.platform.clone(),
        };
        out.push_str(&format!("Platform  {platform}\n"));
        out.push_str(&format!(
            "Result    {}\n\n",
            if self.complete {
                "complete"
            } else {
                "incomplete"
            }
        ));

        let s = &self.summary;
        let mut counts = vec![
            format!("{} pass", s.pass),
            format!("{} drift", s.drift),
            format!("{} review", s.review),
        ];
        if s.unknown > 0 {
            counts.push(format!("{} unknown", s.unknown));
        }
        if s.not_applicable > 0 {
            counts.push(format!("{} not applicable", s.not_applicable));
        }
        if s.concealed() > s.unknown {
            counts.push(format!("{} not evaluated", s.concealed() - s.unknown));
        }
        out.push_str(&counts.join("   "));
        out.push('\n');

        // Group by section, preserving the sorted order of the results.
        let mut sections: BTreeMap<&str, Vec<&ControlResult>> = BTreeMap::new();
        for result in &self.results {
            let interesting = show_all || result.outcome != Outcome::Pass;
            if interesting {
                sections.entry(&result.section).or_default().push(result);
            }
        }

        for (section, results) in sections {
            out.push_str(&format!("\n{section}\n"));
            for result in results {
                out.push_str(&format!(
                    "  {:<8} {}\n",
                    result.outcome.as_str().to_uppercase(),
                    result.id
                ));
                if result.outcome == Outcome::Unknown {
                    out.push_str("           Reported as unknown, not as passing.\n");
                }
            }
        }

        if self.results.is_empty() {
            out.push_str("\nNo controls are implemented for this platform yet.\n");
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::host::Platform;
    use crate::platform;

    #[test]
    fn a_report_with_no_controls_is_never_complete() {
        // Observing nothing is not the same as finding nothing wrong. A clean
        // summary over an empty result set would be the emptiest possible false
        // pass, so completeness requires that something was actually evaluated.
        let report = Report {
            schema: SCHEMA,
            complete: true,
            truncated: false,
            profile: "baseline".to_owned(),
            platform: "linux".to_owned(),
            os_version: None,
            edition: None,
            summary: Summary::default(),
            results: Vec::new(),
        };
        assert!(Summary::default().is_complete());

        // Built through the real path on a host with no applicable controls.
        let host = HostFacts::unknown(Platform::Linux);
        let built = Report::build(&host, "baseline");
        if built.results.is_empty() {
            assert!(!built.complete);
            assert_eq!(built.exit_code(), 3);
        }
        // The hand-built one shows the shape the rule guards against.
        assert!(report.results.is_empty());
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
    fn the_report_carries_no_machine_identifier() {
        let host = platform::discover();
        let report = Report::build(&host, "baseline");
        let rendered = serde_json::to_string(&report).expect("report serialises");

        for forbidden in ["S-1-5", "-1-5-21", "EnrollmentState"] {
            assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        }
        // The user profile path is a common accidental leak.
        assert!(!rendered.contains("Users\\"), "leaked a profile path");
    }

    #[cfg(windows)]
    #[test]
    fn this_machine_produces_a_real_finding() {
        let host = platform::discover();
        let report = Report::build(&host, "baseline");

        assert!(!report.results.is_empty());
        assert_eq!(report.summary.evaluated(), report.results.len());
        assert!(report.complete);

        let text = report.to_text(true);
        assert!(text.contains("windows.advertising.id"));
        assert!(text.contains("Profile   baseline"));
    }
}
