//! Building and rendering a check report.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::catalog;
use crate::engine::evaluate::{Mode, evaluate};
use crate::model::Profile;
use crate::model::host::HostFacts;
use crate::model::outcome::{ControlResult, Exception, Outcome, Summary};
use crate::model::posture::{FrictionTier, PostureVector};
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
    pub posture: PostureVector,
    pub results: Vec<ControlResult>,
}

fn render_meter(ui: &Ui, compliant: usize, total: usize, width: usize) -> String {
    if total == 0 {
        let empty_char = if ui.unicode() { "·" } else { "." };
        let bar = empty_char.repeat(width);
        return format!("[{}]", ui.paint(style::MUTED, &bar));
    }

    let filled_count = ((compliant as f64 / total as f64) * width as f64).round() as usize;
    let filled_count = filled_count.min(width);
    let empty_count = width.saturating_sub(filled_count);

    let (fill_char, empty_char) = if ui.unicode() {
        ("█", "░")
    } else {
        ("=", ".")
    };

    let filled_str = fill_char.repeat(filled_count);
    let empty_str = empty_char.repeat(empty_count);

    let colored_fill = if filled_count > 0 {
        ui.paint(style::outcome_style(Outcome::Pass), &filled_str)
    } else {
        String::new()
    };

    let colored_empty = if empty_count > 0 {
        ui.paint(style::outcome_style(Outcome::Drift), &empty_str)
    } else {
        String::new()
    };

    format!("[{colored_fill}{colored_empty}]")
}

impl Report {
    /// Evaluate every applicable control against this host.
    pub fn build(host: &HostFacts, profile: &str) -> Self {
        Self::build_filtered(host, profile, &[], &[])
    }

    /// Evaluate filtered controls against this host.
    pub fn build_filtered(
        host: &HostFacts,
        profile: &str,
        control_filter: &[String],
        section_filter: &[String],
    ) -> Self {
        Self::build_filtered_workload(host, Some(profile), None, control_filter, section_filter)
    }

    /// Evaluate filtered controls against this host with optional workload persona.
    pub fn build_filtered_workload(
        host: &HostFacts,
        profile: Option<&str>,
        workload: Option<crate::model::posture::WorkloadPersona>,
        control_filter: &[String],
        section_filter: &[String],
    ) -> Self {
        let selected_profile = profile
            .and_then(|p| p.parse::<Profile>().ok())
            .unwrap_or_default();
        let context = catalog::Context::live(host);
        let all_controls = catalog::all();
        let recommended_ids: Option<std::collections::BTreeSet<String>> = workload.map(|w| {
            all_controls
                .iter()
                .filter(|c| {
                    crate::engine::recommend::is_control_recommended_for_workload(&c.spec, w, None)
                })
                .map(|c| c.spec.id.clone())
                .collect()
        });

        let mut results: Vec<ControlResult> = all_controls
            .iter()
            .filter(|c| {
                let matches_control = control_filter.is_empty()
                    || control_filter
                        .iter()
                        .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel));
                let matches_section = section_filter.is_empty()
                    || section_filter.iter().any(|sec| {
                        c.spec.section.eq_ignore_ascii_case(sec)
                            || c.spec
                                .section
                                .to_ascii_lowercase()
                                .starts_with(&sec.to_ascii_lowercase())
                    });
                matches_control && matches_section
            })
            .map(|control| {
                let mode = if !control_filter.is_empty()
                    || recommended_ids
                        .as_ref()
                        .is_some_and(|ids| ids.contains(&control.spec.id))
                    || (recommended_ids.is_none() && control.spec.min_profile <= selected_profile)
                {
                    Mode::Enforce
                } else {
                    Mode::Ignore
                };
                evaluate(
                    &control.spec,
                    mode,
                    &control.observe(&context),
                    host,
                    Exception::None,
                )
            })
            .collect();

        // Deterministic order, so two runs are diffable without normalisation.
        results.sort_by(|a, b| (&a.section, &a.id).cmp(&(&b.section, &b.id)));

        let summary = Summary::of(&results);
        let mut posture = PostureVector::new();
        for r in &results {
            posture.record(r.dimension, r.outcome);
        }

        let profile_str = if let Some(w) = workload {
            format!("workload:{}", w.as_str())
        } else {
            profile.unwrap_or("baseline").to_owned()
        };

        Self {
            schema: SCHEMA,
            // A build with no controls has observed nothing, so it cannot claim
            // to be complete however clean the summary looks.
            complete: summary.is_complete() && !results.is_empty(),
            truncated: false,
            profile: profile_str,
            platform: host.platform.as_str().to_owned(),
            os_version: host.version.known().map(|v| v.display.clone()),
            edition: host.edition.known().cloned(),
            carried: results.len(),
            summary,
            posture,
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
        let field = |name: &str| ui.paint(style::MUTED, &format!("{name:<10}"));

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
            format!(
                "{evaluated} of {} controls in this build (not a full picture of this machine)",
                self.carried
            )
        } else {
            format!(
                "{evaluated} of {} controls, {} could not be established (not a full picture of this machine)",
                self.carried,
                self.summary.concealed()
            )
        };
        out.push_str(&format!("{}{coverage}\n", field("Coverage")));

        // Posture Score meter
        let score_label = if let Some(score_pct) = (self.summary.pass * 100).checked_div(evaluated)
        {
            let meter = render_meter(ui, self.summary.pass, evaluated, 10);
            let score_str = format!("{score_pct:>3}% Hardened");
            let styled_score = if score_pct >= 70 {
                ui.paint(style::outcome_style(Outcome::Pass), &score_str)
            } else {
                ui.paint(style::outcome_style(Outcome::Drift), &score_str)
            };
            let breakdown = if self.summary.drift > 0 {
                format!(
                    "({} pass, {} drift, {} not selected)",
                    self.summary.pass, self.summary.drift, self.summary.not_selected
                )
            } else {
                format!(
                    "({} pass, {} not selected)",
                    self.summary.pass, self.summary.not_selected
                )
            };
            format!(
                "{styled_score} {meter} {}",
                ui.paint(style::MUTED, &breakdown)
            )
        } else {
            let meter = render_meter(ui, 0, 0, 10);
            format!(
                "  0% Hardened {meter} {}",
                ui.paint(style::MUTED, "(no active controls evaluated)")
            )
        };
        out.push_str(&format!("{}{score_label}\n", field("Posture")));

        let active_dimensions: Vec<_> = self
            .posture
            .dimensions
            .iter()
            .filter(|(_, metrics)| {
                show_all || (metrics.compliant + metrics.drift + metrics.concealed > 0)
            })
            .collect();

        if !active_dimensions.is_empty() {
            out.push_str(&format!(
                "\n{}\n",
                ui.paint(style::HEADING, "Posture Dimensions")
            ));
            for (dim, metrics) in active_dimensions {
                let total = metrics.compliant + metrics.drift + metrics.concealed;
                let (meter, status_col, details) =
                    if let Some(pct) = (metrics.compliant * 100).checked_div(total) {
                        let meter = render_meter(ui, metrics.compliant, total, 8);
                        let pct_str = format!("{pct:>3}% compliant");
                        let styled_pct = if metrics.drift > 0 {
                            ui.paint(
                                style::outcome_style(Outcome::Drift),
                                &format!("{pct_str:<15}"),
                            )
                        } else {
                            ui.paint(
                                style::outcome_style(Outcome::Pass),
                                &format!("{pct_str:<15}"),
                            )
                        };
                        let detail_str = if metrics.concealed > 0 {
                            format!(
                                "({}/{} pass, {} drifted, {} unknown)",
                                metrics.compliant, total, metrics.drift, metrics.concealed
                            )
                        } else if metrics.drift > 0 {
                            format!(
                                "({}/{} pass, {} drifted)",
                                metrics.compliant, total, metrics.drift
                            )
                        } else {
                            format!("({}/{} pass)", metrics.compliant, total)
                        };
                        (meter, styled_pct, ui.paint(style::MUTED, &detail_str))
                    } else {
                        let meter = render_meter(ui, 0, 0, 8);
                        (
                            meter,
                            ui.paint(style::MUTED, &format!("{:<15}", "not in profile")),
                            String::new(),
                        )
                    };

                if details.is_empty() {
                    out.push_str(&format!(
                        "  {:<26} {}  {}\n",
                        dim.display_name(),
                        meter,
                        status_col
                    ));
                } else {
                    out.push_str(&format!(
                        "  {:<26} {}  {} {}\n",
                        dim.display_name(),
                        meter,
                        status_col,
                        details
                    ));
                }
            }
        }

        let control_map: BTreeMap<String, catalog::Control> = catalog::all()
            .into_iter()
            .map(|c| (c.spec.id.clone(), c))
            .collect();

        let mut sections: BTreeMap<&str, Vec<&ControlResult>> = BTreeMap::new();
        for result in &self.results {
            if show_all
                || (result.outcome != Outcome::Pass && result.outcome != Outcome::NotSelected)
            {
                sections.entry(&result.section).or_default().push(result);
            }
        }

        for (section, results) in sections {
            let section_title = humanize_section(section);
            out.push_str(&format!("\n{}\n", ui.paint(style::HEADING, section_title)));
            for result in results {
                let (sym, word) = match result.outcome {
                    Outcome::Drift => ("!", "drift"),
                    Outcome::Pass => {
                        if ui.unicode() {
                            ("✓", "pass")
                        } else {
                            ("+", "pass")
                        }
                    }
                    Outcome::Review => ("?", "review"),
                    Outcome::Unknown => ("?", "unknown"),
                    Outcome::Error => ("x", "error"),
                    Outcome::NotApplicable => ("-", "n/a"),
                    Outcome::NotSelected => ("·", "skip"),
                    Outcome::NotChecked => ("?", "unchecked"),
                };
                let badge_txt = format!("{sym} {word}");
                let label = ui.paint(
                    style::outcome_style(result.outcome),
                    &format!("{badge_txt:<9}"),
                );
                out.push_str(&format!("  {label} {}\n", result.title));

                if result.outcome == Outcome::Drift {
                    let dot = if ui.unicode() { "·" } else { "-" };
                    let friction_badge = match result.friction {
                        FrictionTier::Tier0Transparent => {
                            ui.paint(style::outcome_style(Outcome::Pass), "Safe: Zero Breakage")
                        }
                        FrictionTier::Tier1Cosmetic => ui.paint(style::INFO, "Cosmetic Impact"),
                        FrictionTier::Tier2WorkflowAltering => {
                            ui.paint(style::CAVEAT, "Workflow Altering")
                        }
                        FrictionTier::Tier3IncompatibleOrTradeoff => {
                            ui.paint(style::outcome_style(Outcome::Error), "Compatibility Risk")
                        }
                    };

                    let elev_tag = if control_map
                        .get(&result.id)
                        .is_some_and(|c| c.spec.requires_elevation)
                    {
                        format!(
                            " {} {}",
                            ui.paint(style::MUTED, dot),
                            ui.paint(style::CAVEAT, "requires elevation")
                        )
                    } else {
                        String::new()
                    };

                    out.push_str(&format!(
                        "            {} {} {}{}\n",
                        ui.paint(style::MUTED, &result.id),
                        ui.paint(style::MUTED, dot),
                        friction_badge,
                        elev_tag
                    ));
                } else {
                    out.push_str(&format!(
                        "            {}\n",
                        ui.paint(style::MUTED, &result.id)
                    ));
                }

                if let Some(note) = &result.note {
                    out.push_str(&ui.paint(style::CAVEAT, &ui.wrap(note, 12)));
                    out.push('\n');
                }

                if result.outcome.conceals_state() {
                    out.push_str(&ui.paint(
                        style::CAVEAT,
                        "            Reported as unknown, not as passing.\n",
                    ));
                }
            }
        }

        if self.results.is_empty() {
            out.push_str(&format!(
                "\n{}\n",
                ui.wrap(
                    "No controls are implemented for this platform yet, so this says nothing \
                     about the machine.",
                    0,
                )
            ));
        } else if self.summary.drift > 0 {
            let divider = if ui.unicode() {
                "─".repeat(ui.width().min(76))
            } else {
                "-".repeat(ui.width().min(76))
            };
            out.push_str(&format!("\n{}\n", ui.paint(style::MUTED, &divider)));
            out.push_str(&format!(
                "Next Steps: Run '{}' to preview, or '{}' to apply safe remediations.\n",
                ui.paint(style::IDENT, "privr diff"),
                ui.paint(style::IDENT, "privr fix")
            ));
        } else if self.complete && self.summary.drift == 0 {
            out.push_str("\nStatus: All evaluated controls match policy. Machine is compliant.\n");
        }
        out.push('\n');

        out
    }
}

/// Translate an internal section key into a polished, human-facing category title.
pub fn humanize_section(section: &str) -> &str {
    match section {
        "delivery-optimization" => "Delivery Optimization",
        "diagnostics" => "Diagnostics & Crash Telemetry",
        "security" => "Network & Perimeter Security",
        "advertising" => "Advertising & Commercial Tracking",
        "personalization" => "Input & Personalization",
        "location" => "Location & Sensors",
        "search" => "Search & Web Results",
        "activity" => "Activity History & Cloud Sync",
        "clipboard" => "Cloud Clipboard",
        "sensory" => "Sensors & Biometrics",
        "storage" => "Storage & Retention",
        "recall" => "Windows Recall & AI Analysis",
        _ => section,
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
            posture: PostureVector::new(),
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

    #[test]
    fn profile_ladder_escalates_evaluated_controls_monotonically() {
        let host = platform::discover();
        let baseline = Report::build(&host, "baseline");
        let strict = Report::build(&host, "strict");
        let restrictive = Report::build(&host, "restrictive");

        assert_eq!(baseline.profile, "baseline");
        assert_eq!(strict.profile, "strict");
        assert_eq!(restrictive.profile, "restrictive");

        // Total carried controls is identical across profiles.
        assert_eq!(baseline.carried, strict.carried);
        assert_eq!(strict.carried, restrictive.carried);

        // NotSelected strictly decreases as profile level escalates.
        assert!(baseline.summary.not_selected >= strict.summary.not_selected);
        assert!(strict.summary.not_selected >= restrictive.summary.not_selected);
        assert_eq!(restrictive.summary.not_selected, 0);

        // Evaluated controls (pass + drift + review) grow monotonically.
        assert!(baseline.summary.evaluated() <= strict.summary.evaluated());
        assert!(strict.summary.evaluated() <= restrictive.summary.evaluated());
    }

    #[test]
    fn test_render_meter_modes() {
        let plain = Ui::plain();
        assert_eq!(render_meter(&plain, 0, 0, 8), "[........]");
        assert_eq!(render_meter(&plain, 8, 8, 8), "[========]");
        assert_eq!(render_meter(&plain, 4, 8, 8), "[====....]");
        assert_eq!(render_meter(&plain, 0, 8, 8), "[........]");
    }

    #[test]
    fn test_to_text_renders_posture_and_dimensions() {
        let host = platform::discover();
        let report = Report::build(&host, "baseline");
        let plain = Ui::plain();
        let text = report.to_text(&plain, true);

        assert!(text.contains("Posture"));
        assert!(text.contains("Hardened"));
        assert!(text.contains("Posture Dimensions"));
        assert!(text.contains("Behavioral & Commercial"));
    }
}
