//! Building and rendering a check report.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::catalog;
use crate::engine::evaluate::{Mode, Resolution, evaluate};
use crate::model::Profile;
use crate::model::applicability::Applies;
use crate::model::host::HostFacts;
use crate::model::outcome::{ControlResult, Exception, Outcome, Summary};
use crate::model::posture::{FrictionTier, PostureVector};
use crate::ui::{Ui, style};

fn source_refs(sources: &mut Vec<SourceEntry>, compiled: &[catalog::Source]) -> Vec<u32> {
    compiled
        .iter()
        .map(|source| {
            let entry = SourceEntry {
                url: source.url.to_owned(),
                claim: source
                    .claim
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" "),
                reviewed: source.reviewed.to_owned(),
            };
            if let Some(index) = sources.iter().position(|existing| existing == &entry) {
                index as u32
            } else {
                sources.push(entry);
                (sources.len() - 1) as u32
            }
        })
        .collect()
}

fn completed_scope_status(summary: &Summary) -> &'static str {
    if summary.review > 0 {
        "\nStatus: Selected controls were evaluated; review items require operator judgment.\n"
    } else {
        "\nStatus: All evaluated controls in the selected scope match policy.\n"
    }
}

/// The report schema version. Any change to the shape of this output is a
/// change to a published contract and must bump this.
///
/// Schema 2 adds the source table and, on each result, the policy mode,
/// desired state, observed state, observation reason, observation basis, and
/// confidence flag. Schema 1 readers must not parse schema 2 as schema 1.
pub const SCHEMA: u8 = 2;

/// One compiled primary source, shared by every result that cites it.
///
/// Claims and URLs are compiled public text. The table does not carry raw
/// observations, paths, or command output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceEntry {
    pub url: String,
    pub claim: String,
    pub reviewed: String,
}

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
    /// Compiled source metadata cited by `results`, in first-seen catalogue order.
    pub sources: Vec<SourceEntry>,
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
    #[cfg(test)]
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
        Self::build_with_context(
            &catalog::Context::live(host),
            profile,
            workload,
            control_filter,
            section_filter,
        )
    }

    pub(crate) fn build_with_context(
        context: &catalog::Context,
        profile: Option<&str>,
        workload: Option<crate::model::posture::WorkloadPersona>,
        control_filter: &[String],
        section_filter: &[String],
    ) -> Self {
        let host = context.host;
        let selected_profile = profile
            .and_then(|p| p.parse::<Profile>().ok())
            .unwrap_or_default();
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

        let mut sources = Vec::new();
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
                // Keep observation in this adapter layer. The pure evaluator
                // owns outcome precedence, including Ignore before applicability.
                // Not-selected and not-applicable controls do not run a probe.
                // The skipped placeholder is not a failed observation.
                let resolution = if mode == Mode::Ignore
                    || control.spec.applicability.resolve(host).applies != Applies::Yes
                {
                    Resolution::skipped()
                } else {
                    control.observe(context)
                };
                let mut result = evaluate(&control.spec, mode, &resolution, host, Exception::None);
                result.source_refs = source_refs(&mut sources, control.sources);
                result
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
            complete: summary.is_complete(),
            truncated: false,
            profile: profile_str,
            platform: host.platform.as_str().to_owned(),
            os_version: host.version.known().map(|v| v.display.clone()),
            edition: host.edition.known().cloned(),
            carried: all_controls.len(),
            summary,
            posture,
            sources,
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
        let labels = ["Profile", "Platform", "Coverage", "Posture"];
        let label_width = Ui::label_width(&labels);

        let push_field = |out: &mut String, label: &str, value: &str| {
            out.push_str(&ui.field(label, label_width));
            out.push(' ');
            out.push_str(&ui.wrap_after(value, label_width + 1));
            out.push('\n');
        };

        push_field(&mut out, "Profile", &self.profile);

        let platform = match (&self.edition, &self.os_version) {
            (Some(edition), Some(version)) => {
                format!(
                    "{} {edition}, {version}",
                    crate::ui::platform_name(&self.platform)
                )
            }
            _ => crate::ui::platform_name(&self.platform).to_owned(),
        };
        push_field(&mut out, "Platform", &platform);

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
        push_field(&mut out, "Coverage", &coverage);

        // Keep unavailable and excluded outcomes visible even when nothing
        // enters the evaluated denominator.
        let mut counts = vec![format!("{} pass", self.summary.pass)];
        for (count, label) in [
            (self.summary.drift, "drift"),
            (self.summary.review, "review"),
            (self.summary.unknown, "unknown"),
            (self.summary.error, "error"),
            (self.summary.not_checked, "not checked"),
            (self.summary.not_applicable, "not applicable"),
            (self.summary.not_selected, "not selected"),
        ] {
            if count > 0 {
                counts.push(format!("{count} {label}"));
            }
        }
        let breakdown = format!("({})", counts.join(", "));

        let not_evaluated = self.summary.unknown
            + self.summary.error
            + self.summary.not_checked
            + self.summary.not_applicable
            + self.summary.not_selected;
        let mut posture_bits = Vec::new();
        if self.summary.unknown > 0 {
            posture_bits.push(format!("{} unknown", self.summary.unknown));
        }
        if self.summary.not_checked > 0 {
            posture_bits.push(format!("{} not checked", self.summary.not_checked));
        }
        if self.summary.error > 0 {
            posture_bits.push(format!("{} error", self.summary.error));
        }
        let posture_value = if evaluated == 0 {
            let lead = if posture_bits.is_empty() {
                String::new()
            } else {
                format!("{} · ", posture_bits.join(", "))
            };
            if not_evaluated == 0 {
                format!("{lead}no evaluated controls")
            } else {
                format!("{lead}no evaluated controls ({not_evaluated} not evaluated)")
            }
        } else if posture_bits.is_empty() {
            format!(
                "{} of {evaluated} evaluated controls pass",
                self.summary.pass
            )
        } else {
            format!(
                "{} · {} of {evaluated} evaluated controls pass ({not_evaluated} not evaluated)",
                posture_bits.join(", "),
                self.summary.pass
            )
        };
        let posture_style =
            if self.summary.is_complete() && self.summary.drift == 0 && self.summary.review == 0 {
                style::outcome_style(Outcome::Pass)
            } else {
                style::VALUE
            };
        let meter = render_scope_meter(
            ui,
            self.summary.pass,
            self.summary.drift + self.summary.review,
            not_evaluated,
            10,
        );
        out.push_str(&ui.field("Posture", label_width));
        out.push(' ');
        out.push_str(&ui.paint_lines(
            posture_style,
            &ui.wrap_after(&posture_value, label_width + 1),
        ));
        out.push('\n');
        let meter_visual = 12;
        let breakdown_used = label_width + 1 + meter_visual + 1;
        let wrapped_breakdown = ui.wrap_after(&breakdown, breakdown_used);
        out.push_str(&" ".repeat(label_width + 1));
        out.push_str(&meter);
        out.push(' ');
        out.push_str(&ui.paint_lines(style::MUTED, &wrapped_breakdown));
        out.push('\n');

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
                // The denominator is evaluated controls only. Unknowns stay
                // beside the percentage so they cannot look like failures or
                // disappear from the line.
                let evaluated_here = metrics.evaluated();
                let (meter, status_col, details) =
                    if let Some(pct) = (metrics.compliant * 100).checked_div(evaluated_here) {
                        let meter = render_meter(ui, metrics.compliant, evaluated_here, 8);
                        let pct_str = format!("{pct:>3}% compliant");
                        let pct_style = if metrics.drift > 0 {
                            style::outcome_style(Outcome::Drift)
                        } else if metrics.concealed > 0 || metrics.review > 0 {
                            style::VALUE
                        } else {
                            style::outcome_style(Outcome::Pass)
                        };
                        let styled_pct = ui.paint(pct_style, &format!("{pct_str:<15}"));
                        let mut detail_str =
                            format!("({}/{} evaluated pass", metrics.compliant, evaluated_here);
                        if metrics.drift > 0 {
                            detail_str.push_str(&format!(", {} drifted", metrics.drift));
                        }
                        if metrics.review > 0 {
                            detail_str.push_str(&format!(", {} review", metrics.review));
                        }
                        if metrics.concealed > 0 {
                            detail_str.push_str(&format!(", {} unknown", metrics.concealed));
                        }
                        detail_str.push(')');
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

        let mut ordered: Vec<&ControlResult> = self.results.iter().collect();
        ordered.sort_by(|left, right| {
            action_rank(left.outcome)
                .cmp(&action_rank(right.outcome))
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut current_group = None;
        for result in &ordered {
            let folded = !show_all
                && matches!(
                    result.outcome,
                    Outcome::Pass | Outcome::NotApplicable | Outcome::NotSelected
                );
            if folded {
                continue;
            }
            let group = action_group(result.outcome);
            if current_group != Some(group) {
                current_group = Some(group);
                out.push_str(&format!("\n{}\n", ui.paint(style::HEADING, group)));
            }
            write_result_row(&mut out, ui, result, control_map.get(&result.id));
        }

        if !show_all {
            if self.summary.pass > 0 {
                let sentence = format!("{} passing", self.summary.pass);
                out.push('\n');
                out.push_str(&ui.paint_lines(style::MUTED, &ui.wrap(&sentence, 0)));
                out.push('\n');
            }
            let folded = self.summary.not_applicable + self.summary.not_selected;
            if folded > 0 {
                let noun = if folded == 1 {
                    "control is"
                } else {
                    "controls are"
                };
                let sentence =
                    format!("{folded} {noun} not applicable or not selected on this host");
                out.push_str(&ui.paint_lines(style::MUTED, &ui.wrap(&sentence, 0)));
                out.push('\n');
            }
        }

        if self.summary.concealed() > 0 {
            out.push_str(&format!(
                "\n{}\n",
                ui.wrap(
                    "Unknown means privr could not tell. It is never counted as passing.",
                    0
                )
            ));
        }
        if self.carried == 0 {
            out.push_str(&format!(
                "\n{}\n",
                ui.wrap(
                    "No controls are implemented for this platform yet, so this says nothing \
                     about the machine.",
                    0,
                )
            ));
        } else if self.summary.evaluated() == 0 {
            out.push_str(&ui.wrap(
                "\nNo controls were evaluated in the selected scope. This check establishes no \
                 policy compliance. Inspect 'privr list' and choose an applicable control \
                 with 'privr check --control <id>' or an appropriate profile explicitly.\n",
                0,
            ));
        } else if self.summary.drift > 0 {
            let divider = if ui.unicode() {
                "─".repeat(ui.width().min(76))
            } else {
                "-".repeat(ui.width().min(76))
            };
            out.push_str(&format!("\n{}\n", ui.paint(style::MUTED, &divider)));
            let next = "Next Steps: Run 'privr diff' to preview, or 'privr fix' to apply safe remediations.";
            out.push_str(&ui.paint_lines(style::VALUE, &ui.wrap(next, 0)));
            out.push('\n');
        } else if self.complete {
            out.push_str(completed_scope_status(&self.summary));
        }
        out.push('\n');

        out
    }
}

fn action_rank(outcome: Outcome) -> u8 {
    match outcome {
        Outcome::Drift | Outcome::Review => 0,
        Outcome::Unknown | Outcome::NotChecked | Outcome::Error => 1,
        Outcome::Pass => 2,
        Outcome::NotApplicable | Outcome::NotSelected => 3,
    }
}

fn action_group(outcome: Outcome) -> &'static str {
    match action_rank(outcome) {
        0 => "Needs you",
        1 => "Could not tell",
        2 => "Passing",
        _ => "Not applicable or not selected",
    }
}

fn render_scope_meter(
    ui: &Ui,
    pass: usize,
    other_evaluated: usize,
    unevaluated: usize,
    width: usize,
) -> String {
    let parts = [pass, other_evaluated, unevaluated];
    let cells = apportion(&parts, width);
    let (pass_char, other_char, rest_char) = ("=", "!", ".");
    let pass_bar = ui.paint(
        style::outcome_style(Outcome::Pass),
        &pass_char.repeat(cells[0]),
    );
    let other_bar = ui.paint(
        style::outcome_style(Outcome::Drift),
        &other_char.repeat(cells[1]),
    );
    let rest_bar = ui.paint(style::MUTED, &rest_char.repeat(cells[2]));
    format!("[{pass_bar}{other_bar}{rest_bar}]")
}

fn apportion(parts: &[usize; 3], width: usize) -> [usize; 3] {
    let total: usize = parts.iter().sum();
    if total == 0 {
        return [0, 0, width];
    }
    let mut floors = [0usize; 3];
    let mut fractions = [0f64; 3];
    for (index, part) in parts.iter().enumerate() {
        let exact = *part as f64 * width as f64 / total as f64;
        floors[index] = exact.floor() as usize;
        fractions[index] = exact - floors[index] as f64;
    }
    let mut leftover = width.saturating_sub(floors.iter().sum());
    let mut order = [0usize, 1, 2];
    order.sort_by(|left, right| {
        fractions[*right]
            .partial_cmp(&fractions[*left])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for index in order {
        if leftover == 0 {
            break;
        }
        if parts[index] > 0 {
            floors[index] += 1;
            leftover -= 1;
        }
    }
    if leftover > 0 {
        floors[2] += leftover;
    }
    floors
}

fn write_result_row(
    out: &mut String,
    ui: &Ui,
    result: &ControlResult,
    control: Option<&catalog::Control>,
) {
    let word = style::outcome_label(result.outcome).trim();
    let marker = match result.outcome {
        Outcome::Drift => "!",
        Outcome::Pass => "+",
        Outcome::Review | Outcome::Unknown | Outcome::NotChecked => "?",
        Outcome::Error => "x",
        Outcome::NotApplicable => "-",
        Outcome::NotSelected => "-",
    };
    let badge = format!("{marker} {word}");
    let label = ui.paint(
        style::outcome_style(result.outcome),
        &format!("{badge:<12}"),
    );
    out.push_str("  ");
    out.push_str(&label);
    out.push(' ');
    out.push_str(&ui.wrap_after(&result.title, 15));
    out.push('\n');
    out.push_str(&format!(
        "             {}\n",
        ui.paint(style::MUTED, &result.id)
    ));

    if result.outcome == Outcome::Drift {
        let friction_badge = match result.friction {
            FrictionTier::Tier0Transparent => {
                ui.paint(style::outcome_style(Outcome::Pass), "transparent")
            }
            FrictionTier::Tier1Cosmetic => ui.paint(style::INFO, "cosmetic"),
            FrictionTier::Tier2WorkflowAltering => ui.paint(style::CAVEAT, "workflow-altering"),
            FrictionTier::Tier3IncompatibleOrTradeoff => {
                ui.paint(style::outcome_style(Outcome::Error), "compatibility risk")
            }
        };
        out.push_str(&format!("             {friction_badge}"));
        if control.is_some_and(|item| item.spec.requires_elevation) {
            out.push(' ');
            out.push_str(&ui.paint(style::CAVEAT, "requires elevation"));
        }
        out.push('\n');
    }

    if let Some(note) = &result.note {
        let note_style = match result.outcome {
            Outcome::NotApplicable | Outcome::NotSelected => style::MUTED,
            Outcome::Drift | Outcome::Review => style::CAVEAT,
            _ => style::VALUE,
        };
        let wrapped = ui.wrap(note, 13);
        out.push_str(&ui.paint_lines(note_style, &wrapped));
        out.push('\n');
    }
    if let Some(reason) = result.observation_reason {
        let reason_line = ui.wrap(&format!("reason: {}", uncertainty_word(reason)), 13);
        out.push_str(&ui.paint_lines(style::VALUE, &reason_line));
        out.push('\n');
    }
}

fn uncertainty_word(reason: crate::engine::evaluate::Uncertainty) -> &'static str {
    match reason {
        crate::engine::evaluate::Uncertainty::Denied => "denied",
        crate::engine::evaluate::Uncertainty::Malformed => "malformed",
        crate::engine::evaluate::Uncertainty::Unsupported => "unsupported",
        crate::engine::evaluate::Uncertainty::Undetermined => "undetermined",
        crate::engine::evaluate::Uncertainty::EnforcementMechanismOnly => {
            "enforcement mechanism only"
        }
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
    #[cfg(target_os = "linux")]
    #[test]
    fn issue18_file_configuration_never_attests_loaded_storage() {
        use crate::model::outcome::Outcome;
        use crate::platform::linux::systemd::ConfigurationFamily;
        for (family, selector, bytes) in [
            (
                ConfigurationFamily::Coredump,
                "systemd.coredump",
                b"[Coredump]\nStorage=none\nStorage=external\n".as_slice(),
            ),
            (
                ConfigurationFamily::Journald,
                "systemd.journald",
                b"[Journal]\nStorage=volatile\nStorage=persistent\n".as_slice(),
            ),
        ] {
            let host = crate::test_context::host("arch", "hyprland");
            let reader = crate::test_context::configuration_reader(family, bytes);
            let context = crate::test_context::context(&host, &reader);
            let report = super::Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &[selector.to_owned()],
                &[],
            );
            assert_eq!(report.results[0].outcome, Outcome::Unknown);
            assert!(report.results[0].note.as_ref().unwrap().contains(
                if family == ConfigurationFamily::Coredump {
                    "Storage=external"
                } else {
                    "Storage=persistent"
                }
            ));
            assert_eq!(reader.requested_configurations(), vec![family]);
            assert!(reader.requested().is_empty());
            assert_eq!(report.summary.pass, 0);
            assert_eq!(report.summary.drift, 0);
            assert!(!report.complete);
            assert_eq!(report.exit_code(), 3);
        }
    }
    use super::*;
    use crate::model::host::Platform;
    use crate::platform;

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_unevaluated_compiled_scope_is_incomplete() {
        let host = crate::test_context::host("arch", "hyprland");
        let reader = crate::test_context::reader([]);
        let context = crate::test_context::context(&host, &reader);
        let report = Report::build_with_context(&context, Some("baseline"), None, &[], &[]);
        assert_eq!(report.results.len(), 17);
        assert_eq!(report.summary.not_applicable, 7);
        assert_eq!(report.summary.not_selected, 7);
        assert_eq!(report.summary.unknown, 3);
        assert_eq!(report.summary.evaluated(), 0);
        assert!(reader.requested().is_empty());
        assert!(reader.requested_configurations().is_empty());
        assert!(!report.complete);
        assert_eq!(report.exit_code(), 3);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema"], 2);
        assert_eq!(json["complete"], false);
        let text = report.to_text(&Ui::plain(), false);
        assert!(!text.contains("Machine is compliant"));
        assert!(text.contains("No controls were evaluated"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_filters_define_scope_but_not_carried_catalogue() {
        let host = crate::test_context::host("arch", "hyprland");
        let reader = crate::test_context::reader([]);
        let context = crate::test_context::context(&host, &reader);
        for (controls, sections, expected, not_selected, not_applicable) in [
            (vec![], vec!["SyStEmD".to_owned()], 5, 3, 0),
            (vec![], vec!["ubuntu".to_owned()], 2, 0, 2),
            (vec!["missing".to_owned()], vec![], 0, 0, 0),
            (
                vec!["debian".to_owned()],
                vec!["systemd".to_owned()],
                0,
                0,
                0,
            ),
        ] {
            let report =
                Report::build_with_context(&context, Some("baseline"), None, &controls, &sections);
            assert_eq!(report.results.len(), expected);
            assert_eq!(report.summary.not_selected, not_selected);
            assert_eq!(report.summary.not_applicable, not_applicable);
            assert_eq!(report.summary.evaluated(), 0);
            assert_eq!(report.carried, 17);
            assert!(!report.complete);
            assert_eq!(report.exit_code(), 3);
            assert!(
                !report
                    .to_text(&Ui::plain(), true)
                    .contains("No controls are implemented")
            );
        }
        assert!(reader.requested().is_empty());
        assert!(reader.requested_configurations().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_real_probe_pass_drift_and_review_remain_distinct() {
        use crate::platform::linux::evidence::Target;
        for (bytes, outcome, exit) in [
            (b"PARTICIPATE=\"no\"\n".as_slice(), Outcome::Pass, 0),
            (b"PARTICIPATE=\"yes\"\n".as_slice(), Outcome::Drift, 1),
        ] {
            let host = crate::test_context::host("debian", "hyprland");
            let reader = crate::test_context::reader([(
                Target::DebianPopcon,
                crate::test_context::text(bytes),
            )]);
            let context = crate::test_context::context(&host, &reader);
            let report = Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &["debian".to_owned()],
                &[],
            );
            assert_eq!(report.results.len(), 1);
            assert_eq!(report.results[0].outcome, outcome);
            assert!(report.complete);
            assert_eq!(report.exit_code(), exit);
            assert_eq!(report.carried, 17);
            assert_eq!(reader.requested(), vec![Target::DebianPopcon]);
            let control = catalog::all()
                .into_iter()
                .find(|c| c.spec.id.starts_with("debian"))
                .unwrap();
            let review = evaluate(
                &control.spec,
                Mode::Review,
                &control.observe(&context),
                &host,
                Exception::None,
            );
            assert_eq!(review.outcome, Outcome::Review);
            let summary = Summary::of([&review]);
            assert!(summary.is_complete());
            assert_eq!(summary.evaluated(), 1);
            assert!(completed_scope_status(&summary).contains("operator judgment"));
            assert!(!completed_scope_status(&summary).contains("match policy"));
            assert!(
                !report
                    .to_text(&Ui::plain(), true)
                    .contains("Machine is compliant")
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_failed_raw_observations_never_become_a_default_pass() {
        use crate::model::evidence::{
            DenialReason, Evidence, RawValue, UndeterminedReason, ValueKind,
        };
        use crate::model::host::ManagementSource;
        use crate::platform::linux::evidence::{MAX_FILE_BYTES, Target};
        let source = ManagementSource::Unknown;
        let mut reasons = Vec::new();
        for evidence in [
            None,
            Some(Evidence::Denied {
                source,
                reason: DenialReason::Permission,
            }),
            Some(Evidence::Undetermined {
                source,
                reason: UndeterminedReason::ProbeFailed,
            }),
            Some(Evidence::Unsupported { source }),
            Some(Evidence::Malformed {
                source,
                expected: ValueKind::String,
                found: ValueKind::Binary,
            }),
            Some(crate::test_context::text(&[0xff])),
            Some(crate::test_context::text(&vec![b'x'; MAX_FILE_BYTES + 1])),
            Some(Evidence::Present {
                source,
                value: RawValue::u32(0),
            }),
            Some(Evidence::Present {
                source,
                value: RawValue::new(ValueKind::Bool, vec![1]),
            }),
        ] {
            let host = crate::test_context::host("debian", "hyprland");
            let reader = crate::test_context::reader(evidence.map(|e| (Target::DebianPopcon, e)));
            let context = crate::test_context::context(&host, &reader);
            let report = Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &["debian".to_owned()],
                &[],
            );
            assert_eq!(report.results[0].outcome, Outcome::Unknown);
            assert_eq!(report.summary.pass, 0);
            assert!(!report.complete);
            assert_eq!(report.exit_code(), 3);
            assert_eq!(reader.requested(), vec![Target::DebianPopcon]);
            assert!(report.results[0].observed.is_none());
            assert!(!report.results[0].confident);
            assert_eq!(
                report.results[0].observation_basis,
                crate::model::outcome::ObservationBasis::Inconclusive
            );
            let reason = report.results[0].observation_reason;
            assert!(reason.is_some(), "inconclusive result without a reason");
            let json = serde_json::to_string(&report).expect("json");
            assert!(!json.contains("\"bytes\""));
            reasons.push(reason);
        }
        use crate::engine::evaluate::Uncertainty;
        for expected in [
            Uncertainty::Denied,
            Uncertainty::Malformed,
            Uncertainty::Unsupported,
            Uncertainty::Undetermined,
        ] {
            assert!(
                reasons.contains(&Some(expected)),
                "missing {expected:?} in {reasons:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_unknown_applicability_and_ignored_controls_are_not_observed() {
        let host = HostFacts::unknown(Platform::Linux);
        let reader = crate::test_context::reader([]);
        let context = crate::test_context::context(&host, &reader);
        let report = Report::build_with_context(
            &context,
            Some("baseline"),
            None,
            &["debian".to_owned()],
            &[],
        );
        assert_eq!(report.results[0].outcome, Outcome::Unknown);
        assert!(!report.complete);
        let report = Report::build_with_context(
            &context,
            Some("baseline"),
            None,
            &[],
            &["gnome".to_owned()],
        );
        assert_eq!(report.summary.not_selected, 2);
        assert_eq!(report.summary.unknown, 2);
        assert!(reader.requested().is_empty());
        assert!(reader.requested_configurations().is_empty());
        for result in report.results {
            assert_eq!(
                result.management_source,
                crate::model::host::ManagementSource::Unknown
            );
            assert!(result.note.is_none());
            assert!(result.observed.is_none());
            assert!(result.observation_reason.is_none());
            assert_ne!(
                result.observation_basis,
                crate::model::outcome::ObservationBasis::Inconclusive
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_drift_with_unknown_remains_incomplete() {
        use crate::platform::linux::evidence::Target;
        let host = crate::test_context::host("debian", "gnome");
        let reader = crate::test_context::reader([(
            Target::DebianPopcon,
            crate::test_context::text(b"PARTICIPATE=\"yes\"\n"),
        )]);
        let context = crate::test_context::context(&host, &reader);
        let report = Report::build_with_context(&context, Some("baseline"), None, &[], &[]);
        assert_eq!(report.summary.drift, 1);
        assert_eq!(report.summary.unknown, 5);
        assert_eq!(report.summary.evaluated(), 1);
        assert!(!report.complete);
        assert_eq!(report.exit_code(), 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_repeated_selectors_keep_prefix_case_and_and_or_semantics() {
        use crate::platform::linux::evidence::{Reader, Target};
        use crate::platform::linux::systemd::ConfigurationFamily;
        let host = crate::test_context::host("debian", "hyprland");
        let reader = Reader::recorded_with_configurations(
            std::collections::BTreeMap::from([(
                Target::DebianPopcon,
                crate::test_context::text(b"PARTICIPATE=\"no\"\n"),
            )]),
            std::collections::BTreeMap::from([(
                ConfigurationFamily::Journald,
                crate::test_context::configuration(b"[Journal]\nStorage=volatile\n"),
            )]),
        );
        let context = crate::test_context::context(&host, &reader);
        let report = Report::build_with_context(
            &context,
            Some("baseline"),
            None,
            &["debian".to_owned(), "systemd.journald".to_owned()],
            &["DeB".to_owned(), "SYS".to_owned()],
        );
        assert_eq!(report.results.len(), 2);
        assert_eq!(report.summary.pass, 1);
        assert_eq!(report.summary.unknown, 1);
        assert!(!report.complete);
        assert!(report.results.iter().any(|r| {
            r.note
                .as_ref()
                .is_some_and(|note| note.contains("Storage=volatile"))
        }));
        let wrong_case = Report::build_with_context(
            &context,
            Some("baseline"),
            None,
            &["Debian".to_owned()],
            &[],
        );
        assert!(wrong_case.results.is_empty());
        assert!(!wrong_case.complete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_compiled_linux_targets_use_only_the_recorded_reader() {
        use crate::model::evidence::{Evidence, RawValue, ValueKind};
        use crate::model::host::ManagementSource;
        use crate::platform::linux::evidence::Target;
        let absent = Evidence::Absent {
            source: ManagementSource::Unknown,
        };
        let present = Evidence::Present {
            source: ManagementSource::Unknown,
            value: RawValue::new(ValueKind::Bool, vec![1]),
        };
        for (distribution, desktop, selector, entries, expected, requested) in [
            (
                "fedora",
                "hyprland",
                "fedora",
                vec![(
                    Target::FedoraAbrt,
                    crate::test_context::text(b"AutoreportingEnabled = yes\n"),
                )],
                Outcome::Drift,
                vec![Target::FedoraAbrt],
            ),
            (
                "arch",
                "hyprland",
                "systemd.fstrim",
                vec![
                    (Target::FstrimAdmin, absent.clone()),
                    (Target::FstrimLib, absent.clone()),
                    (Target::FstrimVendor, present.clone()),
                ],
                Outcome::Pass,
                vec![Target::FstrimAdmin, Target::FstrimLib, Target::FstrimVendor],
            ),
        ] {
            let host = crate::test_context::host(distribution, desktop);
            let reader = crate::test_context::reader(entries);
            let context = crate::test_context::context(&host, &reader);
            let report = Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &[selector.to_owned()],
                &[],
            );
            assert_eq!(report.results.len(), 1, "{selector}");
            assert_eq!(report.results[0].outcome, expected, "{selector}");
            assert!(report.complete, "{selector}");
            assert_eq!(reader.requested(), requested);
            // An omitted recording must not silently read a real host value.
            let missing = crate::test_context::reader([]);
            let context = crate::test_context::context(&host, &missing);
            let report = Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &[selector.to_owned()],
                &[],
            );
            assert_eq!(report.results[0].outcome, Outcome::Unknown, "{selector}");
            assert_eq!(report.exit_code(), 3);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ubuntu_and_abrt_files_do_not_turn_absence_into_a_pass() {
        use crate::model::evidence::{Evidence, RawValue, ValueKind};
        use crate::model::host::ManagementSource;
        use crate::platform::linux::evidence::Target;

        let source = ManagementSource::Unknown;
        let present = Evidence::Present {
            source,
            value: RawValue::new(ValueKind::Bool, vec![1]),
        };
        let absent = Evidence::Absent { source };
        let host = crate::test_context::host("ubuntu", "hyprland");
        for (selector, target, evidence) in [
            ("ubuntu.insights", Target::UbuntuInsights, present.clone()),
            ("ubuntu.insights", Target::UbuntuInsights, absent.clone()),
            ("ubuntu.report", Target::UbuntuReport, present),
            ("ubuntu.report", Target::UbuntuReport, absent.clone()),
        ] {
            let reader = crate::test_context::reader([(target, evidence)]);
            let context = crate::test_context::context(&host, &reader);
            let report = Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &[selector.to_owned()],
                &[],
            );
            assert_eq!(report.results[0].outcome, Outcome::Unknown, "{selector}");
            assert_eq!(report.summary.pass, 0, "{selector}");
            assert!(!report.complete, "{selector}");
            assert!(report.results[0].observed.is_none(), "{selector}");
            assert_eq!(reader.requested(), vec![target]);
        }

        let host = crate::test_context::host("fedora", "hyprland");
        for bytes in [
            b"AutoreportingEvent=none\n".as_slice(),
            b"AutoreportingEnabled = no\n".as_slice(),
            b"AutoreportingEnabled no\n".as_slice(),
            b"# AutoreportingEnabled = yes\n".as_slice(),
            b"".as_slice(),
        ] {
            let reader = crate::test_context::reader([(
                Target::FedoraAbrt,
                crate::test_context::text(bytes),
            )]);
            let context = crate::test_context::context(&host, &reader);
            let report = Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &["fedora".to_owned()],
                &[],
            );
            assert_eq!(report.results[0].outcome, Outcome::Unknown);
            assert_eq!(report.summary.pass, 0);
            assert!(!report.complete);
        }
        let reader = crate::test_context::reader([(Target::FedoraAbrt, absent)]);
        let context = crate::test_context::context(&host, &reader);
        let report = Report::build_with_context(
            &context,
            Some("baseline"),
            None,
            &["fedora".to_owned()],
            &[],
        );
        assert_eq!(report.results[0].outcome, Outcome::Unknown);
        assert_eq!(report.summary.pass, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kde_userfeedback_file_does_not_establish_telemetry_is_off() {
        use crate::engine::evaluate::Uncertainty;
        use crate::model::evidence::{DenialReason, Evidence};
        use crate::model::host::ManagementSource;
        use crate::model::outcome::ObservationBasis;
        use crate::platform::linux::evidence::Target;

        let host = crate::test_context::host("arch", "kde");
        for bytes in [
            b"FeedbackLevel=0\n# CANARY-SECRET-USER\n".as_slice(),
            b"FeedbackLevel=100\n".as_slice(),
            b"# FeedbackLevel=0\n".as_slice(),
            b"".as_slice(),
        ] {
            let reader = crate::test_context::reader([(
                Target::KdeFeedback,
                crate::test_context::text(bytes),
            )]);
            let context = crate::test_context::context(&host, &reader);
            let report = Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &["kde".to_owned()],
                &[],
            );
            let result = &report.results[0];
            assert_eq!(result.outcome, Outcome::Unknown);
            assert_ne!(result.outcome, Outcome::Pass);
            assert_eq!(report.summary.pass, 0);
            assert!(!report.complete);
            assert!(result.observed.is_none());
            assert!(!result.confident);
            assert_eq!(result.observation_basis, ObservationBasis::Inconclusive);
            assert_eq!(result.observation_reason, Some(Uncertainty::Undetermined));
            let note = result.note.as_deref().unwrap();
            assert!(note.contains("does not establish"));
            assert!(!note.contains('/'));
            assert!(!note.contains("CANARY-SECRET-USER"));
            let json = serde_json::to_string(&report).expect("json");
            assert!(!json.contains("CANARY-SECRET-USER"));
            assert_eq!(reader.requested(), vec![Target::KdeFeedback]);
        }

        let reader = crate::test_context::reader([(
            Target::KdeFeedback,
            Evidence::Absent {
                source: ManagementSource::Unknown,
            },
        )]);
        let context = crate::test_context::context(&host, &reader);
        let report =
            Report::build_with_context(&context, Some("baseline"), None, &["kde".to_owned()], &[]);
        assert_eq!(report.results[0].outcome, Outcome::Unknown);
        assert_eq!(report.summary.pass, 0);
        assert!(!report.complete);

        let reader = crate::test_context::reader([(
            Target::KdeFeedback,
            Evidence::Denied {
                source: ManagementSource::User,
                reason: DenialReason::Permission,
            },
        )]);
        let context = crate::test_context::context(&host, &reader);
        let report =
            Report::build_with_context(&context, Some("baseline"), None, &["kde".to_owned()], &[]);
        let result = &report.results[0];
        assert_eq!(result.outcome, Outcome::Unknown);
        assert_ne!(result.outcome, Outcome::Pass);
        assert_eq!(result.observation_reason, Some(Uncertainty::Denied));
        assert!(result.note.is_none());
    }

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
            sources: Vec::new(),
            results: Vec::new(),
        }
    }

    #[test]
    fn a_report_with_no_controls_is_never_complete() {
        // Observing nothing is not the same as finding nothing wrong. A clean
        // summary over an empty result set would be the emptiest possible false
        // pass, so completeness requires that something was evaluated.
        assert!(!Summary::default().is_complete());

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
    fn headline_preserves_every_outcome_and_qualifies_the_evaluated_percentage() {
        let mut report = empty_report();
        report.summary = Summary {
            pass: 1,
            drift: 2,
            review: 3,
            unknown: 4,
            error: 5,
            not_checked: 6,
            not_applicable: 7,
            not_selected: 8,
        };
        report.complete = false;
        let text = report.to_text(&Ui::plain(), false);
        let headline = text
            .lines()
            .find(|line| line.starts_with("Posture "))
            .expect("headline");
        assert!(headline.starts_with("Posture"));
        assert!(
            flat(headline).contains("4 unknown, 6 not checked, 5 error"),
            "{headline}"
        );
        assert!(flat(headline).contains("1 of 6 evaluated controls pass"));
        assert!(!headline.contains('%'));
        assert!(!text.contains("Hardened"));
        let flat_text = flat(&text);
        for count in [
            "1 pass",
            "2 drift",
            "3 review",
            "4 unknown",
            "5 error",
            "6 not checked",
            "7 not applicable",
            "8 not selected",
        ] {
            assert!(flat_text.contains(count), "missing {count}: {flat_text}");
        }
        assert_eq!(
            text.matches("Unknown means privr could not tell").count(),
            1
        );
    }

    #[test]
    fn zero_evaluated_headline_keeps_unknown_and_excluded_counts_without_a_percentage() {
        let mut report = empty_report();
        report.summary.unknown = 2;
        report.summary.not_selected = 11;
        report.complete = false;
        let text = report.to_text(&Ui::plain(), false);
        let headline = text
            .lines()
            .find(|line| line.starts_with("Posture "))
            .expect("headline");
        assert!(flat(headline).contains("2 unknown"));
        assert!(flat(headline).contains("no evaluated controls"));
        assert!(flat(&text).contains("11 not selected"));
        assert!(!headline.contains('%'));
        assert!(!headline.contains("unavailable"));
        assert_eq!(report.exit_code(), 3);
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
        let mut report = empty_report();
        report.carried = 2;
        report.summary.pass = 1;
        report.summary.drift = 1;
        report.posture.record(
            crate::model::posture::PostureDimension::BehavioralCommercial,
            Outcome::Pass,
        );
        report.posture.record(
            crate::model::posture::PostureDimension::BehavioralCommercial,
            Outcome::Drift,
        );
        let plain = Ui::plain();
        let text = report.to_text(&plain, true);

        assert!(text.contains("Posture"));
        assert!(!text.contains("Hardened"));
        assert!(text.contains("evaluated controls pass"));
        assert!(text.contains("Posture Dimensions"));
        assert!(text.contains("Behavioral & Commercial"));
        assert!(flat(&text).contains("50% compliant"));
        assert!(flat(&text).contains("(1/2 evaluated pass, 1 drifted)"));
    }

    fn synthetic_result(
        id: &str,
        outcome: Outcome,
        note: Option<&str>,
        basis: crate::model::outcome::ObservationBasis,
        observed: Option<&str>,
        reason: Option<crate::engine::evaluate::Uncertainty>,
        confident: bool,
    ) -> ControlResult {
        use crate::model::outcome::*;
        ControlResult {
            id: id.to_owned(),
            title: "Synthetic finding with a long title that must wrap on a narrow terminal"
                .to_owned(),
            section: "diagnostics".to_owned(),
            dimension: crate::model::posture::PostureDimension::DiagnosticCrash,
            friction: crate::model::posture::FrictionTier::Tier0Transparent,
            outcome,
            management_source: crate::model::host::ManagementSource::User,
            remediation: Remediation::AuditOnly,
            remediation_reason: None,
            support: Support::Verified,
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            effect: Effect::Active,
            exception: Exception::None,
            note: note.map(str::to_owned),
            ineffective: None,
            policy_mode: crate::engine::evaluate::Mode::Enforce,
            desired: "disabled".to_owned(),
            observed: observed.map(str::to_owned),
            observation_reason: reason,
            observation_basis: basis,
            confident,
            source_refs: vec![0],
        }
    }

    #[test]
    fn check_text_wraps_at_forty_sixty_and_eighty_eight_columns() {
        use crate::engine::evaluate::Uncertainty;
        use crate::model::outcome::ObservationBasis;
        let mut report = empty_report();
        report.carried = 3;
        report.complete = false;
        report.summary.drift = 1;
        report.summary.unknown = 1;
        report.summary.not_selected = 1;
        report.results = vec![
            synthetic_result(
                "example.drift",
                Outcome::Drift,
                Some(
                    "This note explains a real difference and must stay inside the terminal width.",
                ),
                ObservationBasis::Established,
                Some("enabled"),
                None,
                true,
            ),
            synthetic_result(
                "example.unknown",
                Outcome::Unknown,
                Some("The probe could not tell, so this row is never a pass."),
                ObservationBasis::Inconclusive,
                None,
                Some(Uncertainty::Denied),
                false,
            ),
            synthetic_result(
                "example.skipped",
                Outcome::NotSelected,
                None,
                ObservationBasis::NotSelected,
                None,
                None,
                false,
            ),
        ];
        for width in [40, 60, 88] {
            let text = report.to_text(&Ui::render(false, false, width), false);
            let flat_text = flat(&text);
            assert!(
                flat_text.contains("1 unknown · 0 of 1 evaluated controls pass"),
                "{flat_text}"
            );
            assert_eq!(
                flat_text.matches("It is never counted as passing").count(),
                1
            );
            assert!(!text.contains("example.skipped"));
            assert!(flat_text.contains("1 control is not applicable or not selected"));
            for line in text.lines() {
                assert!(
                    line.chars().count() <= width,
                    "width {width} overflow: {line}"
                );
            }
        }
        let listed = report.to_text(&Ui::render(false, false, 60), true);
        assert!(listed.contains("example.skipped"));
        assert!(listed.contains("Not applicable or not selected"));
        assert!(
            !report
                .to_text(&Ui::render(false, false, 60), false)
                .contains("example.skipped")
        );
    }

    #[test]
    fn concealed_dimension_percentage_is_not_painted_as_a_pass() {
        let mut report = empty_report();
        report.summary.pass = 1;
        report.summary.unknown = 1;
        report.posture.record(
            crate::model::posture::PostureDimension::BehavioralCommercial,
            Outcome::Pass,
        );
        report.posture.record(
            crate::model::posture::PostureDimension::BehavioralCommercial,
            Outcome::Unknown,
        );
        let text = report.to_text(&Ui::plain(), false);
        assert!(text.contains("100% compliant"));
        assert!(flat(&text).contains("(1/1 evaluated pass, 1 unknown)"));
        let coloured = report.to_text(&Ui::render(true, false, 88), false);
        let pct = coloured.find("100% compliant").expect("percentage");
        let prefix = &coloured[..pct];
        assert!(
            !prefix.ends_with("32m"),
            "concealed percentage used pass green: {prefix}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_saved_report_keeps_the_reduced_observation_after_evidence_changes() {
        use crate::model::outcome::ObservationBasis;
        use crate::platform::linux::evidence::Target;
        let host = crate::test_context::host("debian", "hyprland");
        let mut reader = crate::test_context::reader([(
            Target::DebianPopcon,
            crate::test_context::text(b"PARTICIPATE=\"no\"\n# /home/secret-user\n"),
        )]);
        let report = {
            let context = crate::test_context::context(&host, &reader);
            Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &["debian".to_owned()],
                &[],
            )
        };
        let reads = reader.requested().len();
        reader.rewrite(
            Target::DebianPopcon,
            crate::test_context::text(b"PARTICIPATE=\"yes\"\n/home/secret-user\n"),
        );
        assert_eq!(reader.requested().len(), reads);
        let result = &report.results[0];
        assert_eq!(result.outcome, Outcome::Pass);
        assert_eq!(result.observed.as_deref(), Some("disabled"));
        assert_eq!(result.desired, "disabled");
        assert_eq!(result.observation_basis, ObservationBasis::Established);
        assert!(result.observation_reason.is_none());
        assert!(result.confident);
        assert!(result.is_coherent());
        let json = serde_json::to_string(&report).expect("json");
        let text = report.to_text(&Ui::plain(), true);
        for rendered in [&json, &text] {
            assert!(
                !rendered.contains("/home/secret-user"),
                "canary leaked: {rendered}"
            );
            assert!(!rendered.contains("PARTICIPATE"));
        }
        assert!(
            json.contains("\"observed\":\"disabled\"")
                || json.contains("\"observed\": \"disabled\"")
        );
        assert_eq!(report.schema, SCHEMA);
        assert!(!report.sources.is_empty());
        assert!(
            report.sources[result.source_refs[0] as usize]
                .url
                .contains("popularity-contest")
        );
    }
}
