use std::io::{IsTerminal, Write};

use serde::Serialize;

use crate::cli::{
    Cli, ColorWhen, Command, FrictionTier, OutputFormat, Platform, PostureDimension, Profile,
    WorkloadPersona,
};

#[derive(Serialize)]
struct PlanItem {
    id: String,
    title: String,
    section: String,
    current: String,
    desired: String,
    requires_elevation: bool,
    friction: FrictionTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

#[derive(Serialize)]
struct PlanReport {
    schema: u8,
    profile: String,
    workload: Option<WorkloadPersona>,
    platform: String,
    planned_changes: usize,
    unautomated_drift: usize,
    requires_elevation_drift: usize,
    changes: Vec<PlanItem>,
}

#[derive(Serialize)]
struct ApplyReport {
    schema: u8,
    profile: String,
    workload: Option<WorkloadPersona>,
    platform: String,
    transaction_id: String,
    applied_changes: usize,
    unautomated_drift: usize,
    requires_elevation_drift: usize,
}

#[derive(Serialize)]
struct RollbackReport {
    schema: u8,
    transaction_id: String,
    restored_changes: usize,
}

pub fn run(cli: Cli, out: &mut impl Write, err: &mut impl Write) -> i32 {
    match crate::journal::transactions_dir() {
        Ok(root) => run_with_journal_dir(cli, out, err, &root),
        Err(error) => {
            let _ = writeln!(err, "privr: {error}");
            5
        }
    }
}

fn explicit_elevation_required(
    control: &crate::catalog::Control,
    elevated: bool,
    selected: &[String],
) -> bool {
    control.requires_elevation()
        && !elevated
        && selected
            .iter()
            .any(|id| control.spec.id == *id || control.spec.id.starts_with(id))
}

/// Scope of approval when confirming all sections at once.
const APPROVAL_SCOPE: &str = "(y: all sections, s: section-by-section, d: details, q: quit) [N]";

fn section_stop_line(applied: usize, deferred: usize) -> String {
    format!("stopped {applied} sections applied, {deferred} deferred")
}

/// `Ok(true)` proceeds. `Ok(false)` cancels, including an empty entry.
/// `Err(2)` is a confirmation read failure.
fn interpret_confirmation(read: std::io::Result<String>) -> Result<bool, i32> {
    let input = read.map_err(|_| 2)?;
    let trimmed = input.trim();
    Ok(trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalChoice {
    All,
    Step,
    Diff,
    Cancel,
}

fn interpret_approval(read: std::io::Result<String>) -> Result<ApprovalChoice, i32> {
    let input = read.map_err(|_| 2)?;
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
        Ok(ApprovalChoice::All)
    } else if trimmed.eq_ignore_ascii_case("s")
        || trimmed.eq_ignore_ascii_case("step")
        || trimmed.eq_ignore_ascii_case("section")
        || trimmed.eq_ignore_ascii_case("sections")
    {
        Ok(ApprovalChoice::Step)
    } else if trimmed.eq_ignore_ascii_case("d")
        || trimmed.eq_ignore_ascii_case("diff")
        || trimmed.eq_ignore_ascii_case("details")
    {
        Ok(ApprovalChoice::Diff)
    } else {
        Ok(ApprovalChoice::Cancel)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionChoice {
    Approve,
    Skip,
    StopAndApply,
}

fn interpret_section_choice(read: std::io::Result<String>) -> Result<SectionChoice, i32> {
    let input = read.map_err(|_| 2)?;
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
        Ok(SectionChoice::Approve)
    } else if trimmed.eq_ignore_ascii_case("q")
        || trimmed.eq_ignore_ascii_case("quit")
        || trimmed.eq_ignore_ascii_case("stop")
    {
        Ok(SectionChoice::StopAndApply)
    } else {
        Ok(SectionChoice::Skip)
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

/// Narrate concealed rows already stored on a check. This does not probe again.
fn narrate_concealed(report: &crate::report::Report, ui: &crate::ui::Ui) -> String {
    let mut out = String::from("What couldn't be checked:\n");
    for result in report
        .results
        .iter()
        .filter(|result| result.outcome.conceals_state())
    {
        out.push_str(&format!(
            "  {}  {}\n    {}\n",
            result.outcome.as_str(),
            result.title,
            result.id
        ));
        if let Some(note) = &result.note {
            out.push_str(&ui.wrap(note, 4));
            out.push('\n');
        }
        if let Some(reason) = result.observation_reason {
            out.push_str(&format!("    reason: {}\n", uncertainty_word(reason)));
        }
    }
    out.push_str("Unknown means privr could not tell. It is never counted as passing.\n");
    out
}

fn render_verified_block(
    ui: &crate::ui::Ui,
    verified: usize,
    total: usize,
    platform: &str,
    transaction_id: &str,
    unverified: &[String],
) -> String {
    if verified == 0 {
        return String::new();
    }
    let name = crate::ui::platform_name(platform);
    let summary = format!("{verified} of {total} changes on {name}, transaction {transaction_id}");
    let hang = "verified  ".chars().count();
    let mut out = String::new();
    out.push_str(&ui.paint(
        crate::ui::style::outcome_style(crate::model::outcome::Outcome::Pass),
        "verified",
    ));
    out.push_str("  ");
    out.push_str(&ui.wrap_after(&summary, hang));
    out.push('\n');
    for id in unverified {
        let detail = format!("{id} did not verify");
        out.push_str(&" ".repeat(hang));
        out.push_str(&ui.paint(
            crate::ui::style::outcome_style(crate::model::outcome::Outcome::Drift),
            "drift",
        ));
        out.push_str("  ");
        out.push_str(&ui.wrap_after(&detail, hang + "drift  ".chars().count()));
        out.push('\n');
    }
    let command = format!("privr rollback {transaction_id}");
    out.push_str(&" ".repeat(hang));
    out.push_str(&ui.paint(crate::ui::style::MUTED, "undo: "));
    out.push_str(&ui.paint(crate::ui::style::INFO, &command));
    out.push('\n');
    out
}

fn verified_block_for(
    ui: &crate::ui::Ui,
    journal: &crate::journal::TransactionJournal,
    failed: Option<&str>,
) -> String {
    let verified = journal
        .operations
        .iter()
        .filter(|operation| operation.verified)
        .count();
    let mut unverified: Vec<String> = journal
        .operations
        .iter()
        .filter(|operation| !operation.verified)
        .map(|operation| operation.control_id.clone())
        .collect();
    let mut total = journal.operations.len();
    if let Some(id) = failed {
        unverified.push(id.to_owned());
        total += 1;
    }
    render_verified_block(
        ui,
        verified,
        total,
        &journal.platform,
        &journal.transaction_id,
        &unverified,
    )
}

fn validate_control_selectors(
    controls: &[String],
    all_controls: &[crate::catalog::Control],
    err: &mut impl Write,
) -> bool {
    for sel in controls {
        let matches = all_controls
            .iter()
            .any(|c| c.spec.id == *sel || c.spec.id.starts_with(sel));
        if !matches {
            let _ = writeln!(err, "privr: no control matching '{sel}'");
            let suggestions = crate::explain::suggestions(sel);
            if !suggestions.is_empty() {
                let _ = writeln!(err, "\nDid you mean:");
                for item in suggestions {
                    let _ = writeln!(err, "  {item}");
                }
            }
            let _ = writeln!(err, "\nRun privr list to see every control in this build.");
            return false;
        }
    }
    true
}

fn zero_planned_changes_line(
    unautomated_drift: usize,
    summary: &crate::model::outcome::Summary,
) -> String {
    if unautomated_drift > 0 {
        "Planned changes: 0 (drift exists with no automatic remediation; run privr check to review)"
            .to_owned()
    } else if summary.evaluated() == 0 {
        if summary.concealed() > 0 {
            format!(
                "Planned changes: 0 (nothing could be evaluated; {} could not be established; run privr check)",
                summary.concealed()
            )
        } else {
            "Planned changes: 0 (nothing could be evaluated in the selected scope; run privr check)"
                .to_owned()
        }
    } else if summary.concealed() > 0 {
        format!(
            "Planned changes: 0 ({} evaluated, {} could not be established; run privr check)",
            summary.evaluated(),
            summary.concealed()
        )
    } else if summary.review > 0 {
        "Planned changes: 0 (selected controls were evaluated; review items require operator judgment)"
            .to_owned()
    } else {
        "Planned changes: 0 (machine matches policy)".to_owned()
    }
}

fn zero_applied_changes_line(
    requires_elevation_drift: usize,
    unautomated_drift: usize,
    summary: &crate::model::outcome::Summary,
) -> String {
    if requires_elevation_drift > 0 {
        format!(
            "No user-scope changes to apply ({requires_elevation_drift} change(s) require administrative privileges; pass --elevate or run as Administrator)."
        )
    } else if unautomated_drift > 0 {
        "No automated changes to apply (drift exists with no automatic remediation; run privr check to review)."
            .to_owned()
    } else if summary.evaluated() == 0 {
        if summary.concealed() > 0 {
            format!(
                "No changes to apply (nothing could be evaluated; {} could not be established; run privr check).",
                summary.concealed()
            )
        } else {
            "No changes to apply (nothing could be evaluated in the selected scope; run privr check)."
                .to_owned()
        }
    } else if summary.concealed() > 0 {
        format!(
            "No drifted controls to apply ({} evaluated, {} could not be established; run privr check).",
            summary.evaluated(),
            summary.concealed()
        )
    } else if summary.review > 0 {
        "No automated changes to apply (selected controls were evaluated; review items require operator judgment)."
            .to_owned()
    } else {
        "No drifted controls to apply. Machine matches policy.".to_owned()
    }
}

fn run_with_journal_dir(
    cli: Cli,
    out: &mut impl Write,
    err: &mut impl Write,
    journal_dir: &std::path::Path,
) -> i32 {
    run_with_check_context(cli, out, err, journal_dir, None)
}

fn run_with_check_context(
    cli: Cli,
    out: &mut impl Write,
    err: &mut impl Write,
    journal_dir: &std::path::Path,
    check_context: Option<&crate::catalog::Context>,
) -> i32 {
    let format = cli.format;
    let ui = crate::ui::Ui::for_stdout(cli.color.into());
    let elevated_output_path = match &cli.command {
        Some(Command::Apply {
            elevated_output: Some(p),
            ..
        }) => Some(p.clone()),
        Some(Command::Rollback {
            elevated_output: Some(p),
            ..
        }) => Some(p.clone()),
        _ => None,
    };
    let mut dual_out =
        crate::platform::elevation::DualWriter::new(out, elevated_output_path.as_deref());
    let mut dual_err =
        crate::platform::elevation::DualWriter::new(err, elevated_output_path.as_deref());
    let out = &mut dual_out;
    let err = &mut dual_err;
    let is_default_entry = cli.command.is_none();
    match cli.command.unwrap_or(Command::Check {
        profile: Some(Profile::Baseline),
        policy: None,
        workload: None,
        controls: Vec::new(),
        sections: Vec::new(),
        all: false,
        compare: None,
    }) {
        Command::Check {
            profile,
            policy,
            workload,
            controls,
            sections,
            all,
            compare,
        } => {
            if !validate_control_selectors(&controls, &crate::catalog::all(), err) {
                return 2;
            }
            let loaded_policy = match policy {
                Some(ref p) => match crate::policy::CustomPolicy::from_file(p) {
                    Ok(pol) => Some(pol),
                    Err(e) => {
                        let _ = writeln!(err, "{e}");
                        return 2;
                    }
                },
                None => None,
            };

            let profile_str = if let Some(pol) = &loaded_policy {
                Some(pol.extends.as_str())
            } else if profile.is_none() && workload.is_none() {
                Some(Profile::Baseline.as_str())
            } else {
                profile.map(|p| p.as_str())
            };
            let report = {
                // Progress goes to standard error and only when that is a
                // terminal, so a pipe, a redirect, and an agent parse stay
                // clean. The guard clears the line however this scope exits.
                let total_controls = crate::catalog::all().len();
                let msg =
                    format!("Scanning {total_controls} controls across 5 posture dimensions...");
                let _progress = ui.spinner_for(&msg, format);
                if let Some(custom_policy) = &loaded_policy {
                    if let Some(context) = check_context {
                        crate::report::Report::build_with_policy(
                            context,
                            custom_policy,
                            &controls,
                            &sections,
                        )
                    } else {
                        let host = crate::platform::discover();
                        let context = crate::catalog::Context::live(&host);
                        crate::report::Report::build_with_policy(
                            &context,
                            custom_policy,
                            &controls,
                            &sections,
                        )
                    }
                } else if let Some(context) = check_context {
                    crate::report::Report::build_with_context(
                        context,
                        profile_str,
                        workload,
                        &controls,
                        &sections,
                    )
                } else {
                    let host = crate::platform::discover();
                    crate::report::Report::build_filtered_workload(
                        &host,
                        profile_str,
                        workload,
                        &controls,
                        &sections,
                    )
                }
            };

            if let Some(compare_path) = compare {
                let content = match std::fs::read_to_string(&compare_path) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = writeln!(
                            err,
                            "privr: cannot read comparison report from '{}': {e}",
                            compare_path.display()
                        );
                        return 2;
                    }
                };
                let prior_report: crate::report::Report = match serde_json::from_str(&content) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = writeln!(
                            err,
                            "privr: invalid or incompatible comparison report in '{}': {e}",
                            compare_path.display()
                        );
                        return 2;
                    }
                };
                let comparison = crate::report::compare_reports(&prior_report, &report);
                match format {
                    OutputFormat::Json => {
                        let json = serde_json::to_string_pretty(&comparison).unwrap_or_default();
                        let _ = writeln!(out, "{json}");
                    }
                    OutputFormat::Text => {
                        let rendered = crate::report::render_comparison(&ui, &comparison);
                        let _ = write!(out, "{rendered}");
                    }
                }
                if !comparison.complete {
                    return 3;
                }
                if !comparison.regressions.is_empty() || report.summary.drift > 0 {
                    return 1;
                }
                return 0;
            }

            match format {
                OutputFormat::Text => {
                    let _ = write!(out, "{}", report.to_text(&ui, all));
                    let _ = out.flush();

                    // A terminal session can choose a next step. Drift keeps the
                    // preview-or-apply prompt. An incomplete check with no drift
                    // offers the saved concealed rows instead of a second probe.
                    if !cli.no_input
                        && is_default_entry
                        && std::io::stdin().is_terminal()
                        && std::io::stdout().is_terminal()
                    {
                        if report.summary.drift > 0 {
                            let prompt_text = "Action? [y] apply safe fixes, [d] preview diff, [c] clean residue, [e] explain score & critical items, [q] quit (default: q): ";
                            let _ =
                                write!(out, "{}", ui.paint(crate::ui::style::HEADING, prompt_text));
                            let _ = out.flush();

                            let mut input = String::new();
                            if std::io::stdin().read_line(&mut input).is_ok() {
                                let mut trimmed = input.trim().to_lowercase();
                                if trimmed == "e" || trimmed == "explain" {
                                    let overview = crate::explain::render_overview(&ui);
                                    let _ = write!(out, "\n{overview}\n");
                                    let _ = out.flush();
                                    let next_prompt = "Next action? [y] apply safe fixes, [d] preview diff, [c] clean residue, [q] quit (default: q): ";
                                    let _ = write!(
                                        out,
                                        "{}",
                                        ui.paint(crate::ui::style::HEADING, next_prompt)
                                    );
                                    let _ = out.flush();
                                    input.clear();
                                    if std::io::stdin().read_line(&mut input).is_ok() {
                                        trimmed = input.trim().to_lowercase();
                                    }
                                }
                                if trimmed == "y"
                                    || trimmed == "yes"
                                    || trimmed == "a"
                                    || trimmed == "apply"
                                {
                                    return run_with_journal_dir(
                                        Cli {
                                            format,
                                            color: cli.color,
                                            no_input: cli.no_input,
                                            command: Some(Command::Apply {
                                                profile,
                                                policy: None,
                                                workload,
                                                max_friction: None,
                                                dry_run: false,
                                                yes: false,
                                                interactive_sections: false,
                                                accept_risk: Vec::new(),
                                                force: false,
                                                controls,
                                                sections,
                                                elevate: false,
                                                elevated_output: None,
                                            }),
                                        },
                                        out,
                                        err,
                                        journal_dir,
                                    );
                                } else if trimmed == "c" || trimmed == "clean" || trimmed == "purge"
                                {
                                    return run_with_journal_dir(
                                        Cli {
                                            format,
                                            color: cli.color,
                                            no_input: cli.no_input,
                                            command: Some(Command::Clean {
                                                polite: false,
                                                preview: false,
                                                dry_run: false,
                                                yes: false,
                                                categories: Vec::new(),
                                                controls: Vec::new(),
                                                accept_risks: Vec::new(),
                                                trim: false,
                                            }),
                                        },
                                        out,
                                        err,
                                        journal_dir,
                                    );
                                } else if trimmed == "d"
                                    || trimmed == "diff"
                                    || trimmed == "p"
                                    || trimmed == "plan"
                                {
                                    let plan_code = run_with_journal_dir(
                                        Cli {
                                            format,
                                            color: cli.color,
                                            no_input: cli.no_input,
                                            command: Some(Command::Plan {
                                                profile,
                                                policy: None,
                                                workload,
                                                max_friction: None,
                                                controls: controls.clone(),
                                                sections: sections.clone(),
                                            }),
                                        },
                                        out,
                                        err,
                                        journal_dir,
                                    );
                                    if plan_code == 0 {
                                        let apply_prompt = format!(
                                            "Apply these changes now? [y/N] {APPROVAL_SCOPE}: "
                                        );
                                        let _ = write!(
                                            out,
                                            "{}",
                                            ui.paint(crate::ui::style::HEADING, &apply_prompt)
                                        );
                                        let _ = out.flush();
                                        let mut plan_input = String::new();
                                        let read = std::io::stdin()
                                            .read_line(&mut plan_input)
                                            .map(|_| plan_input.clone());
                                        match interpret_confirmation(read) {
                                            Ok(true) => {
                                                return run_with_journal_dir(
                                                    Cli {
                                                        format,
                                                        color: cli.color,
                                                        no_input: cli.no_input,
                                                        command: Some(Command::Apply {
                                                            profile,
                                                            policy: None,
                                                            workload,
                                                            max_friction: None,
                                                            dry_run: false,
                                                            yes: true,
                                                            interactive_sections: false,
                                                            accept_risk: Vec::new(),
                                                            force: false,
                                                            controls,
                                                            sections,
                                                            elevate: false,
                                                            elevated_output: None,
                                                        }),
                                                    },
                                                    out,
                                                    err,
                                                    journal_dir,
                                                );
                                            }
                                            Ok(false) => {}
                                            Err(code) => {
                                                let _ = writeln!(
                                                    err,
                                                    "privr: failed to read confirmation input"
                                                );
                                                return code;
                                            }
                                        }
                                    }
                                }
                            }
                        } else if !report.complete {
                            let prompt_text = "Action? [e] what couldn't be checked and why, [c] clean residue, [q] quit (default: q): ";
                            let _ =
                                write!(out, "{}", ui.paint(crate::ui::style::HEADING, prompt_text));
                            let _ = out.flush();
                            let mut input = String::new();
                            if std::io::stdin().read_line(&mut input).is_ok() {
                                let trimmed = input.trim().to_lowercase();
                                if trimmed == "e" || trimmed == "explain" {
                                    let _ = write!(out, "\n{}", narrate_concealed(&report, &ui));
                                    let _ = out.flush();
                                } else if trimmed == "c" || trimmed == "clean" || trimmed == "purge"
                                {
                                    return run_with_journal_dir(
                                        Cli {
                                            format,
                                            color: cli.color,
                                            no_input: cli.no_input,
                                            command: Some(Command::Clean {
                                                polite: false,
                                                preview: false,
                                                dry_run: false,
                                                yes: false,
                                                categories: Vec::new(),
                                                controls: Vec::new(),
                                                accept_risks: Vec::new(),
                                                trim: false,
                                            }),
                                        },
                                        out,
                                        err,
                                        journal_dir,
                                    );
                                }
                            }
                        } else {
                            let prompt_text =
                                "Action? [c] clean residue & caches, [q] quit (default: q): ";
                            let _ =
                                write!(out, "{}", ui.paint(crate::ui::style::HEADING, prompt_text));
                            let _ = out.flush();
                            let mut input = String::new();
                            if std::io::stdin().read_line(&mut input).is_ok() {
                                let trimmed = input.trim().to_lowercase();
                                if trimmed == "c" || trimmed == "clean" || trimmed == "purge" {
                                    return run_with_journal_dir(
                                        Cli {
                                            format,
                                            color: cli.color,
                                            no_input: cli.no_input,
                                            command: Some(Command::Clean {
                                                polite: false,
                                                preview: false,
                                                dry_run: false,
                                                yes: false,
                                                categories: Vec::new(),
                                                controls: Vec::new(),
                                                accept_risks: Vec::new(),
                                                trim: false,
                                            }),
                                        },
                                        out,
                                        err,
                                        journal_dir,
                                    );
                                }
                            }
                        }
                    }
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &report).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            report.exit_code()
        }
        Command::Plan {
            profile,
            policy,
            workload,
            max_friction,
            controls,
            sections,
        } => {
            let all_controls = crate::catalog::all();
            if !validate_control_selectors(&controls, &all_controls, err) {
                return 2;
            }
            let loaded_policy = match policy {
                Some(ref p) => match crate::policy::CustomPolicy::from_file(p) {
                    Ok(pol) => Some(pol),
                    Err(e) => {
                        let _ = writeln!(err, "{e}");
                        return 2;
                    }
                },
                None => None,
            };
            let mut progress = ui.spinner_for(
                "Evaluating posture and planning eligible remediations...",
                format,
            );
            let discovered_host;
            let live_context;
            let (host, context) = if let Some(ctx) = check_context {
                (ctx.host, ctx)
            } else {
                discovered_host = crate::platform::discover();
                live_context = crate::catalog::Context::live(&discovered_host);
                (&discovered_host, &live_context)
            };
            let (workload, max_friction) =
                if profile.is_none() && workload.is_none() && loaded_policy.is_none() {
                    (
                        Some(WorkloadPersona::General),
                        Some(FrictionTier::Tier1Cosmetic),
                    )
                } else {
                    (workload, max_friction)
                };
            let profile_val = if let Some(pol) = &loaded_policy {
                pol.extends
            } else {
                profile.unwrap_or_default()
            };

            let recommended_ids: Option<std::collections::BTreeSet<String>> = workload.map(|w| {
                all_controls
                    .iter()
                    .filter(|c| {
                        crate::engine::recommend::is_control_recommended_for_workload(
                            &c.spec,
                            w,
                            max_friction,
                        )
                    })
                    .map(|c| c.spec.id.clone())
                    .collect()
            });

            let mut planned = Vec::new();
            let mut unautomated_drift = 0;
            let mut requires_elevation_drift = 0;
            let mut summary = crate::model::outcome::Summary::default();

            for c in &all_controls {
                let matches_control = controls.is_empty()
                    || controls
                        .iter()
                        .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel));
                let matches_section = sections.is_empty()
                    || sections.iter().any(|sec| {
                        c.spec.section.eq_ignore_ascii_case(sec)
                            || c.spec
                                .section
                                .to_ascii_lowercase()
                                .starts_with(&sec.to_ascii_lowercase())
                    });
                if !matches_control || !matches_section {
                    continue;
                }
                let override_opt = loaded_policy
                    .as_ref()
                    .and_then(|pol| pol.controls.get(&c.spec.id));
                let mut spec_clone = c.spec.clone();
                if let Some(ov) = override_opt
                    && let Some(desired_val) = &ov.desired
                {
                    spec_clone.desired = crate::engine::evaluate::SemanticState::new(desired_val);
                }
                let mode = if let Some(ov) = override_opt
                    && let Some(m) = ov.mode
                {
                    m
                } else if !controls.is_empty()
                    || recommended_ids
                        .as_ref()
                        .is_some_and(|recs| recs.contains(&c.spec.id))
                    || (recommended_ids.is_none() && c.spec.min_profile <= profile_val)
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let resolution = if mode == crate::engine::evaluate::Mode::Ignore
                    || spec_clone.applicability.resolve(host).applies
                        != crate::model::applicability::Applies::Yes
                {
                    crate::engine::evaluate::Resolution::skipped()
                } else {
                    c.observe(context)
                };
                let today = crate::policy::today_iso();
                let exception = if let Some(pol) = &loaded_policy {
                    if let Some(ex) = pol.exceptions.iter().find(|e| e.control == c.spec.id) {
                        if resolution.state.as_ref().map(|s| s.0.as_str()) == Some(&ex.accepted) {
                            ex.status(&today)
                        } else {
                            crate::model::outcome::Exception::None
                        }
                    } else {
                        crate::model::outcome::Exception::None
                    }
                } else {
                    crate::model::outcome::Exception::None
                };
                let eval = crate::engine::evaluate::evaluate(
                    &spec_clone,
                    mode,
                    &resolution,
                    host,
                    exception,
                );
                summary.record(&eval);
                if eval.outcome == crate::model::outcome::Outcome::Drift {
                    // Active policy exception suppresses planning remediation
                    if eval.exception == crate::model::outcome::Exception::Active {
                        continue;
                    }
                    if eval.remediation == crate::model::outcome::Remediation::Automatic
                        && c.apply.is_some()
                    {
                        if c.spec.requires_elevation
                            && host.elevated == crate::model::host::Fact::Known(false)
                        {
                            requires_elevation_drift += 1;
                        }
                        let current_str = resolution
                            .state
                            .map(|s| s.0)
                            .unwrap_or_else(|| "drift".to_owned());
                        let details = c.tradeoff.or(Some(c.summary)).map(|s| s.to_string());
                        planned.push(PlanItem {
                            id: c.spec.id.clone(),
                            title: c.title.to_owned(),
                            section: c.spec.section.clone(),
                            current: current_str,
                            desired: spec_clone.desired.0.clone(),
                            requires_elevation: c.spec.requires_elevation,
                            friction: c.spec.friction,
                            details,
                        });
                    } else {
                        unautomated_drift += 1;
                    }
                }
            }
            progress.finish();

            let profile_name = if let Some(pol) = &loaded_policy {
                format!("custom (extends {})", pol.extends)
            } else if let Some(w) = workload {
                format!("workload:{}", w.as_str())
            } else {
                profile_val.as_str().to_owned()
            };

            let plan_report = PlanReport {
                schema: 1,
                profile: profile_name,
                workload,
                platform: host.platform.as_str().to_owned(),
                planned_changes: planned.len(),
                unautomated_drift,
                requires_elevation_drift,
                changes: planned,
            };

            match format {
                OutputFormat::Text => {
                    let labels = ["Workload", "Profile", "Platform", "Planned changes"];
                    let width = crate::ui::Ui::label_width(&labels);
                    if let Some(w) = workload {
                        let _ = write!(out, "{} ", ui.field("Workload", width));
                        let _ = writeln!(out, "{}", ui.wrap_after(w.as_str(), width + 1));
                    } else {
                        let _ = write!(out, "{} ", ui.field("Profile", width));
                        let _ = writeln!(out, "{}", ui.wrap_after(&plan_report.profile, width + 1));
                    }
                    let _ = write!(out, "{} ", ui.field("Platform", width));
                    let _ = writeln!(
                        out,
                        "{}",
                        ui.wrap_after(crate::ui::platform_name(&plan_report.platform), width + 1)
                    );
                    if plan_report.planned_changes == 0 {
                        let _ = writeln!(
                            out,
                            "{}",
                            zero_planned_changes_line(plan_report.unautomated_drift, &summary)
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "Planned changes: {} (changes nothing without privr apply)\n",
                            plan_report.planned_changes
                        );
                        let mut last_section = "";
                        for item in &plan_report.changes {
                            if item.section != last_section {
                                if !last_section.is_empty() {
                                    let _ = writeln!(out);
                                }
                                let _ = writeln!(
                                    out,
                                    "{}",
                                    ui.paint(
                                        crate::ui::style::HEADING,
                                        crate::report::humanize_section(&item.section)
                                    )
                                );
                                last_section = &item.section;
                            }
                            let elev_tag = if item.requires_elevation {
                                format!(
                                    " {}",
                                    ui.paint(crate::ui::style::CAVEAT, "[requires elevation]")
                                )
                            } else {
                                String::new()
                            };
                            let _ = writeln!(
                                out,
                                "  {}{}",
                                ui.paint(crate::ui::style::IDENT, &item.title),
                                elev_tag
                            );
                            let _ = writeln!(
                                out,
                                "    Control:  {}",
                                ui.paint(crate::ui::style::MUTED, &item.id)
                            );
                            let arrow = ui.paint(crate::ui::style::MUTED, "->");
                            let cur_display = ui.paint(
                                crate::ui::style::outcome_style(
                                    crate::model::outcome::Outcome::Drift,
                                ),
                                &item.current,
                            );
                            let des_display = ui.paint(
                                crate::ui::style::outcome_style(
                                    crate::model::outcome::Outcome::Pass,
                                ),
                                &item.desired,
                            );
                            let _ =
                                writeln!(out, "    Change:   {cur_display} {arrow} {des_display}");
                            let _ = writeln!(
                                out,
                                "    Friction: {}",
                                ui.paint(crate::ui::style::MUTED, item.friction.display_name())
                            );
                            if let Some(details) = &item.details {
                                let wrapped = ui.wrap_after(details, 14);
                                let _ = writeln!(
                                    out,
                                    "    Details:  {}",
                                    ui.paint_lines(crate::ui::style::MUTED, &wrapped)
                                );
                            }
                        }
                        if plan_report.unautomated_drift > 0 {
                            let _ = writeln!(
                                out,
                                "\nNote: {} drifted control(s) have no automatic remediation and require manual review (run privr check to inspect).",
                                plan_report.unautomated_drift
                            );
                        }
                        if host.elevated == crate::model::host::Fact::Known(false)
                            && plan_report.requires_elevation_drift > 0
                        {
                            let _ = writeln!(
                                out,
                                "\nNote: {} change(s) require administrative privileges (run privr apply to elevate in-place).",
                                plan_report.requires_elevation_drift
                            );
                        }
                        let _ = writeln!(
                            out,
                            "\nRun privr apply (or privr fix) to apply these changes."
                        );
                    }
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &plan_report).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            0
        }
        Command::Apply {
            profile,
            policy,
            workload,
            max_friction,
            dry_run,
            yes,
            interactive_sections,
            accept_risk,
            force,
            controls,
            sections,
            elevate,
            elevated_output: _,
        } => {
            if dry_run {
                return run_with_check_context(
                    Cli {
                        format,
                        color: cli.color,
                        no_input: cli.no_input,
                        command: Some(Command::Plan {
                            profile,
                            policy,
                            workload,
                            max_friction,
                            controls,
                            sections,
                        }),
                    },
                    out,
                    err,
                    journal_dir,
                    check_context,
                );
            }
            let all_controls = crate::catalog::all();
            if !validate_control_selectors(&controls, &all_controls, err) {
                return 2;
            }
            let loaded_policy = match policy {
                Some(ref p) => match crate::policy::CustomPolicy::from_file(p) {
                    Ok(pol) => Some(pol),
                    Err(e) => {
                        let _ = writeln!(err, "{e}");
                        return 2;
                    }
                },
                None => None,
            };

            let (workload, max_friction) =
                if profile.is_none() && workload.is_none() && loaded_policy.is_none() {
                    (
                        Some(WorkloadPersona::General),
                        Some(FrictionTier::Tier1Cosmetic),
                    )
                } else {
                    (workload, max_friction)
                };

            let mut eval_progress =
                ui.spinner_for("Evaluating controls and posture state...", format);
            let host = crate::platform::discover();
            let is_elevated = host.elevated == crate::model::host::Fact::Known(true);
            let context = crate::catalog::Context::live(&host);
            let profile_val = if let Some(pol) = &loaded_policy {
                pol.extends
            } else {
                profile.unwrap_or_default()
            };
            let mut approved_sections: Option<std::collections::BTreeSet<String>> = None;

            let recommended_ids: Option<std::collections::BTreeSet<String>> = workload.map(|w| {
                all_controls
                    .iter()
                    .filter(|c| {
                        crate::engine::recommend::is_control_recommended_for_workload(
                            &c.spec,
                            w,
                            max_friction,
                        )
                    })
                    .map(|c| c.spec.id.clone())
                    .collect()
            });

            use std::io::IsTerminal;
            let is_interactive =
                !cli.no_input && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

            if !yes {
                if !is_interactive {
                    eval_progress.finish();
                    let _ = writeln!(
                        err,
                        "privr: no terminal for approval; review with privr plan, then run privr apply --yes [--section <name>]"
                    );
                    return 2;
                }

                let mut planned_items = Vec::new();
                let mut unautomated_count = 0;
                let mut elevation_count = 0;
                let mut preview_summary = crate::model::outcome::Summary::default();

                for c in &all_controls {
                    let matches_control = controls.is_empty()
                        || controls
                            .iter()
                            .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel));
                    let matches_section = sections.is_empty()
                        || sections.iter().any(|sec| {
                            c.spec.section.eq_ignore_ascii_case(sec)
                                || c.spec
                                    .section
                                    .to_ascii_lowercase()
                                    .starts_with(&sec.to_ascii_lowercase())
                        });
                    if !matches_control || !matches_section {
                        continue;
                    }
                    let override_opt = loaded_policy
                        .as_ref()
                        .and_then(|pol| pol.controls.get(&c.spec.id));
                    let mut spec_clone = c.spec.clone();
                    if let Some(ov) = override_opt
                        && let Some(desired_val) = &ov.desired
                    {
                        spec_clone.desired =
                            crate::engine::evaluate::SemanticState::new(desired_val);
                    }
                    let mode = if let Some(ov) = override_opt
                        && let Some(m) = ov.mode
                    {
                        m
                    } else if !controls.is_empty()
                        || recommended_ids
                            .as_ref()
                            .is_some_and(|recs| recs.contains(&c.spec.id))
                        || (recommended_ids.is_none() && c.spec.min_profile <= profile_val)
                    {
                        crate::engine::evaluate::Mode::Enforce
                    } else {
                        crate::engine::evaluate::Mode::Ignore
                    };
                    let resolution = if mode == crate::engine::evaluate::Mode::Ignore
                        || spec_clone.applicability.resolve(&host).applies
                            != crate::model::applicability::Applies::Yes
                    {
                        crate::engine::evaluate::Resolution::skipped()
                    } else {
                        c.observe(&context)
                    };
                    let today = crate::policy::today_iso();
                    let exception = if let Some(pol) = &loaded_policy {
                        if let Some(ex) = pol.exceptions.iter().find(|e| e.control == c.spec.id) {
                            if resolution.state.as_ref().map(|s| s.0.as_str()) == Some(&ex.accepted)
                            {
                                ex.status(&today)
                            } else {
                                crate::model::outcome::Exception::None
                            }
                        } else {
                            crate::model::outcome::Exception::None
                        }
                    } else {
                        crate::model::outcome::Exception::None
                    };
                    let eval = crate::engine::evaluate::evaluate(
                        &spec_clone,
                        mode,
                        &resolution,
                        &host,
                        exception,
                    );
                    preview_summary.record(&eval);
                    if eval.outcome == crate::model::outcome::Outcome::Drift {
                        if eval.exception == crate::model::outcome::Exception::Active {
                            continue;
                        }
                        if eval.remediation == crate::model::outcome::Remediation::Automatic
                            && c.apply.is_some()
                        {
                            if c.spec.requires_elevation && !is_elevated {
                                elevation_count += 1;
                            }
                            let current_str = resolution
                                .state
                                .map(|s| s.0)
                                .unwrap_or_else(|| "drift".to_owned());
                            let details = c.tradeoff.or(Some(c.summary)).map(|s| s.to_string());
                            planned_items.push(PlanItem {
                                id: c.spec.id.clone(),
                                title: c.title.to_owned(),
                                section: c.spec.section.clone(),
                                current: current_str,
                                desired: spec_clone.desired.0.clone(),
                                requires_elevation: c.spec.requires_elevation,
                                friction: c.spec.friction,
                                details,
                            });
                        } else {
                            unautomated_count += 1;
                        }
                    }
                }
                eval_progress.finish();

                if planned_items.is_empty() {
                    let _ = writeln!(
                        out,
                        "{}",
                        zero_planned_changes_line(unautomated_count, &preview_summary)
                    );
                    return 0;
                }

                let labels = ["Workload", "Profile", "Platform", "Planned changes"];
                let width = crate::ui::Ui::label_width(&labels);
                if let Some(w) = workload {
                    let _ = write!(out, "{} ", ui.field("Workload", width));
                    let _ = writeln!(out, "{}", ui.wrap_after(w.as_str(), width + 1));
                } else {
                    let _ = write!(out, "{} ", ui.field("Profile", width));
                    let _ = writeln!(out, "{}", ui.wrap_after(profile_val.as_str(), width + 1));
                }
                let _ = write!(out, "{} ", ui.field("Platform", width));
                let _ = writeln!(
                    out,
                    "{}",
                    ui.wrap_after(crate::ui::platform_name(host.platform.as_str()), width + 1)
                );
                let _ = write!(out, "{} ", ui.field("Planned changes", width));
                let _ = writeln!(
                    out,
                    "{}\n",
                    ui.wrap_after(&planned_items.len().to_string(), width + 1)
                );

                let mut last_section = "";
                for item in &planned_items {
                    if item.section != last_section {
                        if !last_section.is_empty() {
                            let _ = writeln!(out);
                        }
                        let _ = writeln!(
                            out,
                            "{}",
                            ui.paint(
                                crate::ui::style::HEADING,
                                crate::report::humanize_section(&item.section)
                            )
                        );
                        last_section = &item.section;
                    }
                    let elev_tag = if item.requires_elevation && !is_elevated {
                        format!(
                            " {}",
                            ui.paint(crate::ui::style::CAVEAT, "[requires elevation]")
                        )
                    } else {
                        String::new()
                    };
                    let _ = writeln!(
                        out,
                        "  {}{}",
                        ui.paint(crate::ui::style::IDENT, &item.title),
                        elev_tag
                    );
                    let _ = writeln!(
                        out,
                        "    Control:  {}",
                        ui.paint(crate::ui::style::MUTED, &item.id)
                    );
                    let arrow = ui.paint(crate::ui::style::MUTED, "->");
                    let cur_display = ui.paint(
                        crate::ui::style::outcome_style(crate::model::outcome::Outcome::Drift),
                        &item.current,
                    );
                    let des_display = ui.paint(
                        crate::ui::style::outcome_style(crate::model::outcome::Outcome::Pass),
                        &item.desired,
                    );
                    let _ = writeln!(out, "    Change:   {cur_display} {arrow} {des_display}");
                    let _ = writeln!(
                        out,
                        "    Friction: {}",
                        ui.paint(crate::ui::style::MUTED, item.friction.display_name())
                    );
                    if let Some(details) = &item.details {
                        let wrapped = ui.wrap_after(details, 14);
                        let _ = writeln!(
                            out,
                            "    Details:  {}",
                            ui.paint_lines(crate::ui::style::MUTED, &wrapped)
                        );
                    }
                }

                if elevation_count > 0 && !is_elevated {
                    let _ = writeln!(
                        out,
                        "\nNote: {} change(s) require administrative privileges.",
                        elevation_count
                    );
                    let _ = writeln!(
                        out,
                        "A Windows User Account Control (UAC) prompt will request approval to elevate."
                    );
                }

                let mut unique_sections: Vec<String> = Vec::new();
                for item in &planned_items {
                    if !unique_sections.contains(&item.section) {
                        unique_sections.push(item.section.clone());
                    }
                }

                let choice = if interactive_sections {
                    ApprovalChoice::Step
                } else {
                    loop {
                        let prompt_msg = format!(
                            "\nApply these {} change(s)? [y/s/d/q] {APPROVAL_SCOPE}: ",
                            planned_items.len()
                        );
                        let _ = write!(out, "{prompt_msg}");
                        let _ = out.flush();

                        let mut input = String::new();
                        let read_res = std::io::stdin()
                            .read_line(&mut input)
                            .map(|_| input.clone());
                        match interpret_approval(read_res) {
                            Ok(ApprovalChoice::Diff) => {
                                let _ = writeln!(
                                    out,
                                    "\n{}",
                                    ui.paint(
                                        crate::ui::style::HEADING,
                                        "Planned Remediations (Detailed Diff):"
                                    )
                                );
                                for item in &planned_items {
                                    let elev_tag = if item.requires_elevation && !is_elevated {
                                        format!(
                                            " {}",
                                            ui.paint(
                                                crate::ui::style::CAVEAT,
                                                "[requires elevation]"
                                            )
                                        )
                                    } else {
                                        String::new()
                                    };
                                    let _ = writeln!(
                                        out,
                                        "  {} [{}]{}",
                                        ui.paint(crate::ui::style::IDENT, &item.title),
                                        ui.paint(crate::ui::style::MUTED, &item.id),
                                        elev_tag
                                    );
                                    let arrow = ui.paint(crate::ui::style::MUTED, "->");
                                    let cur = ui.paint(
                                        crate::ui::style::outcome_style(
                                            crate::model::outcome::Outcome::Drift,
                                        ),
                                        &item.current,
                                    );
                                    let des = ui.paint(
                                        crate::ui::style::outcome_style(
                                            crate::model::outcome::Outcome::Pass,
                                        ),
                                        &item.desired,
                                    );
                                    let _ = writeln!(
                                        out,
                                        "    Section:  {}",
                                        crate::report::humanize_section(&item.section)
                                    );
                                    let _ = writeln!(out, "    Change:   {cur} {arrow} {des}");
                                    let _ = writeln!(
                                        out,
                                        "    Friction: {}",
                                        item.friction.display_name()
                                    );
                                    if let Some(details) = &item.details {
                                        let _ = writeln!(out, "    Details:  {details}");
                                    }
                                }
                                continue;
                            }
                            Ok(c) => break c,
                            Err(code) => {
                                let _ = writeln!(err, "privr: failed to read confirmation input");
                                return code;
                            }
                        }
                    }
                };

                match choice {
                    ApprovalChoice::Cancel => {
                        let _ = writeln!(out, "privr: apply cancelled by user.");
                        return 0;
                    }
                    ApprovalChoice::All => {
                        approved_sections = Some(unique_sections.into_iter().collect());
                    }
                    ApprovalChoice::Step => {
                        let mut approved = std::collections::BTreeSet::new();
                        let mut deferred = std::collections::BTreeSet::new();
                        let mut stopped_early = false;

                        for sec in &unique_sections {
                            if stopped_early {
                                deferred.insert(sec.clone());
                                continue;
                            }
                            let sec_items: Vec<_> =
                                planned_items.iter().filter(|i| i.section == *sec).collect();
                            let humanized = crate::report::humanize_section(sec);
                            let _ = writeln!(
                                out,
                                "\n{}",
                                ui.paint(
                                    crate::ui::style::HEADING,
                                    &format!(
                                        "Section '{}' ({} change(s)):",
                                        humanized,
                                        sec_items.len()
                                    )
                                )
                            );
                            for item in &sec_items {
                                let elev_tag = if item.requires_elevation && !is_elevated {
                                    format!(
                                        " {}",
                                        ui.paint(crate::ui::style::CAVEAT, "[requires elevation]")
                                    )
                                } else {
                                    String::new()
                                };
                                let _ = writeln!(
                                    out,
                                    "  {}{}",
                                    ui.paint(crate::ui::style::IDENT, &item.title),
                                    elev_tag
                                );
                                let arrow = ui.paint(crate::ui::style::MUTED, "->");
                                let cur_display = ui.paint(
                                    crate::ui::style::outcome_style(
                                        crate::model::outcome::Outcome::Drift,
                                    ),
                                    &item.current,
                                );
                                let des_display = ui.paint(
                                    crate::ui::style::outcome_style(
                                        crate::model::outcome::Outcome::Pass,
                                    ),
                                    &item.desired,
                                );
                                let _ = writeln!(
                                    out,
                                    "    Change:   {cur_display} {arrow} {des_display}"
                                );
                                let _ = writeln!(
                                    out,
                                    "    Friction: {}",
                                    ui.paint(crate::ui::style::MUTED, item.friction.display_name())
                                );
                                if let Some(details) = &item.details {
                                    let wrapped = ui.wrap_after(details, 14);
                                    let _ = writeln!(
                                        out,
                                        "    Details:  {}",
                                        ui.paint_lines(crate::ui::style::MUTED, &wrapped)
                                    );
                                }
                            }
                            let prompt = format!(
                                "Apply section '{}'? [y/n/q] (q to stop and apply approved) [N]: ",
                                humanized
                            );
                            let _ = write!(out, "{}", ui.paint(crate::ui::style::HEADING, &prompt));
                            let _ = out.flush();

                            let mut sec_input = String::new();
                            match interpret_section_choice(
                                std::io::stdin()
                                    .read_line(&mut sec_input)
                                    .map(|_| sec_input),
                            ) {
                                Ok(SectionChoice::Approve) => {
                                    approved.insert(sec.clone());
                                }
                                Ok(SectionChoice::Skip) => {
                                    deferred.insert(sec.clone());
                                }
                                Ok(SectionChoice::StopAndApply) => {
                                    stopped_early = true;
                                    deferred.insert(sec.clone());
                                }
                                Err(code) => {
                                    let _ =
                                        writeln!(err, "privr: failed to read section confirmation");
                                    return code;
                                }
                            }
                        }

                        if approved.is_empty() {
                            let _ = writeln!(
                                out,
                                "privr: apply cancelled by user (0 sections approved)."
                            );
                            return 0;
                        }

                        if !deferred.is_empty() {
                            let _ = writeln!(
                                out,
                                "\n{}",
                                ui.paint(
                                    crate::ui::style::MUTED,
                                    &section_stop_line(approved.len(), deferred.len())
                                )
                            );
                        }

                        approved_sections = Some(approved);
                    }
                    ApprovalChoice::Diff => unreachable!(),
                }

                if let Some(appr) = &approved_sections {
                    planned_items.retain(|item| appr.contains(&item.section));
                }
            }
            eval_progress.finish();

            // Check if machine-scope changes require elevation:
            let mut requires_elevation_drift = 0;
            for c in &all_controls {
                let matches_control = controls.is_empty()
                    || controls
                        .iter()
                        .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel));
                let matches_section = sections.is_empty()
                    || sections.iter().any(|sec| {
                        c.spec.section.eq_ignore_ascii_case(sec)
                            || c.spec
                                .section
                                .to_ascii_lowercase()
                                .starts_with(&sec.to_ascii_lowercase())
                    });
                if !matches_control || !matches_section {
                    continue;
                }
                if let Some(appr) = &approved_sections
                    && !appr.contains(&c.spec.section)
                {
                    continue;
                }
                if let Some(recs) = &recommended_ids
                    && !recs.contains(&c.spec.id)
                {
                    continue;
                }
                if !c.spec.requires_elevation || c.apply.is_none() {
                    continue;
                }
                let override_opt = loaded_policy
                    .as_ref()
                    .and_then(|pol| pol.controls.get(&c.spec.id));
                let mut spec_clone = c.spec.clone();
                if let Some(ov) = override_opt
                    && let Some(desired_val) = &ov.desired
                {
                    spec_clone.desired = crate::engine::evaluate::SemanticState::new(desired_val);
                }
                let resolution = c.observe(&context);
                let mode = if let Some(ov) = override_opt
                    && let Some(m) = ov.mode
                {
                    m
                } else if !controls.is_empty()
                    || recommended_ids.is_some()
                    || c.spec.min_profile <= profile_val
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let today = crate::policy::today_iso();
                let exception = if let Some(pol) = &loaded_policy {
                    if let Some(ex) = pol.exceptions.iter().find(|e| e.control == c.spec.id) {
                        if resolution.state.as_ref().map(|s| s.0.as_str()) == Some(&ex.accepted) {
                            ex.status(&today)
                        } else {
                            crate::model::outcome::Exception::None
                        }
                    } else {
                        crate::model::outcome::Exception::None
                    }
                } else {
                    crate::model::outcome::Exception::None
                };
                let eval = crate::engine::evaluate::evaluate(
                    &spec_clone,
                    mode,
                    &resolution,
                    &host,
                    exception,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift
                    && eval.exception != crate::model::outcome::Exception::Active
                    && eval.remediation == crate::model::outcome::Remediation::Automatic
                {
                    requires_elevation_drift += 1;
                }
            }

            let mut perform_elevation = elevate;
            if !perform_elevation && !is_elevated && requires_elevation_drift > 0 && !yes {
                // In interactive mode without --yes, the user was already shown
                // the plan with "[requires elevation]" and confirmed with 'y'.
                perform_elevation = true;
            }

            if perform_elevation && !is_elevated && requires_elevation_drift > 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let temp_file = std::env::temp_dir().join(format!(
                    "privr-elev-{}-{}.tmp",
                    std::process::id(),
                    now.as_millis()
                ));

                let mut child_args = vec!["apply", "--yes"];
                let format_str = match format {
                    OutputFormat::Text => "text",
                    OutputFormat::Json => "json",
                };
                child_args.push("--format");
                child_args.push(format_str);

                let color_str = match cli.color {
                    ColorWhen::Auto => "auto",
                    ColorWhen::Always => "always",
                    ColorWhen::Never => "never",
                };
                child_args.push("--color");
                child_args.push(color_str);

                let workload_str;
                if let Some(w) = workload {
                    child_args.push("--workload");
                    workload_str = clap::ValueEnum::to_possible_value(&w)
                        .map(|pv| pv.get_name().to_string())
                        .unwrap_or_else(|| w.as_str().to_string());
                    child_args.push(&workload_str);
                }
                let friction_str;
                if let Some(f) = max_friction {
                    child_args.push("--max-friction");
                    friction_str = clap::ValueEnum::to_possible_value(&f)
                        .map(|pv| pv.get_name().to_string())
                        .unwrap_or_else(|| f.as_str().to_string());
                    child_args.push(&friction_str);
                }
                let profile_str_val;
                if profile.is_some() {
                    child_args.push("--profile");
                    profile_str_val = clap::ValueEnum::to_possible_value(&profile_val)
                        .map(|pv| pv.get_name().to_string())
                        .unwrap_or_else(|| profile_val.as_str().to_string());
                    child_args.push(&profile_str_val);
                }
                for c_arg in &controls {
                    child_args.push("--control");
                    child_args.push(c_arg);
                }
                if let Some(appr) = &approved_sections {
                    for sec in appr {
                        child_args.push("--section");
                        child_args.push(sec);
                    }
                } else {
                    for s_arg in &sections {
                        child_args.push("--section");
                        child_args.push(s_arg);
                    }
                }
                let policy_str_val;
                if let Some(p) = &policy {
                    child_args.push("--policy");
                    policy_str_val = p.to_string_lossy().to_string();
                    child_args.push(&policy_str_val);
                }
                for r in &accept_risk {
                    child_args.push("--accept-risk");
                    child_args.push(r);
                }
                if force {
                    child_args.push("--force");
                }

                let mut elev_progress = ui.spinner_for(
                    "Requesting administrative elevation (UAC prompt)...",
                    format,
                );
                let res = crate::platform::elevation::run_elevated(&child_args, Some(&temp_file));
                elev_progress.finish();
                let _ = std::fs::remove_file(&temp_file);

                match res {
                    crate::platform::elevation::ElevationResult::Success { exit_code, output } => {
                        if exit_code == 0 {
                            if output.trim().is_empty() {
                                let _ = writeln!(
                                    out,
                                    "Applied changes successfully in elevated session."
                                );
                            } else {
                                let _ = write!(out, "{output}");
                            }
                        } else {
                            if output.trim().is_empty() {
                                let _ = writeln!(
                                    err,
                                    "privr: elevated process failed with exit code {exit_code}."
                                );
                            } else {
                                let _ = write!(err, "{output}");
                            }
                        }
                        let _ = out.flush();
                        let _ = err.flush();
                        return exit_code;
                    }
                    crate::platform::elevation::ElevationResult::Cancelled => {
                        let _ = writeln!(err, "privr: elevation request was cancelled by user.");
                        return 1;
                    }
                    crate::platform::elevation::ElevationResult::Failed(reason) => {
                        let _ = writeln!(
                            err,
                            "privr: elevation failed: {reason}. Run privr as Administrator to apply machine-scope changes."
                        );
                        return 4;
                    }
                }
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let timestamp = crate::report::format_rfc3339_utc(std::time::SystemTime::now());
            let tx_id = format!("tx-{}-{}", now.as_secs(), now.subsec_millis());
            let profile_name = if let Some(pol) = &loaded_policy {
                format!("custom (extends {})", pol.extends)
            } else if let Some(w) = workload {
                format!("workload:{}", w.as_str())
            } else {
                profile_val.as_str().to_owned()
            };
            let mut journal = crate::journal::TransactionJournal {
                schema: crate::journal::JOURNAL_SCHEMA,
                cleanup: None,
                transaction_id: tx_id.clone(),
                timestamp: timestamp.clone(),
                platform: host.platform.as_str().to_owned(),
                profile: profile_name.clone(),
                operations: Vec::new(),
            };

            // Verify journal storage is writable before mutating system state.
            if let Err(e) = crate::journal::save_transaction_in(journal_dir, &journal) {
                let _ = writeln!(
                    err,
                    "privr: failed to initialize transaction journal: {e}. Halting apply."
                );
                return 4;
            }

            let mut unautomated_drift = 0;
            let mut requires_elevation_drift_applied = 0;
            let mut explicit_elevation_failure = None;
            let mut apply_summary = crate::model::outcome::Summary::default();

            let mut apply_progress = ui.spinner_for("Applying privacy remediations...", format);
            for c in &all_controls {
                let matches_control = controls.is_empty()
                    || controls
                        .iter()
                        .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel));
                let matches_section = sections.is_empty()
                    || sections.iter().any(|sec| {
                        c.spec.section.eq_ignore_ascii_case(sec)
                            || c.spec
                                .section
                                .to_ascii_lowercase()
                                .starts_with(&sec.to_ascii_lowercase())
                    });
                if !matches_control || !matches_section {
                    continue;
                }
                if let Some(appr) = &approved_sections
                    && !appr.contains(&c.spec.section)
                {
                    continue;
                }
                let override_opt = loaded_policy
                    .as_ref()
                    .and_then(|pol| pol.controls.get(&c.spec.id));
                let mut spec_clone = c.spec.clone();
                if let Some(ov) = override_opt
                    && let Some(desired_val) = &ov.desired
                {
                    spec_clone.desired = crate::engine::evaluate::SemanticState::new(desired_val);
                }
                let mode = if let Some(ov) = override_opt
                    && let Some(m) = ov.mode
                {
                    m
                } else if !controls.is_empty()
                    || recommended_ids
                        .as_ref()
                        .is_some_and(|recs| recs.contains(&c.spec.id))
                    || (recommended_ids.is_none() && c.spec.min_profile <= profile_val)
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let resolution = if mode == crate::engine::evaluate::Mode::Ignore
                    || spec_clone.applicability.resolve(&host).applies
                        != crate::model::applicability::Applies::Yes
                {
                    crate::engine::evaluate::Resolution::skipped()
                } else {
                    c.observe(&context)
                };
                let today = crate::policy::today_iso();
                let exception = if let Some(pol) = &loaded_policy {
                    if let Some(ex) = pol.exceptions.iter().find(|e| e.control == c.spec.id) {
                        if resolution.state.as_ref().map(|s| s.0.as_str()) == Some(&ex.accepted) {
                            ex.status(&today)
                        } else {
                            crate::model::outcome::Exception::None
                        }
                    } else {
                        crate::model::outcome::Exception::None
                    }
                } else {
                    crate::model::outcome::Exception::None
                };
                let eval = crate::engine::evaluate::evaluate(
                    &spec_clone,
                    mode,
                    &resolution,
                    &host,
                    exception,
                );
                apply_summary.record(&eval);
                if eval.outcome == crate::model::outcome::Outcome::Drift {
                    if eval.exception == crate::model::outcome::Exception::Active {
                        continue;
                    }
                    let is_risk_accepted =
                        force || accept_risk.iter().any(|r| r == "all" || r == &c.spec.id);
                    if !is_interactive
                        && yes
                        && c.spec.friction >= FrictionTier::Tier2WorkflowAltering
                        && !is_risk_accepted
                    {
                        let _ = writeln!(
                            err,
                            "privr: deferring high-friction control '{}': pass --accept-risk {} or --force to apply",
                            c.spec.id, c.spec.id
                        );
                        continue;
                    }
                    if eval.remediation == crate::model::outcome::Remediation::Automatic
                        && c.apply.is_some()
                    {
                        if c.spec.requires_elevation && !is_elevated {
                            if explicit_elevation_required(c, is_elevated, &controls) {
                                explicit_elevation_failure = Some(c.spec.id.clone());
                                break;
                            }
                            requires_elevation_drift_applied += 1;
                            continue;
                        }

                        match c.apply(&context) {
                            Some(Ok(op)) => {
                                journal.operations.push(crate::journal::OperationJournal {
                                    control_id: c.spec.id.clone(),
                                    target_key: op.target_key,
                                    preimage: op.preimage,
                                    postimage: op.postimage,
                                    verified: true,
                                });
                                if let Err(e) =
                                    crate::journal::save_transaction_in(journal_dir, &journal)
                                {
                                    let _ =
                                        write!(out, "{}", verified_block_for(&ui, &journal, None));
                                    let _ = writeln!(
                                        err,
                                        "privr: fatal error writing transaction journal: {e}. Applied {} change(s) (transaction {tx_id}). Halting apply.",
                                        journal.operations.len()
                                    );
                                    return 4;
                                }
                            }
                            Some(Err(e)) => {
                                if !journal.operations.is_empty() {
                                    let _ = write!(
                                        out,
                                        "{}",
                                        verified_block_for(&ui, &journal, Some(&c.spec.id))
                                    );
                                    let _ = writeln!(
                                        err,
                                        "privr: failed to apply {}: {e}. Applied {} prior change(s) (transaction {}). To rollback: privr rollback {}",
                                        c.spec.id,
                                        journal.operations.len(),
                                        tx_id,
                                        tx_id,
                                    );
                                } else {
                                    let _ =
                                        writeln!(err, "privr: failed to apply {}: {e}", c.spec.id);
                                }
                                return 4;
                            }
                            None => {}
                        }
                    } else {
                        unautomated_drift += 1;
                    }
                }
            }
            apply_progress.finish();

            if let Some(failed_id) = explicit_elevation_failure {
                let initial_path = journal_dir.join(format!("{tx_id}.json"));
                let _ = std::fs::remove_file(initial_path);
                let _ = writeln!(
                    err,
                    "privr: failed to apply {failed_id}: applying this control requires administrative privileges (pass --elevate or run as Administrator)"
                );
                return 4;
            }

            if journal.operations.is_empty() {
                let initial_path = journal_dir.join(format!("{tx_id}.json"));
                let _ = std::fs::remove_file(initial_path);
                match format {
                    OutputFormat::Text => {
                        let _ = writeln!(
                            out,
                            "{}",
                            zero_applied_changes_line(
                                requires_elevation_drift_applied,
                                unautomated_drift,
                                &apply_summary,
                            )
                        );
                    }
                    OutputFormat::Json => {
                        let rep = ApplyReport {
                            schema: 1,
                            profile: profile_name,
                            workload,
                            platform: host.platform.as_str().to_owned(),
                            transaction_id: String::new(),
                            applied_changes: 0,
                            unautomated_drift,
                            requires_elevation_drift: requires_elevation_drift_applied,
                        };
                        let _ = serde_json::to_writer_pretty(&mut *out, &rep);
                        let _ = writeln!(out);
                    }
                }
                return 0;
            }

            let apply_report = ApplyReport {
                schema: 1,
                profile: profile_name,
                workload,
                platform: host.platform.as_str().to_owned(),
                transaction_id: tx_id,
                applied_changes: journal.operations.len(),
                unautomated_drift,
                requires_elevation_drift: requires_elevation_drift_applied,
            };

            match format {
                OutputFormat::Text => {
                    let _ = write!(out, "{}", verified_block_for(&ui, &journal, None));
                    if requires_elevation_drift_applied > 0 {
                        let _ = writeln!(
                            out,
                            "\nNote: {} change(s) require administrative privileges (run privr apply --elevate --yes to apply machine-scope changes).",
                            requires_elevation_drift_applied
                        );
                    }
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &apply_report).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            0
        }
        Command::Rollback {
            transaction_id,
            sections,
            yes,
            elevate,
            elevated_output: _,
        } => {
            let transaction_id = match transaction_id {
                Some(id) => id,
                None => {
                    let transactions = crate::journal::list_transactions_in(journal_dir);
                    match transactions.iter().rfind(|tx| !tx.operations.is_empty()) {
                        Some(tx) => tx.transaction_id.clone(),
                        None => {
                            if transactions.is_empty() {
                                let _ = writeln!(
                                    err,
                                    "privr: no reversible transactions; transaction history is empty."
                                );
                            } else {
                                let clean_count = transactions
                                    .iter()
                                    .filter(|tx| tx.profile.starts_with("clean:"))
                                    .count();
                                let _ = writeln!(
                                    err,
                                    "privr: no reversible transactions. {clean_count} cleanup record(s) are recorded; cleanup cannot be rolled back."
                                );
                            }
                            return 5;
                        }
                    }
                }
            };

            if !crate::journal::is_valid_transaction_id(&transaction_id) {
                let _ = writeln!(
                    err,
                    "privr: invalid transaction identifier '{transaction_id}'"
                );
                return 2;
            }

            use std::io::IsTerminal;
            let is_interactive =
                !cli.no_input && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

            if !yes {
                if !is_interactive {
                    let _ = writeln!(
                        err,
                        "privr: no terminal for approval; review with privr history, then run privr rollback {transaction_id} --yes"
                    );
                    return 2;
                }
                let _ = write!(
                    out,
                    "Rollback transaction '{transaction_id}'? [y/N] (Press Enter to cancel): "
                );
                let _ = out.flush();
                let mut input = String::new();
                match interpret_confirmation(
                    std::io::stdin()
                        .read_line(&mut input)
                        .map(|_| input.clone()),
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = writeln!(out, "privr: rollback cancelled by user.");
                        return 0;
                    }
                    Err(code) => {
                        let _ = writeln!(err, "privr: failed to read confirmation input");
                        return code;
                    }
                }
            }

            let journal = match crate::journal::load_transaction_in(journal_dir, &transaction_id) {
                Ok(j) => j,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let _ = writeln!(
                        err,
                        "privr: no transaction record found with ID '{transaction_id}'"
                    );
                    return 2;
                }
                Err(_) => {
                    let _ = writeln!(
                        err,
                        "privr: transaction record '{transaction_id}' is unreadable or unsupported"
                    );
                    return 2;
                }
            };

            if journal.operations.is_empty() {
                if journal.profile.starts_with("clean:") {
                    let _ = writeln!(
                        err,
                        "privr: transaction '{transaction_id}' is an irreversible residue clean and cannot be rolled back."
                    );
                } else {
                    let _ = writeln!(
                        err,
                        "privr: transaction '{transaction_id}' contains no operations to roll back."
                    );
                }
                return 2;
            }

            let host = crate::platform::discover();
            if journal.platform != host.platform.as_str() {
                let _ = writeln!(
                    err,
                    "privr: transaction '{transaction_id}' was recorded on '{}' and cannot be rolled back on '{}'",
                    journal.platform,
                    host.platform.as_str()
                );
                return 2;
            }
            let is_elevated = host.elevated == crate::model::host::Fact::Known(true);
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();

            let matching_ops: Vec<&crate::journal::OperationJournal> = if sections.is_empty() {
                journal.operations.iter().collect()
            } else {
                journal
                    .operations
                    .iter()
                    .filter(|op| {
                        all_controls
                            .iter()
                            .find(|c| c.spec.id == op.control_id)
                            .map(|c| {
                                sections.iter().any(|sec| {
                                    c.spec.section.eq_ignore_ascii_case(sec)
                                        || c.spec
                                            .section
                                            .to_ascii_lowercase()
                                            .starts_with(&sec.to_ascii_lowercase())
                                })
                            })
                            .unwrap_or(false)
                    })
                    .collect()
            };

            if matching_ops.is_empty() {
                if !sections.is_empty() {
                    let _ = writeln!(
                        err,
                        "privr: no operations in transaction '{transaction_id}' match section(s) '{}'",
                        sections.join(", ")
                    );
                } else {
                    let _ = writeln!(
                        err,
                        "privr: transaction '{transaction_id}' contains no operations to roll back."
                    );
                }
                return 2;
            }

            let has_machine_scope = matching_ops.iter().any(|op| {
                all_controls
                    .iter()
                    .find(|c| c.spec.id == op.control_id)
                    .map(|c| c.spec.requires_elevation)
                    .unwrap_or(false)
            });

            if has_machine_scope && !is_elevated {
                let mut perform_elevation = elevate;
                if !perform_elevation && !yes {
                    perform_elevation = true;
                }

                if perform_elevation {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let temp_file = std::env::temp_dir().join(format!(
                        "privr-elev-rb-{}-{}.tmp",
                        std::process::id(),
                        now.as_millis()
                    ));

                    let format_str = match format {
                        OutputFormat::Text => "text",
                        OutputFormat::Json => "json",
                    };
                    let color_str = match cli.color {
                        ColorWhen::Auto => "auto",
                        ColorWhen::Always => "always",
                        ColorWhen::Never => "never",
                    };
                    let mut child_args = vec![
                        "rollback",
                        &transaction_id,
                        "--yes",
                        "--format",
                        format_str,
                        "--color",
                        color_str,
                    ];
                    for sec in &sections {
                        child_args.push("--section");
                        child_args.push(sec);
                    }

                    let mut elev_progress = ui.spinner_for(
                        "Requesting administrative elevation for rollback (UAC prompt)...",
                        format,
                    );
                    let res =
                        crate::platform::elevation::run_elevated(&child_args, Some(&temp_file));
                    elev_progress.finish();
                    let _ = std::fs::remove_file(&temp_file);

                    match res {
                        crate::platform::elevation::ElevationResult::Success {
                            exit_code,
                            output,
                        } => {
                            if exit_code == 0 {
                                if output.trim().is_empty() {
                                    let _ = writeln!(
                                        out,
                                        "Restored changes successfully in elevated session."
                                    );
                                } else {
                                    let _ = write!(out, "{output}");
                                }
                            } else {
                                if output.trim().is_empty() {
                                    let _ = writeln!(
                                        err,
                                        "privr: elevated rollback process failed with exit code {exit_code}."
                                    );
                                } else {
                                    let _ = write!(err, "{output}");
                                }
                            }
                            let _ = out.flush();
                            let _ = err.flush();
                            return exit_code;
                        }
                        crate::platform::elevation::ElevationResult::Cancelled => {
                            let _ =
                                writeln!(err, "privr: elevation request was cancelled by user.");
                            return 1;
                        }
                        crate::platform::elevation::ElevationResult::Failed(reason) => {
                            let _ = writeln!(
                                err,
                                "privr: elevation failed: {reason}. Run privr as Administrator to rollback machine-scope changes."
                            );
                            return 5;
                        }
                    }
                }
            }
            let mut restored = 0;
            let mut restore_progress =
                ui.spinner_for("Restoring previous privacy settings...", format);

            for op in matching_ops.iter().rev() {
                if let Some(c) = all_controls
                    .iter()
                    .find(|item| item.spec.id == op.control_id)
                {
                    match c.rollback(&context, &op.preimage, &op.postimage) {
                        Some(Ok(())) => {
                            restored += 1;
                        }
                        Some(Err(e)) => {
                            let _ = writeln!(
                                err,
                                "privr: conflict during rollback of {}: {e}",
                                c.spec.id
                            );
                            return 5;
                        }
                        None => {}
                    }
                }
            }
            restore_progress.finish();

            let rep = RollbackReport {
                schema: 1,
                transaction_id,
                restored_changes: restored,
            };

            match format {
                OutputFormat::Text => {
                    if sections.is_empty() {
                        let _ = writeln!(
                            out,
                            "Restored {} changes from transaction {}.",
                            rep.restored_changes, rep.transaction_id
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "Restored {} changes in section(s) [{}] from transaction {}.",
                            rep.restored_changes,
                            sections.join(", "),
                            rep.transaction_id
                        );
                    }
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &rep).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            0
        }
        Command::History { purge, yes } => {
            if purge {
                use std::io::IsTerminal;
                let is_interactive = !cli.no_input
                    && std::io::stdin().is_terminal()
                    && std::io::stdout().is_terminal();
                if !yes {
                    if !is_interactive {
                        let _ = writeln!(
                            err,
                            "privr: no terminal for approval; rerun with privr history --purge --yes"
                        );
                        return 2;
                    }
                    let _ = write!(out, "Purge all transaction history records? [y/N]: ");
                    let _ = out.flush();
                    let mut input = String::new();
                    match interpret_confirmation(
                        std::io::stdin()
                            .read_line(&mut input)
                            .map(|_| input.clone()),
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            let _ = writeln!(out, "privr: history purge cancelled.");
                            return 0;
                        }
                        Err(code) => {
                            let _ = writeln!(err, "privr: failed to read confirmation input");
                            return code;
                        }
                    }
                }
                match crate::journal::purge_transactions_in(journal_dir) {
                    Ok(count) => match format {
                        OutputFormat::Text => {
                            let _ = writeln!(out, "Purged {count} transaction history record(s).");
                            0
                        }
                        OutputFormat::Json => {
                            let json = serde_json::json!({
                                "purged": count
                            });
                            let _ = writeln!(out, "{json}");
                            0
                        }
                    },
                    Err(e) => {
                        let _ = writeln!(err, "privr: cannot purge transaction history: {e}");
                        1
                    }
                }
            } else {
                let txs = crate::journal::list_transactions_in(journal_dir);
                match format {
                    OutputFormat::Text => {
                        if txs.is_empty() {
                            let _ = writeln!(
                                out,
                                "No transaction history found. No changes have been applied yet."
                            );
                        } else {
                            let _ =
                                writeln!(out, "Transaction History ({} recorded):\n", txs.len());
                            for tx in txs.iter().rev() {
                                let block = verified_block_for(&ui, tx, None);
                                if block.is_empty() {
                                    if tx.profile.starts_with("clean:") {
                                        let mode_name = tx
                                            .profile
                                            .strip_prefix("clean:")
                                            .unwrap_or(&tx.profile);
                                        let mode_name = if mode_name == "aggressive" {
                                            "thorough"
                                        } else {
                                            mode_name
                                        };
                                        let _ = writeln!(
                                            out,
                                            "{}  disposable residue clean ({})",
                                            ui.paint(crate::ui::style::IDENT, &tx.transaction_id),
                                            mode_name
                                        );
                                        if let Some(cleanup) = &tx.cleanup {
                                            let _ = writeln!(
                                                out,
                                                "          {}",
                                                cleanup.status.as_str()
                                            );
                                            for target in &cleanup.targets {
                                                let not_removed =
                                                    target.files_retained + target.files_denied;
                                                let _ = writeln!(
                                                    out,
                                                    "          {}: {}, {} files removed, {} bytes removed, {} not removed",
                                                    target.id,
                                                    target.status.as_str(),
                                                    target.files_removed,
                                                    target.bytes_removed,
                                                    not_removed
                                                );
                                            }
                                            if cleanup.status
                                                == crate::model::residue::CleanupStatus::Running
                                            {
                                                let _ = writeln!(
                                                    out,
                                                    "          Recorded totals only; an unfinished target may have changed further."
                                                );
                                            }
                                            if let Some(status) = cleanup.trim {
                                                let _ = writeln!(
                                                    out,
                                                    "          hardware TRIM: {}",
                                                    status.as_str()
                                                );
                                            }
                                        } else {
                                            let _ = writeln!(
                                                out,
                                                "          legacy record: completion and removal totals unknown"
                                            );
                                        }
                                    } else {
                                        let _ = writeln!(
                                            out,
                                            "{}  no verified changes",
                                            ui.paint(crate::ui::style::IDENT, &tx.transaction_id)
                                        );
                                    }
                                } else {
                                    let _ = write!(out, "{block}");
                                }
                                let meta = format!(
                                    "{}  profile: {}",
                                    crate::report::format_timestamp_display(&tx.timestamp),
                                    tx.profile
                                );
                                let _ = writeln!(
                                    out,
                                    "{}{}\n",
                                    " ".repeat(10),
                                    ui.paint(crate::ui::style::MUTED, &meta)
                                );
                            }
                            if txs.iter().any(|tx| !tx.operations.is_empty()) {
                                let _ = writeln!(
                                    out,
                                    "To reverse the most recent changes: privr rollback"
                                );
                            } else {
                                let _ = writeln!(
                                    out,
                                    "No reversible transactions are recorded; cleanup cannot be rolled back."
                                );
                            }
                        }
                    }
                    OutputFormat::Json => {
                        if serde_json::to_writer_pretty(&mut *out, &txs).is_ok() {
                            let _ = writeln!(out);
                        }
                    }
                }
                0
            }
        }
        Command::List { platform, query } => {
            // The catalogue a build carries is the platform it was built for.
            // Asking for another one is a question this binary cannot answer,
            // and answering with the local catalogue would be a wrong answer.
            if let Some(requested) = platform
                && requested != Platform::Auto
                && requested.as_str() != crate::model::host::Platform::current().as_str()
            {
                let _ = writeln!(
                    err,
                    "privr: this build carries only {} controls",
                    crate::model::host::Platform::current().as_str()
                );
                return 2;
            }

            let manifest = crate::manifest::Manifest::build(query.as_deref());
            match format {
                OutputFormat::Text => {
                    let _ = write!(out, "{}", manifest.to_text(&ui));
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &manifest).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            0
        }
        Command::Explain { id } => {
            let topic_or_id = id.as_deref().unwrap_or("overview");
            if matches!(
                topic_or_id.to_ascii_lowercase().as_str(),
                "overview" | "score" | "posture" | "critical"
            ) {
                let _ = write!(out, "{}", crate::explain::render_overview(&ui));
                return 0;
            }
            if matches!(
                topic_or_id.to_ascii_lowercase().as_str(),
                "storage" | "trim" | "wipe" | "sanitization" | "ssd"
            ) {
                let _ = write!(out, "{}", crate::explain::render_storage_explanation(&ui));
                return 0;
            }
            if matches!(
                topic_or_id.to_ascii_lowercase().as_str(),
                "residue" | "clean" | "purge" | "forensics" | "cache" | "caches"
            ) {
                let _ = write!(out, "{}", crate::explain::render_residue_explanation(&ui));
                return 0;
            }
            if matches!(
                topic_or_id.to_ascii_lowercase().as_str(),
                "shell" | "history" | "psreadline" | "bash" | "zsh"
            ) {
                let _ = write!(
                    out,
                    "{}",
                    crate::explain::render_shell_history_explanation(&ui)
                );
                return 0;
            }
            match crate::explain::find(topic_or_id) {
                Ok(control) => {
                    let host = crate::platform::discover();
                    let _ = write!(out, "{}", crate::explain::render(&control, &host, &ui));
                    0
                }
                Err(_) => {
                    // A bare failure wastes the caller's next step. Naming close
                    // matches costs nothing and helps a person and an agent alike.
                    let _ = writeln!(err, "privr: no control with the identifier '{topic_or_id}'");
                    let hits = crate::explain::suggestions(topic_or_id);
                    if !hits.is_empty() {
                        let _ = writeln!(
                            err,
                            "
Did you mean:"
                        );
                        for hit in hits {
                            let _ = writeln!(err, "  {hit}");
                        }
                    }
                    let _ = writeln!(
                        err,
                        "
Run privr explain without arguments for the posture overview, or privr list to see every control in this build."
                    );
                    2
                }
            }
        }
        Command::Recommend {
            workload,
            max_friction,
            dimension,
        } => {
            let mut rec_progress = ui.spinner_for(
                "Analyzing posture and computing workload recommendations...",
                format,
            );
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let recommendations = crate::engine::recommend::generate_recommendations(
                &all_controls,
                &context,
                &host,
                workload,
                max_friction,
                dimension,
            );
            rec_progress.finish();

            #[derive(Serialize)]
            struct RecommendReport {
                schema: u8,
                platform: String,
                workload: WorkloadPersona,
                max_friction: Option<FrictionTier>,
                dimension_filter: Option<PostureDimension>,
                recommendations_count: usize,
                recommendations: Vec<crate::model::posture::Recommendation>,
            }

            let report = RecommendReport {
                schema: 1,
                platform: host.platform.as_str().to_owned(),
                workload,
                max_friction,
                dimension_filter: dimension,
                recommendations_count: recommendations.len(),
                recommendations: recommendations.clone(),
            };

            match format {
                OutputFormat::Text => {
                    let labels = [
                        "Command",
                        "Status",
                        "Scope",
                        "Workload",
                        "Max Friction",
                        "Dimension",
                        "Recommendations",
                    ];
                    let width = crate::ui::Ui::label_width(&labels);
                    let row = |label: &str, value: &str| {
                        format!(
                            "{} {}",
                            ui.field(label, width),
                            ui.wrap_after(value, width + 1)
                        )
                    };
                    let _ = writeln!(out, "{}", row("Command", "privr recommend"));
                    let _ = writeln!(out, "{}", row("Status", "recommendation report"));
                    let _ = writeln!(
                        out,
                        "{}",
                        row(
                            "Scope",
                            "full compiled catalogue across profiles; workload and filters apply"
                        )
                    );
                    let _ = writeln!(out, "{}", row("Workload", workload.as_str()));
                    let friction_label = max_friction.map(|f| f.as_str()).unwrap_or("unlimited");
                    let _ = writeln!(out, "{}", row("Max Friction", friction_label));
                    let dim_label = dimension.map(|d| d.as_str()).unwrap_or("all");
                    let _ = writeln!(out, "{}", row("Dimension", dim_label));
                    let _ = writeln!(
                        out,
                        "{}\n",
                        row("Recommendations", &recommendations.len().to_string())
                    );

                    if recommendations.is_empty() {
                        let _ = writeln!(
                            out,
                            "No confirmed drift recommendations matched the workload and filters."
                        );
                        let _ = writeln!(
                            out,
                            "An empty recommendation list is not a compliance result."
                        );
                        let _ =
                            writeln!(out, "Run privr check to see what couldn't be established.");
                    } else {
                        for rec in &recommendations {
                            let friction_badge = ui.paint(
                                match rec.friction_tier {
                                    FrictionTier::Tier0Transparent => {
                                        crate::ui::style::outcome_style(
                                            crate::model::outcome::Outcome::Pass,
                                        )
                                    }
                                    FrictionTier::Tier1Cosmetic => crate::ui::style::MUTED,
                                    FrictionTier::Tier2WorkflowAltering => crate::ui::style::CAVEAT,
                                    FrictionTier::Tier3IncompatibleOrTradeoff => {
                                        crate::ui::style::outcome_style(
                                            crate::model::outcome::Outcome::Drift,
                                        )
                                    }
                                },
                                &format!("[{}]", rec.friction_tier.as_str()),
                            );
                            let _ = writeln!(
                                out,
                                "{}  {} ({})",
                                friction_badge, rec.title, rec.control_id
                            );
                            let _ = writeln!(out, "    Dimension:  {}", rec.dimension.as_str());
                            let _ = writeln!(out, "    Section:    {}", rec.section);
                            let _ = writeln!(
                                out,
                                "    State:      current: {}, desired: {}",
                                rec.current_state, rec.desired_state
                            );
                            let _ = writeln!(
                                out,
                                "    Rationale:  {}",
                                ui.wrap_after(&rec.rationale, 16)
                            );
                            if let Some(tradeoff) = &rec.tradeoff {
                                let _ = writeln!(
                                    out,
                                    "    Trade-off:  {}",
                                    ui.wrap_after(tradeoff, 16)
                                );
                            }
                            let _ = writeln!(out);
                        }
                        let _ = writeln!(
                            out,
                            "Run privr plan to review eligible changes before applying."
                        );
                    }
                    let _ = writeln!(
                        out,
                        "Unknown, unchecked, and filtered controls do not establish compliance. Run privr check for the selected profile's completeness and outcomes."
                    );
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &report).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            0
        }
        Command::Simulate {
            profile,
            policy,
            controls,
            sections,
        } => {
            let all_controls = crate::catalog::all();
            if !validate_control_selectors(&controls, &all_controls, err) {
                return 2;
            }
            let loaded_policy = if let Some(path) = &policy {
                match crate::policy::CustomPolicy::from_file(path) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        let _ = writeln!(err, "{e}");
                        return 2;
                    }
                }
            } else {
                None
            };

            let mut sim_progress =
                ui.spinner_for("Simulating counterfactual posture changes...", format);
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let simulation = if let Some(pol) = &loaded_policy {
                crate::engine::simulate::simulate_with_policy(
                    &all_controls,
                    &context,
                    &host,
                    pol,
                    &controls,
                    &sections,
                )
            } else {
                crate::engine::simulate::simulate_profile(
                    &all_controls,
                    &context,
                    &host,
                    profile.unwrap_or(Profile::Baseline),
                    &controls,
                    &sections,
                )
            };
            sim_progress.finish();

            #[derive(Serialize)]
            struct SimulateReport {
                schema: u8,
                platform: String,
                profile: String,
                simulated_changes: usize,
                unautomated_drift: usize,
                current_posture: crate::model::posture::PostureVector,
                simulated_posture: crate::model::posture::PostureVector,
                friction_breakdown: std::collections::BTreeMap<String, usize>,
                pending_restart_required: bool,
                pending_signout_required: bool,
                simulated_control_ids: Vec<String>,
            }

            let report = SimulateReport {
                schema: 1,
                platform: host.platform.as_str().to_owned(),
                profile: simulation.profile.clone(),
                simulated_changes: simulation.simulated_changes,
                unautomated_drift: simulation.unautomated_drift,
                current_posture: simulation.current_posture.clone(),
                simulated_posture: simulation.simulated_posture.clone(),
                friction_breakdown: simulation.friction_breakdown.clone(),
                pending_restart_required: simulation.pending_restart_required,
                pending_signout_required: simulation.pending_signout_required,
                simulated_control_ids: simulation.simulated_control_ids.clone(),
            };

            match format {
                OutputFormat::Text => {
                    let field =
                        |name: &str| ui.paint(crate::ui::style::MUTED, &format!("{name:<20}"));
                    let _ = writeln!(out, "{}privr simulate", field("Command"));
                    let _ = writeln!(out, "{}simulation report (counterfactual)", field("Status"));
                    let _ = writeln!(out, "{}{}", field("Target Profile"), simulation.profile);
                    let _ = writeln!(
                        out,
                        "{}{}",
                        field("Simulated Changes"),
                        simulation.simulated_changes
                    );
                    if simulation.unautomated_drift > 0 {
                        let _ = writeln!(
                            out,
                            "{}{}",
                            field("Unautomated Drift"),
                            simulation.unautomated_drift
                        );
                    }
                    let _ = writeln!(out);

                    let _ = writeln!(
                        out,
                        "{}",
                        ui.paint(crate::ui::style::HEADING, "Posture Comparison")
                    );
                    let _ = writeln!(
                        out,
                        "  {:<26}  {:<16}  {:<16}",
                        "Dimension", "Current (c/d/c)", "Projected (c/d/c)"
                    );
                    for (dim, cur) in &simulation.current_posture.dimensions {
                        let sim = simulation
                            .simulated_posture
                            .dimensions
                            .get(dim)
                            .copied()
                            .unwrap_or_default();
                        let cur_str = format!("{}/{}/{}", cur.compliant, cur.drift, cur.concealed);
                        let sim_str = format!("{}/{}/{}", sim.compliant, sim.drift, sim.concealed);
                        let _ = writeln!(
                            out,
                            "  {:<26}  {:<16}  {:<16}",
                            dim.display_name(),
                            cur_str,
                            sim_str
                        );
                    }
                    let _ = writeln!(out, "\n  c/d/c = compliant / drift / could not tell");

                    if !simulation.friction_breakdown.is_empty() {
                        let _ = writeln!(
                            out,
                            "\n{}",
                            ui.paint(crate::ui::style::HEADING, "Friction Breakdown")
                        );
                        for (tier, count) in &simulation.friction_breakdown {
                            let _ = writeln!(out, "  {:<32} {}", tier, count);
                        }
                    }

                    if simulation.pending_restart_required || simulation.pending_signout_required {
                        let _ = writeln!(
                            out,
                            "\n{}",
                            ui.paint(crate::ui::style::HEADING, "Session Requirements")
                        );
                        if simulation.pending_restart_required {
                            let _ = writeln!(out, "  System restart required: yes");
                        }
                        if simulation.pending_signout_required {
                            let _ = writeln!(out, "  User sign-out required: yes");
                        }
                    }

                    if simulation.simulated_changes > 0 {
                        let _ = writeln!(
                            out,
                            "\nCounterfactual projection only (machine state unchanged). To apply: privr apply --profile {} --yes",
                            simulation.profile
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "\nNo candidate changes for simulation under current filters."
                        );
                    }
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &report).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            0
        }
        Command::Doctor => {
            let host = crate::platform::discover();
            let report = crate::doctor::diagnose_with_storage(&host, journal_dir);
            match format {
                OutputFormat::Text => {
                    let _ = write!(out, "{}", report.to_text(&ui));
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &report).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            if report.healthy { 0 } else { 3 }
        }
        Command::Mcp { allow_apply } => {
            let stdin = std::io::stdin();
            let reader = stdin.lock();
            crate::mcp::run_stdio(allow_apply, reader, out, err)
        }
        Command::Clean {
            polite,
            preview,
            dry_run,
            yes,
            categories,
            controls,
            accept_risks,
            trim,
        } => {
            let is_preview_mode = preview || dry_run;
            let mode = if polite {
                crate::model::residue::PurgeMode::Polite
            } else {
                crate::model::residue::PurgeMode::Aggressive
            };

            let trim_status = if trim {
                Some(crate::platform::check_volume_trim_support())
            } else {
                None
            };

            if let Err(msg) =
                crate::catalog::residue::validate_residue_selectors(&controls, &categories)
            {
                let _ = writeln!(err, "privr: {msg}");
                return 2;
            }

            let target_specs =
                crate::catalog::residue::select_residue_targets(mode, &controls, &categories);
            if target_specs.is_empty() && !trim {
                let _ = writeln!(err, "privr: no matching residue targets found.");
                return 2;
            }

            if let Err(reason) = crate::platform::validate_residue_roots(&target_specs) {
                let _ = writeln!(err, "privr: {reason}");
                return 5;
            }

            // Check for required risk acknowledgements
            for (spec, selected, _) in &target_specs {
                if *selected && spec.requires_risk_ack && !accept_risks.contains(&spec.id) {
                    let _ = writeln!(
                        err,
                        "privr: target '{}' requires explicit acknowledgement via --accept-risk {}",
                        spec.id, spec.id
                    );
                    return 2;
                }
            }

            // Inspect all targets
            let mut preview_items = Vec::new();
            for (spec, selected, reason) in &target_specs {
                let preview_item =
                    crate::platform::inspect_residue_target(spec, *selected, reason.clone());
                preview_items.push(preview_item);
            }

            let ui = crate::ui::Ui::for_stdout(cli.color.into());

            // If preview requested or noninteractive without --yes
            let is_terminal = !cli.no_input && std::io::stdin().is_terminal();
            let is_dry_run = is_preview_mode || (!yes && !is_terminal);

            if is_dry_run {
                match cli.format {
                    OutputFormat::Json => {
                        let report = crate::model::residue::PurgeReport {
                            schema: 1,
                            mode,
                            dry_run: true,
                            status: None,
                            transaction_id: None,
                            journal_error: None,
                            total_files_affected: preview_items
                                .iter()
                                .filter(|i| i.selected)
                                .map(|i| i.file_count)
                                .sum(),
                            total_bytes_affected: preview_items
                                .iter()
                                .filter(|i| i.selected)
                                .map(|i| i.size_bytes)
                                .sum(),
                            items: preview_items
                                .iter()
                                .filter(|i| i.selected)
                                .map(|i| crate::model::residue::ResiduePurgeItem {
                                    id: i.id.clone(),
                                    title: i.title.clone(),
                                    category: i.category,
                                    trade_off: i.trade_off.clone(),
                                    files_removed: i.file_count,
                                    bytes_reclaimed: i.size_bytes,
                                    files_retained: 0,
                                    files_denied: 0,
                                    error: None,
                                })
                                .collect(),
                            trim: trim_status,
                        };
                        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                        let _ = writeln!(out, "{}", json);
                    }
                    OutputFormat::Text => {
                        let rendered = crate::report::render_purge_preview(
                            &ui,
                            mode,
                            &preview_items,
                            trim_status.as_ref(),
                        );
                        let _ = write!(out, "{}", rendered);
                        if !is_preview_mode {
                            let _ = writeln!(
                                out,
                                "\nRun with --yes to execute clean, or confirm interactively."
                            );
                        }
                    }
                }
                return 0;
            }

            // Interactive confirmation if not --yes
            if !yes && is_terminal {
                let rendered = crate::report::render_purge_preview(
                    &ui,
                    mode,
                    &preview_items,
                    trim_status.as_ref(),
                );
                let _ = write!(out, "{}", rendered);

                let selected_count = preview_items.iter().filter(|i| i.selected).count();
                if selected_count == 0 && !trim {
                    let _ = writeln!(out, "Nothing to clean in selected scope.");
                    return 0;
                }

                let prompt_text = if selected_count == 0 && trim {
                    "\nIssue hardware TRIM to SSD? [y/N]: "
                } else if trim {
                    "\nPermanently clean selected residue and issue hardware TRIM? [y/N]: "
                } else {
                    "\nPermanently clean selected residue? [y/N]: "
                };
                let _ = write!(out, "{}", prompt_text);
                let _ = out.flush();

                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_err()
                    || !interpret_confirmation(Ok(input)).unwrap_or(false)
                {
                    let _ = writeln!(out, "Cleaning cancelled.");
                    return 0;
                }
                let _ = writeln!(out);
            }

            let selected: Vec<_> = target_specs
                .into_iter()
                .filter_map(|(spec, selected, _)| selected.then_some(spec))
                .collect();
            if selected.is_empty() && !trim {
                match cli.format {
                    OutputFormat::Json => {
                        let report = crate::model::residue::PurgeReport {
                            schema: 1,
                            mode,
                            dry_run: false,
                            status: Some(crate::model::residue::CleanupStatus::Completed),
                            transaction_id: None,
                            journal_error: None,
                            total_files_affected: 0,
                            total_bytes_affected: 0,
                            items: Vec::new(),
                            trim: None,
                        };
                        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                        let _ = writeln!(out, "{}", json);
                    }
                    OutputFormat::Text => {
                        let _ = writeln!(out, "Nothing to clean in selected scope.");
                    }
                }
                return 0;
            }
            let report = match crate::cleanup::execute(mode, &selected, trim, journal_dir) {
                Ok(report) => report,
                Err(reason) => {
                    let _ = writeln!(err, "privr: {reason}");
                    return 5;
                }
            };
            let exit_code =
                if report.status == Some(crate::model::residue::CleanupStatus::Completed) {
                    0
                } else {
                    4
                };

            match cli.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                    let _ = writeln!(out, "{}", json);
                }
                OutputFormat::Text => {
                    let rendered = crate::report::render_purge_report(
                        &ui,
                        &report,
                        report.transaction_id.as_deref(),
                    );
                    let _ = write!(out, "{}", rendered);
                }
            }

            exit_code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_analytics_cli_keeps_the_selected_scope_unknown() {
        use clap::Parser;
        let host = crate::model::host::HostFacts::unknown(crate::model::host::Platform::Macos);
        let context = crate::catalog::Context { host: &host };
        for format in ["text", "json"] {
            let cli = Cli::try_parse_from([
                "privr",
                "--color",
                "never",
                "--format",
                format,
                "check",
                "--control",
                "macos.analytics.share-mac",
                "--all",
            ])
            .unwrap();
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                run_with_check_context(
                    cli,
                    &mut out,
                    &mut err,
                    std::path::Path::new("unused-read-only-check"),
                    Some(&context),
                ),
                3,
            );
            assert!(err.is_empty());
            if format == "json" {
                let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
                assert_eq!(report["complete"], false);
                assert_eq!(report["summary"]["unknown"], 1);
                assert_eq!(report["summary"]["pass"], 0);
                assert_eq!(report["results"][0]["management_source"], "unknown");
            } else {
                let text = String::from_utf8(out).unwrap();
                assert!(text.contains("unverified"));
                assert!(
                    !text.contains("All evaluated controls in the selected scope match policy")
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue18_cli_file_only_storage_is_incomplete() {
        use crate::platform::linux::systemd::ConfigurationFamily;
        use clap::Parser;
        for (family, selector, bytes) in [
            (
                ConfigurationFamily::Coredump,
                "systemd.coredump",
                b"[Coredump]\nStorage=none\n".as_slice(),
            ),
            (
                ConfigurationFamily::Journald,
                "systemd.journald",
                b"[Journal]\nStorage=volatile\n".as_slice(),
            ),
        ] {
            let host = crate::test_context::host("arch", "hyprland");
            let reader = crate::test_context::configuration_reader(family, bytes);
            let context = crate::test_context::context(&host, &reader);
            for format in ["text", "json"] {
                let cli = Cli::try_parse_from([
                    "privr",
                    "--color",
                    "never",
                    "--format",
                    format,
                    "check",
                    "--control",
                    selector,
                    "--all",
                ])
                .unwrap();
                let mut out = Vec::new();
                let mut err = Vec::new();
                assert_eq!(
                    run_with_check_context(
                        cli,
                        &mut out,
                        &mut err,
                        std::path::Path::new("unused-read-only-check"),
                        Some(&context)
                    ),
                    3
                );
                assert!(err.is_empty());
                if format == "json" {
                    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
                    assert_eq!(value["complete"], false);
                    assert_eq!(value["summary"]["unknown"], 1);
                    assert!(
                        value["results"][0]["note"]
                            .as_str()
                            .unwrap()
                            .contains("Loaded storage is unverified")
                    );
                } else {
                    let text = String::from_utf8(out).unwrap();
                    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                    assert!(text.contains("Configured intent"));
                    assert!(text.contains("Loaded storage is unverified"));
                    assert!(text.contains(if family == ConfigurationFamily::Coredump {
                        "temporary writes"
                    } else {
                        "existing history"
                    }));
                    assert!(!text.contains("Machine is compliant"));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_cli_default_and_aliases_use_compiled_unevaluated_scope() {
        use clap::Parser;
        let host = crate::test_context::host("arch", "hyprland");
        let reader = crate::test_context::reader([]);
        let context = crate::test_context::context(&host, &reader);
        for command in [
            None,
            Some("check"),
            Some("status"),
            Some("audit"),
            Some("scan"),
        ] {
            for format in ["json", "text"] {
                let mut argv = vec!["privr", "--color", "never", "--format", format];
                if let Some(command) = command {
                    argv.push(command);
                }
                let cli = Cli::try_parse_from(argv).unwrap();
                let mut out = Vec::new();
                let mut err = Vec::new();
                let code = run_with_check_context(
                    cli,
                    &mut out,
                    &mut err,
                    std::path::Path::new("unused-read-only-check"),
                    Some(&context),
                );
                assert_eq!(code, 3, "{command:?}/{format}");
                assert!(err.is_empty());
                if format == "json" {
                    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
                    assert_eq!(value["complete"], false);
                    assert_eq!(value["summary"]["not_selected"], 7);
                    assert_eq!(value["summary"]["unknown"], 3);
                    assert_eq!(value["summary"]["not_applicable"], 7);
                } else {
                    let text = String::from_utf8(out).unwrap();
                    assert!(text.contains("No controls were evaluated"));
                    assert!(text.contains("privr list"));
                    assert!(matches!(
                        Cli::try_parse_from(["privr", "list"]).unwrap().command,
                        Some(Command::List { .. })
                    ));
                    assert!(!text.contains("Machine is compliant"));
                }
            }
        }
        assert!(reader.requested().is_empty());
        assert!(reader.requested_configurations().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_cli_selected_pass_drift_and_visibility_loss_keep_real_exit_codes() {
        use clap::Parser;
        let cases = [
            (Some(crate::test_context::fstrim_enabled()), 0),
            (Some(crate::test_context::fstrim_disabled()), 1),
            (None, 3),
        ];
        for (entries, expected) in cases {
            let host = crate::test_context::host("arch", "hyprland");
            let reader = crate::test_context::reader(entries.unwrap_or_default());
            let context = crate::test_context::context(&host, &reader);
            for format in ["json", "text"] {
                let cli = Cli::try_parse_from([
                    "privr",
                    "--color",
                    "never",
                    "--format",
                    format,
                    "check",
                    "--control",
                    "systemd.fstrim",
                    "--section",
                    "SYS",
                    "--all",
                ])
                .unwrap();
                let mut out = Vec::new();
                let mut err = Vec::new();
                assert_eq!(
                    run_with_check_context(
                        cli,
                        &mut out,
                        &mut err,
                        std::path::Path::new("unused-read-only-check"),
                        Some(&context)
                    ),
                    expected,
                    "{format} exit"
                );
                assert!(err.is_empty());
                if format == "json" {
                    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
                    assert_eq!(value["complete"], expected != 3);
                    assert_eq!(value["results"].as_array().unwrap().len(), 1);
                    assert_eq!(value["carried"], 17);
                }
            }
        }
    }

    /// Collapse whitespace so assertions are not coupled to column padding.
    fn flatten(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn run_for_test(command: Option<Command>) -> (i32, String, String) {
        assert!(
            !matches!(
                command,
                Some(Command::Apply {
                    dry_run: false,
                    yes: true,
                    ..
                })
            ),
            "unit tests must not apply live controls"
        );
        let directory = crate::journal::TestDirectory::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_journal_dir(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Text,
                no_input: false,
                command,
            },
            &mut stdout,
            &mut stderr,
            &directory.0,
        );
        (
            code,
            String::from_utf8(stdout).expect("stdout is UTF-8"),
            String::from_utf8(stderr).expect("stderr is UTF-8"),
        )
    }

    #[test]
    fn the_default_command_checks_this_machine() {
        let (code, stdout, stderr) = run_for_test(None);

        assert!(stderr.is_empty());
        assert!(flatten(&stdout).contains("Profile baseline"));
        // 0 clean, 1 drift, 3 incomplete. Anything else means the report did
        // not decide, which it always must.
        assert!(matches!(code, 0 | 1 | 3), "unexpected exit code {code}");
    }

    #[test]
    fn a_custom_policy_file_fails_closed_rather_than_substituting_a_profile() {
        // Silently evaluating the built-in profile would answer a question the
        // operator did not ask, and report it as though they had.
        let (code, stdout, stderr) = run_for_test(Some(Command::Check {
            profile: None,
            policy: Some("laptop.toml".into()),
            workload: None,
            controls: Vec::new(),
            sections: Vec::new(),
            all: false,
            compare: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("failed to read policy file"));
    }

    #[test]
    fn apply_requires_explicit_consent() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Apply {
            profile: Some(Profile::Baseline),
            workload: None,
            max_friction: None,
            policy: None,
            dry_run: false,
            yes: false,
            interactive_sections: false,
            accept_risk: Vec::new(),
            force: false,
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("no terminal for approval"));
        assert!(stderr.contains("privr apply --yes"));
    }

    #[test]
    fn plan_is_safe_and_reports_planned_changes() {
        let control_id = if cfg!(windows) {
            "windows.advertising.id"
        } else if cfg!(target_os = "macos") {
            "macos.analytics.share-mac"
        } else {
            "debian.popularity-contest.participation"
        };
        let (code, stdout, _) = run_for_test(Some(Command::Plan {
            profile: Some(Profile::Baseline),
            workload: None,
            max_friction: None,
            policy: None,
            controls: vec![control_id.to_owned()],
            sections: Vec::new(),
        }));
        assert_eq!(code, 0);
        assert!(stdout.contains("Profile"));
        assert!(stdout.contains("Planned changes"));
    }

    #[test]
    fn apply_dry_run_aliases_plan() {
        let (code, stdout, _) = run_for_test(Some(Command::Apply {
            profile: Some(Profile::Baseline),
            workload: None,
            max_friction: None,
            policy: None,
            dry_run: true,
            yes: false,
            interactive_sections: false,
            accept_risk: Vec::new(),
            force: false,
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 0);
        assert!(stdout.contains("Profile"));
        assert!(stdout.contains("Planned changes"));
    }

    #[test]
    fn json_output_is_machine_readable() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Json,
                no_input: false,
                command: Some(Command::Doctor),
            },
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let stdout = String::from_utf8(stdout).expect("stdout is UTF-8");
        let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(value["schema"], 1);
        assert_eq!(value["healthy"], true);
    }

    #[test]
    fn explaining_an_unknown_identifier_fails_with_guidance() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Explain {
            id: Some("missing.check".to_owned()),
        }));
        // A usage error, not an incomplete report: the machine was never asked.
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("missing.check"));
        assert!(stderr.contains("privr list"), "no next step offered");
    }

    #[test]
    fn explain_overview_without_arguments_renders_scoring_model() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Explain { id: None }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("privr Posture Model & Critical Controls"));
        assert!(stdout.contains("1. How Posture Is Calculated"));
        assert!(stdout.contains("2. Five Orthogonal Posture Dimensions"));
        assert!(stdout.contains("4. Compiled Controls For This Platform"));
    }

    #[test]
    fn explain_topic_keywords_render_scoring_model() {
        for topic in ["score", "posture", "critical", "overview"] {
            let (code, stdout, stderr) = run_for_test(Some(Command::Explain {
                id: Some(topic.to_owned()),
            }));
            assert_eq!(code, 0, "topic {topic} failed with stderr: {stderr}");
            assert!(stdout.contains("privr Posture Model & Critical Controls"));
        }
    }

    #[test]
    fn explain_known_identifier_succeeds() {
        let control_id = if cfg!(windows) {
            "windows.advertising.id"
        } else if cfg!(target_os = "macos") {
            "macos.analytics.share-mac"
        } else {
            "debian.popularity-contest.participation"
        };
        let (code, stdout, stderr) = run_for_test(Some(Command::Explain {
            id: Some(control_id.to_owned()),
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("Why it matters"));
        assert!(stdout.contains("Evidence"));
    }

    #[test]
    fn check_renders_a_report_header() {
        let (_, stdout, _) = run_for_test(Some(Command::Check {
            profile: Some(Profile::Baseline),
            policy: None,
            workload: None,
            controls: Vec::new(),
            sections: Vec::new(),
            all: true,
            compare: None,
        }));
        let flat = flatten(&stdout);
        assert!(flat.contains("Profile baseline"));
        assert!(flat.contains("Platform"));
        assert!(flat.contains("Coverage"));
    }

    #[test]
    fn confirmed_dry_run_previews_without_applying() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Apply {
            profile: Some(Profile::Baseline),
            workload: None,
            max_friction: None,
            policy: None,
            dry_run: true,
            yes: true,
            interactive_sections: false,
            accept_risk: Vec::new(),
            force: false,
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("Planned changes"));
    }

    #[test]
    fn rollback_requires_confirmation() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: Some("tx-123".to_owned()),
            sections: Vec::new(),
            yes: false,
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("no terminal for approval"));
        assert!(stderr.contains("privr rollback tx-123 --yes"));
    }

    #[test]
    fn rollback_reports_missing_transaction_honestly() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: Some("tx-nonexistent-999".to_owned()),
            sections: Vec::new(),
            yes: true,
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("no transaction record found with ID 'tx-nonexistent-999'"));
    }

    #[test]
    fn rollback_rejects_invalid_transaction_id() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: Some("../escaped".to_owned()),
            sections: Vec::new(),
            yes: true,
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("invalid transaction identifier '../escaped'"));
    }

    #[test]
    fn list_emits_the_capability_manifest_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Json,
                no_input: false,
                command: Some(Command::List {
                    platform: None,
                    query: None,
                }),
            },
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let stdout = String::from_utf8(stdout).expect("stdout is UTF-8");
        let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(
            value["platform"],
            crate::model::host::Platform::current().as_str()
        );
        assert!(value["total"].is_number());
        assert!(value["entries"].is_array());
    }

    #[test]
    fn listing_another_platform_is_refused_rather_than_answered_locally() {
        // A build carries only the platform it was compiled for. Answering with
        // the local catalogue would be a wrong answer to the question asked.
        let other = if cfg!(windows) {
            Platform::Linux
        } else {
            Platform::Windows
        };
        let (code, stdout, stderr) = run_for_test(Some(Command::List {
            platform: Some(other),
            query: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("carries only"));
    }

    #[test]
    fn platform_and_profile_names_are_stable() {
        assert_eq!(Profile::Baseline.as_str(), "baseline");
        assert_eq!(Profile::Strict.as_str(), "strict");
        assert_eq!(Profile::Restrictive.as_str(), "restrictive");
        assert_eq!(Profile::default(), Profile::Baseline);
        assert_eq!(Platform::Auto.as_str(), "auto");
        assert_eq!(Platform::Windows.as_str(), "windows");
        assert_eq!(Platform::Macos.as_str(), "macos");
        assert_eq!(Platform::Linux.as_str(), "linux");
        assert_eq!(Platform::All.as_str(), "all");
    }

    #[test]
    fn plan_reports_planned_or_unautomated_drift() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Plan {
            profile: Some(Profile::Baseline),
            workload: None,
            max_friction: None,
            policy: None,
            controls: Vec::new(),
            sections: Vec::new(),
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("Planned changes:"));
    }

    #[test]
    fn recommend_command_renders_text_and_json() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Recommend {
            workload: WorkloadPersona::Developer,
            max_friction: Some(FrictionTier::Tier1Cosmetic),
            dimension: None,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("privr recommend"));
        assert!(stdout.contains("Workload"));
        assert!(stdout.contains("developer"));
        assert!(stdout.contains("full compiled catalogue across profiles"));
        assert!(
            stdout
                .contains("Unknown, unchecked, and filtered controls do not establish compliance")
        );
        assert!(!stdout.contains("machine matches target posture"));

        // JSON format test
        let mut out = Vec::new();
        let mut err = Vec::new();
        let json_code = run(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Json,
                no_input: false,
                command: Some(Command::Recommend {
                    workload: WorkloadPersona::Creative,
                    max_friction: None,
                    dimension: Some(PostureDimension::ForensicResidue),
                }),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(json_code, 0);
        let val: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(val["schema"], 1);
        assert_eq!(val["workload"], "creative");
        let keys: Vec<_> = val
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "dimension_filter",
                "max_friction",
                "platform",
                "recommendations",
                "recommendations_count",
                "schema",
                "workload"
            ]
        );
    }

    #[test]
    fn simulate_command_renders_text_and_json() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Simulate {
            profile: Some(Profile::Baseline),
            policy: None,
            controls: Vec::new(),
            sections: Vec::new(),
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("privr simulate"));
        assert!(stdout.contains("Posture Comparison"));

        // JSON format test
        let mut out = Vec::new();
        let mut err = Vec::new();
        let json_code = run(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Json,
                no_input: false,
                command: Some(Command::Simulate {
                    profile: Some(Profile::Strict),
                    policy: None,
                    controls: Vec::new(),
                    sections: Vec::new(),
                }),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(json_code, 0);
        let val: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(val["schema"], 1);
        assert_eq!(val["profile"], "strict");
    }

    #[test]
    fn simulate_command_with_custom_policy_evaluates_overrides() {
        let toml = r#"
schema = 1
extends = "baseline"

[controls."windows.advertising.id"]
mode = "enforce"
desired = "disabled"
"#;
        let temp_file =
            std::env::temp_dir().join(format!("privr-sim-policy-test-{}.toml", std::process::id()));
        std::fs::write(&temp_file, toml).expect("write policy");

        let (code, stdout, stderr) = run_for_test(Some(Command::Simulate {
            profile: None,
            policy: Some(temp_file.clone()),
            controls: Vec::new(),
            sections: Vec::new(),
        }));
        let _ = std::fs::remove_file(&temp_file);
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("custom (extends baseline)"));
    }

    #[test]
    fn check_with_sections_filter_limits_scope() {
        let (code, stdout, _) = run_for_test(Some(Command::Check {
            profile: Some(Profile::Baseline),
            policy: None,
            workload: None,
            controls: Vec::new(),
            sections: vec!["advertising".to_owned()],
            all: true,
            compare: None,
        }));
        assert!(matches!(code, 0 | 1 | 3));
        if cfg!(windows) {
            assert!(stdout.contains("windows.advertising.id"));
        }
    }

    #[test]
    fn check_with_workload_evaluates_persona() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Check {
            profile: None,
            policy: None,
            workload: Some(WorkloadPersona::Developer),
            controls: Vec::new(),
            sections: Vec::new(),
            all: false,
            compare: None,
        }));
        assert!(matches!(code, 0 | 1 | 3), "code: {code}, stderr: {stderr}");
        assert!(stdout.contains("workload:developer"));
    }

    #[test]
    fn history_command_renders_text_and_json() {
        let (code, stdout, stderr) = run_for_test(Some(Command::History {
            purge: false,
            yes: false,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(
            stdout.contains("Transaction History")
                || stdout.contains("No transaction history found")
        );

        let directory = crate::journal::TestDirectory::new();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let json_code = run_with_journal_dir(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Json,
                no_input: false,
                command: Some(Command::History {
                    purge: false,
                    yes: false,
                }),
            },
            &mut out,
            &mut err,
            &directory.0,
        );
        assert_eq!(json_code, 0);
        let val: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert!(val.is_array());
    }

    #[test]
    fn history_command_purges_transactions_with_yes() {
        let directory = crate::journal::TestDirectory::new();
        let tx = crate::journal::TransactionJournal {
            schema: crate::journal::JOURNAL_SCHEMA,
            cleanup: None,
            transaction_id: "tx-purge-test".to_owned(),
            timestamp: "2026-10-20T00:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "baseline".to_owned(),
            operations: Vec::new(),
        };
        crate::journal::save_transaction_in(&directory.0, &tx).expect("save tx");
        assert_eq!(crate::journal::list_transactions_in(&directory.0).len(), 1);

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_journal_dir(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Text,
                no_input: false,
                command: Some(Command::History {
                    purge: true,
                    yes: true,
                }),
            },
            &mut out,
            &mut err,
            &directory.0,
        );
        assert_eq!(code, 0);
        let stdout = String::from_utf8(out).expect("utf-8");
        assert!(stdout.contains("Purged 1 transaction history record(s)."));
        assert!(crate::journal::list_transactions_in(&directory.0).is_empty());
    }

    #[test]
    fn rollback_without_transaction_id_reports_empty_isolated_history() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: None,
            sections: Vec::new(),
            yes: true,
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 5);
        assert!(stdout.is_empty());
        assert!(stderr.contains("no reversible transactions; transaction history is empty"));
    }

    #[test]
    fn history_purge_without_yes_refuses_when_not_interactive() {
        let (code, stdout, stderr) = run_for_test(Some(Command::History {
            purge: true,
            yes: false,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(
            stderr.contains(
                "privr: no terminal for approval; rerun with privr history --purge --yes"
            )
        );
    }

    #[test]
    fn rollback_refuses_irreversible_clean_transaction() {
        let directory = crate::journal::TestDirectory::new();
        let clean_tx = crate::journal::TransactionJournal {
            schema: crate::journal::JOURNAL_SCHEMA,
            cleanup: None,
            transaction_id: "clean-123-456".to_owned(),
            timestamp: "2026-11-01T00:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "clean:aggressive".to_owned(),
            operations: Vec::new(),
        };
        crate::journal::save_transaction_in(&directory.0, &clean_tx).expect("save clean tx");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_journal_dir(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Text,
                no_input: false,
                command: Some(Command::Rollback {
                    transaction_id: Some("clean-123-456".to_owned()),
                    sections: Vec::new(),
                    yes: true,
                    elevate: false,
                    elevated_output: None,
                }),
            },
            &mut out,
            &mut err,
            &directory.0,
        );
        assert_eq!(code, 2);
        let stderr = String::from_utf8(err).expect("utf-8");
        assert!(stderr.contains("is an irreversible residue clean and cannot be rolled back"));
    }

    #[test]
    fn rollback_without_id_skips_clean_transactions_to_find_revertible_apply() {
        let directory = crate::journal::TestDirectory::new();
        let apply_tx = crate::journal::TransactionJournal {
            schema: crate::journal::JOURNAL_SCHEMA,
            cleanup: None,
            transaction_id: "tx-apply-1".to_owned(),
            timestamp: "2026-10-01T00:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "baseline".to_owned(),
            operations: vec![crate::journal::OperationJournal {
                control_id: "windows.advertising.id".to_owned(),
                target_key: "HKCU|Software\\Test|Val#native".to_owned(),
                preimage: Some(crate::model::evidence::RawValue::new(
                    crate::model::evidence::ValueKind::U32,
                    vec![1, 0, 0, 0],
                )),
                postimage: crate::model::evidence::RawValue::new(
                    crate::model::evidence::ValueKind::U32,
                    vec![0, 0, 0, 0],
                ),
                verified: true,
            }],
        };
        let clean_tx = crate::journal::TransactionJournal {
            schema: crate::journal::JOURNAL_SCHEMA,
            cleanup: None,
            transaction_id: "clean-recent".to_owned(),
            timestamp: "2026-10-02T00:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "clean:polite".to_owned(),
            operations: Vec::new(),
        };
        crate::journal::save_transaction_in(&directory.0, &apply_tx).expect("save apply tx");
        crate::journal::save_transaction_in(&directory.0, &clean_tx).expect("save clean tx");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let _ = run_with_journal_dir(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Text,
                no_input: false,
                command: Some(Command::Rollback {
                    transaction_id: None,
                    sections: Vec::new(),
                    yes: true,
                    elevate: false,
                    elevated_output: None,
                }),
            },
            &mut out,
            &mut err,
            &directory.0,
        );
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err)
        );
        assert!(combined.contains("tx-apply-1") || combined.contains("windows.advertising.id"));
        assert!(!combined.contains("clean-recent"));
    }

    #[test]
    fn plan_with_workload_and_friction_filters_planned_changes() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Plan {
            profile: None,
            workload: Some(WorkloadPersona::Developer),
            max_friction: Some(FrictionTier::Tier1Cosmetic),
            policy: None,
            controls: Vec::new(),
            sections: Vec::new(),
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(flatten(&stdout).contains("Workload developer"));
        assert!(stdout.contains("Platform"));
    }

    #[test]
    fn apply_with_workload_dry_run_is_safe() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Apply {
            profile: None,
            workload: Some(WorkloadPersona::Developer),
            max_friction: Some(FrictionTier::Tier1Cosmetic),
            policy: None,
            dry_run: true,
            yes: false,
            interactive_sections: false,
            accept_risk: Vec::new(),
            force: false,
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(flatten(&stdout).contains("Workload developer"));
    }

    #[test]
    fn apply_with_workload_and_yes_dry_run_previews() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Apply {
            profile: None,
            workload: Some(WorkloadPersona::Developer),
            max_friction: Some(FrictionTier::Tier0Transparent),
            policy: None,
            dry_run: true,
            yes: true,
            interactive_sections: false,
            accept_risk: Vec::new(),
            force: false,
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("Planned changes"));
        assert!(flatten(&stdout).contains("Workload developer"));
    }

    #[test]
    fn explicit_machine_selection_requires_elevation() {
        let controls = crate::catalog::all();
        let machine = controls
            .iter()
            .find(|c| c.requires_elevation())
            .expect("machine control");
        assert!(explicit_elevation_required(
            machine,
            false,
            std::slice::from_ref(&machine.spec.id)
        ));
        assert!(explicit_elevation_required(
            machine,
            false,
            &[machine
                .spec
                .id
                .split('.')
                .next()
                .expect("platform prefix")
                .to_owned()]
        ));
        assert!(
            !explicit_elevation_required(machine, false, &[]),
            "batch changes defer machine controls"
        );
        assert!(!explicit_elevation_required(
            machine,
            false,
            &["unrelated.control".to_owned()]
        ));
        assert!(!explicit_elevation_required(
            machine,
            true,
            std::slice::from_ref(&machine.spec.id)
        ));
    }

    #[test]
    fn rollback_refuses_unsupported_or_mismatched_journals_before_using_operations() {
        let directory = crate::journal::TestDirectory::new();
        for (schema, stored_id) in [
            (crate::journal::JOURNAL_SCHEMA + 1, "tx-requested"),
            (crate::journal::JOURNAL_SCHEMA, "tx-different"),
        ] {
            let transaction = crate::journal::TransactionJournal {
                schema,
                cleanup: None,
                transaction_id: stored_id.to_owned(),
                timestamp: "2026-10-06T12:00:00Z".to_owned(),
                platform: "windows".to_owned(),
                profile: "baseline".to_owned(),
                operations: Vec::new(),
            };
            let path = directory.0.join("tx-requested.json");
            let bytes = serde_json::to_vec(&transaction).expect("synthetic journal");
            std::fs::write(&path, &bytes).expect("isolated journal");
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run_with_journal_dir(
                Cli {
                    color: crate::cli::ColorWhen::Never,
                    format: OutputFormat::Text,
                    no_input: false,
                    command: Some(Command::Rollback {
                        transaction_id: Some("tx-requested".to_owned()),
                        sections: Vec::new(),
                        yes: true,
                        elevate: false,
                        elevated_output: None,
                    }),
                },
                &mut out,
                &mut err,
                &directory.0,
            );
            assert_eq!(code, 2);
            assert!(out.is_empty());
            assert!(
                String::from_utf8(err)
                    .expect("stderr")
                    .contains("unreadable or unsupported")
            );
            assert_eq!(std::fs::read(&path).expect("preserved journal"), bytes);
        }
    }

    #[test]
    fn confirmation_defaults_to_cancel_and_read_failure_is_usage() {
        assert!(!interpret_confirmation(Ok("\n".to_owned())).expect("empty"));
        assert!(interpret_confirmation(Ok("y\n".to_owned())).expect("yes"));
        assert!(interpret_confirmation(Ok("YES".to_owned())).expect("YES"));
        assert!(!interpret_confirmation(Ok("n".to_owned())).expect("no"));
        assert_eq!(
            interpret_confirmation(Err(std::io::Error::other("closed"))),
            Err(2)
        );
        assert_eq!(
            interpret_approval(Ok("y\n".to_owned())).expect("all"),
            ApprovalChoice::All
        );
        assert_eq!(
            interpret_approval(Ok("s\n".to_owned())).expect("step"),
            ApprovalChoice::Step
        );
        assert_eq!(
            interpret_approval(Ok("step\n".to_owned())).expect("step word"),
            ApprovalChoice::Step
        );
        assert_eq!(
            interpret_approval(Ok("d\n".to_owned())).expect("diff"),
            ApprovalChoice::Diff
        );
        assert_eq!(
            interpret_approval(Ok("diff\n".to_owned())).expect("diff word"),
            ApprovalChoice::Diff
        );
        assert_eq!(
            interpret_approval(Ok("q\n".to_owned())).expect("cancel"),
            ApprovalChoice::Cancel
        );
        assert_eq!(
            interpret_approval(Ok("\n".to_owned())).expect("cancel empty"),
            ApprovalChoice::Cancel
        );

        assert_eq!(
            interpret_section_choice(Ok("y\n".to_owned())).expect("approve"),
            SectionChoice::Approve
        );
        assert_eq!(
            interpret_section_choice(Ok("n\n".to_owned())).expect("skip"),
            SectionChoice::Skip
        );
        assert_eq!(
            interpret_section_choice(Ok("q\n".to_owned())).expect("stop"),
            SectionChoice::StopAndApply
        );
        assert_eq!(
            interpret_section_choice(Ok("\n".to_owned())).expect("skip default"),
            SectionChoice::Skip
        );
        assert_eq!(
            section_stop_line(2, 1),
            "stopped 2 sections applied, 1 deferred"
        );
    }

    #[test]
    fn verified_line_names_the_journal_and_omits_yes() {
        let journal = crate::journal::TransactionJournal {
            schema: crate::journal::JOURNAL_SCHEMA,
            cleanup: None,
            transaction_id: "tx-10-1".to_owned(),
            timestamp: "2026-10-20T00:00:00Z".to_owned(),
            platform: "linux".to_owned(),
            profile: "baseline".to_owned(),
            operations: vec![
                crate::journal::OperationJournal {
                    control_id: "debian.popularity-contest.participation".to_owned(),
                    target_key: "/etc/popularity-contest.conf".to_owned(),
                    preimage: None,
                    postimage: crate::model::evidence::RawValue::new(
                        crate::model::evidence::ValueKind::String,
                        b"PARTICIPATE=\"no\"\n".to_vec(),
                    ),
                    verified: true,
                },
                crate::journal::OperationJournal {
                    control_id: "second.control".to_owned(),
                    target_key: "secret-path".to_owned(),
                    preimage: None,
                    postimage: crate::model::evidence::RawValue::new(
                        crate::model::evidence::ValueKind::String,
                        b"/home/secret-user".to_vec(),
                    ),
                    verified: true,
                },
            ],
        };
        let plain = verified_block_for(&crate::ui::Ui::plain(), &journal, None);
        assert!(plain.contains("verified  2 of 2 changes on Linux, transaction tx-10-1"));
        assert!(plain.contains("undo: privr rollback tx-10-1"));
        assert!(!plain.contains("--yes"));
        assert!(!plain.contains("/home/secret-user"));
        assert!(!plain.contains("secret-path"));
        assert!(!plain.contains('\u{2014}'));

        let partial = verified_block_for(
            &crate::ui::Ui::plain(),
            &journal,
            Some("windows.advertising.id"),
        );
        assert!(partial.contains("verified  2 of 3 changes on Linux"));
        assert!(partial.contains("drift  windows.advertising.id did not verify"));

        let coloured = verified_block_for(&crate::ui::Ui::render(true, false, 60), &journal, None);
        assert!(coloured.contains('\u{1b}'));
        assert!(coloured.contains("privr rollback tx-10-1"));
        assert!(!coloured.contains("--yes"));
    }

    #[test]
    fn history_leads_with_the_verified_line_and_hides_journal_bytes() {
        let directory = crate::journal::TestDirectory::new();
        let transaction = crate::journal::TransactionJournal {
            schema: crate::journal::JOURNAL_SCHEMA,
            cleanup: None,
            transaction_id: "tx-10-2".to_owned(),
            timestamp: "2026-10-20T00:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "baseline".to_owned(),
            operations: vec![crate::journal::OperationJournal {
                control_id: "windows.advertising.id".to_owned(),
                target_key: "HKCU|Software\\SecretUser|Value".to_owned(),
                preimage: None,
                postimage: crate::model::evidence::RawValue::new(
                    crate::model::evidence::ValueKind::U32,
                    vec![0, 0, 0, 0],
                ),
                verified: true,
            }],
        };
        crate::journal::save_transaction_in(&directory.0, &transaction).expect("save");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_journal_dir(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Text,
                no_input: false,
                command: Some(Command::History {
                    purge: false,
                    yes: false,
                }),
            },
            &mut out,
            &mut err,
            &directory.0,
        );
        assert_eq!(code, 0);
        let stdout = String::from_utf8(out).expect("utf-8");
        assert!(stdout.contains("Transaction History"));
        assert!(stdout.contains("verified  1 of 1 changes on Windows, transaction tx-10-2"));
        assert!(stdout.contains("undo: privr rollback tx-10-2"));
        assert!(stdout.contains("2026-10-20 00:00:00 UTC  profile: baseline"));
        assert!(!stdout.contains("SecretUser"));
        assert!(!stdout.contains("HKCU"));
        assert!(!stdout.contains("--yes"));
    }

    #[test]
    fn unknown_control_and_category_selectors_fail_with_exit_code_2_and_write_no_journal() {
        let directory = crate::journal::TestDirectory::new();
        for cmd in [
            Command::Check {
                profile: Some(Profile::Baseline),
                policy: None,
                workload: None,
                controls: vec!["nonexistent.control.id".to_owned()],
                sections: Vec::new(),
                all: false,
                compare: None,
            },
            Command::Plan {
                profile: Some(Profile::Baseline),
                policy: None,
                workload: None,
                max_friction: None,
                controls: vec!["nonexistent.control.id".to_owned()],
                sections: Vec::new(),
            },
            Command::Apply {
                profile: Some(Profile::Baseline),
                policy: None,
                workload: None,
                max_friction: None,
                dry_run: false,
                yes: true,
                interactive_sections: false,
                accept_risk: Vec::new(),
                force: false,
                controls: vec!["nonexistent.control.id".to_owned()],
                sections: Vec::new(),
                elevate: false,
                elevated_output: None,
            },
            Command::Simulate {
                profile: Some(Profile::Baseline),
                policy: None,
                controls: vec!["nonexistent.control.id".to_owned()],
                sections: Vec::new(),
            },
            Command::Clean {
                polite: false,
                preview: true,
                dry_run: false,
                yes: false,
                categories: vec!["bogus".to_owned()],
                controls: Vec::new(),
                accept_risks: Vec::new(),
                trim: false,
            },
            Command::Clean {
                polite: false,
                preview: false,
                dry_run: false,
                yes: true,
                categories: vec!["bogus".to_owned()],
                controls: Vec::new(),
                accept_risks: Vec::new(),
                trim: false,
            },
            Command::Clean {
                polite: false,
                preview: false,
                dry_run: false,
                yes: true,
                categories: Vec::new(),
                controls: vec!["nonexistent.residue.target".to_owned()],
                accept_risks: Vec::new(),
                trim: false,
            },
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run_with_journal_dir(
                Cli {
                    color: crate::cli::ColorWhen::Never,
                    format: OutputFormat::Text,
                    no_input: false,
                    command: Some(cmd),
                },
                &mut out,
                &mut err,
                &directory.0,
            );
            assert_eq!(code, 2);
            assert!(out.is_empty());
            assert!(!err.is_empty());
        }
        assert!(
            crate::journal::list_transactions_in(&directory.0).is_empty(),
            "failed selector validation must never write a transaction journal"
        );
    }

    #[test]
    fn zero_change_plan_and_apply_lines_require_complete_evaluation_before_claiming_compliance() {
        let empty = crate::model::outcome::Summary::default();
        let empty_plan = zero_planned_changes_line(0, &empty);
        assert!(!empty_plan.contains("machine matches policy"));
        assert!(empty_plan.contains("nothing could be evaluated"));

        let empty_apply = zero_applied_changes_line(0, 0, &empty);
        assert!(!empty_apply.contains("Machine matches policy"));
        assert!(empty_apply.contains("nothing could be evaluated"));

        let unknown_only = crate::model::outcome::Summary {
            unknown: 3,
            ..Default::default()
        };
        let unknown_plan = zero_planned_changes_line(0, &unknown_only);
        assert!(!unknown_plan.contains("machine matches policy"));
        assert!(unknown_plan.contains("3 could not be established"));

        let partial = crate::model::outcome::Summary {
            pass: 2,
            unknown: 1,
            ..Default::default()
        };
        let partial_plan = zero_planned_changes_line(0, &partial);
        assert!(!partial_plan.contains("machine matches policy"));
        assert!(partial_plan.contains("2 evaluated, 1 could not be established"));

        let complete_pass = crate::model::outcome::Summary {
            pass: 2,
            ..Default::default()
        };
        assert_eq!(
            zero_planned_changes_line(0, &complete_pass),
            "Planned changes: 0 (machine matches policy)"
        );
        assert_eq!(
            zero_applied_changes_line(0, 0, &complete_pass),
            "No drifted controls to apply. Machine matches policy."
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue52_plan_on_unevaluated_linux_scope_never_claims_machine_matches_policy() {
        let host = crate::test_context::host("arch", "hyprland");
        let reader = crate::test_context::reader([]);
        let context = crate::test_context::context(&host, &reader);
        let directory = crate::journal::TestDirectory::new();
        for cmd in [
            Command::Plan {
                profile: None,
                policy: None,
                workload: None,
                max_friction: None,
                controls: Vec::new(),
                sections: Vec::new(),
            },
            Command::Plan {
                profile: Some(Profile::Strict),
                policy: None,
                workload: None,
                max_friction: None,
                controls: Vec::new(),
                sections: Vec::new(),
            },
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run_with_check_context(
                Cli {
                    color: crate::cli::ColorWhen::Never,
                    format: OutputFormat::Text,
                    no_input: false,
                    command: Some(cmd),
                },
                &mut out,
                &mut err,
                &directory.0,
                Some(&context),
            );
            assert_eq!(code, 0);
            let stdout = String::from_utf8(out).expect("utf-8");
            assert!(
                !stdout.contains("machine matches policy"),
                "unevaluated plan must not claim compliance: {stdout}"
            );
            assert!(stdout.contains("nothing could be evaluated"));
        }
    }
}
