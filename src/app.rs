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
    }) {
        Command::Check {
            profile,
            policy,
            workload,
            controls,
            sections,
            all,
        } => {
            // A custom policy file is not implemented, and silently evaluating
            // the built-in profile instead would answer a question the operator
            // did not ask.
            if policy.is_some() {
                let _ = writeln!(
                    err,
                    "privr: custom policy files are not implemented yet; \
                     omit --policy to use a built-in profile or workload persona"
                );
                return 2;
            }

            let profile_str = if profile.is_none() && workload.is_none() {
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
                let host = crate::platform::discover();
                crate::report::Report::build_filtered_workload(
                    &host,
                    profile_str,
                    workload,
                    &controls,
                    &sections,
                )
            };

            match format {
                OutputFormat::Text => {
                    let _ = write!(out, "{}", report.to_text(&ui, all));
                    let _ = out.flush();

                    // Modern 2026 CLI: In interactive terminal sessions, running default 'privr'
                    // provides an actionable prompt to preview or fix detected drift in-place
                    // without forcing users to re-type one-off commands manually.
                    if is_default_entry
                        && report.summary.drift > 0
                        && std::io::stdin().is_terminal()
                        && std::io::stdout().is_terminal()
                    {
                        let prompt_text = "Action? [y] apply safe fixes, [d] preview diff, [e] explain score & critical items, [q] quit (default: q): ";
                        let _ = write!(out, "{}", ui.paint(crate::ui::style::HEADING, prompt_text));
                        let _ = out.flush();

                        let mut input = String::new();
                        if std::io::stdin().read_line(&mut input).is_ok() {
                            let mut trimmed = input.trim().to_lowercase();
                            if trimmed == "e" || trimmed == "explain" {
                                let overview = crate::explain::render_overview(&ui);
                                let _ = write!(out, "\n{overview}\n");
                                let _ = out.flush();
                                let next_prompt = "Next action? [y] apply safe fixes, [d] preview diff, [q] quit (default: q): ";
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
                                return run(
                                    Cli {
                                        format,
                                        color: cli.color,
                                        command: Some(Command::Apply {
                                            profile,
                                            policy: None,
                                            workload,
                                            max_friction: None,
                                            dry_run: false,
                                            yes: false,
                                            controls,
                                            sections,
                                            elevate: false,
                                            elevated_output: None,
                                        }),
                                    },
                                    out,
                                    err,
                                );
                            } else if trimmed == "d"
                                || trimmed == "diff"
                                || trimmed == "p"
                                || trimmed == "plan"
                            {
                                let plan_code = run(
                                    Cli {
                                        format,
                                        color: cli.color,
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
                                );
                                if plan_code == 0 {
                                    let apply_prompt =
                                        "Apply these changes now? [y/N] (default: N): ";
                                    let _ = write!(
                                        out,
                                        "{}",
                                        ui.paint(crate::ui::style::HEADING, apply_prompt)
                                    );
                                    let _ = out.flush();
                                    let mut plan_input = String::new();
                                    if std::io::stdin().read_line(&mut plan_input).is_ok() {
                                        let plan_trimmed = plan_input.trim().to_lowercase();
                                        if plan_trimmed == "y" || plan_trimmed == "yes" {
                                            return run(
                                                Cli {
                                                    format,
                                                    color: cli.color,
                                                    command: Some(Command::Apply {
                                                        profile,
                                                        policy: None,
                                                        workload,
                                                        max_friction: None,
                                                        dry_run: false,
                                                        yes: false,
                                                        controls,
                                                        sections,
                                                        elevate: false,
                                                        elevated_output: None,
                                                    }),
                                                },
                                                out,
                                                err,
                                            );
                                        }
                                    }
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
            if policy.is_some() {
                let _ = writeln!(
                    err,
                    "privr: custom policy files are not implemented yet; \
                     omit --policy to use a built-in profile or workload persona"
                );
                return 2;
            }
            let mut progress = ui.spinner_for(
                "Evaluating posture and planning eligible remediations...",
                format,
            );
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let (workload, max_friction) = if profile.is_none() && workload.is_none() {
                (
                    Some(WorkloadPersona::General),
                    Some(FrictionTier::Tier1Cosmetic),
                )
            } else {
                (workload, max_friction)
            };
            let profile_val = profile.unwrap_or_default();

            let recommended_ids: Option<std::collections::BTreeSet<String>> = workload.map(|w| {
                crate::engine::recommend::generate_recommendations(
                    &all_controls,
                    &context,
                    &host,
                    w,
                    max_friction,
                    None,
                )
                .into_iter()
                .map(|r| r.control_id)
                .collect()
            });

            let mut planned = Vec::new();
            let mut unautomated_drift = 0;
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
                if let Some(recs) = &recommended_ids
                    && !recs.contains(&c.spec.id)
                {
                    continue;
                }
                let resolution = c.observe(&context);
                let mode = if !controls.is_empty()
                    || recommended_ids.is_some()
                    || c.spec.min_profile <= profile_val
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let eval = crate::engine::evaluate::evaluate(
                    &c.spec,
                    mode,
                    &resolution,
                    &host,
                    crate::model::outcome::Exception::None,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift {
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
                            desired: c.spec.desired.0.clone(),
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

            let profile_name = if let Some(w) = workload {
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
                    if let Some(w) = workload {
                        let _ = writeln!(out, "Workload {}", w.as_str());
                    } else {
                        let _ = writeln!(out, "Profile  {}", plan_report.profile);
                    }
                    let _ = writeln!(out, "Platform {}", plan_report.platform);
                    if plan_report.planned_changes == 0 {
                        if plan_report.unautomated_drift > 0 {
                            let _ = writeln!(
                                out,
                                "Planned changes: 0 (drift exists with no automatic remediation; run privr check to review)"
                            );
                        } else {
                            let _ = writeln!(out, "Planned changes: 0 (machine matches policy)");
                        }
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
                                let _ = writeln!(
                                    out,
                                    "    Details:  {}",
                                    ui.paint(crate::ui::style::MUTED, details)
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
            controls,
            sections,
            elevate,
            elevated_output: _,
        } => {
            if dry_run {
                return run(
                    Cli {
                        format,
                        color: cli.color,
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
                );
            }
            if policy.is_some() {
                let _ = writeln!(
                    err,
                    "privr: custom policy files are not implemented yet; \
                     omit --policy to use a built-in profile or workload persona"
                );
                return 2;
            }

            let (workload, max_friction) = if profile.is_none() && workload.is_none() {
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
            let all_controls = crate::catalog::all();
            let profile_val = profile.unwrap_or_default();

            let recommended_ids: Option<std::collections::BTreeSet<String>> = workload.map(|w| {
                crate::engine::recommend::generate_recommendations(
                    &all_controls,
                    &context,
                    &host,
                    w,
                    max_friction,
                    None,
                )
                .into_iter()
                .map(|r| r.control_id)
                .collect()
            });

            use std::io::IsTerminal;
            let is_interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

            if !yes {
                if !is_interactive {
                    eval_progress.finish();
                    let _ = writeln!(
                        err,
                        "privr: interactive approval is not implemented; pass --yes"
                    );
                    return 2;
                }

                let mut planned_items = Vec::new();
                let mut unautomated_count = 0;
                let mut elevation_count = 0;

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
                    if let Some(recs) = &recommended_ids
                        && !recs.contains(&c.spec.id)
                    {
                        continue;
                    }
                    let resolution = c.observe(&context);
                    let mode = if !controls.is_empty()
                        || recommended_ids.is_some()
                        || c.spec.min_profile <= profile_val
                    {
                        crate::engine::evaluate::Mode::Enforce
                    } else {
                        crate::engine::evaluate::Mode::Ignore
                    };
                    let eval = crate::engine::evaluate::evaluate(
                        &c.spec,
                        mode,
                        &resolution,
                        &host,
                        crate::model::outcome::Exception::None,
                    );
                    if eval.outcome == crate::model::outcome::Outcome::Drift {
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
                                desired: c.spec.desired.0.clone(),
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
                    if unautomated_count > 0 {
                        let _ = writeln!(
                            out,
                            "Planned changes: 0 (drift exists with no automatic remediation; run privr check to review)"
                        );
                    } else {
                        let _ = writeln!(out, "Planned changes: 0 (machine matches policy)");
                    }
                    return 0;
                }

                if let Some(w) = workload {
                    let _ = writeln!(out, "Workload {}", w.as_str());
                } else {
                    let _ = writeln!(out, "Profile  {}", profile_val.as_str());
                }
                let _ = writeln!(out, "Platform {}", host.platform.as_str());
                let _ = writeln!(out, "Planned changes: {}\n", planned_items.len());

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
                        let _ = writeln!(
                            out,
                            "    Details:  {}",
                            ui.paint(crate::ui::style::MUTED, details)
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

                let prompt_msg = format!(
                    "\nApply these {} change(s)? [Y/n] (Press Enter to confirm): ",
                    planned_items.len()
                );
                let _ = write!(out, "{prompt_msg}");
                let _ = out.flush();

                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_err() {
                    let _ = writeln!(err, "privr: failed to read confirmation input");
                    return 1;
                }
                let trimmed = input.trim();
                if !trimmed.is_empty()
                    && !trimmed.eq_ignore_ascii_case("y")
                    && !trimmed.eq_ignore_ascii_case("yes")
                {
                    let _ = writeln!(out, "privr: apply cancelled by user.");
                    return 0;
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
                if let Some(recs) = &recommended_ids
                    && !recs.contains(&c.spec.id)
                {
                    continue;
                }
                if !c.spec.requires_elevation || c.apply.is_none() {
                    continue;
                }
                let resolution = c.observe(&context);
                let mode = if !controls.is_empty()
                    || recommended_ids.is_some()
                    || c.spec.min_profile <= profile_val
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let eval = crate::engine::evaluate::evaluate(
                    &c.spec,
                    mode,
                    &resolution,
                    &host,
                    crate::model::outcome::Exception::None,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift
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
                        .expect("valid value")
                        .get_name()
                        .to_string();
                    child_args.push(&workload_str);
                }
                let friction_str;
                if let Some(f) = max_friction {
                    child_args.push("--max-friction");
                    friction_str = clap::ValueEnum::to_possible_value(&f)
                        .expect("valid value")
                        .get_name()
                        .to_string();
                    child_args.push(&friction_str);
                }
                let profile_str_val;
                if profile.is_some() {
                    child_args.push("--profile");
                    profile_str_val = clap::ValueEnum::to_possible_value(&profile_val)
                        .expect("valid value")
                        .get_name()
                        .to_string();
                    child_args.push(&profile_str_val);
                }
                for c_arg in &controls {
                    child_args.push("--control");
                    child_args.push(c_arg);
                }
                for s_arg in &sections {
                    child_args.push("--section");
                    child_args.push(s_arg);
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
            let timestamp = format!("{}.{:03}", now.as_secs(), now.subsec_millis());
            let tx_id = format!("tx-{}-{}", now.as_secs(), now.subsec_millis());
            let profile_name = if let Some(w) = workload {
                format!("workload:{}", w.as_str())
            } else {
                profile_val.as_str().to_owned()
            };
            let mut journal = crate::journal::TransactionJournal {
                schema: crate::journal::JOURNAL_SCHEMA,
                transaction_id: tx_id.clone(),
                timestamp: timestamp.clone(),
                platform: host.platform.as_str().to_owned(),
                profile: profile_name.clone(),
                operations: Vec::new(),
            };

            // Verify journal storage is writable before mutating system state.
            if let Err(e) = crate::journal::save_transaction(&journal) {
                let _ = writeln!(
                    err,
                    "privr: failed to initialize transaction journal: {e}. Halting apply."
                );
                return 4;
            }

            let mut unautomated_drift = 0;
            let mut requires_elevation_drift_applied = 0;
            let mut explicit_elevation_failure = None;

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
                if let Some(recs) = &recommended_ids
                    && !recs.contains(&c.spec.id)
                {
                    continue;
                }
                let resolution = c.observe(&context);
                let mode = if !controls.is_empty()
                    || recommended_ids.is_some()
                    || c.spec.min_profile <= profile_val
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let eval = crate::engine::evaluate::evaluate(
                    &c.spec,
                    mode,
                    &resolution,
                    &host,
                    crate::model::outcome::Exception::None,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift {
                    if eval.remediation == crate::model::outcome::Remediation::Automatic
                        && c.apply.is_some()
                    {
                        if c.spec.requires_elevation && !is_elevated {
                            if !controls.is_empty()
                                && controls
                                    .iter()
                                    .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel))
                            {
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
                                if let Err(e) = crate::journal::save_transaction(&journal) {
                                    let _ = writeln!(
                                        err,
                                        "privr: fatal error writing transaction journal: {e}. Applied {} change(s) (transaction {}). Halting apply.",
                                        journal.operations.len(),
                                        tx_id
                                    );
                                    return 4;
                                }
                            }
                            Some(Err(e)) => {
                                if !journal.operations.is_empty() {
                                    let _ = writeln!(
                                        err,
                                        "privr: failed to apply {}: {e}. Applied {} prior change(s) (transaction {}). To rollback: privr rollback {} --yes",
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
                let initial_path = crate::journal::transactions_dir().join(format!("{tx_id}.json"));
                let _ = std::fs::remove_file(initial_path);
                let _ = writeln!(
                    err,
                    "privr: failed to apply {failed_id}: applying this control requires administrative privileges (pass --elevate or run as Administrator)"
                );
                return 4;
            }

            if journal.operations.is_empty() {
                let initial_path = crate::journal::transactions_dir().join(format!("{tx_id}.json"));
                let _ = std::fs::remove_file(initial_path);
                match format {
                    OutputFormat::Text => {
                        if requires_elevation_drift_applied > 0 {
                            let _ = writeln!(
                                out,
                                "No user-scope changes to apply ({} change(s) require administrative privileges; pass --elevate or run as Administrator).",
                                requires_elevation_drift_applied
                            );
                        } else if unautomated_drift > 0 {
                            let _ = writeln!(
                                out,
                                "No automated changes to apply (drift exists with no automatic remediation; run privr check to review)."
                            );
                        } else {
                            let _ = writeln!(
                                out,
                                "No drifted controls to apply. Machine matches policy."
                            );
                        }
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
                    let _ = writeln!(
                        out,
                        "Applied {} changes (transaction {}).",
                        apply_report.applied_changes, apply_report.transaction_id
                    );
                    let _ = writeln!(
                        out,
                        "All changes verified. To reverse, run: privr rollback {} --yes",
                        apply_report.transaction_id
                    );
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
            yes,
            elevate,
            elevated_output: _,
        } => {
            let transaction_id = match transaction_id {
                Some(id) => id,
                None => match crate::journal::latest_transaction() {
                    Some(tx) => tx.transaction_id,
                    None => {
                        let _ = writeln!(err, "privr: no transaction history found to roll back.");
                        return 1;
                    }
                },
            };

            use std::io::IsTerminal;
            let is_interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

            if !yes {
                if !is_interactive {
                    let _ = writeln!(
                        err,
                        "privr: interactive approval is not implemented; pass --yes to confirm rollback"
                    );
                    return 2;
                }
                let _ = write!(
                    out,
                    "Rollback transaction '{transaction_id}'? [Y/n] (Press Enter to confirm): "
                );
                let _ = out.flush();
                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_err() {
                    let _ = writeln!(err, "privr: failed to read confirmation input");
                    return 1;
                }
                let trimmed = input.trim();
                if !trimmed.is_empty()
                    && !trimmed.eq_ignore_ascii_case("y")
                    && !trimmed.eq_ignore_ascii_case("yes")
                {
                    let _ = writeln!(out, "privr: rollback cancelled by user.");
                    return 0;
                }
            }

            if !crate::journal::is_valid_transaction_id(&transaction_id) {
                let _ = writeln!(
                    err,
                    "privr: invalid transaction identifier '{transaction_id}'"
                );
                return 2;
            }

            let journal = match crate::journal::load_transaction(&transaction_id) {
                Ok(j) => j,
                Err(_) => {
                    let _ = writeln!(
                        err,
                        "privr: no transaction record found with ID '{transaction_id}'"
                    );
                    return 2;
                }
            };

            let host = crate::platform::discover();
            let is_elevated = host.elevated == crate::model::host::Fact::Known(true);
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();

            let has_machine_scope = journal.operations.iter().any(|op| {
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
                    let child_args = [
                        "rollback",
                        &transaction_id,
                        "--yes",
                        "--format",
                        format_str,
                        "--color",
                        color_str,
                    ];

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

            for op in journal.operations.iter().rev() {
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
                    let _ = writeln!(
                        out,
                        "Restored {} changes from transaction {}.",
                        rep.restored_changes, rep.transaction_id
                    );
                }
                OutputFormat::Json => {
                    if serde_json::to_writer_pretty(&mut *out, &rep).is_ok() {
                        let _ = writeln!(out);
                    }
                }
            }
            0
        }
        Command::History => {
            let txs = crate::journal::list_transactions();
            match format {
                OutputFormat::Text => {
                    if txs.is_empty() {
                        let _ = writeln!(
                            out,
                            "No transaction history found. No changes have been applied yet."
                        );
                    } else {
                        let _ = writeln!(out, "Transaction History ({} recorded):\n", txs.len());
                        for tx in txs.iter().rev() {
                            let _ = writeln!(
                                out,
                                "  {}  [{}]  {} change(s)  profile: {}",
                                ui.paint(crate::ui::style::IDENT, &tx.transaction_id),
                                tx.timestamp,
                                tx.operations.len(),
                                tx.profile
                            );
                        }
                        let _ = writeln!(
                            out,
                            "\nTo reverse the most recent changes: privr undo (or privr rollback)"
                        );
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
                    let field =
                        |name: &str| ui.paint(crate::ui::style::MUTED, &format!("{name:<16}"));
                    let _ = writeln!(out, "{}privr recommend", field("Command"));
                    let _ = writeln!(out, "{}recommendation report", field("Status"));
                    let _ = writeln!(out, "{}{}", field("Workload"), workload.as_str());
                    let friction_label = max_friction.map(|f| f.as_str()).unwrap_or("unlimited");
                    let _ = writeln!(out, "{}{}", field("Max Friction"), friction_label);
                    let dim_label = dimension.map(|d| d.as_str()).unwrap_or("all");
                    let _ = writeln!(out, "{}{}", field("Dimension"), dim_label);
                    let _ = writeln!(
                        out,
                        "{}{}\n",
                        field("Recommendations"),
                        recommendations.len()
                    );

                    if recommendations.is_empty() {
                        let _ = writeln!(
                            out,
                            "No recommendations matching workload and friction constraints (machine matches target posture)."
                        );
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
                            let _ = writeln!(out, "    Rationale:  {}", rec.rationale);
                            if let Some(tradeoff) = &rec.tradeoff {
                                let _ = writeln!(out, "    Trade-off:  {}", tradeoff);
                            }
                            let _ = writeln!(out);
                        }
                        let _ = writeln!(out, "To apply recommended controls, run: privr apply");
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
        Command::Simulate {
            profile,
            controls,
            sections,
        } => {
            let mut sim_progress =
                ui.spinner_for("Simulating counterfactual posture changes...", format);
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let simulation = crate::engine::simulate::simulate_profile(
                &all_controls,
                &context,
                &host,
                profile,
                &controls,
                &sections,
            );
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
                            dim.as_str(),
                            cur_str,
                            sim_str
                        );
                    }

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
            let report = crate::doctor::diagnose(&host);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collapse whitespace so assertions are not coupled to column padding.
    fn flatten(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn run_for_test(command: Option<Command>) -> (i32, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Text,
                command,
            },
            &mut stdout,
            &mut stderr,
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
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("not implemented"));
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
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("pass --yes"));
    }

    #[test]
    fn plan_is_safe_and_reports_planned_changes() {
        let (code, stdout, _) = run_for_test(Some(Command::Plan {
            profile: Some(Profile::Baseline),
            workload: None,
            max_friction: None,
            policy: None,
            controls: vec!["windows.advertising.id".to_owned()],
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
        assert!(stdout.contains("4. Most Critical Privacy & Security Controls"));
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
    fn check_renders_a_report_header() {
        let (_, stdout, _) = run_for_test(Some(Command::Check {
            profile: Some(Profile::Baseline),
            policy: None,
            workload: None,
            controls: Vec::new(),
            sections: Vec::new(),
            all: true,
        }));
        let flat = flatten(&stdout);
        assert!(flat.contains("Profile baseline"));
        assert!(flat.contains("Platform"));
        assert!(flat.contains("Coverage"));
    }

    #[test]
    fn confirmed_apply_reports_clean_state_or_applied() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Apply {
            profile: Some(Profile::Baseline),
            workload: None,
            max_friction: None,
            policy: None,
            dry_run: false,
            yes: true,
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(
            stdout.contains("Machine matches policy")
                || stdout.contains("Applied")
                || stdout.contains("No automated changes to apply")
                || stdout.contains("No user-scope changes to apply")
        );
    }

    #[test]
    fn rollback_requires_confirmation() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: Some("tx-123".to_owned()),
            yes: false,
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("confirm rollback"));
    }

    #[test]
    fn rollback_reports_missing_transaction_honestly() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: Some("tx-nonexistent-999".to_owned()),
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

        // JSON format test
        let mut out = Vec::new();
        let mut err = Vec::new();
        let json_code = run(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Json,
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
    }

    #[test]
    fn simulate_command_renders_text_and_json() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Simulate {
            profile: Profile::Baseline,
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
                command: Some(Command::Simulate {
                    profile: Profile::Strict,
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
    fn check_with_sections_filter_limits_scope() {
        let (code, stdout, _) = run_for_test(Some(Command::Check {
            profile: Some(Profile::Baseline),
            policy: None,
            workload: None,
            controls: Vec::new(),
            sections: vec!["advertising".to_owned()],
            all: true,
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
        }));
        assert!(matches!(code, 0 | 1 | 3), "code: {code}, stderr: {stderr}");
        assert!(stdout.contains("workload:developer"));
    }

    #[test]
    fn history_command_renders_text_and_json() {
        let (code, stdout, stderr) = run_for_test(Some(Command::History));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(
            stdout.contains("Transaction History")
                || stdout.contains("No transaction history found")
        );

        let mut out = Vec::new();
        let mut err = Vec::new();
        let json_code = run(
            Cli {
                color: crate::cli::ColorWhen::Never,
                format: OutputFormat::Json,
                command: Some(Command::History),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(json_code, 0);
        let val: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert!(val.is_array());
    }

    #[test]
    fn rollback_without_transaction_id_handles_missing_or_latest() {
        let (code, _, _) = run_for_test(Some(Command::Rollback {
            transaction_id: None,
            yes: true,
            elevate: false,
            elevated_output: None,
        }));
        // If no transactions exist, exit code 1. If one exists, it attempts rollback.
        assert!(matches!(code, 0 | 1 | 2 | 4));
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
        assert!(stdout.contains("Workload developer"));
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
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(stdout.contains("Workload developer"));
    }

    #[test]
    fn apply_with_workload_and_yes_succeeds() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Apply {
            profile: None,
            workload: Some(WorkloadPersona::Developer),
            max_friction: Some(FrictionTier::Tier0Transparent),
            policy: None,
            dry_run: false,
            yes: true,
            controls: Vec::new(),
            sections: Vec::new(),
            elevate: false,
            elevated_output: None,
        }));
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(
            stdout.contains("Applied")
                || stdout.contains("No user-scope changes to apply")
                || stdout.contains("Machine matches policy")
                || stdout.contains("No automated changes to apply")
        );
    }

    #[test]
    fn unelevated_explicit_machine_control_fails_closed_with_code_4() {
        let host = crate::platform::discover();
        if host.elevated == crate::model::host::Fact::Known(false) {
            let control_id = if cfg!(windows) {
                "windows.security.llmnr".to_owned()
            } else if cfg!(target_os = "macos") {
                "analytics.share-mac".to_owned()
            } else {
                "debian.popularity-contest".to_owned()
            };
            let (code, stdout, stderr) = run_for_test(Some(Command::Apply {
                profile: None,
                workload: None,
                max_friction: None,
                policy: None,
                dry_run: false,
                yes: true,
                controls: vec![control_id],
                sections: Vec::new(),
                elevate: false,
                elevated_output: None,
            }));
            assert_eq!(code, 4, "stdout: {stdout}");
            assert!(stderr.contains("administrative privileges"));
        }
    }
}
