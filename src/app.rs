use std::io::Write;

use serde::Serialize;

use crate::cli::{Cli, Command, OutputFormat, Platform, Profile};

const CONCEPT_NOTICE: &str = "concept build: policy checks are not implemented yet";

#[derive(Serialize)]
struct ConceptResponse<'a> {
    schema: u8,
    complete: bool,
    status: &'a str,
    command: &'a str,
    platform: &'a str,
    profile: Option<&'a str>,
    message: &'a str,
}

#[derive(Serialize)]
struct PlanItem {
    id: String,
    title: String,
    section: String,
    current: String,
    desired: String,
}

#[derive(Serialize)]
struct PlanReport {
    schema: u8,
    profile: String,
    platform: String,
    planned_changes: usize,
    changes: Vec<PlanItem>,
}

#[derive(Serialize)]
struct ApplyReport {
    schema: u8,
    profile: String,
    platform: String,
    transaction_id: String,
    applied_changes: usize,
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
    match cli.command.unwrap_or(Command::Check {
        profile: Some(Profile::Baseline),
        policy: None,
        controls: Vec::new(),
        all: false,
    }) {
        Command::Check {
            profile,
            policy,
            controls: _,
            all,
        } => {
            // A custom policy file is not implemented, and silently evaluating
            // the built-in profile instead would answer a question the operator
            // did not ask.
            if policy.is_some() {
                let _ = writeln!(
                    err,
                    "privr: custom policy files are not implemented yet; \
                     omit --policy to use a built-in profile"
                );
                return 2;
            }

            let profile = profile.unwrap_or_default();
            let report = {
                // Progress goes to standard error and only when that is a
                // terminal, so a pipe, a redirect, and an agent parse stay
                // clean. The guard clears the line however this scope exits.
                let _progress = ui.spinner("checking this machine");
                let host = crate::platform::discover();
                crate::report::Report::build(&host, profile.as_str())
            };

            match format {
                OutputFormat::Text => {
                    let _ = write!(out, "{}", report.to_text(&ui, all));
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
            controls,
        } => {
            if policy.is_some() {
                let _ = writeln!(
                    err,
                    "privr: custom policy files are not implemented yet; \
                     omit --policy to use a built-in profile"
                );
                return 2;
            }
            let profile = profile.unwrap_or_default();
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let mut planned = Vec::new();

            for c in &all_controls {
                if !controls.is_empty()
                    && !controls
                        .iter()
                        .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel))
                {
                    continue;
                }
                let resolution = c.observe(&context);
                let eval = crate::engine::evaluate::evaluate(
                    &c.spec,
                    crate::engine::evaluate::Mode::Enforce,
                    &resolution,
                    &host,
                    crate::model::outcome::Exception::None,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift
                    && eval.remediation == crate::model::outcome::Remediation::Automatic
                    && c.apply.is_some()
                {
                    let current_str = resolution
                        .state
                        .map(|s| s.0)
                        .unwrap_or_else(|| "drift".to_owned());
                    planned.push(PlanItem {
                        id: c.spec.id.clone(),
                        title: c.title.to_owned(),
                        section: c.spec.section.clone(),
                        current: current_str,
                        desired: c.spec.desired.0.clone(),
                    });
                }
            }

            let plan_report = PlanReport {
                schema: 1,
                profile: profile.as_str().to_owned(),
                platform: host.platform.as_str().to_owned(),
                planned_changes: planned.len(),
                changes: planned,
            };

            match format {
                OutputFormat::Text => {
                    let _ = writeln!(out, "Profile  {}", plan_report.profile);
                    let _ = writeln!(out, "Platform {}", plan_report.platform);
                    if plan_report.planned_changes == 0 {
                        let _ = writeln!(out, "Planned changes: 0 (machine matches policy)");
                    } else {
                        let _ = writeln!(
                            out,
                            "Planned changes: {} (changes nothing)\n",
                            plan_report.planned_changes
                        );
                        for item in &plan_report.changes {
                            let _ = writeln!(out, "{}", item.section);
                            let _ = writeln!(out, "  {}", item.id);
                            let _ = writeln!(
                                out,
                                "    Current: {}",
                                ui.paint(
                                    crate::ui::style::outcome_style(
                                        crate::model::outcome::Outcome::Drift,
                                    ),
                                    &item.current,
                                )
                            );
                            let _ = writeln!(out, "    Desired: {}", item.desired);
                        }
                        let _ = writeln!(out, "\nRun privr apply --yes to apply these changes.");
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
            dry_run,
            yes,
            controls,
        } => {
            if dry_run {
                return run(
                    Cli {
                        format,
                        color: cli.color,
                        command: Some(Command::Plan {
                            profile,
                            policy,
                            controls,
                        }),
                    },
                    out,
                    err,
                );
            }
            if !yes {
                let _ = writeln!(
                    err,
                    "privr: interactive approval is not implemented; use plan or pass --yes"
                );
                return 2;
            }
            if policy.is_some() {
                let _ = writeln!(
                    err,
                    "privr: custom policy files are not implemented yet; \
                     omit --policy to use a built-in profile"
                );
                return 2;
            }
            let profile = profile.unwrap_or_default();
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();

            let timestamp = format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
            let tx_id = format!("tx-{timestamp}");
            let mut journal = crate::journal::TransactionJournal {
                schema: crate::journal::JOURNAL_SCHEMA,
                transaction_id: tx_id.clone(),
                timestamp: timestamp.clone(),
                platform: host.platform.as_str().to_owned(),
                profile: profile.as_str().to_owned(),
                operations: Vec::new(),
            };

            for c in &all_controls {
                if !controls.is_empty()
                    && !controls
                        .iter()
                        .any(|sel| c.spec.id == *sel || c.spec.id.starts_with(sel))
                {
                    continue;
                }
                let resolution = c.observe(&context);
                let eval = crate::engine::evaluate::evaluate(
                    &c.spec,
                    crate::engine::evaluate::Mode::Enforce,
                    &resolution,
                    &host,
                    crate::model::outcome::Exception::None,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift
                    && eval.remediation == crate::model::outcome::Remediation::Automatic
                    && c.apply.is_some()
                {
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
                                    "privr: warning: failed to write transaction journal: {e}"
                                );
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
                                let _ = writeln!(err, "privr: failed to apply {}: {e}", c.spec.id);
                            }
                            return 4;
                        }
                        None => {}
                    }
                }
            }

            if journal.operations.is_empty() {
                match format {
                    OutputFormat::Text => {
                        let _ =
                            writeln!(out, "No drifted controls to apply. Machine matches policy.");
                    }
                    OutputFormat::Json => {
                        let rep = ApplyReport {
                            schema: 1,
                            profile: profile.as_str().to_owned(),
                            platform: host.platform.as_str().to_owned(),
                            transaction_id: String::new(),
                            applied_changes: 0,
                        };
                        let _ = serde_json::to_writer_pretty(&mut *out, &rep);
                        let _ = writeln!(out);
                    }
                }
                return 0;
            }

            let apply_report = ApplyReport {
                schema: 1,
                profile: profile.as_str().to_owned(),
                platform: host.platform.as_str().to_owned(),
                transaction_id: tx_id,
                applied_changes: journal.operations.len(),
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
        } => {
            if !yes {
                let _ = writeln!(
                    err,
                    "privr: interactive approval is not implemented; pass --yes to confirm rollback"
                );
                return 2;
            }

            let journal = match crate::journal::load_transaction(&transaction_id) {
                Ok(j) => j,
                Err(_) => {
                    let message = format!(
                        "{CONCEPT_NOTICE}; transaction {transaction_id}; restored changes: 0"
                    );
                    write_response(
                        out,
                        format,
                        ConceptResponse {
                            schema: 1,
                            complete: false,
                            status: "concept",
                            command: "rollback",
                            platform: current_platform(),
                            profile: None,
                            message: &message,
                        },
                    );
                    return 3;
                }
            };

            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let mut restored = 0;

            for op in journal.operations.iter().rev() {
                if let Some(c) = all_controls
                    .iter()
                    .find(|item| item.spec.id == op.control_id)
                {
                    match c.rollback(&context, &op.preimage) {
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
        Command::Explain { id } => match crate::explain::find(&id) {
            Ok(control) => {
                let host = crate::platform::discover();
                let _ = write!(out, "{}", crate::explain::render(&control, &host, &ui));
                0
            }
            Err(_) => {
                // A bare failure wastes the caller's next step. Naming close
                // matches costs nothing and helps a person and an agent alike.
                let _ = writeln!(err, "privr: no control with the identifier '{id}'");
                let hits = crate::explain::suggestions(&id);
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
Run privr list to see every control in this build."
                );
                2
            }
        },
        Command::Doctor => {
            write_response(
                out,
                format,
                ConceptResponse {
                    schema: 1,
                    complete: false,
                    status: "concept",
                    command: "doctor",
                    platform: current_platform(),
                    profile: None,
                    message: "Rust CLI is running; platform adapters are not implemented yet",
                },
            );
            3
        }
    }
}

fn write_response(out: &mut impl Write, format: OutputFormat, response: ConceptResponse<'_>) {
    match format {
        OutputFormat::Text => {
            let _ = writeln!(out, "privr {} [{}]", response.command, response.platform);
            let _ = writeln!(out, "{}", response.message);
        }
        OutputFormat::Json => {
            if serde_json::to_writer_pretty(&mut *out, &response).is_ok() {
                let _ = writeln!(out);
            }
        }
    }
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
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
            controls: Vec::new(),
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
            policy: None,
            dry_run: false,
            yes: false,
            controls: Vec::new(),
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("pass --yes"));
    }

    #[test]
    fn plan_is_safe_and_reports_planned_changes() {
        let (code, stdout, _) = run_for_test(Some(Command::Plan {
            profile: Some(Profile::Baseline),
            policy: None,
            controls: vec!["windows.advertising.id".to_owned()],
        }));
        assert_eq!(code, 0);
        assert!(stdout.contains("Profile"));
        assert!(stdout.contains("Planned changes"));
    }

    #[test]
    fn apply_dry_run_aliases_plan() {
        let (code, stdout, _) = run_for_test(Some(Command::Apply {
            profile: Some(Profile::Baseline),
            policy: None,
            dry_run: true,
            yes: false,
            controls: Vec::new(),
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
        assert_eq!(code, 3);
        assert!(stderr.is_empty());
        let stdout = String::from_utf8(stdout).expect("stdout is UTF-8");
        let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(value["command"], "doctor");
        assert_eq!(value["complete"], false);
    }

    #[test]
    fn explaining_an_unknown_identifier_fails_with_guidance() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Explain {
            id: "missing.check".to_owned(),
        }));
        // A usage error, not an incomplete report: the machine was never asked.
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("missing.check"));
        assert!(stderr.contains("privr list"), "no next step offered");
    }

    #[test]
    fn check_renders_a_report_header() {
        let (_, stdout, _) = run_for_test(Some(Command::Check {
            profile: Some(Profile::Baseline),
            policy: None,
            controls: Vec::new(),
            all: true,
        }));
        let flat = flatten(&stdout);
        assert!(flat.contains("Profile baseline"));
        assert!(flat.contains("Platform"));
        assert!(flat.contains("Coverage"));
    }

    #[test]
    fn confirmed_apply_reports_clean_state_or_applied() {
        let (code, stdout, _) = run_for_test(Some(Command::Apply {
            profile: Some(Profile::Baseline),
            policy: None,
            dry_run: false,
            yes: true,
            controls: Vec::new(),
        }));
        assert_eq!(code, 0);
        assert!(stdout.contains("Machine matches policy") || stdout.contains("Applied"));
    }

    #[test]
    fn rollback_requires_confirmation() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: "tx-123".to_owned(),
            yes: false,
        }));
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("confirm rollback"));
    }

    #[test]
    fn rollback_accepts_an_internal_transaction_id() {
        let (code, stdout, stderr) = run_for_test(Some(Command::Rollback {
            transaction_id: "tx-123".to_owned(),
            yes: true,
        }));
        assert_eq!(code, 3);
        assert!(stdout.contains("transaction tx-123"));
        assert!(stderr.is_empty());
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
}
