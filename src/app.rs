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

pub fn run(cli: Cli, out: &mut impl Write, err: &mut impl Write) -> i32 {
    let format = cli.format;
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

            let host = crate::platform::discover();
            let profile = profile.unwrap_or_default();
            let report = crate::report::Report::build(&host, profile.as_str());

            match format {
                OutputFormat::Text => {
                    let _ = write!(out, "{}", report.to_text(all));
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
            let qualifier = selection_text(&controls, policy.as_ref());
            let message = format!(
                "{CONCEPT_NOTICE}; planned changes: 0{}",
                qualifier
                    .map(|value| format!("; {value}"))
                    .unwrap_or_default()
            );
            write_response(
                out,
                format,
                ConceptResponse {
                    schema: 1,
                    complete: false,
                    status: "concept",
                    command: "plan",
                    platform: current_platform(),
                    profile: selected_profile(profile, policy.as_ref()),
                    message: &message,
                },
            );
            3
        }
        Command::Apply {
            profile,
            policy,
            dry_run,
            yes,
            controls,
        } => {
            if dry_run {
                let qualifier = selection_text(&controls, policy.as_ref());
                let message = format!(
                    "{CONCEPT_NOTICE}; planned changes: 0{}",
                    qualifier
                        .map(|value| format!("; {value}"))
                        .unwrap_or_default()
                );
                write_response(
                    out,
                    format,
                    ConceptResponse {
                        schema: 1,
                        complete: false,
                        status: "concept",
                        command: "plan",
                        platform: current_platform(),
                        profile: selected_profile(profile, policy.as_ref()),
                        message: &message,
                    },
                );
                return 3;
            }
            if !yes {
                let _ = writeln!(
                    err,
                    "privr: interactive approval is not implemented; use plan or pass --yes"
                );
                return 2;
            }
            let selection = selection_text(&controls, policy.as_ref());
            let message = format!(
                "{CONCEPT_NOTICE}; applied changes: 0{}",
                selection
                    .map(|value| format!("; {value}"))
                    .unwrap_or_default()
            );
            write_response(
                out,
                format,
                ConceptResponse {
                    schema: 1,
                    complete: false,
                    status: "concept",
                    command: "apply",
                    platform: current_platform(),
                    profile: selected_profile(profile, policy.as_ref()),
                    message: &message,
                },
            );
            3
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
            let message =
                format!("{CONCEPT_NOTICE}; transaction {transaction_id}; restored changes: 0");
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
            3
        }
        Command::List { platform } => {
            let selected = platform.unwrap_or(Platform::Auto);
            write_response(
                out,
                format,
                ConceptResponse {
                    schema: 1,
                    complete: false,
                    status: "concept",
                    command: "list",
                    platform: selected.as_str(),
                    profile: None,
                    message: CONCEPT_NOTICE,
                },
            );
            3
        }
        Command::Explain { id } => {
            let message = format!("check '{id}' is not registered in the concept build");
            write_response(
                out,
                format,
                ConceptResponse {
                    schema: 1,
                    complete: false,
                    status: "not_found",
                    command: "explain",
                    platform: current_platform(),
                    profile: None,
                    message: &message,
                },
            );
            3
        }
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

fn selection_text(controls: &[String], policy: Option<&std::path::PathBuf>) -> Option<String> {
    match (controls.is_empty(), policy) {
        (true, None) => None,
        (false, None) => Some(format!("selected controls: {}", controls.join(", "))),
        (true, Some(path)) => Some(format!("policy: {}", path.display())),
        (false, Some(path)) => Some(format!(
            "policy: {}; selected controls: {}",
            path.display(),
            controls.join(", ")
        )),
    }
}

fn selected_profile(
    profile: Option<Profile>,
    policy: Option<&std::path::PathBuf>,
) -> Option<&'static str> {
    policy
        .is_none()
        .then(|| profile.unwrap_or_default().as_str())
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

    fn run_for_test(command: Option<Command>) -> (i32, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            Cli {
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
        assert!(stdout.contains("Profile   baseline"));
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
    fn plan_is_safe_and_reports_incomplete() {
        let (code, stdout, _) = run_for_test(Some(Command::Plan {
            profile: Some(Profile::Baseline),
            policy: None,
            controls: vec!["windows.telemetry".to_owned()],
        }));
        assert_eq!(code, 3);
        assert!(stdout.contains("privr plan"));
        assert!(stdout.contains("planned changes: 0"));
        assert!(stdout.contains("windows.telemetry"));
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
        assert_eq!(code, 3);
        assert!(stdout.contains("privr plan"));
    }

    #[test]
    fn json_output_is_machine_readable() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            Cli {
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
    fn explain_unknown_check_has_distinct_exit_code() {
        let (code, stdout, _) = run_for_test(Some(Command::Explain {
            id: "missing.check".to_owned(),
        }));
        assert_eq!(code, 3);
        assert!(stdout.contains("missing.check"));
    }

    #[test]
    fn check_renders_a_report_header() {
        let (_, stdout, _) = run_for_test(Some(Command::Check {
            profile: Some(Profile::Baseline),
            policy: None,
            controls: Vec::new(),
            all: true,
        }));
        assert!(stdout.contains("Profile   baseline"));
        assert!(stdout.contains("Platform  "));
        assert!(stdout.contains("Result    "));
    }

    #[test]
    fn confirmed_apply_still_reports_concept_as_incomplete() {
        let (code, stdout, _) = run_for_test(Some(Command::Apply {
            profile: None,
            policy: Some("laptop.toml".into()),
            dry_run: false,
            yes: true,
            controls: Vec::new(),
        }));
        assert_eq!(code, 3);
        assert!(stdout.contains("privr apply"));
        assert!(stdout.contains("policy: laptop.toml"));
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
    fn list_supports_platform_and_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            Cli {
                format: OutputFormat::Json,
                command: Some(Command::List {
                    platform: Some(Platform::All),
                }),
            },
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
        assert!(stderr.is_empty());
        let stdout = String::from_utf8(stdout).expect("stdout is UTF-8");
        let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(value["platform"], "all");
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
