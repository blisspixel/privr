use assert_cmd::Command;
use predicates::prelude::*;

struct DoctorStorage(std::path::PathBuf);

impl DoctorStorage {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("privr-cli-doctor-{}-{next}", std::process::id()));
        std::fs::create_dir(&path).expect("private doctor storage");
        Self(std::fs::canonicalize(path).expect("canonical private doctor storage"))
    }

    fn command(&self) -> Command {
        let mut command = Command::cargo_bin("privr").expect("binary");
        self.isolate(&mut command);
        command
    }

    fn isolate(&self, command: &mut Command) {
        command
            .env("XDG_DATA_HOME", &self.0)
            .env("LOCALAPPDATA", &self.0);
    }
}

impl Drop for DoctorStorage {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove private doctor storage");
    }
}

#[test]
fn help_exposes_the_canonical_workflow() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Audit privacy settings"))
        .stdout(predicate::str::contains("check"))
        .stdout(predicate::str::contains("plan"))
        .stdout(predicate::str::contains("apply"))
        .stdout(predicate::str::contains("rollback"));
}

#[test]
fn check_emits_a_versioned_json_report() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["check", "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"schema\": 2"))
        .stdout(predicate::str::contains("\"profile\": \"baseline\""))
        .stdout(predicate::str::contains("\"summary\""))
        .stdout(predicate::str::contains("\"results\""));
}

#[test]
fn check_never_reports_a_machine_identifier() {
    // The report is designed to be safe to forward, including to a model. A
    // security identifier or a profile path appearing here would defeat the
    // agent integration the tool is built for.
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["check", "--format", "json", "--all"])
        .assert()
        .stdout(predicate::str::contains("S-1-5").not())
        .stdout(predicate::str::contains("Users\\").not());
}

#[test]
fn a_custom_policy_file_is_refused_rather_than_substituted() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["check", "--policy", "nonexistent.toml"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("failed to read policy file"));
}

#[test]
fn apply_without_confirmation_fails_closed() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .arg("apply")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no terminal for approval"))
        .stderr(predicate::str::contains("privr apply --yes"));
}

#[test]
fn rollback_fails_when_transaction_record_missing() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let isolated =
        std::env::temp_dir().join(format!("privr-cli-history-{}-{nanos}", std::process::id()));
    // Override only the child process. The isolated location has no journals,
    // so an existing real tx-123 can never be selected by this test.
    command
        .env("LOCALAPPDATA", &isolated)
        .env("XDG_DATA_HOME", &isolated);
    command
        .args(["rollback", "tx-123", "--yes"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "no transaction record found with ID 'tx-123'",
        ));
}

#[test]
fn doctor_reports_health_and_exposes_no_identifiers() {
    let storage = DoctorStorage::new();
    let mut command = storage.command();
    command
        .args(["doctor", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": 1"))
        .stdout(predicate::str::contains("\"healthy\": true"))
        .stdout(predicate::str::contains("\"storage\""))
        .stdout(predicate::str::contains("S-1-5").not())
        .stdout(predicate::str::contains("Users\\").not());
}

#[test]
fn doctor_text_output_is_informative_and_clean() {
    let storage = DoctorStorage::new();
    let mut command = storage.command();
    command
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("privr doctor"))
        .stdout(predicate::str::contains("Platform"))
        .stdout(predicate::str::contains("Platform Adapters"))
        .stdout(predicate::str::contains("Storage and State"))
        .stdout(predicate::str::contains("Catalogue and Schemas"))
        .stdout(predicate::str::contains(
            "Transaction storage checks passed",
        ))
        .stdout(predicate::str::contains(
            "Other host capabilities remain unverified",
        ));
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_does_not_trust_user_environment_for_privilege() {
    let storage = DoctorStorage::new();
    let run = |user: &str| {
        let output = storage
            .command()
            .env("USER", user)
            .args(["doctor", "--format", "json"])
            .output()
            .expect("doctor process");
        assert!(output.status.success());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("doctor JSON")
    };
    let root_label = run("root");
    let ordinary_label = run("synthetic-user");
    assert_eq!(root_label["privilege"], ordinary_label["privilege"]);
    assert_eq!(root_label["os"]["edition"], "not applicable");
    assert_eq!(root_label["schema"], 1);
    assert!(
        !root_label["adapters"]
            .as_array()
            .expect("adapters")
            .iter()
            .any(|adapter| adapter == "systemd_dbus" || adapter == "gsettings")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn no_recommendations_in_an_empty_dimension_does_not_claim_compliance() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["recommend", "--dimension", "ambient-sensor"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "full compiled catalogue across profiles",
        ))
        .stdout(predicate::str::contains(
            "No confirmed drift recommendations matched",
        ))
        .stdout(predicate::str::contains("do not establish compliance"))
        .stdout(predicate::str::contains("machine matches target posture").not());
}

#[test]
fn plan_reports_planned_changes_or_honest_drift_summary() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["plan", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": 1"))
        .stdout(predicate::str::contains("\"planned_changes\""))
        .stdout(predicate::str::contains("\"unautomated_drift\""));
}

#[test]
fn check_profile_ladder_escalation() {
    let mut cmd_base = Command::cargo_bin("privr").expect("binary");
    cmd_base
        .args(["check", "--profile", "baseline", "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"profile\": \"baseline\""));

    let mut cmd_strict = Command::cargo_bin("privr").expect("binary");
    cmd_strict
        .args(["check", "--profile", "strict", "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"profile\": \"strict\""));

    let mut cmd_restrictive = Command::cargo_bin("privr").expect("binary");
    cmd_restrictive
        .args(["check", "--profile", "restrictive", "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"profile\": \"restrictive\""));
}

#[test]
fn list_exposes_profile_tiers() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["list", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"profile\": \"baseline\""))
        .stdout(predicate::str::contains("\"profile\": \"strict\""))
        .stdout(predicate::str::contains("\"profile\": \"restrictive\""));
}

#[test]
fn recommend_cli_generates_persona_recommendations() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["recommend", "--workload", "developer", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": 1"))
        .stdout(predicate::str::contains("\"workload\": \"developer\""))
        .stdout(predicate::str::contains("\"recommendations\""));
}

#[test]
fn simulate_cli_projects_counterfactual_posture() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["simulate", "--profile", "baseline", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": 1"))
        .stdout(predicate::str::contains("\"current_posture\""))
        .stdout(predicate::str::contains("\"simulated_posture\""));
}

#[test]
fn check_cli_with_section_filter() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args([
            "check",
            "--section",
            "advertising",
            "--format",
            "json",
            "--all",
        ])
        .assert()
        .stdout(predicate::str::contains("\"schema\": 2"));
}

#[test]
fn plan_cli_with_section_filter() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["plan", "--section", "advertising", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": 1"));
}

#[test]
fn plan_defaults_to_sensible_daily_driver_workload() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["plan", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"workload\": \"general\""));
}

#[test]
fn recommend_suggests_reviewing_a_plan_or_reports_no_confirmed_drift() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command.arg("recommend").assert().success().stdout(
        predicate::str::contains("Run privr plan to review eligible changes before applying.").or(
            predicate::str::contains("No confirmed drift recommendations matched"),
        ),
    );
}

#[test]
fn apply_help_shows_elevate_flag() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--elevate"))
        .stdout(predicate::str::contains("-e"));
}

#[test]
fn apply_help_shows_interactive_sections_flag() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--interactive-sections"))
        .stdout(predicate::str::contains("-i"));
}

#[test]
fn explain_without_arguments_shows_scoring_and_critical_controls() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .arg("explain")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "privr Posture Model & Critical Controls",
        ))
        .stdout(predicate::str::contains("How Posture Is Calculated"))
        .stdout(predicate::str::contains(
            "Five Orthogonal Posture Dimensions",
        ))
        .stdout(predicate::str::contains(
            "Compiled Controls For This Platform",
        ));
}

#[test]
fn explain_topic_keywords_show_scoring_model() {
    for topic in ["score", "posture", "critical", "overview"] {
        let mut command = Command::cargo_bin("privr").expect("binary");
        command
            .args(["explain", topic])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "privr Posture Model & Critical Controls",
            ));
    }
}

#[test]
fn explain_storage_topic_shows_flash_mechanics_and_sanitization() {
    for topic in ["storage", "trim", "wipe"] {
        let mut command = Command::cargo_bin("privr").expect("binary");
        command
            .args(["explain", topic])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "privr Storage Privacy & Forensic Sanitization Architecture",
            ))
            .stdout(predicate::str::contains("Physical Reality: Flash Storage"))
            .stdout(predicate::str::contains("Hardware TRIM"))
            .stdout(predicate::str::contains("Chip-Off Forensics"))
            .stdout(predicate::str::contains("NIST SP 800-88"));
    }
}

#[test]
fn explain_residue_topic_shows_forensics_and_hygiene() {
    for topic in ["residue", "clean", "purge", "forensics"] {
        let mut command = Command::cargo_bin("privr").expect("binary");
        command
            .args(["explain", topic])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "privr Disposable Residue & Forensic Sanitization Architecture",
            ))
            .stdout(predicate::str::contains("Forensic Residue"))
            .stdout(predicate::str::contains("Polite Mode vs Aggressive Mode"))
            .stdout(predicate::str::contains("Scientific Sanitization"))
            .stdout(predicate::str::contains(
                "AI Agent & Developer Workspace Hygiene",
            ));
    }
}

#[test]
fn explain_known_control_shows_evidence_and_rationale() {
    let control_id = if cfg!(windows) {
        "windows.advertising.id"
    } else if cfg!(target_os = "macos") {
        "macos.analytics.share-mac"
    } else {
        "debian.popularity-contest.participation"
    };
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["explain", control_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("Why it matters"))
        .stdout(predicate::str::contains("Evidence"));
}

#[test]
fn explain_shell_topic_shows_history_architecture() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["explain", "shell"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "privr Shell Command History Privacy Architecture",
        ))
        .stdout(predicate::str::contains(
            "1. Physical Retention: How Shells Record Commands",
        ))
        .stdout(predicate::str::contains(
            "3. Recommended Posture: Session-Only Command History",
        ));
}

#[test]
fn clean_preview_defaults_to_dry_run_and_shows_plan() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--preview"])
        .assert()
        .success()
        .stdout(predicate::str::contains("privr clean (preview"))
        .stdout(predicate::str::contains("Plan:"));
}

#[test]
fn clean_dry_run_alias_works() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("privr clean (preview"))
        .stdout(predicate::str::contains("Plan:"));
}

#[test]
fn clean_category_filter_scopes_selection() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--preview", "--category", "ai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Claude desktop"))
        .stdout(predicate::str::contains("Plan: 2 to clean"));
}

#[test]
fn clean_help_shows_examples_and_categories() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Categories:"))
        .stdout(predicate::str::contains("Examples:"))
        .stdout(predicate::str::contains("privr clean --category"));
}

#[test]
fn purge_alias_still_works() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["purge", "--preview"])
        .assert()
        .success()
        .stdout(predicate::str::contains("privr clean (preview"));
}

#[test]
fn purge_preview_json_is_valid() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    let assert = command
        .args(["clean", "--preview", "--format", "json"])
        .assert()
        .success();

    let output = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid json report");
    assert_eq!(parsed["schema"], 1);
    assert_eq!(parsed["dry_run"], true);
    assert!(parsed["items"].is_array());
}

#[test]
fn purge_polite_retains_thumbnail_cache() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--preview", "--polite"])
        .assert()
        .success()
        .stdout(predicate::str::contains("retained"))
        .stdout(predicate::str::contains("thumbnail"));
}

#[test]
fn purge_with_control_filter_scopes_selection() {
    let ctrl_id = if cfg!(windows) {
        "windows.residue.temp"
    } else if cfg!(target_os = "linux") {
        "linux.residue.mesa-shader"
    } else {
        "browser.residue.safari-cache"
    };
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--preview", "--control", ctrl_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("Plan: 1 to clean"));
}

#[test]
fn clean_preview_with_trim_shows_hardware_maintenance() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--preview", "--trim"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Hardware Storage Maintenance"));
}

#[test]
fn clean_preview_with_trim_json_contains_trim_status() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    let assert = command
        .args(["clean", "--preview", "--trim", "--format", "json"])
        .assert()
        .success();

    let output = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid json report");
    assert_eq!(parsed["schema"], 1);
    assert_eq!(parsed["dry_run"], true);
    assert!(parsed["trim"].is_object());
    assert!(parsed["trim"]["volume"].is_string());
    assert!(parsed["trim"]["media_type"].is_string());
}

#[test]
fn history_purge_with_yes_executes_safely() {
    let inherited = DoctorStorage::new();
    let isolated = DoctorStorage::new();
    let record = br#"{"schema":1,"transaction_id":"apply-test","timestamp":"1.000","platform":"linux","profile":"baseline","operations":[]}"#;
    let seed = |storage: &DoctorStorage| {
        let root = storage.0.join("privr/state/transactions");
        std::fs::create_dir_all(&root).expect("create fixture journal root");
        let path = root.join("apply-test.json");
        std::fs::write(&path, record).expect("seed fixture journal");
        path
    };
    let sentinel = seed(&inherited);
    let selected = seed(&isolated);
    // Simulate inherited user storage using a second disposable root. Override
    // only this child, never the process-wide environment of parallel tests.
    let mut command = inherited.command();
    isolated.isolate(&mut command);
    command
        .args(["history", "--purge", "-y"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Purged 1 transaction history record(s).",
        ));
    assert!(!selected.exists(), "the isolated record must be purged");
    assert_eq!(std::fs::read(sentinel).expect("preserved sentinel"), record);
}

#[test]
fn check_compare_identifies_regression_and_outputs_provenance() {
    let mut check_cmd = Command::cargo_bin("privr").expect("binary");
    let assert = check_cmd.args(["check", "--format", "json"]).assert();

    let output = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    let temp_file =
        std::env::temp_dir().join(format!("privr-prior-test-{}.json", std::process::id()));
    std::fs::write(&temp_file, output).expect("write temp report");

    let mut compare_cmd = Command::cargo_bin("privr").expect("binary");
    let result = compare_cmd
        .args(["check", "--compare", temp_file.to_str().expect("str")])
        .assert();

    let _ = std::fs::remove_file(&temp_file);

    result
        .stdout(predicate::str::contains(
            "privr check (post-update comparison)",
        ))
        .stdout(predicate::str::contains("Observation Provenance"))
        .stdout(predicate::str::contains("Prior check:"))
        .stdout(predicate::str::contains("Current check:"))
        .stdout(predicate::str::contains("Summary:"));
}

#[test]
fn check_compare_format_json_emits_structured_comparison() {
    let mut check_cmd = Command::cargo_bin("privr").expect("binary");
    let assert = check_cmd.args(["check", "--format", "json"]).assert();

    let output = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    let temp_file =
        std::env::temp_dir().join(format!("privr-prior-json-test-{}.json", std::process::id()));
    std::fs::write(&temp_file, output).expect("write temp report");

    let mut compare_cmd = Command::cargo_bin("privr").expect("binary");
    let assert_cmp = compare_cmd
        .args([
            "check",
            "--compare",
            temp_file.to_str().expect("str"),
            "--format",
            "json",
        ])
        .assert();

    let _ = std::fs::remove_file(&temp_file);

    let cmp_output = String::from_utf8(assert_cmp.get_output().stdout.clone()).expect("utf-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&cmp_output).expect("valid comparison json");
    assert_eq!(parsed["schema"], 2);
    assert!(parsed["prior"].is_object());
    assert!(parsed["current"].is_object());
    assert!(parsed["regressions"].is_array());
    assert!(parsed["remediations"].is_array());
    assert!(parsed["newly_applicable"].is_array());
}

#[test]
fn check_with_valid_custom_toml_policy_evaluates_overrides_and_exceptions() {
    let toml = r#"
schema = 1
extends = "builtin:baseline@0.1"

[controls."windows.advertising.id"]
mode = "ignore"

[[exceptions]]
control = "windows.security.wpad"
accepted = "enabled"
reason = "Intranet proxy routing required"
expires = "2029-01-01"
"#;
    let temp_file = std::env::temp_dir().join(format!(
        "privr-custom-policy-test-{}.toml",
        std::process::id()
    ));
    std::fs::write(&temp_file, toml).expect("write custom policy");

    let mut cmd = Command::cargo_bin("privr").expect("binary");
    let assert = cmd
        .args([
            "check",
            "--policy",
            temp_file.to_str().expect("str"),
            "--all",
        ])
        .assert();

    let _ = std::fs::remove_file(&temp_file);

    let output = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    assert!(output.contains("custom (extends baseline)"));
}

#[test]
fn rollback_help_shows_section_filter() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["rollback", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--section"))
        .stdout(predicate::str::contains("-s"));
}

#[test]
fn apply_help_shows_accept_risk_and_force() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--accept-risk"))
        .stdout(predicate::str::contains("--force"));
}

#[test]
fn clean_help_shows_accept_risk() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--accept-risk"));
}

#[test]
fn rollback_refuses_cross_platform_transaction() {
    let storage = DoctorStorage::new();
    let tx_dir = storage.0.join("privr").join("state").join("transactions");
    std::fs::create_dir_all(&tx_dir).expect("create tx dir");
    let foreign_platform = if cfg!(windows) { "linux" } else { "windows" };
    let tx = privr::journal::TransactionJournal {
        schema: privr::journal::JOURNAL_SCHEMA,
        cleanup: None,
        transaction_id: "tx-foreign-99".to_owned(),
        timestamp: "2026-11-03T01:00:00Z".to_owned(),
        platform: foreign_platform.to_owned(),
        profile: "baseline".to_owned(),
        operations: vec![privr::journal::OperationJournal {
            control_id: "fake.control".to_owned(),
            target_key: "fake.key".to_owned(),
            preimage: None,
            postimage: privr::model::evidence::RawValue::new(
                privr::model::evidence::ValueKind::U32,
                vec![0, 0, 0, 0],
            ),
            verified: true,
        }],
    };
    let content = serde_json::to_string_pretty(&tx).expect("serialize foreign tx");
    std::fs::write(tx_dir.join("tx-foreign-99.json"), content).expect("write foreign tx");

    let mut cmd = storage.command();
    cmd.args(["rollback", "tx-foreign-99", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("was recorded on"))
        .stderr(predicate::str::contains("and cannot be rolled back on"));
}

#[test]
fn simulate_cli_with_custom_policy() {
    let toml = r#"
schema = 1
extends = "builtin:baseline@0.1"

[controls."windows.advertising.id"]
mode = "ignore"
"#;
    let temp_file =
        std::env::temp_dir().join(format!("privr-sim-policy-test-{}.toml", std::process::id()));
    std::fs::write(&temp_file, toml).expect("write policy");

    let mut cmd = Command::cargo_bin("privr").expect("binary");
    let assert = cmd
        .args(["simulate", "--policy", temp_file.to_str().expect("path")])
        .assert()
        .success();

    let _ = std::fs::remove_file(&temp_file);
    let output = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    assert!(output.contains("custom (extends baseline)"));
}

#[test]
fn console_history_cleanup_uses_the_documented_platform_root() {
    let storage = DoctorStorage::new();
    let root = if cfg!(windows) {
        storage.0.join("Microsoft/Windows/PowerShell/PSReadLine")
    } else {
        storage.0.join("powershell/PSReadLine")
    };
    std::fs::create_dir_all(&root).expect("fixture history directory");
    let history = root.join("ConsoleHost_history.txt");
    std::fs::write(&history, "fixture command recall").expect("seed history");
    let id = if cfg!(windows) {
        "windows.residue.powershell-history"
    } else if cfg!(target_os = "macos") {
        "macos.residue.powershell-history"
    } else {
        "linux.residue.powershell-history"
    };
    for preview in [true, false] {
        let mut command = storage.command();
        command
            .env("HOME", &storage.0)
            .env("USERPROFILE", &storage.0)
            .env("APPDATA", &storage.0)
            .env("XDG_CACHE_HOME", &storage.0)
            .env("XDG_CONFIG_HOME", &storage.0)
            .env("TEMP", &storage.0)
            .env("TMP", &storage.0)
            .args(["clean", "--control", id, "--yes", "--format", "json"]);
        if preview {
            command.arg("--preview");
        }
        let output = command.assert().success();
        let report: serde_json::Value =
            serde_json::from_slice(&output.get_output().stdout).expect("JSON");
        assert_eq!(report["total_files_affected"], 1);
        assert_eq!(report["dry_run"], preview);
        assert_eq!(history.exists(), preview);
        assert!(
            report["items"][0]["trade_off"]
                .as_str()
                .expect("tradeoff")
                .contains("Close PowerShell first")
        );
    }
}

#[test]
fn legacy_cleanup_history_is_unknown_and_never_a_reversible_transaction() {
    let storage = DoctorStorage::new();
    let root = storage.0.join("privr/state/transactions");
    std::fs::create_dir_all(&root).expect("isolated journal root");
    let record = br#"{"schema":1,"transaction_id":"clean-legacy","timestamp":"1.000","platform":"linux","profile":"clean:aggressive","operations":[]}"#;
    let path = root.join("clean-legacy.json");
    std::fs::write(&path, record).expect("legacy fixture");
    storage
        .command()
        .arg("history")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "legacy record: completion and removal totals unknown",
        ))
        .stdout(predicate::str::contains("To reverse the most recent changes").not());
    storage
        .command()
        .args(["rollback", "--yes"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("1 cleanup record(s)"))
        .stderr(predicate::str::contains("no reversible transactions"));
    assert_eq!(
        std::fs::read(path).expect("legacy journal preserved"),
        record
    );
}
