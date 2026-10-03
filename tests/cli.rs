use assert_cmd::Command;
use predicates::prelude::*;

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
        .stdout(predicate::str::contains("\"schema\": 1"))
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
        .stderr(predicate::str::contains("not implemented"));
}

#[test]
fn apply_without_confirmation_fails_closed() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .arg("apply")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("pass --yes"));
}

#[test]
fn rollback_fails_when_transaction_record_missing() {
    let mut command = Command::cargo_bin("privr").expect("binary");
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
    let mut command = Command::cargo_bin("privr").expect("binary");
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
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("privr doctor"))
        .stdout(predicate::str::contains("Platform"))
        .stdout(predicate::str::contains("Platform Adapters"))
        .stdout(predicate::str::contains("Storage and State"))
        .stdout(predicate::str::contains("Catalogue and Schemas"))
        .stdout(predicate::str::contains("System is healthy"));
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
        .stdout(predicate::str::contains("\"schema\": 1"));
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
fn recommend_suggests_privr_apply() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command.arg("recommend").assert().success().stdout(
        predicate::str::contains("To apply recommended controls, run: privr apply").or(
            predicate::str::contains(
                "No recommendations matching workload and friction constraints",
            ),
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
