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
fn rollback_uses_a_transaction_id() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["rollback", "tx-123", "--yes"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("transaction tx-123"));
}
