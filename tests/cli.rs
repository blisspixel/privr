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
fn check_reports_incomplete_json() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["check", "--format", "json"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("\"command\": \"check\""))
        .stdout(predicate::str::contains("\"complete\": false"))
        .stdout(predicate::str::contains("\"status\": \"concept\""));
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
