#![cfg(target_os = "linux")]

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("privr-roots-{}-{next}", std::process::id()));
        std::fs::create_dir(&root).expect("create fixture");
        let fixture = Self(std::fs::canonicalize(root).expect("absolute fixture"));
        for name in [
            "home",
            "cwd",
            "override/cache",
            "override/config",
            "override/data",
            "override/state",
        ] {
            std::fs::create_dir_all(fixture.0.join(name)).expect("create isolated roots");
        }
        fixture
    }

    fn command(&self, value: Option<&str>, valid_home: bool) -> Command {
        let mut command = Command::cargo_bin("privr").expect("binary");
        command.current_dir(self.0.join("cwd"));
        command.env(
            "HOME",
            if valid_home {
                self.0.join("home")
            } else {
                PathBuf::from("")
            },
        );
        for (key, suffix) in [
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_STATE_HOME", "state"),
        ] {
            match value {
                None => {
                    command.env_remove(key);
                }
                Some("absolute") => {
                    command.env(key, self.0.join("override").join(suffix));
                }
                Some(value) => {
                    command.env(key, value);
                }
            }
        }
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove fixture");
    }
}

fn seed(path: &Path) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    std::fs::write(path, b"fixture-private-content").expect("seed canary");
}

fn assert_preserved(paths: &[PathBuf]) {
    for path in paths {
        assert_eq!(
            std::fs::read(path).expect("canary preserved"),
            b"fixture-private-content"
        );
    }
}

#[test]
fn cleanup_and_journals_never_resolve_invalid_xdg_values_against_cwd() {
    for value in [None, Some(""), Some("relative"), Some("absolute")] {
        let fixture = Fixture::new();
        let roots = if value == Some("absolute") {
            [
                fixture.0.join("override/cache"),
                fixture.0.join("override/config"),
                fixture.0.join("override/data"),
            ]
        } else {
            [
                fixture.0.join("home/.cache"),
                fixture.0.join("home/.config"),
                fixture.0.join("home/.local/share"),
            ]
        };
        let state_root = if value == Some("absolute") {
            fixture.0.join("override/state")
        } else {
            fixture.0.join("home/.local/state")
        };
        let selected = [
            roots[0].join("pip/canary"),
            roots[1].join("Code/Cache/canary"),
            roots[2].join("recently-used.xbel"),
        ];
        let mut canaries = Vec::new();
        for base in [fixture.0.join("cwd"), fixture.0.join("cwd/relative")] {
            for suffix in [
                "pip/canary",
                "Code/Cache/canary",
                "recently-used.xbel",
                "privr/transactions/sentinel.json",
                "privr/state/transactions/sentinel.json",
            ] {
                let path = base.join(suffix);
                seed(&path);
                canaries.push(path);
            }
        }
        for path in &selected {
            seed(path);
        }
        let scope = [
            "clean",
            "--control",
            "dev.residue.pip-cache",
            "--control",
            "editor.residue.vscode",
            "--control",
            "linux.residue.recent-files",
            "--format",
            "json",
        ];
        let output = fixture
            .command(value, true)
            .args(scope)
            .arg("--preview")
            .assert()
            .success();
        let preview: serde_json::Value =
            serde_json::from_slice(&output.get_output().stdout).expect("preview JSON");
        assert_eq!(preview["total_files_affected"], 3);
        assert_preserved(&selected);
        assert_preserved(&canaries);
        let output = fixture
            .command(value, true)
            .args(scope)
            .arg("--yes")
            .assert()
            .success();
        let report: serde_json::Value =
            serde_json::from_slice(&output.get_output().stdout).expect("cleanup JSON");
        assert_eq!(report["total_files_affected"], 3);
        for path in &selected {
            assert!(!path.exists(), "selected residue must be removed");
        }
        assert_preserved(&canaries);
        let journals = state_root.join("privr/transactions");
        assert_eq!(
            std::fs::read_dir(&journals).expect("journal root").count(),
            1
        );
        fixture
            .command(value, true)
            .args(["history", "--purge", "--yes"])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "Purged 1 transaction history record(s).",
            ));
        assert_eq!(
            std::fs::read_dir(&journals).expect("journal root").count(),
            0
        );
        assert_preserved(&canaries);
    }
}

#[test]
fn missing_absolute_home_and_data_root_refuses_before_any_deletion() {
    for home in [None, Some(""), Some("relative")] {
        for value in [None, Some(""), Some("relative")] {
            let fixture = Fixture::new();
            let canaries = [
                fixture.0.join("cwd/pip/canary"),
                fixture.0.join("cwd/privr/transactions/sentinel.json"),
                fixture.0.join("cwd/privr/state/transactions/sentinel.json"),
            ];
            for path in &canaries {
                seed(path);
            }
            for args in [
                vec!["clean", "--preview"],
                vec!["clean", "--yes"],
                vec!["history", "--purge", "--yes"],
            ] {
                let mut command = fixture.command(value, false);
                match home {
                    Some(home) => {
                        command.env("HOME", home);
                    }
                    None => {
                        command.env_remove("HOME");
                    }
                }
                command
                    .args(args)
                    .assert()
                    .code(5)
                    .stderr(predicate::str::contains(
                        "set an absolute XDG_STATE_HOME or HOME",
                    ));
                assert_preserved(&canaries);
            }
        }
    }
}

#[test]
fn absolute_overrides_work_without_home_and_missing_cache_root_is_explained() {
    let fixture = Fixture::new();
    let selected = fixture.0.join("override/cache/pip/canary");
    seed(&selected);
    fixture
        .command(Some("absolute"), false)
        .args(["clean", "--yes", "--control", "dev.residue.pip-cache"])
        .assert()
        .success();
    assert!(!selected.exists());
    fixture
        .command(Some("absolute"), false)
        .env("XDG_CACHE_HOME", "")
        .args(["clean", "--preview", "--control", "dev.residue.pip-cache"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains(
            "no absolute user root is available",
        ));
}

#[test]
fn default_cleanup_removes_supported_activity_with_one_confirmation() {
    let fixture = Fixture::new();
    let cache = fixture.0.join("override/cache/pip/canary");
    let recent = fixture.0.join("override/data/recently-used.xbel");
    let history = fixture
        .0
        .join("override/data/powershell/PSReadLine/ConsoleHost_history.txt");
    let document = fixture.0.join("home/Documents/work.txt");
    let selected = [cache, recent, history];
    for path in selected.iter().chain([&document]) {
        seed(path);
    }
    fixture
        .command(Some("absolute"), true)
        .args(["clean", "--preview", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Deletion is permanent"))
        .stdout(predicate::str::contains("linux.residue.powershell-history"))
        .stdout(predicate::str::contains("Close PowerShell first"));
    assert_preserved(&selected);
    let preview = fixture
        .command(Some("absolute"), true)
        .args(["clean", "--preview", "--format", "json"])
        .assert()
        .success();
    let preview: serde_json::Value =
        serde_json::from_slice(&preview.get_output().stdout).expect("preview JSON");
    let item = preview["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "linux.residue.powershell-history")
        .expect("history target");
    assert!(
        item["trade_off"]
            .as_str()
            .expect("tradeoff")
            .contains("open shells can rewrite history")
    );
    fixture
        .command(Some("absolute"), true)
        .args(["clean", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("3 files removed"));
    for path in &selected {
        assert!(
            !path.exists(),
            "default cleanup must remove supported residue"
        );
    }
    assert_preserved(&[document]);
}

#[test]
fn cleanup_help_describes_linux_targets_and_all_main_categories() {
    let mut command = Command::cargo_bin("privr").expect("binary");
    command
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GTK recently used files"))
        .stdout(predicate::str::contains("Mozilla Firefox"))
        .stdout(predicate::str::contains("app, apps:"))
        .stdout(predicate::str::contains("%TEMP%").not())
        .stdout(predicate::str::contains("DirectX").not());
}

struct CleanupChild(Option<std::process::Child>);

impl Drop for CleanupChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn interrupted_cleanup(signal: Option<&str>, mcp: bool) {
    const FILES: usize = 20_000;
    let fixture = Fixture::new();
    let cache = fixture.0.join("override/cache/pip");
    std::fs::create_dir_all(&cache).expect("fixture cache");
    for index in 0..FILES {
        std::fs::write(
            cache.join(format!("private-fixture-{index}")),
            b"fixture-private-content",
        )
        .expect("seed cache");
    }
    let mut command = fixture.command(Some("absolute"), true);
    if mcp {
        command.args(["mcp", "--allow-apply"]);
    } else {
        command.args([
            "clean",
            "--yes",
            "--control",
            "dev.residue.pip-cache",
            "--format",
            "json",
        ]);
    }
    let mut process = std::process::Command::new(command.get_program());
    process
        .args(command.get_args())
        .current_dir(command.get_current_dir().unwrap());
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            process.env(key, value);
        } else {
            process.env_remove(key);
        }
    }
    let child = process
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn isolated cleanup");
    let mut child = CleanupChild(Some(child));
    if mcp {
        use std::io::Write;
        let request = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"privr_clean","arguments":{"dry_run":false,"yes":true,"control":"dev.residue.pip-cache"}}});
        let mut input = child.0.as_mut().unwrap().stdin.take().unwrap();
        writeln!(input, "{request}").expect("send cleanup request");
    } else {
        drop(child.0.as_mut().unwrap().stdin.take());
    }
    let root = fixture.0.join("override/state/privr/transactions");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "cleanup did not start before deadline"
        );
        assert!(
            child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "cleanup ended before interruption could be tested"
        );
        let remaining = std::fs::read_dir(&cache)
            .expect("cache root preserved")
            .count();
        if root.exists() && remaining < FILES {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    if let Some(signal) = signal {
        let pid = child.0.as_ref().unwrap().id().to_string();
        assert!(
            std::process::Command::new("kill")
                .args(["-s", signal, &pid])
                .status()
                .expect("signal fixture child")
                .success()
        );
    } else {
        child
            .0
            .as_mut()
            .unwrap()
            .kill()
            .expect("hard kill fixture child");
    }
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "cleanup did not stop before deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let output = child
        .0
        .take()
        .unwrap()
        .wait_with_output()
        .expect("partial output");
    let remaining = std::fs::read_dir(&cache).unwrap().count();
    assert!(
        remaining > 0 && remaining < FILES,
        "test must interrupt an actual partial deletion"
    );
    let records: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(records.len(), 1, "only the committed journal should remain");
    let bytes = std::fs::read(&records[0]).unwrap();
    let journal: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let serialized = String::from_utf8(bytes).unwrap();
    assert!(!serialized.contains("private-fixture"));
    assert!(!serialized.contains("fixture-private-content"));
    assert!(!serialized.contains(fixture.0.to_str().unwrap()));
    if signal.is_some() {
        assert_eq!(output.status.code(), Some(if mcp { 0 } else { 4 }));
        let output_json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("partial JSON output");
        let report = if mcp {
            assert_eq!(output_json["result"]["isError"], true);
            serde_json::from_str(
                output_json["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap(),
            )
            .expect("partial tool report")
        } else {
            output_json
        };
        assert_eq!(report["status"], "interrupted");
        assert_eq!(report["total_files_affected"], FILES - remaining);
        assert_eq!(journal["cleanup"]["status"], "interrupted");
        assert_eq!(
            journal["cleanup"]["targets"][0]["files_removed"],
            FILES - remaining
        );
        fixture
            .command(Some("absolute"), true)
            .arg("history")
            .assert()
            .success()
            .stdout(predicate::str::contains("interrupted"));
    } else {
        assert!(!output.status.success());
        assert_eq!(journal["cleanup"]["status"], "running");
        fixture
            .command(Some("absolute"), true)
            .arg("history")
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "unfinished (completion unverified)",
            ))
            .stdout(predicate::str::contains("completed").not());
    }
}

#[test]
fn sigint_and_sigterm_preserve_exact_partial_cleanup_totals() {
    for signal in ["INT", "TERM"] {
        interrupted_cleanup(Some(signal), false);
    }
}

#[test]
fn hard_kill_leaves_an_explicitly_unfinished_cleanup_record() {
    interrupted_cleanup(None, false);
}

#[test]
fn mcp_sigterm_returns_partial_error_report() {
    interrupted_cleanup(Some("TERM"), true);
}

#[test]
fn successive_mcp_cleanups_have_independent_completed_receipts() {
    let fixture = Fixture::new();
    seed(&fixture.0.join("override/cache/pip/canary"));
    let request = |id| serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"privr_clean","arguments":{"dry_run":false,"yes":true,"control":"dev.residue.pip-cache"}}});
    let output = fixture
        .command(Some("absolute"), true)
        .args(["mcp", "--allow-apply"])
        .write_stdin(format!("{}\n{}\n", request(1), request(2)))
        .assert()
        .success();
    let lines: Vec<_> = output
        .get_output()
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(lines.len(), 2);
    let mut ids = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let response: serde_json::Value = serde_json::from_slice(line).unwrap();
        assert_eq!(response["result"]["isError"], false);
        let report: serde_json::Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(report["status"], "completed");
        assert_eq!(
            report["total_files_affected"],
            if index == 0 { 1 } else { 0 }
        );
        let id = report["transaction_id"].as_str().unwrap().to_owned();
        let journal: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                fixture
                    .0
                    .join("override/state/privr/transactions")
                    .join(format!("{id}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(journal["cleanup"]["status"], "completed");
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1]);
}
