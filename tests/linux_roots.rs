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
        let journals = roots[2].join("privr/state/transactions");
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
                        "set an absolute XDG_DATA_HOME or HOME",
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
