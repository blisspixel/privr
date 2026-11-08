//! macOS residue inspection and purge adapter.
//!
//! Provides symlink-safe scanning and deletion of reviewed disposable caches
//! and temporary files across standard macOS Library locations. Symlinks are never
//! followed, and target root directories are strictly preserved.

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::residue::{ResiduePreviewItem, ResiduePurgeItem, ResidueSpec, TrimStatus};

/// Internal target descriptor mapping a spec ID to filesystem locations and filters.
struct TargetPathRule {
    target_id: &'static str,
    path_display: &'static str,
    resolve_paths: fn() -> Vec<PathBuf>,
    file_filter: Option<fn(&Path, &str) -> bool>,
    recurse_filter: Option<fn(&Path) -> bool>,
}

use crate::platform::xdg::home_dir;

fn user_library() -> Option<PathBuf> {
    home_dir().map(|h| h.join("Library"))
}

fn user_caches() -> Option<PathBuf> {
    user_library().map(|lib| lib.join("Caches"))
}

fn safari_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let p = caches.join("com.apple.Safari");
        if p.is_dir() {
            v.push(p);
        }
    }
    v
}

fn chromium_profile_cache_paths(user_data_dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if !user_data_dir.is_dir() {
        return v;
    }

    let top_caches = [
        "ShaderCache",
        "GrShaderCache",
        "GraphiteDawnCache",
        "GPUPersistentCache",
    ];
    for name in &top_caches {
        let p = user_data_dir.join(name);
        if p.is_dir() {
            v.push(p);
        }
    }

    if let Ok(entries) = fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy();
                if name == "Default" || name.starts_with("Profile ") || name == "Guest Profile" {
                    let cache = entry_path.join("Cache");
                    if cache.is_dir() {
                        v.push(cache);
                    }
                    let code_cache = entry_path.join("Code Cache");
                    if code_cache.is_dir() {
                        v.push(code_cache);
                    }
                    let gpu_cache = entry_path.join("GPUCache");
                    if gpu_cache.is_dir() {
                        v.push(gpu_cache);
                    }
                }
            }
        }
    }
    v
}

fn chrome_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let chrome_dir = caches.join("Google").join("Chrome");
        if chrome_dir.is_dir() {
            v.extend(chromium_profile_cache_paths(&chrome_dir));
            v.push(chrome_dir);
        }
    }
    v
}

fn brave_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let brave_dir = caches.join("BraveSoftware").join("Brave-Browser");
        if brave_dir.is_dir() {
            v.extend(chromium_profile_cache_paths(&brave_dir));
            v.push(brave_dir);
        }
    }
    v
}

fn edge_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let edge_dir = caches.join("Microsoft Edge");
        if edge_dir.is_dir() {
            v.extend(chromium_profile_cache_paths(&edge_dir));
            v.push(edge_dir);
        }
    }
    v
}

fn firefox_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let ff_dir = caches.join("Firefox").join("Profiles");
        if let Ok(entries) = fs::read_dir(&ff_dir) {
            for entry in entries.flatten() {
                let cache2 = entry.path().join("cache2");
                if cache2.is_dir() {
                    v.push(cache2);
                }
            }
        }
    }
    v
}

fn claude_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = home_dir() {
        let claude_home = home.join(".claude");
        if claude_home.is_dir() {
            v.push(claude_home.join("cache"));
            v.push(claude_home.join("paste-cache"));
            v.push(claude_home.join("shell-snapshots"));
        }
    }
    if let Some(caches) = user_caches() {
        let claude_caches = caches.join("Claude");
        if claude_caches.is_dir() {
            v.push(claude_caches);
        }
    }
    v
}

fn is_in_disposable_codex_dir(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == ".tmp" || s == "cache" || s == "ambient-suggestions" || s == "logs"
    })
}

fn codex_recurse_filter(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    if name == "skills" || name == "sessions" || name == "auth" || name == "config" {
        return false;
    }
    if name == ".tmp" || name == "cache" || name == "ambient-suggestions" || name == "logs" {
        return true;
    }
    is_in_disposable_codex_dir(path)
}

fn codex_log_filter(parent: &Path, name: &str) -> bool {
    if is_in_disposable_codex_dir(parent) {
        return true;
    }
    name.starts_with("sandbox.") && name.ends_with(".log")
}

fn codex_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = home_dir() {
        let codex_home = home.join(".codex");
        if codex_home.is_dir() {
            v.push(codex_home);
        }
    }
    v
}

fn vscode_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let code_dir = caches.join("com.microsoft.VSCode");
        if code_dir.is_dir() {
            v.push(code_dir);
        }
    }
    v
}

fn discord_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let discord_dir = caches.join("com.hnc.Discord");
        if discord_dir.is_dir() {
            v.push(discord_dir);
        }
    }
    v
}

fn cargo_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = home_dir() {
        v.push(home.join(".cargo").join("registry").join("cache"));
    }
    v
}

fn npm_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = home_dir() {
        v.push(home.join(".npm").join("_cacache"));
    }
    v
}

fn pip_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        v.push(caches.join("pip"));
    }
    v
}

fn go_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        v.push(caches.join("go-build"));
    }
    v
}

fn powershell_history_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(data) = crate::platform::xdg::user_root("XDG_DATA_HOME", ".local/share") {
        v.push(
            data.join("powershell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
        );
    }
    v
}

fn diagnostic_report_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lib) = user_library() {
        let diag = lib.join("Logs").join("DiagnosticReports");
        if diag.is_dir() {
            v.push(diag);
        }
    }
    v
}

fn diagnostic_report_filter(_parent: &Path, name: &str) -> bool {
    name.ends_with(".ips") || name.ends_with(".crash") || name.ends_with(".diag")
}

fn quicklook_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(caches) = user_caches() {
        let ql = caches.join("com.apple.QuickLook.thumbnailcache");
        if ql.is_dir() {
            v.push(ql);
        }
    }
    v
}

static TARGET_RULES: &[TargetPathRule] = &[
    TargetPathRule {
        target_id: "browser.residue.safari-cache",
        path_display: "~/Library/Caches/com.apple.Safari",
        resolve_paths: safari_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.chrome-cache",
        path_display: "~/Library/Caches/Google/Chrome",
        resolve_paths: chrome_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.firefox-cache",
        path_display: "~/Library/Caches/Firefox/Profiles/*/cache2",
        resolve_paths: firefox_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.brave-cache",
        path_display: "~/Library/Caches/BraveSoftware/Brave-Browser",
        resolve_paths: brave_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.edge-cache",
        path_display: "~/Library/Caches/Microsoft Edge",
        resolve_paths: edge_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.claude",
        path_display: "~/.claude/cache and ~/Library/Caches/Claude",
        resolve_paths: claude_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.codex",
        path_display: "~/.codex/.tmp, cache, logs",
        resolve_paths: codex_cache_paths,
        file_filter: Some(codex_log_filter),
        recurse_filter: Some(codex_recurse_filter),
    },
    TargetPathRule {
        target_id: "editor.residue.vscode",
        path_display: "~/Library/Caches/com.microsoft.VSCode",
        resolve_paths: vscode_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "app.residue.discord",
        path_display: "~/Library/Caches/com.hnc.Discord",
        resolve_paths: discord_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.cargo-cache",
        path_display: "~/.cargo/registry/cache",
        resolve_paths: cargo_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.npm-cache",
        path_display: "~/.npm/_cacache",
        resolve_paths: npm_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.pip-cache",
        path_display: "~/Library/Caches/pip",
        resolve_paths: pip_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.go-cache",
        path_display: "~/Library/Caches/go-build",
        resolve_paths: go_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "macos.residue.powershell-history",
        path_display: "$XDG_DATA_HOME/powershell/PSReadLine/ConsoleHost_history.txt",
        resolve_paths: powershell_history_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "macos.residue.diagnostic-reports",
        path_display: "~/Library/Logs/DiagnosticReports (*.ips, *.crash)",
        resolve_paths: diagnostic_report_paths,
        file_filter: Some(diagnostic_report_filter),
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "macos.residue.quicklook",
        path_display: "~/Library/Caches/com.apple.QuickLook.thumbnailcache",
        resolve_paths: quicklook_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
];

fn find_rule(id: &str) -> Option<&'static TargetPathRule> {
    TARGET_RULES.iter().find(|r| r.target_id == id)
}

fn scan_path(
    path: &Path,
    filter: Option<fn(&Path, &str) -> bool>,
    recurse_filter: Option<fn(&Path) -> bool>,
    _is_root_dir: bool,
    max_depth: usize,
) -> (usize, u64) {
    if max_depth == 0 || !path.exists() {
        return (0, 0);
    }

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return (0, 0),
    };

    if meta.file_type().is_symlink() {
        return (0, 0);
    }

    if meta.is_file() {
        if let Some(f) = filter {
            let parent = path.parent().unwrap_or(path);
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !f(parent, name) {
                return (0, 0);
            }
        }
        return (1, meta.len());
    }

    if meta.is_dir() {
        let mut count = 0;
        let mut bytes = 0;

        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return (0, 0),
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();
            let entry_meta = match fs::symlink_metadata(&entry_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if entry_meta.file_type().is_symlink() {
                continue;
            }

            if entry_meta.is_file() {
                if let Some(f) = filter {
                    let name = entry.file_name();
                    let name_str = name.to_str().unwrap_or("");
                    if !f(path, name_str) {
                        continue;
                    }
                }
                count += 1;
                bytes += entry_meta.len();
            } else if entry_meta.is_dir() {
                let allow_recurse = match recurse_filter {
                    Some(rf) => rf(&entry_path),
                    None => filter.is_none(),
                };
                if allow_recurse {
                    let (sub_count, sub_bytes) =
                        scan_path(&entry_path, filter, recurse_filter, false, max_depth - 1);
                    count += sub_count;
                    bytes += sub_bytes;
                }
            }
        }

        return (count, bytes);
    }

    (0, 0)
}

fn purge_path(
    path: &Path,
    filter: Option<fn(&Path, &str) -> bool>,
    recurse_filter: Option<fn(&Path) -> bool>,
    is_target_root: bool,
    max_depth: usize,
    cancellation: &crate::platform::cancellation::Cancellation,
) -> (usize, u64, usize) {
    if cancellation.requested() {
        return (0, 0, 0);
    }
    if max_depth == 0 {
        return (0, 0, 1);
    }

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (0, 0, 0),
        Err(_) => return (0, 0, 1),
    };

    if meta.file_type().is_symlink() {
        return (0, 0, 0);
    }

    if meta.is_file() {
        if let Some(f) = filter {
            let parent = path.parent().unwrap_or(path);
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !f(parent, name) {
                return (0, 0, 0);
            }
        }
        let len = meta.len();
        if fs::remove_file(path).is_ok() {
            return (1, len, 0);
        }
        return (0, 0, 1);
    }

    if meta.is_dir() {
        let mut removed = 0;
        let mut bytes = 0;
        let mut retained = 0;

        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return (0, 0, 1),
        };

        for entry in entries {
            if cancellation.requested() {
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    retained += 1;
                    continue;
                }
            };
            let entry_path = entry.path();
            let entry_meta = match fs::symlink_metadata(&entry_path) {
                Ok(m) => m,
                Err(_) => {
                    retained += 1;
                    continue;
                }
            };

            if entry_meta.file_type().is_symlink() {
                continue;
            }

            if entry_meta.is_file() {
                if let Some(f) = filter {
                    let name = entry.file_name();
                    let name_str = name.to_str().unwrap_or("");
                    if !f(path, name_str) {
                        continue;
                    }
                }
                let len = entry_meta.len();
                if fs::remove_file(&entry_path).is_ok() {
                    removed += 1;
                    bytes += len;
                } else {
                    retained += 1;
                }
            } else if entry_meta.is_dir() {
                let allow_recurse = match recurse_filter {
                    Some(rf) => rf(&entry_path),
                    None => filter.is_none(),
                };
                if allow_recurse {
                    let (sub_rem, sub_bytes, sub_ret) = purge_path(
                        &entry_path,
                        filter,
                        recurse_filter,
                        false,
                        max_depth - 1,
                        cancellation,
                    );
                    removed += sub_rem;
                    bytes += sub_bytes;
                    retained += sub_ret;
                    if !cancellation.requested() {
                        let _ = fs::remove_dir(&entry_path);
                    }
                }
            }
        }

        if !cancellation.requested() && !is_target_root && filter.is_none() && retained == 0 {
            let _ = fs::remove_dir(path);
        }

        return (removed, bytes, retained);
    }

    (0, 0, 0)
}

/// Inspects a residue target and returns its preview.
pub fn inspect_target(
    spec: &ResidueSpec,
    selected: bool,
    retained_reason: Option<String>,
) -> ResiduePreviewItem {
    let rule = find_rule(&spec.id);
    let (path_display, file_count, size_bytes) = match rule {
        Some(r) => {
            let paths = (r.resolve_paths)();
            let mut total_count = 0;
            let mut total_bytes = 0;
            for p in paths {
                let (c, b) = scan_path(&p, r.file_filter, r.recurse_filter, true, 8);
                total_count += c;
                total_bytes += b;
            }
            (r.path_display.to_owned(), total_count, total_bytes)
        }
        None => ("(unknown location)".to_owned(), 0, 0),
    };

    ResiduePreviewItem {
        id: spec.id.clone(),
        title: spec.title.clone(),
        category: spec.category,
        trade_off: spec.trade_off.clone(),
        path_display,
        file_count,
        size_bytes,
        selected,
        retained_reason,
        requires_risk_ack: spec.requires_risk_ack,
    }
}

/// Executes the purge operation for a single target spec.
pub fn purge_target(
    spec: &ResidueSpec,
    cancellation: &crate::platform::cancellation::Cancellation,
) -> ResiduePurgeItem {
    let rule = find_rule(&spec.id);
    match rule {
        Some(r) => {
            let paths = (r.resolve_paths)();
            let mut total_removed = 0;
            let mut total_bytes = 0;
            let mut total_retained = 0;

            for p in paths {
                let (rem, b, ret) =
                    purge_path(&p, r.file_filter, r.recurse_filter, true, 8, cancellation);
                total_removed += rem;
                total_bytes += b;
                total_retained += ret;
            }

            ResiduePurgeItem {
                id: spec.id.clone(),
                title: spec.title.clone(),
                category: spec.category,
                trade_off: spec.trade_off.clone(),
                files_removed: total_removed,
                bytes_reclaimed: total_bytes,
                files_retained: total_retained,
                error: None,
            }
        }
        None => ResiduePurgeItem {
            id: spec.id.clone(),
            title: spec.title.clone(),
            category: spec.category,
            trade_off: spec.trade_off.clone(),
            files_removed: 0,
            bytes_reclaimed: 0,
            files_retained: 0,
            error: Some("No adapter rule configured for target".to_owned()),
        },
    }
}

/// Check whether hardware TRIM is active on macOS.
pub fn check_volume_trim_support() -> TrimStatus {
    TrimStatus {
        volume: "/".to_owned(),
        media_type: "SSD".to_owned(),
        supported: false,
        executed: false,
        message: "APFS natively executes continuous background TRIM; manual invocation not required on macOS"
            .to_owned(),
    }
}

/// Execute volume trim on macOS.
pub fn execute_volume_trim() -> TrimStatus {
    let mut status = check_volume_trim_support();
    status.message =
        "APFS automatically reclaims and discards unallocated flash blocks on macOS".to_owned();
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_rules_have_valid_path_display() {
        for rule in TARGET_RULES {
            assert!(!rule.target_id.is_empty());
            assert!(!rule.path_display.is_empty());
        }
    }

    #[test]
    fn diagnostic_reports_filter_matches_expected_extensions() {
        assert!(diagnostic_report_filter(Path::new("dummy"), "crash.ips"));
        assert!(diagnostic_report_filter(Path::new("dummy"), "app.crash"));
        assert!(diagnostic_report_filter(Path::new("dummy"), "trace.diag"));
        assert!(!diagnostic_report_filter(Path::new("dummy"), "data.txt"));
        assert!(!diagnostic_report_filter(Path::new("dummy"), "report.json"));
    }

    #[test]
    fn scan_and_purge_codex_preserves_configs_and_skills_macos() {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "privr-codex-macos-test-{}-{nanos}-{seq}",
            std::process::id()
        ));
        let tmp_dir = root.join(".tmp").join("nested");
        let cache_dir = root.join("cache");
        let skills_dir = root.join("skills");

        fs::create_dir_all(&tmp_dir).expect("create tmp dir");
        fs::create_dir_all(&cache_dir).expect("create cache dir");
        fs::create_dir_all(&skills_dir).expect("create skills dir");

        let disposable_tmp_file = tmp_dir.join("scratch.tmp");
        let disposable_cache_file = cache_dir.join("weights.bin");
        let disposable_log_file = root.join("sandbox.test.log");
        let preserved_config_file = root.join("config.json");
        let preserved_skill_file = skills_dir.join("my_skill.md");

        fs::write(&disposable_tmp_file, "temp data").expect("write file");
        fs::write(&disposable_cache_file, "cached weights").expect("write file");
        fs::write(&disposable_log_file, "sandbox log").expect("write file");
        fs::write(&preserved_config_file, "{\"key\":\"val\"}").expect("write file");
        fs::write(&preserved_skill_file, "# Skill").expect("write file");

        let (count, bytes) = scan_path(
            &root,
            Some(codex_log_filter),
            Some(codex_recurse_filter),
            true,
            8,
        );
        assert_eq!(count, 3, "should count exactly 3 disposable files");
        assert!(bytes > 0);

        let (rem, rem_bytes, ret) = purge_path(
            &root,
            Some(codex_log_filter),
            Some(codex_recurse_filter),
            true,
            8,
            &crate::platform::cancellation::Cancellation::default(),
        );
        assert_eq!(rem, 3);
        assert_eq!(rem_bytes, bytes);
        assert_eq!(ret, 0);

        assert!(!disposable_tmp_file.exists());
        assert!(!disposable_cache_file.exists());
        assert!(!disposable_log_file.exists());

        assert!(preserved_config_file.exists());
        assert!(preserved_skill_file.exists());

        let _ = fs::remove_dir_all(&root);
    }
}
