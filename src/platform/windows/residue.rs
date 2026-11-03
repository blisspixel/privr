//! Windows residue inspection and purge adapter.
//!
//! Provides lock-aware scanning and safe deletion of reviewed disposable caches
//! and temporary files. Symlinks and reparse points are never traversed. Locked
//! files are skipped without failing the overall operation.

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

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

fn local_app_data() -> Option<PathBuf> {
    env_path("LOCALAPPDATA")
        .or_else(|| env_path("USERPROFILE").map(|p| p.join("AppData").join("Local")))
}

fn app_data() -> Option<PathBuf> {
    env_path("APPDATA")
        .or_else(|| env_path("USERPROFILE").map(|p| p.join("AppData").join("Roaming")))
}

fn user_profile() -> Option<PathBuf> {
    env_path("USERPROFILE")
}

fn temp_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(t) = env_path("TEMP").or_else(|| env_path("TMP")) {
        v.push(t);
    }
    v
}

fn crash_dump_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        v.push(lad.join("CrashDumps"));
    }
    v
}

fn thumbnail_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        v.push(lad.join("Microsoft").join("Windows").join("Explorer"));
    }
    v
}

fn thumbnail_filter(_parent: &Path, name: &str) -> bool {
    name.starts_with("thumbcache_") && name.ends_with(".db")
}

fn directx_shader_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        v.push(lad.join("D3DSCache"));
    }
    v
}

fn edge_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        let edge_default = lad
            .join("Microsoft")
            .join("Edge")
            .join("User Data")
            .join("Default");
        v.push(edge_default.join("Cache").join("Cache_Data"));
        v.push(edge_default.join("Code Cache"));
        v.push(edge_default.join("GPUCache"));
    }
    v
}

fn chrome_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        let chrome_default = lad
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        v.push(chrome_default.join("Cache").join("Cache_Data"));
        v.push(chrome_default.join("Code Cache"));
        v.push(chrome_default.join("GPUCache"));
    }
    v
}

fn discord_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(ad) = app_data() {
        let discord = ad.join("discord");
        v.push(discord.join("Cache"));
        v.push(discord.join("Code Cache"));
        v.push(discord.join("GPUCache"));
        v.push(discord.join("DawnCache"));
        v.push(discord.join("DawnGraphiteCache"));
        v.push(discord.join("DawnWebGPUCache"));
    }
    v
}

fn claude_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(ad) = app_data() {
        let claude_app = ad.join("Claude");
        v.push(claude_app.join("Cache"));
        v.push(claude_app.join("Code Cache"));
    }
    if let Some(up) = user_profile() {
        let claude_home = up.join(".claude");
        v.push(claude_home.join("paste-cache"));
        v.push(claude_home.join("debug"));
        v.push(claude_home.join("shell-snapshots"));
    }
    v
}

fn codex_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(up) = user_profile() {
        v.push(up.join(".codex"));
    }
    v
}

fn is_in_disposable_codex_dir(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str();
        s == ".tmp" || s == "cache" || s == "ambient-suggestions"
    })
}

fn codex_log_filter(parent: &Path, name: &str) -> bool {
    is_in_disposable_codex_dir(parent) || (name.starts_with("sandbox.") && name.ends_with(".log"))
}

fn codex_recurse_filter(dir: &Path) -> bool {
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == ".tmp"
        || name == "cache"
        || name == "ambient-suggestions"
        || is_in_disposable_codex_dir(dir)
}

fn recent_files_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(ad) = app_data() {
        let recent = ad.join("Microsoft").join("Windows").join("Recent");
        v.push(recent.join("AutomaticDestinations"));
        v.push(recent.join("CustomDestinations"));
        v.push(recent);
    }
    v
}

fn recent_files_filter(_parent: &Path, name: &str) -> bool {
    name.ends_with(".lnk")
        || name.ends_with(".automaticDestinations-ms")
        || name.ends_with(".customDestinations-ms")
}

fn inetcache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        v.push(lad.join("Microsoft").join("Windows").join("INetCache"));
    }
    v
}

fn vscode_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(ad) = app_data() {
        let code = ad.join("Code");
        v.push(code.join("Cache"));
        v.push(code.join("CachedData"));
        v.push(code.join("Service Worker").join("CacheStorage"));
    }
    v
}

fn pip_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        v.push(lad.join("pip").join("cache"));
    }
    v
}

fn npm_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        v.push(lad.join("npm-cache"));
    }
    if let Some(ad) = app_data() {
        v.push(ad.join("npm-cache"));
    }
    v
}

fn local_low_app_data() -> Option<PathBuf> {
    local_app_data()
        .and_then(|p| p.parent().map(|appdata| appdata.join("LocalLow")))
        .or_else(|| user_profile().map(|p| p.join("AppData").join("LocalLow")))
}

fn cryptnet_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(ll) = local_low_app_data() {
        let base = ll.join("Microsoft").join("CryptnetUrlCache");
        v.push(base.join("Content"));
        v.push(base.join("MetaData"));
    }
    v
}

fn wer_report_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        let wer = lad.join("Microsoft").join("Windows").join("WER");
        v.push(wer.join("ReportArchive"));
        v.push(wer.join("ReportQueue"));
    }
    if let Some(pdata) = env_path("ProgramData") {
        let wer = pdata.join("Microsoft").join("Windows").join("WER");
        v.push(wer.join("ReportArchive"));
        v.push(wer.join("ReportQueue"));
    }
    v
}

fn firefox_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        let profiles = lad.join("Mozilla").join("Firefox").join("Profiles");
        if let Ok(entries) = fs::read_dir(&profiles) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    v.push(path.join("cache2"));
                    v.push(path.join("startupCache"));
                }
            }
        }
    }
    v
}

fn brave_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        let default_dir = lad
            .join("BraveSoftware")
            .join("Brave-Browser")
            .join("User Data")
            .join("Default");
        v.push(default_dir.join("Cache"));
        v.push(default_dir.join("Code Cache"));
    }
    v
}

fn delivery_optimization_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(lad) = local_app_data() {
        v.push(
            lad.join("Microsoft")
                .join("Windows")
                .join("DeliveryOptimization")
                .join("Cache"),
        );
    }
    v
}

fn powershell_history_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(ad) = app_data() {
        v.push(
            ad.join("Microsoft")
                .join("Windows")
                .join("PowerShell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
        );
    }
    v
}

static TARGET_RULES: &[TargetPathRule] = &[
    TargetPathRule {
        target_id: "windows.residue.temp",
        path_display: "%TEMP%",
        resolve_paths: temp_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.crash-dumps",
        path_display: "%LOCALAPPDATA%\\CrashDumps",
        resolve_paths: crash_dump_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.thumbnail-cache",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
        resolve_paths: thumbnail_cache_paths,
        file_filter: Some(thumbnail_filter),
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.directx-shader",
        path_display: "%LOCALAPPDATA%\\D3DSCache",
        resolve_paths: directx_shader_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.edge-cache",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache",
        resolve_paths: edge_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.chrome-cache",
        path_display: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache",
        resolve_paths: chrome_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "app.residue.discord",
        path_display: "%APPDATA%\\discord\\Cache",
        resolve_paths: discord_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.claude",
        path_display: "%APPDATA%\\Claude\\Cache, ~/.claude/paste-cache",
        resolve_paths: claude_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.codex",
        path_display: "~/.codex/.tmp, cache, sandbox.*.log",
        resolve_paths: codex_cache_paths,
        file_filter: Some(codex_log_filter),
        recurse_filter: Some(codex_recurse_filter),
    },
    TargetPathRule {
        target_id: "windows.residue.recent-files",
        path_display: "%APPDATA%\\Microsoft\\Windows\\Recent (.lnk, Jump Lists)",
        resolve_paths: recent_files_paths,
        file_filter: Some(recent_files_filter),
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.inetcache",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache",
        resolve_paths: inetcache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "editor.residue.vscode",
        path_display: "%APPDATA%\\Code\\CachedData, Service Worker",
        resolve_paths: vscode_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.pip-cache",
        path_display: "%LOCALAPPDATA%\\pip\\cache",
        resolve_paths: pip_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.npm-cache",
        path_display: "%LOCALAPPDATA%\\npm-cache",
        resolve_paths: npm_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.cryptnet-cache",
        path_display: "%USERPROFILE%\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache",
        resolve_paths: cryptnet_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.wer-reports",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Windows\\WER (ReportArchive, ReportQueue)",
        resolve_paths: wer_report_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.firefox-cache",
        path_display: "%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cache2",
        resolve_paths: firefox_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.brave-cache",
        path_display: "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache",
        resolve_paths: brave_cache_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.delivery-optimization",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Windows\\DeliveryOptimization\\Cache",
        resolve_paths: delivery_optimization_paths,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.powershell-history",
        path_display: "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        resolve_paths: powershell_history_paths,
        file_filter: None,
        recurse_filter: None,
    },
];

fn find_rule(id: &str) -> Option<&'static TargetPathRule> {
    TARGET_RULES.iter().find(|r| r.target_id == id)
}

/// Determine whether metadata represents a symlink, NTFS junction, or reparse point.
fn is_reparse_point_or_symlink(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_type().is_symlink() || (meta.file_attributes() & 0x0000_0400) != 0
}

/// Reset read-only attribute on Windows to allow deleting disposable cache files.
/// Stated reason: on Windows NTFS, `set_readonly(false)` directly toggles the
/// `FILE_ATTRIBUTE_READONLY` flag without Unix world-writable side effects.
#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly_if_set(meta: &fs::Metadata, path: &Path) {
    let mut perms = meta.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);
    }
}

/// Recursively scans a path counting files and bytes without following reparse points or symlinks.
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

    if is_reparse_point_or_symlink(&meta) {
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

            if is_reparse_point_or_symlink(&entry_meta) {
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
        path_display,
        file_count,
        size_bytes,
        selected,
        retained_reason,
        requires_risk_ack: spec.requires_risk_ack,
    }
}

/// Recursively removes files and empty directories within a target, handling locked files cleanly.
fn purge_path(
    path: &Path,
    filter: Option<fn(&Path, &str) -> bool>,
    recurse_filter: Option<fn(&Path) -> bool>,
    is_target_root: bool,
    max_depth: usize,
) -> (usize, u64, usize) {
    if max_depth == 0 || !path.exists() {
        return (0, 0, 0);
    }

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return (0, 0, 0),
    };

    if is_reparse_point_or_symlink(&meta) {
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
        // Attempt resetting readonly attribute before declaring locked/retained
        clear_readonly_if_set(&meta, path);
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

        for entry in entries.flatten() {
            let entry_path = entry.path();
            let entry_meta = match fs::symlink_metadata(&entry_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if is_reparse_point_or_symlink(&entry_meta) {
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
                    clear_readonly_if_set(&entry_meta, &entry_path);
                    if fs::remove_file(&entry_path).is_ok() {
                        removed += 1;
                        bytes += len;
                        continue;
                    }
                    retained += 1;
                }
            } else if entry_meta.is_dir() {
                let allow_recurse = match recurse_filter {
                    Some(rf) => rf(&entry_path),
                    None => filter.is_none(),
                };
                if allow_recurse {
                    let (sub_rem, sub_bytes, sub_ret) =
                        purge_path(&entry_path, filter, recurse_filter, false, max_depth - 1);
                    removed += sub_rem;
                    bytes += sub_bytes;
                    retained += sub_ret;
                    // Attempt to clean up directory if it's now empty
                    let _ = fs::remove_dir(&entry_path);
                }
            }
        }

        // Never delete the target root directory itself (e.g. %TEMP% or Explorer)
        if !is_target_root && filter.is_none() && retained == 0 {
            let _ = fs::remove_dir(path);
        }

        return (removed, bytes, retained);
    }

    (0, 0, 0)
}

/// Executes the purge operation for a single target spec.
pub fn purge_target(spec: &ResidueSpec) -> ResiduePurgeItem {
    let rule = find_rule(&spec.id);
    match rule {
        Some(r) => {
            let paths = (r.resolve_paths)();
            let mut total_removed = 0;
            let mut total_bytes = 0;
            let mut total_retained = 0;

            for p in paths {
                let (rem, b, ret) = purge_path(&p, r.file_filter, r.recurse_filter, true, 8);
                total_removed += rem;
                total_bytes += b;
                total_retained += ret;
            }

            ResiduePurgeItem {
                id: spec.id.clone(),
                title: spec.title.clone(),
                category: spec.category,
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
            files_removed: 0,
            bytes_reclaimed: 0,
            files_retained: 0,
            error: Some("No adapter rule configured for target".to_owned()),
        },
    }
}

/// Helper to determine the primary Windows system drive letter.
pub fn system_drive_letter() -> char {
    if let Some(ch) = std::env::var("SystemDrive")
        .ok()
        .and_then(|drive| drive.chars().find(|c| c.is_ascii_alphabetic()))
    {
        return ch.to_ascii_uppercase();
    }
    if let Some(ch) = std::env::var("USERPROFILE")
        .ok()
        .and_then(|profile| profile.chars().find(|c| c.is_ascii_alphabetic()))
    {
        return ch.to_ascii_uppercase();
    }
    'C'
}

/// Check whether the volume containing user data supports hardware TRIM.
pub fn check_volume_trim_support(drive_letter: char) -> TrimStatus {
    let drive_letter = drive_letter.to_ascii_uppercase();
    if !drive_letter.is_ascii_alphabetic() {
        return TrimStatus {
            volume: format!("{drive_letter}:"),
            media_type: "Unknown".to_owned(),
            supported: false,
            executed: false,
            message: "Invalid drive letter specified".to_owned(),
        };
    }
    let drive_str = format!("{drive_letter}:");
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         (Get-PhysicalDisk | Where-Object DeviceId -eq (Get-Partition -DriveLetter '{drive_letter}').DiskNumber).MediaType"
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output();

    let (media, supported, msg) = match output {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
            if s.contains("SSD") {
                (
                    "SSD".to_owned(),
                    true,
                    "Solid-state drive eligible for hardware TRIM / Deallocate (0 B flash wear)"
                        .to_owned(),
                )
            } else if s.contains("HDD") {
                (
                    "HDD".to_owned(),
                    false,
                    "Rotational magnetic media detected; hardware TRIM not applicable".to_owned(),
                )
            } else {
                (
                    "Unknown".to_owned(),
                    false,
                    "Storage media type could not be verified; hardware TRIM skipped for safety"
                        .to_owned(),
                )
            }
        }
        _ => (
            "Unknown".to_owned(),
            false,
            "Could not query physical disk media type; hardware TRIM skipped for safety".to_owned(),
        ),
    };

    TrimStatus {
        volume: drive_str,
        media_type: media,
        supported,
        executed: false,
        message: msg,
    }
}

/// Execute hardware TRIM across the volume's unallocated clusters.
pub fn execute_volume_trim(drive_letter: char) -> TrimStatus {
    let mut status = check_volume_trim_support(drive_letter);
    if !status.supported {
        return status;
    }

    let drive_arg = format!("{drive_letter}:");
    let output = std::process::Command::new("defrag.exe")
        .args([&drive_arg, "/L"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            status.executed = true;
            status.message = format!(
                "Hardware TRIM / Deallocate completed on {} (0 B flash wear, active DZAT)",
                status.volume
            );
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let msg = if !stderr.is_empty() {
                stderr
            } else {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .unwrap_or("defrag reported failure")
                    .to_string()
            };
            status.message = format!("Hardware TRIM failed: {msg}");
        }
        Err(e) => {
            status.message = format!("Failed to launch defrag for TRIM: {e}");
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_drive_letter_is_alphabetic() {
        let drive = system_drive_letter();
        assert!(drive.is_ascii_alphabetic());
        assert!(drive.is_ascii_uppercase());
    }

    #[test]
    fn trim_support_rejects_non_alphabetic_character() {
        let status = check_volume_trim_support('?');
        assert!(!status.supported);
        assert!(!status.executed);
        assert_eq!(status.media_type, "Unknown");
        assert!(status.message.contains("Invalid drive letter"));
    }

    #[test]
    fn codex_disposable_filtering_and_recursion() {
        let codex_root = Path::new(r"C:\Users\Test\.codex");
        let tmp_nested = codex_root.join(".tmp").join("session-abc");
        let cache_nested = codex_root.join("cache").join("models");
        let ambient = codex_root.join("ambient-suggestions");
        let skills = codex_root.join("skills");
        let sessions = codex_root.join("sessions");

        assert!(is_in_disposable_codex_dir(&tmp_nested));
        assert!(is_in_disposable_codex_dir(&cache_nested));
        assert!(is_in_disposable_codex_dir(&ambient));
        assert!(!is_in_disposable_codex_dir(&skills));
        assert!(!is_in_disposable_codex_dir(&sessions));

        assert!(codex_recurse_filter(&codex_root.join(".tmp")));
        assert!(codex_recurse_filter(&tmp_nested));
        assert!(codex_recurse_filter(&codex_root.join("cache")));
        assert!(codex_recurse_filter(&cache_nested));
        assert!(codex_recurse_filter(&ambient));
        assert!(!codex_recurse_filter(&skills));
        assert!(!codex_recurse_filter(&sessions));

        assert!(codex_log_filter(codex_root, "sandbox.2026-11-01.log"));
        assert!(!codex_log_filter(codex_root, "config.json"));
        assert!(!codex_log_filter(codex_root, "other.log"));
        assert!(codex_log_filter(&tmp_nested, "output.bin"));
        assert!(codex_log_filter(&cache_nested, "weights.dat"));
    }

    #[test]
    fn scan_and_purge_codex_preserves_configs_and_skills() {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "privr-codex-test-{}-{nanos}-{seq}",
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

    #[test]
    fn local_low_and_cryptnet_resolvers() {
        if let Some(ll) = local_low_app_data() {
            assert!(ll.to_string_lossy().contains("LocalLow"));
        }
        let crypt_paths = cryptnet_cache_paths();
        if !crypt_paths.is_empty() {
            assert!(
                crypt_paths
                    .iter()
                    .any(|p| p.to_string_lossy().contains("Content"))
            );
            assert!(
                crypt_paths
                    .iter()
                    .any(|p| p.to_string_lossy().contains("MetaData"))
            );
        }
    }

    #[test]
    fn wer_report_resolvers() {
        let wer_paths = wer_report_paths();
        if !wer_paths.is_empty() {
            assert!(
                wer_paths
                    .iter()
                    .any(|p| p.to_string_lossy().contains("ReportArchive"))
            );
            assert!(
                wer_paths
                    .iter()
                    .any(|p| p.to_string_lossy().contains("ReportQueue"))
            );
        }
    }
}
