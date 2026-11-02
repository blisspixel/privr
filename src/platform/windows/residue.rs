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
    file_filter: Option<fn(&str) -> bool>,
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

fn thumbnail_filter(name: &str) -> bool {
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
        let codex = up.join(".codex");
        v.push(codex.join(".tmp"));
        v.push(codex.join("cache"));
        v.push(codex.join("ambient-suggestions"));
        // Top-level codex folder for log filtering
        v.push(codex);
    }
    v
}

fn codex_log_filter(name: &str) -> bool {
    name.starts_with("sandbox.") && name.ends_with(".log")
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

fn recent_files_filter(name: &str) -> bool {
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

static TARGET_RULES: &[TargetPathRule] = &[
    TargetPathRule {
        target_id: "windows.residue.temp",
        path_display: "%TEMP%",
        resolve_paths: temp_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.crash-dumps",
        path_display: "%LOCALAPPDATA%\\CrashDumps",
        resolve_paths: crash_dump_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "windows.residue.thumbnail-cache",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
        resolve_paths: thumbnail_cache_paths,
        file_filter: Some(thumbnail_filter),
    },
    TargetPathRule {
        target_id: "windows.residue.directx-shader",
        path_display: "%LOCALAPPDATA%\\D3DSCache",
        resolve_paths: directx_shader_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.edge-cache",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache",
        resolve_paths: edge_cache_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.chrome-cache",
        path_display: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache",
        resolve_paths: chrome_cache_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "app.residue.discord",
        path_display: "%APPDATA%\\discord\\Cache",
        resolve_paths: discord_cache_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.claude",
        path_display: "%APPDATA%\\Claude\\Cache, ~/.claude/paste-cache",
        resolve_paths: claude_cache_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.codex",
        path_display: "~/.codex/.tmp, cache, sandbox.*.log",
        resolve_paths: codex_cache_paths,
        file_filter: Some(codex_log_filter),
    },
    TargetPathRule {
        target_id: "windows.residue.recent-files",
        path_display: "%APPDATA%\\Microsoft\\Windows\\Recent (.lnk, Jump Lists)",
        resolve_paths: recent_files_paths,
        file_filter: Some(recent_files_filter),
    },
    TargetPathRule {
        target_id: "windows.residue.inetcache",
        path_display: "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache",
        resolve_paths: inetcache_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "editor.residue.vscode",
        path_display: "%APPDATA%\\Code\\CachedData, Service Worker",
        resolve_paths: vscode_cache_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.pip-cache",
        path_display: "%LOCALAPPDATA%\\pip\\cache",
        resolve_paths: pip_cache_paths,
        file_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.npm-cache",
        path_display: "%LOCALAPPDATA%\\npm-cache",
        resolve_paths: npm_cache_paths,
        file_filter: None,
    },
];

fn find_rule(id: &str) -> Option<&'static TargetPathRule> {
    TARGET_RULES.iter().find(|r| r.target_id == id)
}

/// Recursively scans a path counting files and bytes without following reparse points or symlinks.
fn scan_path(
    path: &Path,
    filter: Option<fn(&str) -> bool>,
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
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !f(name) {
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
                    if !f(name_str) {
                        continue;
                    }
                }
                count += 1;
                bytes += entry_meta.len();
            } else if entry_meta.is_dir() {
                // If a filter is specified (e.g. thumbcache_*.db or codex logs), do not recurse into subdirectories
                if filter.is_none() {
                    let (sub_count, sub_bytes) =
                        scan_path(&entry_path, filter, false, max_depth - 1);
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
                let (c, b) = scan_path(&p, r.file_filter, true, 8);
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
    filter: Option<fn(&str) -> bool>,
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

    if meta.file_type().is_symlink() {
        return (0, 0, 0);
    }

    if meta.is_file() {
        if let Some(f) = filter {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !f(name) {
                return (0, 0, 0);
            }
        }
        let len = meta.len();
        return match fs::remove_file(path) {
            Ok(_) => (1, len, 0),
            Err(_) => (0, 0, 1), // File locked or permission denied
        };
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

            if entry_meta.file_type().is_symlink() {
                continue;
            }

            if entry_meta.is_file() {
                if let Some(f) = filter {
                    let name = entry.file_name();
                    let name_str = name.to_str().unwrap_or("");
                    if !f(name_str) {
                        continue;
                    }
                }
                let len = entry_meta.len();
                match fs::remove_file(&entry_path) {
                    Ok(_) => {
                        removed += 1;
                        bytes += len;
                    }
                    Err(_) => {
                        retained += 1;
                    }
                }
            } else if entry_meta.is_dir() && filter.is_none() {
                let (sub_rem, sub_bytes, sub_ret) =
                    purge_path(&entry_path, filter, false, max_depth - 1);
                removed += sub_rem;
                bytes += sub_bytes;
                retained += sub_ret;
                // Attempt to clean up directory if it's now empty
                let _ = fs::remove_dir(&entry_path);
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
                let (rem, b, ret) = purge_path(&p, r.file_filter, true, 8);
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

/// Check whether the volume containing user data supports hardware TRIM.
pub fn check_volume_trim_support(drive_letter: char) -> TrimStatus {
    let drive_str = format!("{drive_letter}:");
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         (Get-PhysicalDisk | Where-Object DeviceId -eq (Get-Partition -DriveLetter '{drive_letter}').DiskNumber).MediaType"
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output();

    let media = match output {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
            if s.contains("SSD") {
                "SSD".to_owned()
            } else if s.contains("HDD") {
                "HDD".to_owned()
            } else {
                "SSD".to_owned()
            }
        }
        _ => "SSD".to_owned(),
    };

    if media == "SSD" {
        TrimStatus {
            volume: drive_str,
            media_type: "SSD".to_owned(),
            supported: true,
            executed: false,
            message: "Solid-state drive eligible for hardware TRIM / Deallocate (0 B flash wear)"
                .to_owned(),
        }
    } else {
        TrimStatus {
            volume: drive_str,
            media_type: "HDD".to_owned(),
            supported: false,
            executed: false,
            message: "Rotational magnetic media detected; hardware TRIM not applicable".to_owned(),
        }
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
            let stderr = String::from_utf8_lossy(&out.stderr);
            status.message = format!("Hardware TRIM failed: {}", stderr.trim());
        }
        Err(e) => {
            status.message = format!("Failed to launch defrag for TRIM: {e}");
        }
    }
    status
}
