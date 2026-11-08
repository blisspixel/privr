//! Linux residue inspection and purge adapter.
//!
//! Provides symlink-safe scanning and deletion of reviewed disposable caches
//! and temporary files across standard XDG locations. Symlinks are never
//! followed, and target root directories are strictly preserved.

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::residue::{ResiduePreviewItem, ResiduePurgeItem, ResidueSpec, TrimStatus};

/// Internal target descriptor mapping a spec ID to filesystem locations and filters.
struct TargetPathRule {
    target_id: &'static str,
    path_display: &'static str,
    resolve_paths: fn() -> Vec<PathBuf>,
    root: UserRoot,
    file_filter: Option<fn(&Path, &str) -> bool>,
    recurse_filter: Option<fn(&Path) -> bool>,
}

enum UserRoot {
    Home,
    Cache,
    Config,
    Data,
    HomeOrConfig,
}

impl UserRoot {
    fn available(&self) -> bool {
        match self {
            Self::Home => home_dir().is_some(),
            Self::Cache => xdg_cache_home().is_some(),
            Self::Config => xdg_config_home().is_some(),
            Self::Data => xdg_data_home().is_some(),
            Self::HomeOrConfig => home_dir().is_some() || xdg_config_home().is_some(),
        }
    }
}

const INVALID_ROOT: &str = "Cannot resolve target: no absolute user root is available";

use crate::platform::xdg::home_dir;

fn xdg_cache_home() -> Option<PathBuf> {
    crate::platform::xdg::user_root("XDG_CACHE_HOME", ".cache")
}

fn xdg_config_home() -> Option<PathBuf> {
    crate::platform::xdg::user_root("XDG_CONFIG_HOME", ".config")
}

fn xdg_data_home() -> Option<PathBuf> {
    crate::platform::xdg::user_root("XDG_DATA_HOME", ".local/share")
}

fn thumbnail_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cache) = xdg_cache_home() {
        let thumb_root = cache.join("thumbnails");
        v.push(thumb_root.join("normal"));
        v.push(thumb_root.join("large"));
        v.push(thumb_root.join("x-large"));
        v.push(thumb_root.join("xx-large"));
        v.push(thumb_root.join("fail"));
    }
    v
}

fn mesa_shader_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cache) = xdg_cache_home() {
        v.push(cache.join("mesa_shader_cache"));
    }
    v
}

fn recent_files_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(data) = xdg_data_home() {
        v.push(data.join("recently-used.xbel"));
    }
    v
}

fn powershell_history_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(data) = xdg_data_home() {
        v.push(
            data.join("powershell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
        );
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
    if let Some(cache) = xdg_cache_home() {
        let chrome_dir = cache.join("google-chrome");
        if chrome_dir.is_dir() {
            v.extend(chromium_profile_cache_paths(&chrome_dir));
            v.push(chrome_dir);
        }
    }
    v
}

fn chromium_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cache) = xdg_cache_home() {
        let chrom_dir = cache.join("chromium");
        if chrom_dir.is_dir() {
            v.extend(chromium_profile_cache_paths(&chrom_dir));
            v.push(chrom_dir);
        }
    }
    v
}

fn brave_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cache) = xdg_cache_home() {
        let brave_dir = cache.join("BraveSoftware").join("Brave-Browser");
        if brave_dir.is_dir() {
            v.extend(chromium_profile_cache_paths(&brave_dir));
            v.push(brave_dir);
        }
    }
    v
}

fn edge_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cache) = xdg_cache_home() {
        let edge_dir = cache.join("microsoft-edge");
        if edge_dir.is_dir() {
            v.extend(chromium_profile_cache_paths(&edge_dir));
            v.push(edge_dir);
        }
    }
    v
}

fn firefox_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cache) = xdg_cache_home() {
        let ff_dir = cache.join("mozilla").join("firefox");
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
    if let Some(cfg) = xdg_config_home() {
        let claude_cfg = cfg.join("Claude");
        if claude_cfg.is_dir() {
            v.push(claude_cfg.join("Cache"));
            v.push(claude_cfg.join("Code Cache"));
            v.push(claude_cfg.join("GPUCache"));
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
    if let Some(cfg) = xdg_config_home() {
        let code_dir = cfg.join("Code");
        if code_dir.is_dir() {
            v.push(code_dir.join("Cache"));
            v.push(code_dir.join("CachedData"));
            v.push(code_dir.join("CachedExtensionVSIXs"));
            v.push(code_dir.join("Code Cache"));
            v.push(code_dir.join("GPUCache"));
        }
    }
    v
}

fn discord_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cfg) = xdg_config_home() {
        let discord_dir = cfg.join("discord");
        if discord_dir.is_dir() {
            v.push(discord_dir.join("Cache"));
            v.push(discord_dir.join("Code Cache"));
            v.push(discord_dir.join("GPUCache"));
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
    if let Some(cache) = xdg_cache_home() {
        v.push(cache.join("pip"));
    }
    v
}

fn go_cache_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cache) = xdg_cache_home() {
        v.push(cache.join("go-build"));
    }
    v
}

static TARGET_RULES: &[TargetPathRule] = &[
    TargetPathRule {
        target_id: "linux.residue.thumbnails",
        path_display: "$XDG_CACHE_HOME/thumbnails/*",
        resolve_paths: thumbnail_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "linux.residue.mesa-shader",
        path_display: "$XDG_CACHE_HOME/mesa_shader_cache",
        resolve_paths: mesa_shader_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "linux.residue.recent-files",
        path_display: "$XDG_DATA_HOME/recently-used.xbel",
        resolve_paths: recent_files_paths,
        root: UserRoot::Data,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "linux.residue.powershell-history",
        path_display: "$XDG_DATA_HOME/powershell/PSReadLine/ConsoleHost_history.txt",
        resolve_paths: powershell_history_paths,
        root: UserRoot::Data,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.firefox-cache",
        path_display: "$XDG_CACHE_HOME/mozilla/firefox/*/cache2",
        resolve_paths: firefox_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.chrome-cache",
        path_display: "$XDG_CACHE_HOME/google-chrome/*/Cache",
        resolve_paths: chrome_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.chromium-cache",
        path_display: "$XDG_CACHE_HOME/chromium/*/Cache",
        resolve_paths: chromium_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.brave-cache",
        path_display: "$XDG_CACHE_HOME/BraveSoftware/Brave-Browser/*/Cache",
        resolve_paths: brave_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "browser.residue.edge-cache",
        path_display: "$XDG_CACHE_HOME/microsoft-edge/*/Cache",
        resolve_paths: edge_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.claude",
        path_display: "~/.claude/cache and $XDG_CONFIG_HOME/Claude/Cache",
        resolve_paths: claude_cache_paths,
        root: UserRoot::HomeOrConfig,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "ai.residue.codex",
        path_display: "~/.codex/.tmp, cache, logs",
        resolve_paths: codex_cache_paths,
        root: UserRoot::Home,
        file_filter: Some(codex_log_filter),
        recurse_filter: Some(codex_recurse_filter),
    },
    TargetPathRule {
        target_id: "editor.residue.vscode",
        path_display: "$XDG_CONFIG_HOME/Code/Cache and CachedData",
        resolve_paths: vscode_cache_paths,
        root: UserRoot::Config,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "app.residue.discord",
        path_display: "$XDG_CONFIG_HOME/discord/Cache",
        resolve_paths: discord_cache_paths,
        root: UserRoot::Config,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.cargo-cache",
        path_display: "~/.cargo/registry/cache",
        resolve_paths: cargo_cache_paths,
        root: UserRoot::Home,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.npm-cache",
        path_display: "~/.npm/_cacache",
        resolve_paths: npm_cache_paths,
        root: UserRoot::Home,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.pip-cache",
        path_display: "$XDG_CACHE_HOME/pip",
        resolve_paths: pip_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
    TargetPathRule {
        target_id: "dev.residue.go-cache",
        path_display: "$XDG_CACHE_HOME/go-build",
        resolve_paths: go_cache_paths,
        root: UserRoot::Cache,
        file_filter: None,
        recurse_filter: None,
    },
];

fn find_rule(id: &str) -> Option<&'static TargetPathRule> {
    TARGET_RULES.iter().find(|r| r.target_id == id)
}

pub(crate) fn validate_target_root(spec: &ResidueSpec) -> Result<(), &'static str> {
    match find_rule(&spec.id) {
        Some(rule) if rule.root.available() => Ok(()),
        Some(_) => Err(INVALID_ROOT),
        None => Err("No adapter rule configured for target"),
    }
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
    if let Some(rule) = rule
        && !rule.root.available()
    {
        return ResiduePreviewItem {
            id: spec.id.clone(),
            title: spec.title.clone(),
            category: spec.category,
            trade_off: spec.trade_off.clone(),
            path_display: rule.path_display.to_owned(),
            file_count: 0,
            size_bytes: 0,
            selected: false,
            retained_reason: Some(INVALID_ROOT.to_owned()),
            requires_risk_ack: spec.requires_risk_ack,
        };
    }
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
        Some(r) if !r.root.available() => ResiduePurgeItem {
            id: spec.id.clone(),
            title: spec.title.clone(),
            category: spec.category,
            trade_off: spec.trade_off.clone(),
            files_removed: 0,
            bytes_reclaimed: 0,
            files_retained: 0,
            error: Some(INVALID_ROOT.to_owned()),
        },
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

/// Check whether the root mount supports hardware TRIM on Linux.
pub fn check_volume_trim_support() -> TrimStatus {
    // Check if fstrim is available in PATH
    let fstrim_exists = std::process::Command::new("fstrim")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !fstrim_exists {
        return TrimStatus {
            volume: "/".to_owned(),
            media_type: "Unknown".to_owned(),
            supported: false,
            executed: false,
            message: "fstrim utility not found in PATH; hardware TRIM not available".to_owned(),
        };
    }

    // Run fstrim dry-run on /
    let dry_run = std::process::Command::new("fstrim")
        .args(["--dry-run", "-v", "/"])
        .output();

    match dry_run {
        Ok(out) if out.status.success() => TrimStatus {
            volume: "/".to_owned(),
            media_type: "SSD".to_owned(),
            supported: true,
            executed: false,
            message: "Root filesystem eligible for fstrim cluster deallocation (0 B flash wear)"
                .to_owned(),
        },
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            TrimStatus {
                volume: "/".to_owned(),
                media_type: "Unknown".to_owned(),
                supported: false,
                executed: false,
                message: if !stderr.is_empty() {
                    format!("fstrim check reported: {stderr}")
                } else {
                    "Underlying block device does not support discard or requires elevated privilege".to_owned()
                },
            }
        }
        Err(e) => TrimStatus {
            volume: "/".to_owned(),
            media_type: "Unknown".to_owned(),
            supported: false,
            executed: false,
            message: format!("Failed to check fstrim support: {e}"),
        },
    }
}

/// Execute fstrim across the root filesystem.
pub fn execute_volume_trim() -> TrimStatus {
    let mut status = check_volume_trim_support();
    if !status.supported {
        return status;
    }

    let output = std::process::Command::new("fstrim")
        .args(["-v", "/"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            status.executed = true;
            status.message =
                format!("Hardware TRIM / fstrim completed on / (0 B flash wear): {stdout}");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            status.message = format!("fstrim failed: {stderr}");
        }
        Err(e) => {
            status.message = format!("Failed to launch fstrim: {e}");
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_rules_have_valid_path_display() {
        for rule in TARGET_RULES {
            assert!(!rule.target_id.is_empty());
            assert!(!rule.path_display.is_empty());
        }
    }

    #[test]
    fn codex_disposable_filtering_and_recursion_linux() {
        let codex_root = Path::new("/home/user/.codex");
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
    fn scan_and_purge_codex_preserves_configs_and_skills_linux() {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "privr-codex-linux-test-{}-{nanos}-{seq}",
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

    #[test]
    fn chromium_profile_cache_resolver_linux() {
        let temp =
            std::env::temp_dir().join(format!("privr-chrometest-linux-{}", std::process::id()));
        let default_profile = temp.join("Default");
        let profile_1 = temp.join("Profile 1");
        let other_dir = temp.join("System Profile");
        let _ = fs::create_dir_all(default_profile.join("Cache"));
        let _ = fs::create_dir_all(profile_1.join("Code Cache"));
        let _ = fs::create_dir_all(temp.join("ShaderCache"));
        let _ = fs::create_dir_all(other_dir);

        let paths = chromium_profile_cache_paths(&temp);
        let path_strs: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();

        assert!(path_strs.iter().any(|p| p.contains("ShaderCache")));
        assert!(
            path_strs
                .iter()
                .any(|p| p.contains("Default") && p.contains("Cache"))
        );
        assert!(
            path_strs
                .iter()
                .any(|p| p.contains("Profile 1") && p.contains("Code Cache"))
        );

        let _ = fs::remove_dir_all(&temp);
    }
}
