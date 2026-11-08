//! The catalogue of reviewed residue and purge targets.
//!
//! Each entry describes a reviewed category of disposable or rebuildable data,
//! its privacy relevance, trade-offs, and eligibility for polite retention.
//! No target path or deletion rule is accepted from outside the binary.

use crate::model::residue::{PurgeMode, ResidueCategory, ResidueSpec};

/// The compiled list of supported Windows residue targets.
pub static WINDOWS_RESIDUE_TARGETS: &[ResidueSpec] = &[ResidueSpec {
    id: String::new(), // Populated in initializer helper
    title: String::new(),
    category: ResidueCategory::TemporaryFiles,
    description: String::new(),
    trade_off: String::new(),
    polite_retained: false,
    requires_risk_ack: false,
}];

/// Returns all reviewed residue target specifications for the current platform.
pub fn compiled_residue_targets() -> Vec<ResidueSpec> {
    #[cfg(windows)]
    {
        windows_targets()
    }
    #[cfg(target_os = "linux")]
    {
        linux_targets()
    }
    #[cfg(target_os = "macos")]
    {
        macos_targets()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn windows_targets() -> Vec<ResidueSpec> {
    vec![
        ResidueSpec {
            id: "windows.residue.temp".to_owned(),
            title: "User temporary files".to_owned(),
            category: ResidueCategory::TemporaryFiles,
            description: "Temporary extraction and scratch files created in the user profile (%TEMP%).".to_owned(),
            trade_off: "Applications or installers running in the background may re-create scratch files.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.crash-dumps".to_owned(),
            title: "Application crash dumps".to_owned(),
            category: ResidueCategory::CrashDumps,
            description: "Memory dump files (*.dmp) written by Windows Error Reporting when applications crash.".to_owned(),
            trade_off: "Removes diagnostic post-mortem information for recently crashed applications.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.thumbnail-cache".to_owned(),
            title: "File Explorer thumbnail cache".to_owned(),
            category: ResidueCategory::ThumbnailCache,
            description: "Cached thumbnail preview databases (thumbcache_*.db) created by Windows Explorer.".to_owned(),
            trade_off: "Explorer will momentarily regenerate previews when browsing picture and video folders.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.directx-shader".to_owned(),
            title: "DirectX shader cache".to_owned(),
            category: ResidueCategory::ShaderCache,
            description: "Precompiled graphics shader cache files in D3DSCache.".to_owned(),
            trade_off: "3D applications and games will recompile shaders on their next launch.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.edge-cache".to_owned(),
            title: "Microsoft Edge web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page resources, images, and script bytecode for Microsoft Edge.".to_owned(),
            trade_off: "Visited websites will re-download images and resources; logins and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.chrome-cache".to_owned(),
            title: "Google Chrome web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page resources, images, and script bytecode for Google Chrome.".to_owned(),
            trade_off: "Visited websites will re-download images and resources; logins and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "app.residue.discord".to_owned(),
            title: "Discord media cache".to_owned(),
            category: ResidueCategory::AppCache,
            description: "Cached avatars, embedded images, and media attachments from Discord.".to_owned(),
            trade_off: "Media in channels will be re-downloaded when viewed; account and session state are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "ai.residue.claude".to_owned(),
            title: "Claude desktop and agent cache".to_owned(),
            category: ResidueCategory::AgentResidue,
            description: "Temporary clipboard paste caches, shell snapshots, debug traces, and Electron web cache.".to_owned(),
            trade_off: "Cached UI assets will reload; credentials, active sessions, and conversation history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "ai.residue.codex".to_owned(),
            title: "Codex temporary files and debug logs".to_owned(),
            category: ResidueCategory::AgentResidue,
            description: "Scratch temporary files in .tmp, web cache, and dated sandbox execution logs.".to_owned(),
            trade_off: "Temporary sandbox scratchpads are removed; chat history and credentials are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.recent-files".to_owned(),
            title: "Windows recent items and Jump Lists".to_owned(),
            category: ResidueCategory::RecentActivity,
            description: "Recent document shortcut links (.lnk) and taskbar Jump List tracking databases (AutomaticDestinations).".to_owned(),
            trade_off: "Clears taskbar Jump Lists and recent file menus; underlying files are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.inetcache".to_owned(),
            title: "Windows temporary internet files".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Temporary internet files and cached web assets in INetCache.".to_owned(),
            trade_off: "Cached web page assets from legacy Windows components and Office will reload.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "editor.residue.vscode".to_owned(),
            title: "Visual Studio Code editor cache".to_owned(),
            category: ResidueCategory::AppCache,
            description: "Compiled V8 bytecode, web view caches, and service worker storage in Code.".to_owned(),
            trade_off: "Extension web views and bytecode recompile on next use; user settings and projects are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.pip-cache".to_owned(),
            title: "Python pip package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded wheel archives and HTTP index cache for Python pip.".to_owned(),
            trade_off: "Packages re-download from PyPI on next install; active virtualenvs are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.npm-cache".to_owned(),
            title: "Node.js npm package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded tarballs and index cache in npm-cache.".to_owned(),
            trade_off: "Packages re-download from npm registry on next install; node_modules directories are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.cryptnet-cache".to_owned(),
            title: "CryptoAPI certificate URL cache".to_owned(),
            category: ResidueCategory::RecentActivity,
            description: "Cached certificate revocation (CRL/OCSP) queries that reveal domains and HTTPS endpoints contacted by the OS and background apps.".to_owned(),
            trade_off: "Windows will re-query certificate revocation status on subsequent secure TLS connections.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.wer-reports".to_owned(),
            title: "Windows Error Reporting archives and queues".to_owned(),
            category: ResidueCategory::CrashDumps,
            description: "Diagnostic error reports and crash metadata packages recording faulting binaries and memory offsets in WER.".to_owned(),
            trade_off: "Removes historical crash telemetry packages prepared for submission to Microsoft.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.firefox-cache".to_owned(),
            title: "Mozilla Firefox web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets, images, and script bytecode for Mozilla Firefox.".to_owned(),
            trade_off: "Visited websites will re-download images; logins, history, and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.brave-cache".to_owned(),
            title: "Brave Browser web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets and script bytecode for Brave Browser.".to_owned(),
            trade_off: "Visited websites will re-download resources; logins, shields settings, and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.delivery-optimization".to_owned(),
            title: "Windows Delivery Optimization peer cache".to_owned(),
            category: ResidueCategory::TemporaryFiles,
            description: "Cached peer-to-peer Windows update and application delivery chunks.".to_owned(),
            trade_off: "Updates will re-download directly from Microsoft servers rather than local network peers.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.powershell-history".to_owned(),
            title: "PowerShell console command history".to_owned(),
            category: ResidueCategory::RecentActivity,
            description: "Plaintext command history recorded by PSReadLine (ConsoleHost_history.txt), which frequently captures sensitive parameters and paths.".to_owned(),
            trade_off: "Permanently removes saved ConsoleHost command recall. Close PowerShell first; open shells can rewrite history. Custom history paths and other hosts are not covered.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.activity-history".to_owned(),
            title: "Windows Activity History database (Connected Devices Platform)".to_owned(),
            category: ResidueCategory::RecentActivity,
            description: "SQLite database logging chronological app launches, document access timestamps, and cross-device clipboard history payloads.".to_owned(),
            trade_off: "Clears historical activity timeline and cross-device clipboard cache; system recreates an empty database.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.cargo-cache".to_owned(),
            title: "Rust Cargo crate package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded .crate archive packages cached by Cargo in the user profile.".to_owned(),
            trade_off: "Cargo will re-download crates from the registry on next build if not already extracted in the project.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.chromium-cache".to_owned(),
            title: "Chromium web cache (open-source)".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets and script bytecode for open-source Chromium builds.".to_owned(),
            trade_off: "Visited websites will re-download assets; logins, cookies, and browsing history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "windows.residue.icon-cache".to_owned(),
            title: "Windows Explorer icon cache".to_owned(),
            category: ResidueCategory::ThumbnailCache,
            description: "Cached desktop and application icon preview databases (iconcache_*.db) created by File Explorer.".to_owned(),
            trade_off: "Explorer will rebuild icon caches on demand as applications and shortcuts are viewed.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.nuget-cache".to_owned(),
            title: "NuGet package and HTTP cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Cached .nupkg packages and HTTP response metadata in %LOCALAPPDATA%\\NuGet\\v3-cache.".to_owned(),
            trade_off: "NuGet will re-download package metadata and packages on subsequent dotnet restore or build.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.go-cache".to_owned(),
            title: "Go compiler build cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Cached compilation artifacts and test results in %LOCALAPPDATA%\\go-build.".to_owned(),
            trade_off: "Go will recompile packages on subsequent go build or go test execution.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
    ]
}

#[cfg(target_os = "linux")]
fn linux_targets() -> Vec<ResidueSpec> {
    vec![
        ResidueSpec {
            id: "linux.residue.thumbnails".to_owned(),
            title: "FreeDesktop thumbnail cache".to_owned(),
            category: ResidueCategory::ThumbnailCache,
            description: "Cached thumbnail preview images ($XDG_CACHE_HOME/thumbnails) generated by desktop file managers.".to_owned(),
            trade_off: "File managers will momentarily regenerate previews when browsing picture and video folders.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "linux.residue.mesa-shader".to_owned(),
            title: "Mesa 3D graphics shader cache".to_owned(),
            category: ResidueCategory::ShaderCache,
            description: "Precompiled OpenGL and Vulkan pipeline shaders in $XDG_CACHE_HOME/mesa_shader_cache.".to_owned(),
            trade_off: "3D applications and games will recompile shaders on their next launch.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "linux.residue.recent-files".to_owned(),
            title: "GTK recently used files database".to_owned(),
            category: ResidueCategory::RecentActivity,
            description: "XML database logging opened file paths and applications in $XDG_DATA_HOME/recently-used.xbel.".to_owned(),
            trade_off: "Clears GTK and desktop recent file lists; underlying files are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "linux.residue.powershell-history".to_owned(),
            title: "PowerShell console command history".to_owned(),
            category: ResidueCategory::RecentActivity,
            description: "Plaintext command history recorded by PSReadLine in $XDG_DATA_HOME/powershell.".to_owned(),
            trade_off: "Permanently removes saved ConsoleHost command recall. Close PowerShell first; open shells can rewrite history. Custom history paths and other hosts are not covered.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.firefox-cache".to_owned(),
            title: "Mozilla Firefox web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets, images, and script bytecode for Mozilla Firefox in $XDG_CACHE_HOME.".to_owned(),
            trade_off: "Visited websites will re-download assets; logins, cookies, and browsing history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.chrome-cache".to_owned(),
            title: "Google Chrome web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page resources, images, and script bytecode for Google Chrome.".to_owned(),
            trade_off: "Visited websites will re-download resources; logins and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.chromium-cache".to_owned(),
            title: "Chromium web cache (open-source)".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets and script bytecode for open-source Chromium builds.".to_owned(),
            trade_off: "Visited websites will re-download assets; logins, cookies, and browsing history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.brave-cache".to_owned(),
            title: "Brave Browser web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets and script bytecode for Brave Browser.".to_owned(),
            trade_off: "Visited websites will re-download resources; logins, shields settings, and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.edge-cache".to_owned(),
            title: "Microsoft Edge web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page resources, images, and script bytecode for Microsoft Edge on Linux.".to_owned(),
            trade_off: "Visited websites will re-download images and resources; logins and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "ai.residue.claude".to_owned(),
            title: "Claude desktop and agent cache".to_owned(),
            category: ResidueCategory::AgentResidue,
            description: "Temporary clipboard paste caches, shell snapshots, and Electron web cache in ~/.claude and $XDG_CONFIG_HOME.".to_owned(),
            trade_off: "Cached UI assets will reload; credentials, active sessions, and conversation history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "ai.residue.codex".to_owned(),
            title: "Codex temporary files and debug logs".to_owned(),
            category: ResidueCategory::AgentResidue,
            description: "Scratch temporary files in .tmp, web cache, and dated sandbox execution logs in ~/.codex.".to_owned(),
            trade_off: "Temporary sandbox scratchpads are removed; chat history and credentials are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "editor.residue.vscode".to_owned(),
            title: "Visual Studio Code editor cache".to_owned(),
            category: ResidueCategory::AppCache,
            description: "Compiled V8 bytecode, web view caches, and service worker storage in $XDG_CONFIG_HOME/Code.".to_owned(),
            trade_off: "Extension web views and bytecode recompile on next use; user settings and projects are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "app.residue.discord".to_owned(),
            title: "Discord media cache".to_owned(),
            category: ResidueCategory::AppCache,
            description: "Cached avatars, embedded images, and media attachments from Discord in $XDG_CONFIG_HOME/discord.".to_owned(),
            trade_off: "Media in channels will be re-downloaded when viewed; account and session state are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.cargo-cache".to_owned(),
            title: "Rust Cargo crate package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded .crate archive packages cached by Cargo in ~/.cargo/registry/cache.".to_owned(),
            trade_off: "Cargo will re-download crates from the registry on next build if not already extracted in the project.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.npm-cache".to_owned(),
            title: "Node.js npm package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded tarballs and index cache in ~/.npm/_cacache.".to_owned(),
            trade_off: "Packages re-download from npm registry on next install; node_modules directories are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.pip-cache".to_owned(),
            title: "Python pip package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded wheel archives and HTTP index cache for Python pip in $XDG_CACHE_HOME/pip.".to_owned(),
            trade_off: "Packages re-download from PyPI on next install; active virtualenvs are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.go-cache".to_owned(),
            title: "Go compiler build cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Cached compilation artifacts and test results in $XDG_CACHE_HOME/go-build.".to_owned(),
            trade_off: "Go will recompile packages on subsequent go build or go test execution.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
    ]
}

#[cfg(target_os = "macos")]
fn macos_targets() -> Vec<ResidueSpec> {
    vec![
        ResidueSpec {
            id: "browser.residue.safari-cache".to_owned(),
            title: "Apple Safari web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets and script bytecode in ~/Library/Caches/com.apple.Safari.".to_owned(),
            trade_off: "Visited websites will re-download assets; logins, cookies, and browsing history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.chrome-cache".to_owned(),
            title: "Google Chrome web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page resources, images, and script bytecode for Google Chrome in ~/Library/Caches.".to_owned(),
            trade_off: "Visited websites will re-download resources; logins and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.firefox-cache".to_owned(),
            title: "Mozilla Firefox web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets, images, and script bytecode for Mozilla Firefox in ~/Library/Caches.".to_owned(),
            trade_off: "Visited websites will re-download assets; logins, cookies, and browsing history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.brave-cache".to_owned(),
            title: "Brave Browser web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page assets and script bytecode for Brave Browser in ~/Library/Caches.".to_owned(),
            trade_off: "Visited websites will re-download resources; logins, shields settings, and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "browser.residue.edge-cache".to_owned(),
            title: "Microsoft Edge web cache".to_owned(),
            category: ResidueCategory::BrowserCache,
            description: "Cached web page resources, images, and script bytecode for Microsoft Edge on macOS.".to_owned(),
            trade_off: "Visited websites will re-download images and resources; logins and cookies are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "ai.residue.claude".to_owned(),
            title: "Claude desktop and agent cache".to_owned(),
            category: ResidueCategory::AgentResidue,
            description: "Temporary clipboard paste caches, shell snapshots, and Electron web cache in ~/.claude and ~/Library/Caches.".to_owned(),
            trade_off: "Cached UI assets will reload; credentials, active sessions, and conversation history are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "ai.residue.codex".to_owned(),
            title: "Codex temporary files and debug logs".to_owned(),
            category: ResidueCategory::AgentResidue,
            description: "Scratch temporary files in .tmp, web cache, and dated sandbox execution logs in ~/.codex.".to_owned(),
            trade_off: "Temporary sandbox scratchpads are removed; chat history and credentials are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "editor.residue.vscode".to_owned(),
            title: "Visual Studio Code editor cache".to_owned(),
            category: ResidueCategory::AppCache,
            description: "Compiled V8 bytecode, web view caches, and service worker storage in ~/Library/Caches/com.microsoft.VSCode.".to_owned(),
            trade_off: "Extension web views and bytecode recompile on next use; user settings and projects are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "app.residue.discord".to_owned(),
            title: "Discord media cache".to_owned(),
            category: ResidueCategory::AppCache,
            description: "Cached avatars, embedded images, and media attachments from Discord in ~/Library/Caches.".to_owned(),
            trade_off: "Media in channels will be re-downloaded when viewed; account and session state are preserved.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.cargo-cache".to_owned(),
            title: "Rust Cargo crate package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded .crate archive packages cached by Cargo in ~/.cargo/registry/cache.".to_owned(),
            trade_off: "Cargo will re-download crates from the registry on next build if not already extracted in the project.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.npm-cache".to_owned(),
            title: "Node.js npm package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded tarballs and index cache in ~/.npm/_cacache.".to_owned(),
            trade_off: "Packages re-download from npm registry on next install; node_modules directories are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.pip-cache".to_owned(),
            title: "Python pip package cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Downloaded wheel archives and HTTP index cache for Python pip in ~/Library/Caches/pip.".to_owned(),
            trade_off: "Packages re-download from PyPI on next install; active virtualenvs are untouched.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "dev.residue.go-cache".to_owned(),
            title: "Go compiler build cache".to_owned(),
            category: ResidueCategory::PackageCache,
            description: "Cached compilation artifacts and test results in ~/Library/Caches/go-build.".to_owned(),
            trade_off: "Go will recompile packages on subsequent go build or go test execution.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "macos.residue.powershell-history".to_owned(),
            title: "PowerShell console command history".to_owned(),
            category: ResidueCategory::RecentActivity,
            description: "Plaintext command history recorded by PSReadLine under XDG_DATA_HOME/powershell or ~/.local/share/powershell.".to_owned(),
            trade_off: "Permanently removes saved ConsoleHost command recall. Close PowerShell first; open shells can rewrite history. Custom history paths and other hosts are not covered.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "macos.residue.diagnostic-reports".to_owned(),
            title: "Diagnostic crash and error reports".to_owned(),
            category: ResidueCategory::CrashDumps,
            description: "Application crash logs and diagnostic reports in ~/Library/Logs/DiagnosticReports.".to_owned(),
            trade_off: "Removes historical crash telemetry and diagnostic traces for third-party applications.".to_owned(),
            polite_retained: false,
            requires_risk_ack: false,
        },
        ResidueSpec {
            id: "macos.residue.quicklook".to_owned(),
            title: "Quick Look thumbnail preview cache".to_owned(),
            category: ResidueCategory::ThumbnailCache,
            description: "Cached thumbnail previews generated by Quick Look in ~/Library/Caches/com.apple.QuickLook.thumbnailcache.".to_owned(),
            trade_off: "Finder momentarily regenerates previews when browsing folders with Quick Look.".to_owned(),
            polite_retained: true,
            requires_risk_ack: false,
        },
    ]
}

pub fn matches_category_filter(category: ResidueCategory, filter: &str) -> bool {
    let f = filter.trim().to_lowercase();
    match f.as_str() {
        "all" => true,
        "system" => matches!(
            category,
            ResidueCategory::TemporaryFiles
                | ResidueCategory::CrashDumps
                | ResidueCategory::ThumbnailCache
                | ResidueCategory::ShaderCache
        ),
        "temp" | "temporary" => matches!(category, ResidueCategory::TemporaryFiles),
        "crash" | "dumps" => matches!(category, ResidueCategory::CrashDumps),
        "thumbnail" | "thumbnails" => matches!(category, ResidueCategory::ThumbnailCache),
        "shader" | "shaders" => matches!(category, ResidueCategory::ShaderCache),
        "browser" | "browsers" => matches!(category, ResidueCategory::BrowserCache),
        "app" | "apps" => matches!(category, ResidueCategory::AppCache),
        "ai" | "agent" | "agents" => matches!(category, ResidueCategory::AgentResidue),
        "recent" | "activity" => matches!(category, ResidueCategory::RecentActivity),
        "dev" | "developer" | "package" | "packages" => {
            matches!(category, ResidueCategory::PackageCache)
        }
        _ => false,
    }
}

pub fn is_known_category_filter(filter: &str) -> bool {
    matches!(
        filter.trim().to_ascii_lowercase().as_str(),
        "all"
            | "system"
            | "temp"
            | "temporary"
            | "crash"
            | "dumps"
            | "thumbnail"
            | "thumbnails"
            | "shader"
            | "shaders"
            | "browser"
            | "browsers"
            | "app"
            | "apps"
            | "ai"
            | "agent"
            | "agents"
            | "recent"
            | "activity"
            | "dev"
            | "developer"
            | "package"
            | "packages"
    )
}

/// Validate `--control` and `--category` selectors against compiled residue targets.
pub fn validate_residue_selectors(
    control_filters: &[String],
    category_filters: &[String],
) -> Result<(), String> {
    let targets = compiled_residue_targets();
    for cat in category_filters {
        if !is_known_category_filter(cat) {
            return Err(format!(
                "unknown residue category '{cat}'. Valid categories: system, temp, crash, thumbnails, shaders, browsers, apps, ai, recent, dev, all."
            ));
        }
        if !targets
            .iter()
            .any(|spec| matches_category_filter(spec.category, cat))
        {
            return Err(format!(
                "no residue targets on this platform match category '{cat}'."
            ));
        }
    }
    for sel in control_filters {
        if !targets
            .iter()
            .any(|spec| spec.id == *sel || spec.id.starts_with(sel))
        {
            return Err(format!(
                "no residue target matching '{sel}'. Run privr clean --preview to see available residue targets."
            ));
        }
    }
    Ok(())
}

/// Filter target specs by selection criteria and purge mode.
pub fn select_residue_targets(
    mode: PurgeMode,
    control_filters: &[String],
    category_filters: &[String],
) -> Vec<(ResidueSpec, bool, Option<String>)> {
    let targets = compiled_residue_targets();
    targets
        .into_iter()
        .map(|spec| {
            let matches_ctrl = if control_filters.is_empty() {
                true
            } else {
                control_filters
                    .iter()
                    .any(|filter| spec.id == *filter || spec.id.starts_with(filter))
            };

            let matches_cat = if category_filters.is_empty() {
                true
            } else {
                category_filters
                    .iter()
                    .any(|cat| matches_category_filter(spec.category, cat))
            };

            if !matches_ctrl || !matches_cat {
                return (spec, false, Some("not selected by filters".to_owned()));
            }

            if mode == PurgeMode::Polite && spec.polite_retained {
                (
                    spec,
                    false,
                    Some("retained in polite mode (convenience/workflow cache)".to_owned()),
                )
            } else {
                (spec, true, None)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_residue_targets_have_unique_ids() {
        let targets = compiled_residue_targets();
        let mut ids = std::collections::HashSet::new();
        for target in targets {
            assert!(ids.insert(target.id.clone()), "Duplicate ID: {}", target.id);
            assert!(!target.id.is_empty());
            assert!(!target.title.is_empty());
            assert!(!target.description.is_empty());
        }
    }

    #[test]
    fn test_polite_mode_filters_thumbnail_cache() {
        let aggressive = select_residue_targets(PurgeMode::Aggressive, &[], &[]);
        let polite = select_residue_targets(PurgeMode::Polite, &[], &[]);

        #[cfg(windows)]
        {
            let thumb_agg = aggressive
                .iter()
                .find(|(s, _, _)| s.id == "windows.residue.thumbnail-cache");
            let thumb_pol = polite
                .iter()
                .find(|(s, _, _)| s.id == "windows.residue.thumbnail-cache");
            assert!(
                thumb_agg.unwrap().1,
                "Thumbnail cache should be selected in aggressive mode"
            );
            assert!(
                !thumb_pol.unwrap().1,
                "Thumbnail cache should be retained in polite mode"
            );
        }
        #[cfg(target_os = "linux")]
        {
            let thumb_agg = aggressive
                .iter()
                .find(|(s, _, _)| s.id == "linux.residue.thumbnails");
            let thumb_pol = polite
                .iter()
                .find(|(s, _, _)| s.id == "linux.residue.thumbnails");
            assert!(
                thumb_agg.unwrap().1,
                "Thumbnail cache should be selected in aggressive mode"
            );
            assert!(
                !thumb_pol.unwrap().1,
                "Thumbnail cache should be retained in polite mode"
            );
        }
        #[cfg(target_os = "macos")]
        {
            let thumb_agg = aggressive
                .iter()
                .find(|(s, _, _)| s.id == "macos.residue.quicklook");
            let thumb_pol = polite
                .iter()
                .find(|(s, _, _)| s.id == "macos.residue.quicklook");
            assert!(
                thumb_agg.unwrap().1,
                "QuickLook cache should be selected in aggressive mode"
            );
            assert!(
                !thumb_pol.unwrap().1,
                "QuickLook cache should be retained in polite mode"
            );
        }
    }

    #[test]
    fn thorough_default_includes_activity_without_additional_acknowledgement() {
        let targets = select_residue_targets(PurgeMode::Aggressive, &[], &[]);
        let activity: Vec<_> = targets
            .iter()
            .filter(|(spec, _, _)| spec.category == ResidueCategory::RecentActivity)
            .collect();
        assert!(
            !activity.is_empty(),
            "the compiled platform must expose its activity targets"
        );
        for (spec, selected, reason) in activity {
            assert!(*selected, "{} must be selected by default", spec.id);
            assert!(reason.is_none());
            assert!(
                !spec.requires_risk_ack,
                "routine history cleanup uses whole-plan confirmation"
            );
            assert!(!spec.trade_off.is_empty());
        }
    }

    #[test]
    fn test_category_filter_selects_expected_targets() {
        let ai_targets = select_residue_targets(PurgeMode::Aggressive, &[], &["ai".to_owned()]);
        for (spec, selected, _) in ai_targets {
            if spec.category == ResidueCategory::AgentResidue {
                assert!(selected);
            } else {
                assert!(!selected);
            }
        }
    }

    #[test]
    fn test_validate_residue_selectors_rejects_unknown_categories_and_targets() {
        assert!(validate_residue_selectors(&[], &["all".to_owned()]).is_ok());
        assert!(validate_residue_selectors(&[], &["browsers".to_owned()]).is_ok());
        assert!(validate_residue_selectors(&[], &["bogus".to_owned()]).is_err());
        assert!(validate_residue_selectors(&["nonexistent.target".to_owned()], &[]).is_err());
        assert!(validate_residue_selectors(&["browser.residue".to_owned()], &[]).is_ok());
    }
}
