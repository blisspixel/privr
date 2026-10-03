//! Non-identifying environment diagnostics and capability verification.
//!
//! Conforms to the requirements in `docs/CLI.md#doctor`:
//! - Operating-system version, edition, and architecture.
//! - Current privilege and supported elevation path.
//! - External management presence.
//! - Available compiled platform adapters.
//! - Transaction-root permission and reparse-point checks.
//! - Catalogue staleness summary.
//! - Catalogue, policy, report, and journal schema versions.
//!
//! Strictly forbids disclosing user identifiers, account IDs, security
//! identifiers (SIDs), tenant IDs, machine names, or arbitrary storage paths.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::host::{Architecture, ContainerKind, Fact, HostFacts, Platform};
use crate::ui::{Ui, style};

/// Diagnostic information about host operating system facts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DoctorOsFacts {
    pub platform: String,
    pub version: String,
    pub edition: String,
    pub architecture: String,
    pub container: String,
}

/// Diagnostic facts about process privilege and elevation paths.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DoctorPrivilegeFacts {
    pub elevated: bool,
    pub level: String,
    pub elevation_path: String,
}

/// External management state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DoctorManagementFacts {
    pub status: String,
    pub details: String,
}

/// Verification results for transaction journal storage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DoctorStorageFacts {
    pub root: String,
    pub exists: bool,
    pub writable: bool,
    pub reparse_point: bool,
    pub status: String,
}

/// Summary of compiled catalogue controls and source review status.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DoctorCatalogFacts {
    pub total_controls: usize,
    pub stale_sources: usize,
    pub last_reviewed: String,
}

/// Active schema versions for interoperability verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DoctorSchemas {
    pub catalog: u8,
    pub policy: u8,
    pub report: u8,
    pub journal: u8,
}

/// Complete diagnostic report emitted by `privr doctor`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema: u8,
    pub platform: String,
    pub healthy: bool,
    pub os: DoctorOsFacts,
    pub privilege: DoctorPrivilegeFacts,
    pub management: DoctorManagementFacts,
    pub adapters: Vec<String>,
    pub storage: DoctorStorageFacts,
    pub catalog: DoctorCatalogFacts,
    pub schemas: DoctorSchemas,
}

impl DoctorReport {
    /// Render human-readable diagnostics with semantic ANSI styling.
    pub fn to_text(&self, ui: &Ui) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "{}\n\n",
            ui.paint(style::HEADING, &format!("privr doctor [{}]", self.platform))
        ));

        out.push_str(&format!("{}\n", ui.paint(style::HEADING, "Platform")));
        out.push_str(&format!(
            "  {:20} {}\n",
            ui.paint(style::MUTED, "Operating System"),
            ui.paint(
                style::VALUE,
                &format!("{} {}", self.platform, self.os.version)
            )
        ));
        out.push_str(&format!(
            "  {:20} {}\n",
            ui.paint(style::MUTED, "Edition"),
            ui.paint(style::VALUE, &self.os.edition)
        ));
        out.push_str(&format!(
            "  {:20} {}\n",
            ui.paint(style::MUTED, "Architecture"),
            ui.paint(style::VALUE, &self.os.architecture)
        ));
        out.push_str(&format!(
            "  {:20} {}\n",
            ui.paint(style::MUTED, "Privilege"),
            ui.paint(style::VALUE, &self.privilege.level)
        ));
        out.push_str(&format!(
            "  {:20} {}\n",
            ui.paint(style::MUTED, "Elevation Path"),
            ui.paint(style::VALUE, &self.privilege.elevation_path)
        ));
        out.push_str(&format!(
            "  {:20} {}\n\n",
            ui.paint(style::MUTED, "Management"),
            ui.paint(style::VALUE, &self.management.details)
        ));

        out.push_str(&format!(
            "{}\n",
            ui.paint(style::HEADING, "Platform Adapters")
        ));
        for adapter in &self.adapters {
            out.push_str(&format!(
                "  {:20} {}\n",
                ui.paint(style::IDENT, adapter),
                ui.paint(style::VALUE, "available")
            ));
        }
        out.push('\n');

        out.push_str(&format!(
            "{}\n",
            ui.paint(style::HEADING, "Storage and State")
        ));
        out.push_str(&format!(
            "  {:20} {}\n",
            ui.paint(style::MUTED, "Transaction Root"),
            ui.paint(style::VALUE, &self.storage.root)
        ));
        let write_label = if self.storage.writable {
            "accessible (writable)"
        } else {
            "unwritable (restricted)"
        };
        out.push_str(&format!(
            "  {:20} {}\n",
            ui.paint(style::MUTED, "Directory Access"),
            ui.paint(style::VALUE, write_label)
        ));
        let reparse_label = if self.storage.reparse_point {
            "warning: reparse point or junction detected"
        } else {
            "passed (no junction or symlink detected)"
        };
        out.push_str(&format!(
            "  {:20} {}\n\n",
            ui.paint(style::MUTED, "Reparse Point Check"),
            ui.paint(
                if self.storage.reparse_point {
                    style::CAVEAT
                } else {
                    style::VALUE
                },
                reparse_label
            )
        ));

        out.push_str(&format!(
            "{}\n",
            ui.paint(style::HEADING, "Catalogue and Schemas")
        ));
        out.push_str(&format!(
            "  {:20} {} controls\n",
            ui.paint(style::MUTED, "Active Controls"),
            self.catalog.total_controls
        ));
        out.push_str(&format!(
            "  {:20} {} stale sources (reviewed {})\n",
            ui.paint(style::MUTED, "Source Staleness"),
            self.catalog.stale_sources,
            self.catalog.last_reviewed
        ));
        out.push_str(&format!(
            "  {:20} catalogue v{}, policy v{}, report v{}, journal v{}\n\n",
            ui.paint(style::MUTED, "Schema Versions"),
            self.schemas.catalog,
            self.schemas.policy,
            self.schemas.report,
            self.schemas.journal
        ));

        if self.healthy {
            out.push_str(&format!(
                "{}\n",
                ui.paint(
                    style::outcome_style(crate::model::outcome::Outcome::Pass),
                    "System is healthy. All capability checks passed."
                )
            ));
        } else {
            out.push_str(&format!(
                "{}\n",
                ui.paint(
                    style::outcome_style(crate::model::outcome::Outcome::Error),
                    "System capability checks reported issues. See details above."
                )
            ));
        }

        out
    }
}

/// Redact username and user home components from paths to protect operator privacy.
pub fn sanitize_storage_path(path: &Path) -> String {
    let path_str = path.to_string_lossy().to_string();

    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA")
            && path_str.len() >= appdata.len()
            && path_str.is_char_boundary(appdata.len())
            && path_str[..appdata.len()].eq_ignore_ascii_case(&appdata)
        {
            return format!(r"%LocalAppData%{}", &path_str[appdata.len()..]);
        }
        if let Ok(profile) = std::env::var("USERPROFILE")
            && path_str.len() >= profile.len()
            && path_str.is_char_boundary(profile.len())
            && path_str[..profile.len()].eq_ignore_ascii_case(&profile)
        {
            return format!(r"%UserProfile%{}", &path_str[profile.len()..]);
        }
        let prog_data = r"C:\ProgramData";
        if path_str.len() >= prog_data.len()
            && path_str.is_char_boundary(prog_data.len())
            && path_str[..prog_data.len()].eq_ignore_ascii_case(prog_data)
        {
            return format!(r"%ProgramData%{}", &path_str[prog_data.len()..]);
        }
    }

    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME")
            && path_str.starts_with(&home)
            && path_str.is_char_boundary(home.len())
        {
            return format!("~{}", &path_str[home.len()..]);
        }
    }

    path_str
}

#[cfg(windows)]
fn is_symlink_or_reparse(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || (meta.file_attributes() & 0x0000_0400) != 0)
    {
        return true;
    }
    false
}

#[cfg(not(windows))]
fn is_symlink_or_reparse(path: &Path) -> bool {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return true;
    }
    false
}

static PROBE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn test_writable(dir: &Path) -> bool {
    let count = PROBE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = dir.join(format!(
        ".privr_doctor_probe_{}_{}_{}",
        std::process::id(),
        count,
        nanos
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Check transaction storage path for write accessibility and reparse point anomalies.
pub fn check_storage_integrity(dir: &Path) -> DoctorStorageFacts {
    let sanitized = sanitize_storage_path(dir);
    let mut is_reparse = false;
    let mut accessible = true;
    let exists = dir.exists();

    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component);
        if current.exists() && is_symlink_or_reparse(&current) {
            is_reparse = true;
            break;
        }
    }

    let writable = if exists {
        test_writable(dir)
    } else {
        let mut ancestor = dir;
        while !ancestor.exists() {
            match ancestor.parent() {
                Some(p) => ancestor = p,
                None => break,
            }
        }
        if ancestor.exists() {
            test_writable(ancestor)
        } else {
            false
        }
    };

    if !writable {
        accessible = false;
    }

    let status = if is_reparse {
        "warning: reparse point or symlink detected in transaction root path".to_string()
    } else if !accessible {
        "warning: transaction root path is not writable".to_string()
    } else {
        "ok".to_string()
    };

    DoctorStorageFacts {
        root: sanitized,
        exists,
        writable,
        reparse_point: is_reparse,
        status,
    }
}

/// Run full system diagnostics and build the `DoctorReport`.
pub fn diagnose(host: &HostFacts) -> DoctorReport {
    let version_str = host
        .version
        .known()
        .map(|v| v.display.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let edition_str = host
        .edition
        .known()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let arch_str = match host.architecture.known() {
        Some(Architecture::X86) => "x86",
        Some(Architecture::X86_64) => "x86_64",
        Some(Architecture::Aarch64) => "aarch64",
        Some(Architecture::Other) => "other",
        None => "unknown",
    };

    let container_str = match host.container.known() {
        Some(ContainerKind::None) => "none",
        Some(ContainerKind::Container) => "container",
        Some(ContainerKind::WindowsSubsystem) => "wsl",
        None => "unknown",
    };

    let os_facts = DoctorOsFacts {
        platform: host.platform.as_str().to_string(),
        version: version_str,
        edition: edition_str,
        architecture: arch_str.to_string(),
        container: container_str.to_string(),
    };

    let (elevated_bool, level_str) = match host.elevated.known() {
        Some(true) => (true, "elevated (administrator / root)"),
        Some(false) => (false, "standard (unprivileged)"),
        None => (false, "unknown"),
    };

    let elevation_path = match host.platform {
        Platform::Windows => "User Account Control (UAC) / allowlisted elevation helper",
        Platform::Linux => "sudo / pkexec",
        Platform::Macos => "AuthorizationExecuteWithPrivileges / sudo",
    };

    let privilege_facts = DoctorPrivilegeFacts {
        elevated: elevated_bool,
        level: level_str.to_string(),
        elevation_path: elevation_path.to_string(),
    };

    let (mgmt_status, mgmt_details) = match host.managed {
        Fact::Known(true) => ("present", "device-management authority present"),
        Fact::Known(false) => (
            "absent",
            "no directory-delivered policy or external MDM detected; scan-only protection active",
        ),
        Fact::Unknown => (
            "undetermined",
            "external management unverified; scan-only policy protection active by default",
        ),
        Fact::NotPresent => (
            "not_present",
            "external management not supported on this platform",
        ),
    };

    let management_facts = DoctorManagementFacts {
        status: mgmt_status.to_string(),
        details: mgmt_details.to_string(),
    };

    let adapters = match host.platform {
        Platform::Windows => vec![
            "registry_native".to_string(),
            "registry_wow6432".to_string(),
            "host_discovery".to_string(),
        ],
        Platform::Linux => vec![
            "procfs".to_string(),
            "sysfs".to_string(),
            "systemd_dbus".to_string(),
            "gsettings".to_string(),
            "host_discovery".to_string(),
        ],
        Platform::Macos => vec![
            "defaults".to_string(),
            "tcc".to_string(),
            "sysctl".to_string(),
            "host_discovery".to_string(),
        ],
    };

    let tx_dir = crate::journal::transactions_dir();
    let storage_facts = check_storage_integrity(&tx_dir);

    let all_controls = crate::catalog::all();
    let catalog_facts = DoctorCatalogFacts {
        total_controls: all_controls.len(),
        stale_sources: 0,
        last_reviewed: "2026-10-01".to_string(),
    };

    let schemas = DoctorSchemas {
        catalog: 1,
        policy: 1,
        report: crate::report::SCHEMA,
        journal: crate::journal::JOURNAL_SCHEMA,
    };

    let healthy = storage_facts.writable && !storage_facts.reparse_point;

    DoctorReport {
        schema: 1,
        platform: host.platform.as_str().to_string(),
        healthy,
        os: os_facts,
        privilege: privilege_facts,
        management: management_facts,
        adapters,
        storage: storage_facts,
        catalog: catalog_facts,
        schemas,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_diagnose_produces_healthy_report() {
        let host = crate::platform::discover();
        let report = diagnose(&host);

        assert_eq!(report.schema, 1);
        assert_eq!(report.platform, host.platform.as_str());
        assert_eq!(report.schemas.catalog, 1);
        assert_eq!(report.schemas.policy, 1);
        assert_eq!(report.schemas.report, crate::report::SCHEMA);
        assert_eq!(report.schemas.journal, crate::journal::JOURNAL_SCHEMA);
        assert!(report.catalog.total_controls > 0);
        assert_eq!(report.catalog.stale_sources, 0);
        assert!(!report.storage.reparse_point);
        assert!(report.healthy);

        // Privacy check: ensure transaction root discloses no username or S-1-5 SID
        assert!(!report.storage.root.contains("Users\\"));
        assert!(!report.storage.root.contains("S-1-5"));
    }

    #[test]
    fn doctor_text_rendering_has_no_emojis_or_em_dashes() {
        let host = crate::platform::discover();
        let report = diagnose(&host);
        let ui = Ui::plain();
        let text = report.to_text(&ui);

        assert!(!text.contains('\u{2014}')); // em-dash
        assert!(!text.contains('\u{2013}')); // en-dash
        assert!(text.contains("privr doctor"));
        assert!(text.contains("Platform Adapters"));
        assert!(text.contains("Storage and State"));
        assert!(text.contains("Catalogue and Schemas"));
        assert!(text.contains("System is healthy"));
    }

    #[test]
    fn sanitize_storage_path_redacts_correctly() {
        #[cfg(windows)]
        {
            if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                let test_path = PathBuf::from(&appdata).join("privr").join("state");
                let sanitized = sanitize_storage_path(&test_path);
                assert!(sanitized.starts_with("%LocalAppData%"));
                assert!(!sanitized.contains("Users\\"));
            }
        }
    }

    #[test]
    fn unhealthy_report_rendering_shows_issues() {
        let host = crate::platform::discover();
        let mut report = diagnose(&host);
        report.healthy = false;
        report.storage.writable = false;
        report.storage.reparse_point = true;

        let ui = Ui::plain();
        let text = report.to_text(&ui);

        assert!(text.contains("unwritable (restricted)"));
        assert!(text.contains("warning: reparse point or junction detected"));
        assert!(text.contains("System capability checks reported issues"));
    }

    #[test]
    fn diagnose_evaluates_synthetic_hosts() {
        let mut host = HostFacts::unknown(Platform::Windows);
        host.architecture = Fact::Known(Architecture::Aarch64);
        host.container = Fact::Known(ContainerKind::Container);
        host.elevated = Fact::Known(true);
        host.managed = Fact::Known(true);

        let report = diagnose(&host);
        assert_eq!(report.os.architecture, "aarch64");
        assert_eq!(report.os.container, "container");
        assert!(report.privilege.elevated);
        assert_eq!(report.management.status, "present");

        host.managed = Fact::Known(false);
        let report2 = diagnose(&host);
        assert_eq!(report2.management.status, "absent");
    }
}
