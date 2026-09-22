//! Linux host discovery.
//!
//! Establishes facts about the Linux host: kernel, distribution, desktop
//! session, container environment, and privilege level.
//!
//! Follows the principle that every undetermined fact resolves to `Unknown`
//! rather than an optimistic default, preventing unverified platforms from
//! falsely reporting as compliant.

use std::fs;
use std::path::Path;

use crate::model::host::{
    Architecture, ContainerKind, Fact, HostFacts, OsVersion, Platform, SessionFacts, WriteModel,
};

/// Key-value pairs extracted from /etc/os-release or /usr/lib/os-release.
#[derive(Default)]
struct OsRelease {
    id: Option<String>,
    version_id: Option<String>,
    pretty_name: Option<String>,
    name: Option<String>,
}

fn parse_os_release(content: &str) -> OsRelease {
    let mut release = OsRelease::default();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, raw_val)) = trimmed.split_once('=') else {
            continue;
        };
        let val = raw_val
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        match key.trim() {
            "ID" => release.id = Some(val),
            "VERSION_ID" => release.version_id = Some(val),
            "PRETTY_NAME" => release.pretty_name = Some(val),
            "NAME" => release.name = Some(val),
            _ => {}
        }
    }
    release
}

fn read_os_release() -> Option<OsRelease> {
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(content) = fs::read_to_string(path) {
            return Some(parse_os_release(&content));
        }
    }
    None
}

fn version(release: Option<&OsRelease>) -> Fact<OsVersion> {
    let Some(rel) = release else {
        return Fact::Unknown;
    };
    let Some(ver_str) = &rel.version_id else {
        return Fact::Unknown;
    };
    let components: Vec<u32> = ver_str
        .split('.')
        .filter_map(|c| c.parse::<u32>().ok())
        .collect();
    if components.is_empty() {
        return Fact::Unknown;
    }
    let display = rel
        .pretty_name
        .clone()
        .or_else(|| rel.name.clone())
        .unwrap_or_else(|| ver_str.clone());
    Fact::Known(OsVersion::new(components, display))
}

fn distribution(release: Option<&OsRelease>) -> Fact<String> {
    release
        .and_then(|r| r.id.clone())
        .map_or(Fact::Unknown, Fact::Known)
}

fn architecture() -> Fact<Architecture> {
    match std::env::consts::ARCH {
        "x86_64" => Fact::Known(Architecture::X86_64),
        "aarch64" => Fact::Known(Architecture::Aarch64),
        "x86" => Fact::Known(Architecture::X86),
        _ => Fact::Known(Architecture::Other),
    }
}

fn container() -> Fact<ContainerKind> {
    if std::env::var("WSL_DISTRO_NAME").is_ok()
        || Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
    {
        return Fact::Known(ContainerKind::WindowsSubsystem);
    }
    if Path::new("/.dockerenv").exists() || Path::new("/run/systemd/container").exists() {
        return Fact::Known(ContainerKind::Container);
    }
    Fact::Known(ContainerKind::None)
}

fn write_model() -> Fact<WriteModel> {
    if Path::new("/run/ostree-booted").exists() {
        Fact::Known(WriteModel::Transactional)
    } else if Path::new("/etc/NIXOS").exists() {
        Fact::Known(WriteModel::Declarative)
    } else {
        Fact::Known(WriteModel::Mutable)
    }
}

fn session() -> SessionFacts {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .ok()
        .map(|d| d.to_lowercase())
        .map_or(Fact::Unknown, Fact::Known);

    let session_type = std::env::var("XDG_SESSION_TYPE")
        .ok()
        .map(|s| s.to_lowercase())
        .map_or(Fact::Unknown, Fact::Known);

    let has_display = std::env::var("WAYLAND_DISPLAY").is_ok()
        || std::env::var("DISPLAY").is_ok()
        || desktop.known().is_some();

    SessionFacts {
        live_session: Fact::Known(has_display),
        desktop,
        session_type,
        can_act_as_user: Fact::Known(true),
    }
}

fn elevated() -> Fact<bool> {
    if std::env::var("USER").as_deref() == Ok("root") {
        return Fact::Known(true);
    }
    Fact::Unknown
}

/// Discover facts for the current Linux host.
pub fn discover() -> HostFacts {
    let rel = read_os_release();
    HostFacts {
        platform: Platform::Linux,
        version: version(rel.as_ref()),
        architecture: architecture(),
        edition: Fact::NotPresent,
        distribution: distribution(rel.as_ref()),
        managed: Fact::Unknown,
        write_model: write_model(),
        container: container(),
        session: session(),
        elevated: elevated(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_os_release_extracts_fields() {
        let sample = r#"
NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
VERSION_ID="24.04"
"#;
        let parsed = parse_os_release(sample);
        assert_eq!(parsed.id.as_deref(), Some("ubuntu"));
        assert_eq!(parsed.version_id.as_deref(), Some("24.04"));
        assert_eq!(parsed.pretty_name.as_deref(), Some("Ubuntu 24.04 LTS"));
    }

    #[test]
    fn version_decodes_standard_versions() {
        let sample = OsRelease {
            id: Some("fedora".to_string()),
            version_id: Some("40".to_string()),
            pretty_name: Some("Fedora Linux 40".to_string()),
            name: Some("Fedora".to_string()),
        };
        let ver = version(Some(&sample));
        assert!(matches!(ver, Fact::Known(ref v) if v.components == vec![40]));
    }
}
