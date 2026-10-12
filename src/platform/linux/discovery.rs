//! Linux host discovery.
//!
//! Establishes facts about the Linux host: kernel, distribution, desktop
//! session, container environment, and privilege level.
//!
//! Follows the principle that every undetermined fact resolves to `Unknown`
//! rather than an optimistic default, preventing unverified platforms from
//! falsely reporting as compliant.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use crate::model::host::{
    Architecture, ContainerKind, Fact, HostFacts, OsVersion, Platform, SessionFacts, WriteModel,
};

const MAX_DISCOVERY_BYTES: usize = 64 * 1024;

/// Display and machine-readable fields from the authoritative os-release file.
#[derive(Default)]
struct OsRelease {
    id: Option<String>,
    version_id: Option<String>,
    pretty_name: Option<String>,
    name: Option<String>,
}

fn parse_os_release(content: &str) -> OsRelease {
    let mut release = OsRelease::default();
    if content.len() > MAX_DISCOVERY_BYTES
        || content.chars().any(|ch| ch.is_control() && ch != '\n')
    {
        return release;
    }
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, raw_val)) = trimmed.split_once('=') else {
            continue;
        };
        // A malformed later assignment must not revive an earlier value.
        let val = release_value(raw_val);
        match key {
            "ID" => {
                release.id = val.filter(|value| {
                    !value.is_empty()
                        && value.bytes().all(|ch| {
                            ch.is_ascii_lowercase() || ch.is_ascii_digit() || b"._-".contains(&ch)
                        })
                });
            }
            "VERSION_ID" => release.version_id = val,
            "PRETTY_NAME" => release.pretty_name = val.filter(|value| !value.is_empty()),
            "NAME" => release.name = val.filter(|value| !value.is_empty()),
            _ => {}
        }
    }
    release
}

/// Decode a single literal assignment without expansion or shell execution.
fn release_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let quote = raw.chars().next().filter(|ch| *ch == '\'' || *ch == '"');
    let body = match quote {
        Some(quote) => raw.strip_prefix(quote)?.strip_suffix(quote)?,
        None => raw,
    };
    let mut value = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch.is_control() {
            return None;
        }
        if ch == '\\' && quote != Some('\'') {
            let next = chars.next()?;
            if quote == Some('"') && !matches!(next, '$' | '`' | '"' | '\\') {
                value.push('\\');
            }
            value.push(next);
        } else {
            if Some(ch) == quote
                || (quote != Some('\'') && matches!(ch, '$' | '`'))
                || (quote.is_none() && (ch.is_whitespace() || matches!(ch, '\'' | '"')))
            {
                return None;
            }
            value.push(ch);
        }
    }
    Some(value)
}

fn read_bounded(path: &str) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_DISCOVERY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DISCOVERY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "discovery file exceeds limit",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "discovery file is not UTF-8"))
}

fn os_release_from(mut read: impl FnMut(&str) -> io::Result<String>) -> Option<OsRelease> {
    let content = match read("/etc/os-release") {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            read("/usr/lib/os-release").ok()?
        }
        Err(_) => return None,
    };
    Some(parse_os_release(&content))
}

fn read_os_release() -> Option<OsRelease> {
    os_release_from(read_bounded)
}

fn version(release: Option<&OsRelease>) -> Fact<OsVersion> {
    let Some(rel) = release else {
        return Fact::Unknown;
    };
    let Some(ver_str) = &rel.version_id else {
        return Fact::Unknown;
    };
    let components: Option<Vec<u32>> = ver_str
        .split('.')
        .map(|component| {
            if component.is_empty() || !component.bytes().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            component.parse::<u32>().ok()
        })
        .collect();
    let Some(components) = components else {
        return Fact::Unknown;
    };
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

/// Reduce procfs's real/effective/saved/filesystem UID record immediately.
/// No user identifier or other status field leaves discovery.
fn privilege_from_status(content: &str) -> Fact<bool> {
    if content.len() > MAX_DISCOVERY_BYTES {
        return Fact::Unknown;
    }
    let mut records = content.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let Some(record) = records.next() else {
        return Fact::Unknown;
    };
    if records.next().is_some() {
        return Fact::Unknown;
    }
    let ids: Option<Vec<u32>> = record
        .split_ascii_whitespace()
        .map(|field| {
            if field.is_empty() || !field.bytes().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            field.parse().ok()
        })
        .collect();
    match ids.as_deref() {
        Some([_, effective, _, _]) => Fact::Known(*effective == 0),
        _ => Fact::Unknown,
    }
}

fn elevated() -> Fact<bool> {
    read_bounded("/proc/self/status")
        .map(|content| privilege_from_status(&content))
        .unwrap_or(Fact::Unknown)
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

    #[test]
    fn empty_display_fields_fall_back_without_erasing_a_known_numeric_version() {
        let release = parse_os_release("ID=example\nVERSION_ID=1.2\nPRETTY_NAME=\"\"\nNAME=\"\"\n");
        assert_eq!(
            version(Some(&release)),
            Fact::Known(OsVersion::new(vec![1, 2], "1.2"))
        );
    }

    #[test]
    fn discovery_reads_bound_bytes_reject_invalid_utf8_and_support_release_symlinks() {
        let directory = crate::journal::TestDirectory::new();
        let file = directory.0.join("release");
        let path = file.to_str().expect("synthetic path");
        fs::write(&file, b"ID=example\n").expect("fixture");
        assert_eq!(read_bounded(path).expect("bounded read"), "ID=example\n");
        let link = directory.0.join("release-link");
        std::os::unix::fs::symlink(&file, &link).expect("release symlink");
        assert_eq!(
            read_bounded(link.to_str().expect("synthetic path"))
                .expect("supported release symlink"),
            "ID=example\n"
        );
        fs::write(&file, [0xff]).expect("invalid bytes");
        assert_eq!(
            read_bounded(path).expect_err("invalid UTF-8").kind(),
            io::ErrorKind::InvalidData
        );
        fs::write(&file, vec![b'x'; MAX_DISCOVERY_BYTES + 1]).expect("oversized fixture");
        assert_eq!(
            read_bounded(path).expect_err("byte limit").kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(&file).expect("remove fixture");
        assert_eq!(
            read_bounded(path).expect_err("missing file").kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn rolling_distribution_is_known_without_inventing_a_numeric_version() {
        let release = parse_os_release("NAME=\"Omarchy\"\nID=omarchy\nID_LIKE=arch\n");
        assert_eq!(distribution(Some(&release)), Fact::Known("omarchy".into()));
        assert_eq!(version(Some(&release)), Fact::Unknown);
    }

    #[test]
    fn malformed_version_components_never_become_a_partial_version() {
        for value in ["", "rolling", "24.bad.04", "1..2", "-1", "+1", "4294967296"] {
            let release = parse_os_release(&format!("ID=example\nVERSION_ID=\"{value}\"\n"));
            assert_eq!(version(Some(&release)), Fact::Unknown, "{value}");
        }
    }

    #[test]
    fn release_values_are_literals_with_matching_quotes_and_escapes() {
        assert_eq!(
            release_value("\"Example \\\"Linux\\\"\""),
            Some("Example \"Linux\"".into())
        );
        assert_eq!(
            release_value("Example\\ Linux"),
            Some("Example Linux".into())
        );
        assert_eq!(
            release_value("'Literal $NAME'"),
            Some("Literal $NAME".into())
        );
        for raw in [
            "\"unclosed",
            "'unclosed",
            "\"one\"\"two\"",
            "$NAME",
            "`id`",
            "bad\\",
            "two words",
        ] {
            assert_eq!(release_value(raw), None, "{raw}");
        }
    }

    #[test]
    fn malformed_or_oversized_release_does_not_supply_host_facts() {
        for content in [
            "ID=arch\nNAME=bad\u{1b}[31m\n".to_owned(),
            "x".repeat(MAX_DISCOVERY_BYTES + 1),
        ] {
            let release = parse_os_release(&content);
            assert_eq!(distribution(Some(&release)), Fact::Unknown);
            assert_eq!(version(Some(&release)), Fact::Unknown);
        }
        for id in ["", "Arch", "../arch", "arch linux"] {
            let release = parse_os_release(&format!("ID=\"{id}\"\n"));
            assert_eq!(distribution(Some(&release)), Fact::Unknown, "{id}");
        }
    }

    #[test]
    fn last_release_assignment_wins_even_when_malformed() {
        let release = parse_os_release("ID=old\nID=new\nVERSION_ID=1\nVERSION_ID=\"bad\n");
        assert_eq!(distribution(Some(&release)), Fact::Known("new".into()));
        assert_eq!(version(Some(&release)), Fact::Unknown);
    }

    #[test]
    fn vendor_release_is_read_only_when_admin_release_is_missing() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidData,
            io::ErrorKind::Other,
        ] {
            let mut paths = Vec::new();
            let release = os_release_from(|path| {
                paths.push(path.to_owned());
                Err(io::Error::from(kind))
            });
            assert!(release.is_none());
            assert_eq!(paths, ["/etc/os-release"]);
        }
        let mut paths = Vec::new();
        let release = os_release_from(|path| {
            paths.push(path.to_owned());
            if path == "/etc/os-release" {
                Err(io::Error::from(io::ErrorKind::NotFound))
            } else {
                Ok("ID=vendor\n".to_owned())
            }
        })
        .expect("vendor fallback");
        assert_eq!(distribution(Some(&release)), Fact::Known("vendor".into()));
        assert_eq!(paths, ["/etc/os-release", "/usr/lib/os-release"]);
    }

    #[test]
    fn present_admin_release_excludes_vendor_even_when_empty_or_malformed() {
        for content in ["", "ID=\"unclosed\n", "ID=admin\n"] {
            let mut paths = Vec::new();
            let release = os_release_from(|path| {
                paths.push(path.to_owned());
                Ok(content.to_owned())
            })
            .expect("present authoritative file");
            assert_eq!(paths, ["/etc/os-release"]);
            assert_ne!(distribution(Some(&release)), Fact::Known("vendor".into()));
        }
    }

    #[test]
    fn privilege_uses_effective_uid_instead_of_real_saved_or_filesystem_uid() {
        for (status, expected) in [
            ("Uid:\t1000\t0\t1000\t1000\n", true),
            ("Uid:\t0\t1000\t0\t0\n", false),
            ("Uid:\t1000\t1000\t1000\t1000\n", false),
            ("Uid:\t0\t0\t0\t0\n", true),
        ] {
            assert_eq!(privilege_from_status(status), Fact::Known(expected));
        }
    }

    #[test]
    fn invalid_uid_records_remain_unknown() {
        for status in [
            "",
            "Name:\texample\n",
            "Uid: 0 0 0\n",
            "Uid: 0 0 0 0 0\n",
            "Uid: 0 -1 0 0\n",
            "Uid: 0 +0 0 0\n",
            "Uid: 0 root 0 0\n",
            "Uid: 0 4294967296 0 0\n",
            "Uid: 0 0 0 0\nUid: 0 0 0 0\n",
            "Uid: 0 0\0 0 0\n",
        ] {
            assert_eq!(privilege_from_status(status), Fact::Unknown, "{status:?}");
        }
        assert_eq!(
            privilege_from_status(&"x".repeat(MAX_DISCOVERY_BYTES + 1)),
            Fact::Unknown
        );
    }
}
