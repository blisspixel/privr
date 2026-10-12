//! Bounded, version-labelled file intent, never loaded systemd state.

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::engine::evaluate::{Resolution, Uncertainty};
use crate::model::evidence::{RawValue, ValueKind};
use crate::model::host::ManagementSource;

use super::evidence::MAX_FILE_BYTES;

const MAX_ENTRIES: usize = 64;
const MAX_TOTAL_BYTES: usize = 512 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigurationFamily {
    Coredump,
    Journald,
}

impl ConfigurationFamily {
    fn filename(self) -> &'static str {
        match self {
            Self::Coredump => "coredump.conf",
            Self::Journald => "journald.conf",
        }
    }

    fn section(self) -> &'static str {
        match self {
            Self::Coredump => "Coredump",
            Self::Journald => "Journal",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigurationRoot {
    Etc,
    Run,
    UsrLocalLib,
    UsrLib,
}

const ROOTS: [ConfigurationRoot; 4] = [
    ConfigurationRoot::Etc,
    ConfigurationRoot::Run,
    ConfigurationRoot::UsrLocalLib,
    ConfigurationRoot::UsrLib,
];

impl ConfigurationRoot {
    fn path(self) -> &'static Path {
        Path::new(match self {
            Self::Etc => "/etc/systemd",
            Self::Run => "/run/systemd",
            Self::UsrLocalLib => "/usr/local/lib/systemd",
            Self::UsrLib => "/usr/lib/systemd",
        })
    }
}

/// Raw file bytes retain their storage type. Only the exact null-device link
/// is a mask; other links, special files and observed races are uncertain.
#[derive(Clone, Debug)]
pub enum ConfigurationFile {
    Absent,
    Regular(RawValue),
    Mask,
    Uncertain(Uncertainty),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryListing {
    Absent,
    Complete(Vec<Vec<u8>>),
    Uncertain(Uncertainty),
}

#[derive(Clone, Debug)]
pub struct RootEvidence {
    pub main: ConfigurationFile,
    pub before: DirectoryListing,
    pub after: DirectoryListing,
    pub files: BTreeMap<Vec<u8>, ConfigurationFile>,
}

/// Omitted roots, listings and winning file observations are not absence.
#[derive(Clone, Debug, Default)]
pub struct ConfigurationEvidence {
    pub roots: BTreeMap<ConfigurationRoot, RootEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfiguredStorage {
    Unspecified,
    None,
    External,
    Journal,
    Volatile,
    Persistent,
    Auto,
}

impl ConfiguredStorage {
    fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified (no observed Storage assignment)",
            Self::None => "Storage=none",
            Self::External => "Storage=external",
            Self::Journal => "Storage=journal",
            Self::Volatile => "Storage=volatile",
            Self::Persistent => "Storage=persistent",
            Self::Auto => "Storage=auto",
        }
    }
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != b"."
        && name != b".."
        && std::str::from_utf8(name).is_ok_and(|name| !name.chars().any(char::is_control))
        && !name
            .iter()
            .any(|b| b.is_ascii_control() || matches!(b, b'/' | b'\\'))
}

fn winners(
    evidence: &ConfigurationEvidence,
) -> Result<BTreeMap<Vec<u8>, ConfigurationRoot>, Uncertainty> {
    let mut winners = BTreeMap::new();
    let mut count = 0;
    for root in ROOTS {
        let observed = evidence.roots.get(&root).ok_or(Uncertainty::Undetermined)?;
        if observed.before != observed.after {
            return Err(Uncertainty::Undetermined);
        }
        match &observed.before {
            DirectoryListing::Absent => {}
            DirectoryListing::Uncertain(reason) => return Err(*reason),
            DirectoryListing::Complete(names) => {
                let mut seen = std::collections::BTreeSet::new();
                for name in names {
                    if !valid_name(name) || !name.ends_with(b".conf") || !seen.insert(name) {
                        return Err(Uncertainty::Malformed);
                    }
                    count += 1;
                    if count > MAX_ENTRIES {
                        return Err(Uncertainty::Undetermined);
                    }
                    winners.entry(name.clone()).or_insert(root);
                }
            }
        }
    }
    Ok(winners)
}

pub fn configured_storage(
    family: ConfigurationFamily,
    evidence: &ConfigurationEvidence,
) -> Result<ConfiguredStorage, Uncertainty> {
    let selected = winners(evidence)?;
    let mut storage = ConfiguredStorage::Unspecified;
    let mut total = 0;
    for root in ROOTS {
        let observed = evidence.roots.get(&root).ok_or(Uncertainty::Undetermined)?;
        match &observed.main {
            ConfigurationFile::Absent => continue,
            file => {
                parse_file(family, file, &mut storage, &mut total)?;
                break;
            }
        }
    }
    for (name, root) in selected {
        let file = evidence.roots[&root]
            .files
            .get(&name)
            .ok_or(Uncertainty::Undetermined)?;
        // A listed winning file disappearing is not positive absence.
        if matches!(file, ConfigurationFile::Absent) {
            return Err(Uncertainty::Undetermined);
        }
        parse_file(family, file, &mut storage, &mut total)?;
    }
    Ok(storage)
}

fn parse_file(
    family: ConfigurationFamily,
    file: &ConfigurationFile,
    storage: &mut ConfiguredStorage,
    total: &mut usize,
) -> Result<(), Uncertainty> {
    match file {
        ConfigurationFile::Absent | ConfigurationFile::Mask => Ok(()),
        ConfigurationFile::Uncertain(reason) => Err(*reason),
        ConfigurationFile::Regular(value) => {
            if value.kind != ValueKind::String {
                return Err(Uncertainty::Malformed);
            }
            *total = total
                .checked_add(value.bytes.len())
                .ok_or(Uncertainty::Undetermined)?;
            if value.bytes.len() > MAX_FILE_BYTES || *total > MAX_TOTAL_BYTES {
                return Err(Uncertainty::Undetermined);
            }
            let text = std::str::from_utf8(&value.bytes).map_err(|_| Uncertainty::Malformed)?;
            if text
                .chars()
                .any(|c| c == '\0' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t')))
            {
                return Err(Uncertainty::Malformed);
            }
            let mut relevant = false;
            for line in text.split('\n') {
                if line.len() > MAX_LINE_BYTES {
                    return Err(Uncertainty::Undetermined);
                }
                let line = line.strip_suffix('\r').unwrap_or(line);
                if line.contains('\r') {
                    return Err(Uncertainty::Malformed);
                }
                let line = line.trim_matches([' ', '\t']);
                if line.is_empty() || line.starts_with(['#', ';']) {
                    continue;
                }
                // Continuations change logical-line boundaries and are outside
                // this conservative subset, including in unrelated sections.
                if line.ends_with('\\') {
                    return Err(Uncertainty::Malformed);
                }
                if line.starts_with('[') {
                    let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
                    else {
                        return Err(Uncertainty::Malformed);
                    };
                    if section.contains(['[', ']']) {
                        return Err(Uncertainty::Malformed);
                    }
                    relevant = section == family.section();
                    continue;
                }
                if !relevant {
                    continue;
                }
                let Some((key, value)) = line.split_once('=') else {
                    if line
                        .split_whitespace()
                        .next()
                        .is_some_and(|key| key.eq_ignore_ascii_case("Storage"))
                    {
                        return Err(Uncertainty::Malformed);
                    }
                    continue;
                };
                if key
                    .trim_matches([' ', '\t'])
                    .eq_ignore_ascii_case("Storage")
                {
                    if key.trim_matches([' ', '\t']) != "Storage" {
                        return Err(Uncertainty::Malformed);
                    }
                    *storage = match (family, value.trim_matches([' ', '\t'])) {
                        (_, "none") => ConfiguredStorage::None,
                        (ConfigurationFamily::Coredump, "external") => ConfiguredStorage::External,
                        (ConfigurationFamily::Coredump, "journal") => ConfiguredStorage::Journal,
                        (ConfigurationFamily::Journald, "volatile") => ConfiguredStorage::Volatile,
                        (ConfigurationFamily::Journald, "persistent") => {
                            ConfiguredStorage::Persistent
                        }
                        (ConfigurationFamily::Journald, "auto") => ConfiguredStorage::Auto,
                        _ => return Err(Uncertainty::Malformed),
                    };
                }
            }
            Ok(())
        }
    }
}

pub fn resolve(family: ConfigurationFamily, evidence: &ConfigurationEvidence) -> Resolution {
    let (reason, intent) = match configured_storage(family, evidence) {
        Ok(storage) => (Uncertainty::Undetermined, storage.label()),
        Err(Uncertainty::Denied) => (Uncertainty::Denied, "unavailable (access denied)"),
        Err(Uncertainty::Malformed) => (
            Uncertainty::Malformed,
            "unavailable (unsupported syntax or evidence type)",
        ),
        Err(reason) => (
            reason,
            "unavailable (incomplete, changed or bounded evidence)",
        ),
    };
    let mut resolution = Resolution::uncertain(reason, ManagementSource::LocalPolicy);
    let limits = match family {
        ConfigurationFamily::Coredump => {
            "Storage concerns permanent core retention; temporary writes and backtrace availability depend on unverified processing."
        }
        ConfigurationFamily::Journald => {
            "Storage does not attest forwarding, other namespaces or deletion of existing history."
        }
    };
    resolution.note = Some(format!(
        "Configured intent under systemd v262 standard paths: {intent}. Loaded storage is unverified: component version/build, loaded generation, instance and higher-precedence inputs are not attested. {limits}"
    ));
    resolution
}

fn io_uncertainty(error: &std::io::Error) -> Uncertainty {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        Uncertainty::Denied
    } else {
        Uncertainty::Undetermined
    }
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn read_file(path: &Path) -> ConfigurationFile {
    read_file_with(path, MAX_FILE_BYTES, || {})
}

fn read_file_with(path: &Path, limit: usize, after_read: impl FnOnce()) -> ConfigurationFile {
    let read = || -> Result<ConfigurationFile, Uncertainty> {
        match std::fs::symlink_metadata(path.parent().ok_or(Uncertainty::Undetermined)?) {
            Ok(parent) if !parent.is_dir() || parent.file_type().is_symlink() => {
                return Err(Uncertainty::Undetermined);
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(io_uncertainty(&error));
            }
            _ => {}
        }
        let before = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ConfigurationFile::Absent);
            }
            Err(error) => return Err(io_uncertainty(&error)),
        };
        if before.file_type().is_symlink() {
            let target = std::fs::read_link(path).map_err(|e| io_uncertainty(&e))?;
            let after = std::fs::symlink_metadata(path).map_err(|e| io_uncertainty(&e))?;
            if target.as_os_str().as_bytes() == b"/dev/null" && same_file(&before, &after) {
                return Ok(ConfigurationFile::Mask);
            }
            return Err(Uncertainty::Undetermined);
        }
        if !before.is_file() || before.len() > limit as u64 {
            return Err(Uncertainty::Undetermined);
        }
        // Nonblocking open prevents a concurrent FIFO substitution from hanging.
        // O_NOFOLLOW prevents following a concurrently planted final symlink.
        use std::os::unix::fs::OpenOptionsExt;
        // Linux UAPI O_NONBLOCK and O_NOFOLLOW on the supported x86_64 and
        // aarch64 targets. No platform-neutral file API exposes these flags.
        const O_NONBLOCK: i32 = 0x800;
        const O_NOFOLLOW: i32 = 0x20000;
        let file = File::options()
            .read(true)
            .custom_flags(O_NONBLOCK | O_NOFOLLOW)
            .open(path)
            .map_err(|e| io_uncertainty(&e))?;
        let opened = file.metadata().map_err(|e| io_uncertainty(&e))?;
        if !opened.is_file() || !same_file(&before, &opened) {
            return Err(Uncertainty::Undetermined);
        }
        let mut bytes = Vec::new();
        (&file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_uncertainty(&e))?;
        after_read();
        let after = file.metadata().map_err(|e| io_uncertainty(&e))?;
        let path_after = std::fs::symlink_metadata(path).map_err(|e| io_uncertainty(&e))?;
        if bytes.len() > limit || !same_file(&opened, &after) || !same_file(&after, &path_after) {
            return Err(Uncertainty::Undetermined);
        }
        Ok(ConfigurationFile::Regular(RawValue::new(
            ValueKind::String,
            bytes,
        )))
    };
    read().unwrap_or_else(ConfigurationFile::Uncertain)
}

fn list_directory(path: &Path) -> DirectoryListing {
    list_directory_with(path, || {})
}

fn list_directory_with(path: &Path, after_listing: impl FnOnce()) -> DirectoryListing {
    let read = || -> Result<DirectoryListing, Uncertainty> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DirectoryListing::Absent);
            }
            Err(error) => return Err(io_uncertainty(&error)),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Uncertainty::Undetermined);
        }
        let entries = std::fs::read_dir(path).map_err(|e| io_uncertainty(&e))?;
        let mut names = Vec::new();
        for entry in entries {
            let name = entry
                .map_err(|e| io_uncertainty(&e))?
                .file_name()
                .as_bytes()
                .to_vec();
            if !name.ends_with(b".conf") {
                continue;
            }
            if !valid_name(&name) {
                return Err(Uncertainty::Malformed);
            }
            if names.len() == MAX_ENTRIES {
                return Err(Uncertainty::Undetermined);
            }
            names.push(name);
        }
        names.sort();
        after_listing();
        let after = std::fs::symlink_metadata(path).map_err(|e| io_uncertainty(&e))?;
        if !same_file(&metadata, &after) {
            return Err(Uncertainty::Undetermined);
        }
        Ok(DirectoryListing::Complete(names))
    };
    read().unwrap_or_else(DirectoryListing::Uncertain)
}

pub(super) fn read_live(family: ConfigurationFamily) -> ConfigurationEvidence {
    collect(family, ROOTS.map(|root| root.path().to_path_buf()))
}

fn collect(family: ConfigurationFamily, paths: [PathBuf; 4]) -> ConfigurationEvidence {
    let mut evidence = ConfigurationEvidence::default();
    let mut directory_metadata = BTreeMap::new();
    let mut selected_main = false;
    let mut total = 0;
    for (root, path) in ROOTS.into_iter().zip(&paths) {
        let main = if selected_main {
            ConfigurationFile::Uncertain(Uncertainty::Undetermined)
        } else {
            let main = read_file(&path.join(family.filename()));
            selected_main = !matches!(main, ConfigurationFile::Absent);
            if let ConfigurationFile::Regular(value) = &main {
                total += value.bytes.len();
            }
            main
        };
        let directory = path.join(format!("{}.d", family.filename()));
        directory_metadata.insert(root, std::fs::symlink_metadata(&directory).ok());
        let before = list_directory(&directory);
        evidence.roots.insert(
            root,
            RootEvidence {
                main,
                after: before.clone(),
                before,
                files: BTreeMap::new(),
            },
        );
    }
    if let Ok(selected) = winners(&evidence) {
        for (name, root) in selected {
            let index = ROOTS
                .iter()
                .position(|r| *r == root)
                .expect("compiled root");
            let file = if total > MAX_TOTAL_BYTES {
                ConfigurationFile::Uncertain(Uncertainty::Undetermined)
            } else {
                read_file_with(
                    &paths[index]
                        .join(format!("{}.d", family.filename()))
                        .join(std::ffi::OsString::from_vec(name.clone())),
                    MAX_FILE_BYTES.min(MAX_TOTAL_BYTES - total),
                    || {},
                )
            };
            if let ConfigurationFile::Regular(value) = &file {
                total += value.bytes.len();
            }
            evidence
                .roots
                .get_mut(&root)
                .expect("collected root")
                .files
                .insert(name, file);
        }
    }
    for (root, path) in ROOTS.into_iter().zip(&paths) {
        let directory = path.join(format!("{}.d", family.filename()));
        let after = list_directory(&directory);
        let metadata_after = std::fs::symlink_metadata(&directory).ok();
        let unchanged = match (&directory_metadata[&root], &metadata_after) {
            (Some(before), Some(after)) => same_file(before, after),
            (None, None) => true,
            _ => false,
        };
        evidence.roots.get_mut(&root).expect("collected root").after = if unchanged {
            after
        } else {
            DirectoryListing::Uncertain(Uncertainty::Undetermined)
        };
    }
    evidence
}

#[cfg(test)]
mod tests;
