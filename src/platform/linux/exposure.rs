//! Desktop-independent network exposure and thumbnail observations.
//!
//! NetworkManager and Avahi share one drop-in merge. systemd-resolved is read
//! from its D-Bus properties. Thumbnail presence is the cache directory itself.
//! Recorded observations never fall back to the live machine.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::evidence::Reader;
use super::systemd::{self, ConfigurationFile, DirectoryListing};
use crate::engine::evaluate::{Resolution, SemanticState, Uncertainty};
use crate::model::evidence::{RawValue, ValueKind};
use crate::model::host::ManagementSource;

const MAX_COMMAND_BYTES: usize = 256 * 1024;
const MAX_WALK_ENTRIES: usize = 10_000;
const MAX_URI_BYTES: usize = 200;

#[derive(Clone, Debug)]
pub enum LayerBody {
    Absent,
    File(ConfigurationFile),
    Directory {
        listing: DirectoryListing,
        files: BTreeMap<Vec<u8>, ConfigurationFile>,
    },
    Unreadable(Uncertainty),
}

#[derive(Clone, Debug)]
pub struct NmFiles {
    pub installed: bool,
    pub vendor_main: LayerBody,
    pub vendor_dropin: LayerBody,
    pub run_dropin: LayerBody,
    pub etc_main: LayerBody,
    pub etc_dropin: LayerBody,
    pub intern: LayerBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activity {
    Active,
    Inactive,
    Unknown(Uncertainty),
}

#[derive(Clone, Debug)]
pub struct AvahiFiles {
    pub installed: bool,
    pub active: Activity,
    pub vendor_main: LayerBody,
    pub vendor_dropin: LayerBody,
    pub run_dropin: LayerBody,
    pub etc_main: LayerBody,
    pub etc_dropin: LayerBody,
}

#[derive(Clone, Debug)]
pub enum ResolvedRecord {
    NotPresent,
    Unreadable(Uncertainty),
    Values {
        llmnr: String,
        mdns: String,
        links_llmnr: Vec<String>,
        links_mdns: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub enum ThumbnailRecord {
    Absent,
    Unreadable(Uncertainty),
    Present(u64),
}

#[derive(Clone, Debug, Default)]
pub struct ExposureRecords {
    pub network_manager: Option<NmFiles>,
    pub avahi: Option<AvahiFiles>,
    pub resolved: Option<ResolvedRecord>,
    pub thumbnails: Option<ThumbnailRecord>,
}

pub fn network_manager(reader: &Reader) -> Resolution {
    match reader.network_manager() {
        None => uncertain(Uncertainty::Undetermined),
        Some(files) if !files.installed => not_installed("NetworkManager is not installed."),
        Some(files) => match connectivity(&files) {
            Ok(state) => state,
            Err(reason) => uncertain(reason),
        },
    }
}

pub fn avahi(reader: &Reader) -> Resolution {
    match reader.avahi() {
        None => uncertain(Uncertainty::Undetermined),
        Some(files) if !files.installed => not_installed("avahi-daemon is not installed."),
        Some(files) => match publishing(&files) {
            Ok(state) => state,
            Err(reason) => uncertain(reason),
        },
    }
}

pub fn resolved_llmnr(reader: &Reader) -> Resolution {
    resolved(reader, true)
}

pub fn resolved_mdns(reader: &Reader) -> Resolution {
    resolved(reader, false)
}

pub fn thumbnails(reader: &Reader) -> Resolution {
    match reader.thumbnails() {
        None => uncertain(Uncertainty::Undetermined),
        Some(ThumbnailRecord::Absent) => thumbnail_not_established(
            "The thumbnail directory is absent. The standard stores generated previews there. Absence is not evidence that generation is off.",
        ),
        // An empty directory has no preview files. Creating it, or clearing it,
        // does not disable the thumbnailer that will write the next preview.
        Some(ThumbnailRecord::Present(0)) => thumbnail_not_established(
            "The thumbnail directory holds no preview files. That is not evidence that generation is off.",
        ),
        Some(ThumbnailRecord::Present(bytes)) => noted(
            Resolution::determined(enabled(), ManagementSource::User),
            format!("FreeDesktop thumbnail directory holds {bytes} bytes."),
        ),
        Some(ThumbnailRecord::Unreadable(reason)) => uncertain(reason),
    }
}

fn thumbnail_not_established(note: &str) -> Resolution {
    noted(
        Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::Unknown),
        note,
    )
}

fn resolved(reader: &Reader, llmnr: bool) -> Resolution {
    let Some(record) = reader.resolved() else {
        return uncertain(Uncertainty::Undetermined);
    };
    match record {
        ResolvedRecord::NotPresent => {
            not_installed("systemd-resolved is not available on the system bus.")
        }
        ResolvedRecord::Unreadable(reason) => uncertain(reason),
        ResolvedRecord::Values {
            llmnr: global_llmnr,
            mdns: global_mdns,
            links_llmnr,
            links_mdns,
        } => {
            let (global, links) = if llmnr {
                (global_llmnr, links_llmnr)
            } else {
                (global_mdns, links_mdns)
            };
            match multicast_state(&global, &links) {
                Ok((off, note)) => noted(
                    Resolution::determined(
                        if off { disabled() } else { enabled() },
                        ManagementSource::LocalPolicy,
                    ),
                    note,
                ),
                Err(reason) => uncertain(reason),
            }
        }
    }
}

fn connectivity(files: &NmFiles) -> Result<Resolution, Uncertainty> {
    let NmLayers {
        files: selected,
        intern_hidden,
    } = ordered_nm(files)?;
    let mut values: BTreeMap<String, (String, ManagementSource)> = BTreeMap::new();
    for (file, source) in selected {
        for (key, value) in assignments(&file, "connectivity")? {
            if matches!(key.as_str(), "enabled" | "uri" | "interval") {
                values.insert(key, (value, source));
            }
        }
    }
    let enabled_flag = match values.get("enabled") {
        Some((value, _)) => Some(parse_bool(value)?),
        None => None,
    };
    let interval_zero = match values.get("interval") {
        Some((value, _)) => parse_u32(value)? == 0,
        None => false,
    };
    let uri = match values.get("uri") {
        Some((value, source)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some((publishable_uri(trimmed)?.to_owned(), *source))
            }
        }
        None => None,
    };
    let checking = enabled_flag != Some(false) && uri.is_some() && !interval_zero;
    let (source, mut note) = if enabled_flag == Some(false) {
        let source = values
            .get("enabled")
            .map(|(_, source)| *source)
            .unwrap_or(ManagementSource::Default);
        let uri_note = uri
            .as_ref()
            .map(|(uri, _)| format!("; uri {uri}"))
            .unwrap_or_default();
        (source, format!("connectivity enabled false{uri_note}"))
    } else if interval_zero {
        (
            values
                .get("interval")
                .map(|(_, source)| *source)
                .unwrap_or(ManagementSource::Default),
            "connectivity interval 0".to_owned(),
        )
    } else if let Some((uri, source)) = uri {
        (source, format!("connectivity uri {uri}"))
    } else {
        (
            ManagementSource::Default,
            "connectivity uri unset".to_owned(),
        )
    };
    if let Some(reason) = intern_hidden {
        if !checking {
            return Err(reason);
        }
        note.push_str("; runtime override unreadable");
    }
    Ok(noted(
        Resolution::determined(if checking { enabled() } else { disabled() }, source),
        note,
    ))
}

/// Publish settings decide whether the daemon announces this host.
///
/// `systemctl is-active` prints whether the unit is running. `inactive` means
/// stopped, and `failed` means the unit failed. Neither state is
/// `disable-publishing`, which defaults to no. `publish-addresses` defaults
/// to yes, so a stopped daemon with those defaults stays unknown.
fn publishing(files: &AvahiFiles) -> Result<Resolution, Uncertainty> {
    if let Activity::Unknown(reason) = files.active {
        return Err(reason);
    }
    let selected = ordered_avahi(files)?;
    let mut values: BTreeMap<String, (String, ManagementSource)> = BTreeMap::new();
    for (file, source) in selected {
        for (key, value) in assignments(&file, "publish")? {
            if matches!(
                key.as_str(),
                "disable-publishing"
                    | "publish-addresses"
                    | "publish-hinfo"
                    | "publish-workstation"
            ) {
                values.insert(key, (value, source));
            }
        }
    }
    let flag = |key: &str, default: bool| -> Result<(bool, ManagementSource), Uncertainty> {
        match values.get(key) {
            Some((value, source)) => Ok((parse_bool(value)?, *source)),
            None => Ok((default, ManagementSource::Default)),
        }
    };
    let (disable_publishing, disable_source) = flag("disable-publishing", false)?;
    let (addresses, address_source) = flag("publish-addresses", true)?;
    let (hinfo, hinfo_source) = flag("publish-hinfo", false)?;
    let (workstation, workstation_source) = flag("publish-workstation", false)?;
    let publishing = !disable_publishing && (addresses || hinfo || workstation);
    let activity = match files.active {
        Activity::Active => "active",
        Activity::Inactive => "inactive",
        Activity::Unknown(_) => "unknown",
    };
    let note = format!(
        "service {activity}; disable-publishing {}; publish-addresses {}; publish-hinfo {}; publish-workstation {}",
        yes_no(disable_publishing),
        yes_no(addresses),
        yes_no(hinfo),
        yes_no(workstation)
    );
    let explicit = [
        disable_source,
        address_source,
        hinfo_source,
        workstation_source,
    ]
    .into_iter()
    .find(|source| *source != ManagementSource::Default)
    .unwrap_or(ManagementSource::Default);
    // A unit that is not running has not been shown to be configured off.
    // The next start uses these publish settings. Only those settings can
    // establish that announcements are off.
    if publishing && files.active != Activity::Active {
        let mut resolution =
            Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::Unknown);
        resolution.note = Some(format!(
            "{note}. The service is not active, so this does not establish that publishing is off."
        ));
        return Ok(resolution);
    }
    Ok(noted(
        Resolution::determined(if publishing { enabled() } else { disabled() }, explicit),
        note,
    ))
}

struct NmLayers {
    files: Vec<(ConfigurationFile, ManagementSource)>,
    intern_hidden: Option<Uncertainty>,
}

fn ordered_nm(files: &NmFiles) -> Result<NmLayers, Uncertainty> {
    let mut ordered = Vec::new();
    push_file(
        &mut ordered,
        &files.vendor_main,
        ManagementSource::LocalPolicy,
    )?;
    let run_names = directory_names(&files.run_dropin)?;
    let etc_names = directory_names(&files.etc_dropin)?;
    let mut hidden = run_names;
    hidden.extend(etc_names.iter().cloned());
    push_directory(
        &mut ordered,
        &files.vendor_dropin,
        &hidden,
        ManagementSource::LocalPolicy,
    )?;
    push_directory(
        &mut ordered,
        &files.run_dropin,
        &etc_names,
        ManagementSource::LocalPolicy,
    )?;
    push_file(&mut ordered, &files.etc_main, ManagementSource::User)?;
    push_directory(
        &mut ordered,
        &files.etc_dropin,
        &BTreeSet::new(),
        ManagementSource::User,
    )?;
    // intern.conf is root-only on common installs and is read last. When it
    // cannot be read, an already-enabled check stays drift. A disabled check
    // stays unknown, because the unread file can turn the check on.
    let intern_hidden = match &files.intern {
        LayerBody::Absent => None,
        LayerBody::Unreadable(reason) => Some(*reason),
        LayerBody::Directory { .. } => return Err(Uncertainty::Malformed),
        LayerBody::File(ConfigurationFile::Absent) => None,
        LayerBody::File(ConfigurationFile::Uncertain(reason)) => Some(*reason),
        LayerBody::File(file) => {
            admit(file)?;
            ordered.push((file.clone(), ManagementSource::LocalPolicy));
            None
        }
    };
    Ok(NmLayers {
        files: ordered,
        intern_hidden,
    })
}

fn ordered_avahi(
    files: &AvahiFiles,
) -> Result<Vec<(ConfigurationFile, ManagementSource)>, Uncertainty> {
    let mut ordered = Vec::new();
    push_file(
        &mut ordered,
        &files.vendor_main,
        ManagementSource::LocalPolicy,
    )?;
    let run_names = directory_names(&files.run_dropin)?;
    let etc_names = directory_names(&files.etc_dropin)?;
    let mut hidden = run_names;
    hidden.extend(etc_names.iter().cloned());
    push_directory(
        &mut ordered,
        &files.vendor_dropin,
        &hidden,
        ManagementSource::LocalPolicy,
    )?;
    push_directory(
        &mut ordered,
        &files.run_dropin,
        &etc_names,
        ManagementSource::LocalPolicy,
    )?;
    push_file(&mut ordered, &files.etc_main, ManagementSource::User)?;
    push_directory(
        &mut ordered,
        &files.etc_dropin,
        &BTreeSet::new(),
        ManagementSource::User,
    )?;
    Ok(ordered)
}

fn directory_names(layer: &LayerBody) -> Result<BTreeSet<Vec<u8>>, Uncertainty> {
    match layer {
        LayerBody::Absent => Ok(BTreeSet::new()),
        LayerBody::Unreadable(reason) => Err(*reason),
        LayerBody::File(_) => Err(Uncertainty::Malformed),
        LayerBody::Directory { listing, .. } => match listing {
            DirectoryListing::Absent => Ok(BTreeSet::new()),
            DirectoryListing::Uncertain(reason) => Err(*reason),
            DirectoryListing::Complete(names) => Ok(names.iter().cloned().collect()),
        },
    }
}

fn push_file(
    ordered: &mut Vec<(ConfigurationFile, ManagementSource)>,
    layer: &LayerBody,
    source: ManagementSource,
) -> Result<(), Uncertainty> {
    match layer {
        LayerBody::Absent => Ok(()),
        LayerBody::Unreadable(reason) => Err(*reason),
        LayerBody::Directory { .. } => Err(Uncertainty::Malformed),
        LayerBody::File(file) => {
            admit(file)?;
            ordered.push((file.clone(), source));
            Ok(())
        }
    }
}

fn push_directory(
    ordered: &mut Vec<(ConfigurationFile, ManagementSource)>,
    layer: &LayerBody,
    hidden: &BTreeSet<Vec<u8>>,
    source: ManagementSource,
) -> Result<(), Uncertainty> {
    match layer {
        LayerBody::Absent => Ok(()),
        LayerBody::Unreadable(reason) => Err(*reason),
        LayerBody::File(_) => Err(Uncertainty::Malformed),
        LayerBody::Directory { listing, files } => {
            let DirectoryListing::Complete(names) = listing else {
                return match listing {
                    DirectoryListing::Absent => Ok(()),
                    DirectoryListing::Uncertain(reason) => Err(*reason),
                    DirectoryListing::Complete(_) => unreachable!(),
                };
            };
            for name in names {
                if hidden.contains(name) {
                    continue;
                }
                let Some(file) = files.get(name) else {
                    return Err(Uncertainty::Undetermined);
                };
                admit(file)?;
                ordered.push((file.clone(), source));
            }
            Ok(())
        }
    }
}

fn admit(file: &ConfigurationFile) -> Result<(), Uncertainty> {
    match file {
        ConfigurationFile::Absent | ConfigurationFile::Mask | ConfigurationFile::Regular(_) => {
            Ok(())
        }
        ConfigurationFile::Uncertain(reason) => Err(*reason),
    }
}

fn assignments(
    file: &ConfigurationFile,
    section: &str,
) -> Result<Vec<(String, String)>, Uncertainty> {
    let ConfigurationFile::Regular(value) = file else {
        return Ok(Vec::new());
    };
    if value.kind != ValueKind::String {
        return Err(Uncertainty::Malformed);
    }
    let text = std::str::from_utf8(&value.bytes).map_err(|_| Uncertainty::Malformed)?;
    if text
        .chars()
        .any(|ch| ch == '\0' || (ch.is_control() && !matches!(ch, '\n' | '\r' | '\t')))
    {
        return Err(Uncertainty::Malformed);
    }
    let mut relevant = false;
    let mut found = Vec::new();
    for line in text.split('\n') {
        if line.len() > 4096 {
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
        if line.ends_with('\\') {
            return Err(Uncertainty::Malformed);
        }
        if line.starts_with('[') {
            let Some(name) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            else {
                return Err(Uncertainty::Malformed);
            };
            if name.contains(['[', ']']) {
                return Err(Uncertainty::Malformed);
            }
            relevant = name == section;
            continue;
        }
        if !relevant {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim_matches([' ', '\t']);
        if key.is_empty() || key.chars().any(|ch| ch.is_whitespace()) {
            return Err(Uncertainty::Malformed);
        }
        found.push((key.to_owned(), raw.trim_matches([' ', '\t']).to_owned()));
    }
    Ok(found)
}

fn parse_bool(value: &str) -> Result<bool, Uncertainty> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(Uncertainty::Malformed),
    }
}

fn parse_u32(value: &str) -> Result<u32, Uncertainty> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Uncertainty::Malformed);
    }
    value.parse().map_err(|_| Uncertainty::Malformed)
}

fn publishable_uri(uri: &str) -> Result<&str, Uncertainty> {
    if uri.len() > MAX_URI_BYTES
        || uri.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        || !(uri.starts_with("http://") || uri.starts_with("https://"))
    {
        return Err(Uncertainty::Malformed);
    }
    let host = uri
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .unwrap_or("");
    if host.is_empty() || host.contains('@') {
        return Err(Uncertainty::Undetermined);
    }
    Ok(uri)
}

pub fn parse_dbus_string(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("s ")?.trim();
    let rest = rest.strip_prefix('"')?;
    let rest = rest.strip_suffix('"')?;
    if rest.contains(['\\', '"']) || !matches!(rest, "yes" | "no" | "resolve") {
        return None;
    }
    Some(rest.to_owned())
}

pub fn parse_link_object_paths(tree: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let marker = "/org/freedesktop/resolve1/link/_";
    let mut rest = tree;
    while let Some(index) = rest.find(marker) {
        let start = &rest[index..];
        let end = start
            .find(|ch: char| {
                !ch.is_ascii_digit() && ch != '/' && ch != '_' && !ch.is_ascii_alphabetic()
            })
            .unwrap_or(start.len());
        let path = &start[..end];
        if let Some(name) = path.rsplit('/').next()
            && name.starts_with('_')
            && name.len() > 1
            && name[1..].bytes().all(|byte| byte.is_ascii_digit())
        {
            paths.push(path.to_owned());
        }
        rest = &start[marker.len()..];
    }
    paths.sort();
    paths.dedup();
    paths
}

fn multicast_state(global: &str, links: &[String]) -> Result<(bool, String), Uncertainty> {
    let mut enabled_links = 0usize;
    let mut disabled_links = 0usize;
    if !matches!(global, "yes" | "no" | "resolve") {
        return Err(Uncertainty::Malformed);
    }
    for link in links {
        match link.as_str() {
            "no" => disabled_links += 1,
            "yes" | "resolve" => enabled_links += 1,
            _ => return Err(Uncertainty::Malformed),
        }
    }
    let off = global == "no" && enabled_links == 0;
    let note =
        format!("global {global}; {disabled_links} links no; {enabled_links} links yes or resolve");
    Ok((off, note))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn enabled() -> SemanticState {
    SemanticState::new("enabled")
}

fn disabled() -> SemanticState {
    SemanticState::new("disabled")
}

fn uncertain(reason: Uncertainty) -> Resolution {
    Resolution::uncertain(reason, ManagementSource::LocalPolicy)
}

fn not_installed(note: &str) -> Resolution {
    noted(
        Resolution::inert(disabled(), ManagementSource::Default),
        note,
    )
}

fn noted(mut resolution: Resolution, note: impl Into<String>) -> Resolution {
    resolution.note = Some(note.into());
    resolution
}

pub fn read_live_network_manager() -> Option<NmFiles> {
    let installed = match installed(&[
        "/usr/bin/NetworkManager",
        "/usr/sbin/NetworkManager",
        "/usr/lib/systemd/system/NetworkManager.service",
        "/lib/systemd/system/NetworkManager.service",
    ]) {
        Ok(installed) => installed,
        Err(reason) => {
            return Some(NmFiles {
                installed: true,
                vendor_main: LayerBody::Unreadable(reason),
                vendor_dropin: LayerBody::Absent,
                run_dropin: LayerBody::Absent,
                etc_main: LayerBody::Absent,
                etc_dropin: LayerBody::Absent,
                intern: LayerBody::Absent,
            });
        }
    };
    Some(NmFiles {
        installed,
        vendor_main: live_file("/usr/lib/NetworkManager/NetworkManager.conf"),
        vendor_dropin: live_directory("/usr/lib/NetworkManager/conf.d"),
        run_dropin: live_directory("/run/NetworkManager/conf.d"),
        etc_main: live_file("/etc/NetworkManager/NetworkManager.conf"),
        etc_dropin: live_directory("/etc/NetworkManager/conf.d"),
        intern: live_file("/var/lib/NetworkManager/NetworkManager-intern.conf"),
    })
}

pub fn read_live_avahi() -> Option<AvahiFiles> {
    let installed = match installed(&[
        "/usr/sbin/avahi-daemon",
        "/usr/bin/avahi-daemon",
        "/usr/lib/systemd/system/avahi-daemon.service",
        "/lib/systemd/system/avahi-daemon.service",
    ]) {
        Ok(false) => {
            return Some(AvahiFiles {
                installed: false,
                active: Activity::Inactive,
                vendor_main: LayerBody::Absent,
                vendor_dropin: LayerBody::Absent,
                run_dropin: LayerBody::Absent,
                etc_main: LayerBody::Absent,
                etc_dropin: LayerBody::Absent,
            });
        }
        Ok(true) => true,
        Err(reason) => {
            return Some(AvahiFiles {
                installed: true,
                active: Activity::Unknown(reason),
                vendor_main: LayerBody::Absent,
                vendor_dropin: LayerBody::Absent,
                run_dropin: LayerBody::Absent,
                etc_main: LayerBody::Absent,
                etc_dropin: LayerBody::Absent,
            });
        }
    };
    Some(AvahiFiles {
        installed,
        active: systemctl_active("avahi-daemon.service"),
        vendor_main: live_file("/usr/lib/avahi/avahi-daemon.conf"),
        vendor_dropin: live_directory("/usr/lib/avahi/avahi-daemon.conf.d"),
        run_dropin: live_directory("/run/avahi/avahi-daemon.conf.d"),
        etc_main: live_file("/etc/avahi/avahi-daemon.conf"),
        etc_dropin: live_directory("/etc/avahi/avahi-daemon.conf.d"),
    })
}

pub fn read_live_resolved() -> Option<ResolvedRecord> {
    Some(match resolved_from_bus() {
        Ok(record) => record,
        Err(reason) => ResolvedRecord::Unreadable(reason),
    })
}

pub fn read_live_thumbnails() -> Option<ThumbnailRecord> {
    Some(match thumbnail_directory() {
        Ok(path) => match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                ThumbnailRecord::Unreadable(Uncertainty::Undetermined)
            }
            Ok(_) => match directory_size(&path) {
                Ok(bytes) => ThumbnailRecord::Present(bytes),
                Err(reason) => ThumbnailRecord::Unreadable(reason),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ThumbnailRecord::Absent,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                ThumbnailRecord::Unreadable(Uncertainty::Denied)
            }
            Err(_) => ThumbnailRecord::Unreadable(Uncertainty::Undetermined),
        },
        Err(reason) => ThumbnailRecord::Unreadable(reason),
    })
}

fn live_file(path: &str) -> LayerBody {
    match systemd::read_regular(Path::new(path)) {
        ConfigurationFile::Absent => LayerBody::Absent,
        other => LayerBody::File(other),
    }
}

fn live_directory(path: &str) -> LayerBody {
    let (listing, files) = systemd::read_conf_directory(Path::new(path));
    match listing {
        DirectoryListing::Absent => LayerBody::Absent,
        DirectoryListing::Uncertain(reason) => LayerBody::Unreadable(reason),
        DirectoryListing::Complete(_) => LayerBody::Directory { listing, files },
    }
}

fn installed(paths: &[&str]) -> Result<bool, Uncertainty> {
    let mut denied = false;
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Uncertainty::Undetermined);
            }
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => denied = true,
            Err(_) => return Err(Uncertainty::Undetermined),
        }
    }
    if denied {
        Err(Uncertainty::Denied)
    } else {
        Ok(false)
    }
}

fn systemctl_active(unit: &str) -> Activity {
    let Some(binary) = ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
    else {
        return Activity::Unknown(Uncertainty::Undetermined);
    };
    let Ok(output) = Command::new(binary).args(["is-active", unit]).output() else {
        return Activity::Unknown(Uncertainty::Undetermined);
    };
    if output.stdout.len() > MAX_COMMAND_BYTES {
        return Activity::Unknown(Uncertainty::Undetermined);
    }
    activity_from_is_active(&String::from_utf8_lossy(&output.stdout))
}

/// Classify `systemctl is-active` stdout. The command prints the process
/// state, not whether the unit is enabled and not whether publishing is off.
fn activity_from_is_active(stdout: &str) -> Activity {
    match stdout.trim() {
        "active" | "activating" | "reloading" => Activity::Active,
        "inactive" | "failed" | "deactivating" => Activity::Inactive,
        _ => Activity::Unknown(Uncertainty::Undetermined),
    }
}

fn resolved_from_bus() -> Result<ResolvedRecord, Uncertainty> {
    let Some(binary) = ["/usr/bin/busctl", "/bin/busctl"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
    else {
        return Ok(ResolvedRecord::NotPresent);
    };
    let llmnr = busctl(
        binary,
        &[
            "get-property",
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            "LLMNR",
        ],
    )?;
    let mdns = busctl(
        binary,
        &[
            "get-property",
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            "MulticastDNS",
        ],
    )?;
    let tree = busctl(binary, &["tree", "org.freedesktop.resolve1"])?;
    let (llmnr, mdns, tree) = match (llmnr, mdns, tree) {
        (BusReply::Text(llmnr), BusReply::Text(mdns), BusReply::Text(tree)) => (llmnr, mdns, tree),
        (BusReply::NotPresent, _, _)
        | (_, BusReply::NotPresent, _)
        | (_, _, BusReply::NotPresent) => {
            return Ok(ResolvedRecord::NotPresent);
        }
    };
    let llmnr = parse_dbus_string(&llmnr).ok_or(Uncertainty::Malformed)?;
    let mdns = parse_dbus_string(&mdns).ok_or(Uncertainty::Malformed)?;
    let mut links_llmnr = Vec::new();
    let mut links_mdns = Vec::new();
    for path in parse_link_object_paths(&tree) {
        if !path.starts_with("/org/freedesktop/resolve1/link/_") {
            return Err(Uncertainty::Malformed);
        }
        let link_llmnr = match busctl(
            binary,
            &[
                "get-property",
                "org.freedesktop.resolve1",
                &path,
                "org.freedesktop.resolve1.Link",
                "LLMNR",
            ],
        )? {
            BusReply::Text(text) => parse_dbus_string(&text).ok_or(Uncertainty::Malformed)?,
            BusReply::NotPresent => return Ok(ResolvedRecord::NotPresent),
        };
        let link_mdns = match busctl(
            binary,
            &[
                "get-property",
                "org.freedesktop.resolve1",
                &path,
                "org.freedesktop.resolve1.Link",
                "MulticastDNS",
            ],
        )? {
            BusReply::Text(text) => parse_dbus_string(&text).ok_or(Uncertainty::Malformed)?,
            BusReply::NotPresent => return Ok(ResolvedRecord::NotPresent),
        };
        links_llmnr.push(link_llmnr);
        links_mdns.push(link_mdns);
    }
    Ok(ResolvedRecord::Values {
        llmnr,
        mdns,
        links_llmnr,
        links_mdns,
    })
}

enum BusReply {
    Text(String),
    NotPresent,
}

fn busctl(binary: &str, args: &[&str]) -> Result<BusReply, Uncertainty> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|_| Uncertainty::Undetermined)?;
    if output.stdout.len() > MAX_COMMAND_BYTES || output.stderr.len() > MAX_COMMAND_BYTES {
        return Err(Uncertainty::Undetermined);
    }
    if output.status.success() {
        let text = String::from_utf8(output.stdout).map_err(|_| Uncertainty::Malformed)?;
        return Ok(BusReply::Text(text));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("not provided by any")
        || lower.contains("name has no owner")
        || lower.contains("service unknown")
        || lower.contains("no such file")
    {
        return Ok(BusReply::NotPresent);
    }
    if lower.contains("failed to connect") {
        return Err(Uncertainty::Undetermined);
    }
    Err(Uncertainty::Undetermined)
}

fn thumbnail_directory() -> Result<PathBuf, Uncertainty> {
    if let Some(cache) = std::env::var_os("XDG_CACHE_HOME")
        && !cache.is_empty()
    {
        let cache = PathBuf::from(cache);
        if !cache.is_absolute() {
            return Err(Uncertainty::Undetermined);
        }
        return Ok(cache.join("thumbnails"));
    }
    let Some(home) = std::env::var_os("HOME") else {
        return Err(Uncertainty::Undetermined);
    };
    if home.is_empty() {
        return Err(Uncertainty::Undetermined);
    }
    Ok(PathBuf::from(home).join(".cache").join("thumbnails"))
}

fn directory_size(root: &Path) -> Result<u64, Uncertainty> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0usize;
    let mut total = 0u64;
    while let Some(directory) = pending.pop() {
        let read = std::fs::read_dir(&directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                Uncertainty::Denied
            } else {
                Uncertainty::Undetermined
            }
        })?;
        for entry in read {
            let entry = entry.map_err(|_| Uncertainty::Undetermined)?;
            entries += 1;
            if entries > MAX_WALK_ENTRIES {
                return Err(Uncertainty::Undetermined);
            }
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|error| {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    Uncertainty::Denied
                } else {
                    Uncertainty::Undetermined
                }
            })?;
            if metadata.file_type().is_symlink() {
                return Err(Uncertainty::Undetermined);
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            } else {
                return Err(Uncertainty::Undetermined);
            }
        }
    }
    Ok(total)
}

pub fn text_file(bytes: &[u8]) -> LayerBody {
    LayerBody::File(ConfigurationFile::Regular(RawValue::new(
        ValueKind::String,
        bytes.to_vec(),
    )))
}

pub fn absent_files() -> NmFiles {
    NmFiles {
        installed: true,
        vendor_main: LayerBody::Absent,
        vendor_dropin: LayerBody::Absent,
        run_dropin: LayerBody::Absent,
        etc_main: LayerBody::Absent,
        etc_dropin: LayerBody::Absent,
        intern: LayerBody::Absent,
    }
}

pub fn absent_avahi() -> AvahiFiles {
    AvahiFiles {
        installed: true,
        active: Activity::Active,
        vendor_main: LayerBody::Absent,
        vendor_dropin: LayerBody::Absent,
        run_dropin: LayerBody::Absent,
        etc_main: LayerBody::Absent,
        etc_dropin: LayerBody::Absent,
    }
}

pub fn dropin(name: &str, bytes: &[u8]) -> LayerBody {
    let mut files = BTreeMap::new();
    files.insert(
        name.as_bytes().to_vec(),
        ConfigurationFile::Regular(RawValue::new(ValueKind::String, bytes.to_vec())),
    );
    LayerBody::Directory {
        listing: DirectoryListing::Complete(vec![name.as_bytes().to_vec()]),
        files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::outcome::Outcome;
    use crate::report::Report;

    fn checked(id: &str, profile: &str, records: ExposureRecords) -> (Outcome, Option<String>) {
        let host = crate::test_context::host("arch", "hyprland");
        let reader = crate::test_context::reader_with_exposure([], records);
        let context = crate::test_context::context(&host, &reader);
        let report =
            Report::build_with_context(&context, Some(profile), None, &[id.to_owned()], &[]);
        assert_eq!(report.results.len(), 1, "{id}");
        let result = &report.results[0];
        (result.outcome, result.note.clone())
    }

    #[test]
    fn parsers_accept_resolved_property_text_and_link_paths() {
        assert_eq!(parse_dbus_string("s \"no\"\n").as_deref(), Some("no"));
        assert_eq!(
            parse_dbus_string("s \"resolve\"").as_deref(),
            Some("resolve")
        );
        assert!(parse_dbus_string("s \"maybe\"").is_none());
        assert!(parse_dbus_string("b true").is_none());
        let tree = "\
└─ /org/freedesktop/resolve1
  └─ /org/freedesktop/resolve1/link
    ├─ /org/freedesktop/resolve1/link/_31
    └─ /org/freedesktop/resolve1/link/_2
";
        assert_eq!(
            parse_link_object_paths(tree),
            [
                "/org/freedesktop/resolve1/link/_2".to_owned(),
                "/org/freedesktop/resolve1/link/_31".to_owned()
            ]
        );
    }

    #[test]
    fn networkmanager_fixtures_cover_precedence_absence_and_failure() {
        let uri = b"[connectivity]\nuri=http://ping.archlinux.org/nm-check.txt\n";
        let mut vendor = absent_files();
        vendor.vendor_dropin = dropin("20-connectivity.conf", uri);
        let (outcome, note) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(vendor),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Drift);
        assert!(
            note.unwrap()
                .contains("http://ping.archlinux.org/nm-check.txt")
        );

        let mut etc = absent_files();
        etc.vendor_dropin = dropin("20-connectivity.conf", uri);
        etc.etc_main = text_file(b"[connectivity]\nenabled=false\n");
        let (outcome, note) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(etc),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Pass);
        assert!(note.unwrap().contains("enabled false"));

        let mut shadowed = absent_files();
        shadowed.vendor_dropin = dropin("20-connectivity.conf", uri);
        shadowed.etc_dropin = dropin(
            "20-connectivity.conf",
            b"[connectivity]\nuri=https://example.invalid/nm\n",
        );
        let (outcome, note) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(shadowed),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Drift);
        let note = note.unwrap();
        assert!(note.contains("https://example.invalid/nm"));
        assert!(!note.contains("ping.archlinux.org"));

        let mut missing = absent_files();
        missing.installed = false;
        let (outcome, _) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(missing),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::NotApplicable);

        let mut hidden_on = absent_files();
        hidden_on.vendor_dropin = dropin("20-connectivity.conf", uri);
        hidden_on.intern = LayerBody::File(ConfigurationFile::Uncertain(Uncertainty::Denied));
        let (outcome, note) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(hidden_on),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Drift);
        assert!(
            note.unwrap()
                .contains("http://ping.archlinux.org/nm-check.txt")
        );

        let mut hidden_off = absent_files();
        hidden_off.etc_main = text_file(b"[connectivity]\nenabled=false\n");
        hidden_off.intern = LayerBody::Unreadable(Uncertainty::Denied);
        let (outcome, _) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(hidden_off),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Unknown);

        let mut runtime_off = absent_files();
        runtime_off.vendor_dropin = dropin("20-connectivity.conf", uri);
        runtime_off.intern = text_file(b"[connectivity]\nenabled=false\n");
        let (outcome, note) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(runtime_off),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Pass);
        assert!(note.unwrap().contains("enabled false"));

        let mut denied = absent_files();
        denied.etc_dropin = LayerBody::Unreadable(Uncertainty::Denied);
        let (outcome, _) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords {
                network_manager: Some(denied),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Unknown);

        let (outcome, _) = checked(
            "networkmanager.connectivity.check",
            "baseline",
            ExposureRecords::default(),
        );
        assert_eq!(outcome, Outcome::Unknown);
    }

    #[test]
    fn avahi_fixtures_cover_defaults_overrides_and_absence() {
        let (outcome, note) = checked(
            "avahi.mdns.publishing",
            "strict",
            ExposureRecords {
                avahi: Some(absent_avahi()),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Drift);
        assert!(note.unwrap().contains("publish-addresses yes"));

        let mut disabled = absent_avahi();
        disabled.etc_main = text_file(b"[publish]\ndisable-publishing=yes\n");
        let (outcome, _) = checked(
            "avahi.mdns.publishing",
            "strict",
            ExposureRecords {
                avahi: Some(disabled),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Pass);

        let mut drop_in = absent_avahi();
        drop_in.etc_main = text_file(b"[publish]\npublish-addresses=yes\n");
        drop_in.etc_dropin = dropin("10-quiet.conf", b"[publish]\ndisable-publishing=yes\n");
        let (outcome, _) = checked(
            "avahi.mdns.publishing",
            "strict",
            ExposureRecords {
                avahi: Some(drop_in),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Pass);

        let mut gone = absent_avahi();
        gone.installed = false;
        let (outcome, _) = checked(
            "avahi.mdns.publishing",
            "strict",
            ExposureRecords {
                avahi: Some(gone),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::NotApplicable);

        let mut denied = absent_avahi();
        denied.etc_main = LayerBody::Unreadable(Uncertainty::Denied);
        let (outcome, _) = checked(
            "avahi.mdns.publishing",
            "strict",
            ExposureRecords {
                avahi: Some(denied),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Unknown);
    }

    #[test]
    fn is_active_tokens_distinguish_running_from_stopped_failed_and_unknown() {
        for token in ["active", "activating", "reloading", " active\n"] {
            assert_eq!(
                activity_from_is_active(token),
                Activity::Active,
                "{token:?}"
            );
        }
        // These three tokens share one state. A stopped, failed, or stopping
        // daemon must not become a pass while the publish settings stay on.
        for token in ["inactive", "failed", "deactivating", " failed\n"] {
            assert_eq!(
                activity_from_is_active(token),
                Activity::Inactive,
                "{token:?}"
            );
        }
        for token in [
            "",
            "unknown",
            "not-found",
            "maintenance",
            "INACTIVE",
            "failed extra",
        ] {
            assert!(
                matches!(
                    activity_from_is_active(token),
                    Activity::Unknown(Uncertainty::Undetermined)
                ),
                "{token:?}"
            );
        }
    }

    #[test]
    fn stopped_avahi_does_not_pass_unless_publish_settings_are_off() {
        let host = crate::test_context::host("arch", "hyprland");
        let mut commented = absent_avahi();
        commented.active = Activity::Inactive;
        commented.etc_main =
            text_file(b"[publish]\n# disable-publishing=yes\n# /home/secret-user\n");
        let reader = crate::test_context::reader_with_exposure(
            [],
            ExposureRecords {
                avahi: Some(commented),
                ..ExposureRecords::default()
            },
        );
        let context = crate::test_context::context(&host, &reader);
        let report = Report::build_with_context(
            &context,
            Some("strict"),
            None,
            &["avahi.mdns.publishing".to_owned()],
            &[],
        );
        let result = &report.results[0];
        assert_eq!(result.outcome, Outcome::Unknown);
        assert_ne!(result.outcome, Outcome::Pass);
        assert!(!report.complete);
        assert!(!result.confident);
        assert_eq!(result.observed, None);
        assert_eq!(result.observation_reason, Some(Uncertainty::Undetermined));
        assert_eq!(result.management_source, ManagementSource::Unknown);
        let note = result.note.as_deref().expect("note");
        assert!(note.contains("service inactive"));
        assert!(note.contains("publish-addresses yes"));
        assert!(note.contains("does not establish that publishing is off"));
        assert!(!note.contains('/'));
        assert!(!note.contains("secret-user"));
        let json = serde_json::to_string(&report).expect("report json");
        assert!(!json.contains("secret-user"));

        let mut disabled = absent_avahi();
        disabled.active = Activity::Inactive;
        disabled.etc_main = text_file(b"[publish]\ndisable-publishing=yes\n# /home/secret-user\n");
        let (outcome, note) = checked(
            "avahi.mdns.publishing",
            "strict",
            ExposureRecords {
                avahi: Some(disabled),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Pass);
        let note = note.expect("note");
        assert!(note.contains("disable-publishing yes"));
        assert!(note.contains("service inactive"));
        assert!(!note.contains("does not establish"));
        assert!(!note.contains("secret-user"));
        assert!(!note.contains('/'));

        let mut quiet = absent_avahi();
        quiet.active = Activity::Inactive;
        quiet.etc_main = text_file(
            b"[publish]\npublish-addresses=no\npublish-hinfo=no\npublish-workstation=no\n",
        );
        let (outcome, note) = checked(
            "avahi.mdns.publishing",
            "strict",
            ExposureRecords {
                avahi: Some(quiet),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(outcome, Outcome::Pass);
        let note = note.expect("note");
        assert!(note.contains("publish-addresses no"));
        assert!(note.contains("publish-hinfo no"));
        assert!(note.contains("publish-workstation no"));
        assert!(!note.contains("does not establish"));
        assert!(!note.contains('/'));
    }

    #[test]
    fn resolved_and_thumbnail_fixtures_do_not_pass_without_evidence() {
        let quiet = ResolvedRecord::Values {
            llmnr: "no".to_owned(),
            mdns: "no".to_owned(),
            links_llmnr: vec!["no".to_owned(), "no".to_owned()],
            links_mdns: vec!["no".to_owned()],
        };
        let (llmnr, _) = checked(
            "systemd.resolved.llmnr",
            "baseline",
            ExposureRecords {
                resolved: Some(quiet.clone()),
                ..ExposureRecords::default()
            },
        );
        let (mdns, note) = checked(
            "systemd.resolved.mdns",
            "baseline",
            ExposureRecords {
                resolved: Some(quiet),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(llmnr, Outcome::Pass);
        assert_eq!(mdns, Outcome::Pass);
        assert!(note.unwrap().contains("global no"));

        let noisy = ResolvedRecord::Values {
            llmnr: "no".to_owned(),
            mdns: "resolve".to_owned(),
            links_llmnr: vec!["yes".to_owned()],
            links_mdns: vec!["no".to_owned()],
        };
        let (llmnr, _) = checked(
            "systemd.resolved.llmnr",
            "baseline",
            ExposureRecords {
                resolved: Some(noisy.clone()),
                ..ExposureRecords::default()
            },
        );
        let (mdns, _) = checked(
            "systemd.resolved.mdns",
            "baseline",
            ExposureRecords {
                resolved: Some(noisy),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(llmnr, Outcome::Drift);
        assert_eq!(mdns, Outcome::Drift);

        for record in [
            ResolvedRecord::NotPresent,
            ResolvedRecord::Unreadable(Uncertainty::Denied),
        ] {
            let expect = match record {
                ResolvedRecord::NotPresent => Outcome::NotApplicable,
                _ => Outcome::Unknown,
            };
            let (outcome, _) = checked(
                "systemd.resolved.llmnr",
                "baseline",
                ExposureRecords {
                    resolved: Some(record),
                    ..ExposureRecords::default()
                },
            );
            assert_eq!(outcome, expect);
            assert_ne!(outcome, Outcome::Pass);
        }

        let (absent, note) = checked(
            "freedesktop.thumbnails.caching",
            "strict",
            ExposureRecords {
                thumbnails: Some(ThumbnailRecord::Absent),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(absent, Outcome::Unknown);
        assert_ne!(absent, Outcome::Pass);
        let absent_note = note.unwrap();
        assert!(absent_note.contains("not evidence"));
        assert!(!absent_note.contains('/'));
        let (empty, note) = checked(
            "freedesktop.thumbnails.caching",
            "strict",
            ExposureRecords {
                thumbnails: Some(ThumbnailRecord::Present(0)),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(empty, Outcome::Unknown);
        assert_ne!(empty, Outcome::Pass);
        let empty_note = note.unwrap();
        assert!(empty_note.contains("no preview files"));
        assert!(!empty_note.contains('/'));
        let (present, note) = checked(
            "freedesktop.thumbnails.caching",
            "strict",
            ExposureRecords {
                thumbnails: Some(ThumbnailRecord::Present(42)),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(present, Outcome::Drift);
        assert_ne!(present, Outcome::Pass);
        assert!(note.unwrap().contains("42"));
        let (unknown, _) = checked(
            "freedesktop.thumbnails.caching",
            "strict",
            ExposureRecords {
                thumbnails: Some(ThumbnailRecord::Unreadable(Uncertainty::Denied)),
                ..ExposureRecords::default()
            },
        );
        assert_eq!(unknown, Outcome::Unknown);
    }
}
