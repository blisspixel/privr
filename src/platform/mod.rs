//! Platform adapters.
//!
//! Each platform module owns its own probing and its own effective-state
//! resolution, because precedence is platform-specific and control-specific.
//! The engine never learns any of it.
//!
//! Modules are gated by target rather than selected at runtime, so code for a
//! platform is not merely unreachable elsewhere, it is not compiled.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

pub mod cancellation;
pub mod elevation;

#[cfg(not(windows))]
pub(crate) mod xdg;

use crate::model::host::HostFacts;
use crate::model::residue::{ResiduePreviewItem, ResiduePurgeItem, ResidueSpec, TrimStatus};

/// Discover the facts this host presents.
///
/// On a platform whose adapters are not implemented, every fact is unknown.
/// That is the honest answer: it leaves every control undetermined rather than
/// reporting a machine as compliant that was never examined.
pub fn discover() -> HostFacts {
    #[cfg(windows)]
    {
        windows::discovery::discover()
    }
    #[cfg(target_os = "linux")]
    {
        linux::discovery::discover()
    }
    #[cfg(target_os = "macos")]
    {
        macos::discovery::discover()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HostFacts::unknown(crate::model::host::Platform::current())
    }
}

/// Refuse unresolved user roots before inspecting or deleting a selected target.
pub(crate) fn validate_residue_roots(
    targets: &[(ResidueSpec, bool, Option<String>)],
) -> Result<(), String> {
    for (spec, selected, _) in targets {
        if !selected {
            continue;
        }
        #[cfg(target_os = "linux")]
        if let Err(reason) = linux::residue::validate_target_root(spec) {
            return Err(format!("{}: {reason}", spec.id));
        }
        #[cfg(target_os = "macos")]
        if xdg::home_dir().is_none() {
            return Err(format!("{}: no absolute HOME is available", spec.id));
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = spec;
    }
    Ok(())
}

/// Inspect a residue target and return its preview item.
pub fn inspect_residue_target(
    spec: &ResidueSpec,
    selected: bool,
    retained_reason: Option<String>,
) -> ResiduePreviewItem {
    #[cfg(windows)]
    {
        windows::residue::inspect_target(spec, selected, retained_reason)
    }
    #[cfg(target_os = "linux")]
    {
        linux::residue::inspect_target(spec, selected, retained_reason)
    }
    #[cfg(target_os = "macos")]
    {
        macos::residue::inspect_target(spec, selected, retained_reason)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        ResiduePreviewItem {
            id: spec.id.clone(),
            title: spec.title.clone(),
            category: spec.category,
            trade_off: spec.trade_off.clone(),
            path_display: "(unsupported platform)".to_owned(),
            file_count: 0,
            size_bytes: 0,
            selected,
            retained_reason,
            requires_risk_ack: spec.requires_risk_ack,
        }
    }
}

/// Execute purge for a residue target and return its result item.
pub fn purge_residue_target(
    spec: &ResidueSpec,
    cancellation: &cancellation::Cancellation,
) -> ResiduePurgeItem {
    #[cfg(windows)]
    {
        windows::residue::purge_target(spec, cancellation)
    }
    #[cfg(target_os = "linux")]
    {
        linux::residue::purge_target(spec, cancellation)
    }
    #[cfg(target_os = "macos")]
    {
        macos::residue::purge_target(spec, cancellation)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        ResiduePurgeItem {
            id: spec.id.clone(),
            title: spec.title.clone(),
            category: spec.category,
            trade_off: spec.trade_off.clone(),
            files_removed: 0,
            bytes_reclaimed: 0,
            files_retained: 0,
            error: Some("Platform does not support residue purge".to_owned()),
        }
    }
}

/// Query hardware TRIM capability for the volume containing user data.
pub fn check_volume_trim_support() -> TrimStatus {
    #[cfg(windows)]
    {
        let drive = windows::residue::system_drive_letter();
        windows::residue::check_volume_trim_support(drive)
    }
    #[cfg(target_os = "linux")]
    {
        linux::residue::check_volume_trim_support()
    }
    #[cfg(target_os = "macos")]
    {
        macos::residue::check_volume_trim_support()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        TrimStatus {
            volume: "unknown".to_owned(),
            media_type: "Unknown".to_owned(),
            supported: false,
            executed: false,
            message: "Hardware TRIM is not supported on this platform".to_owned(),
        }
    }
}

/// Execute hardware TRIM / unmap across unallocated space.
pub fn execute_volume_trim() -> TrimStatus {
    #[cfg(windows)]
    {
        let drive = windows::residue::system_drive_letter();
        windows::residue::execute_volume_trim(drive)
    }
    #[cfg(target_os = "linux")]
    {
        linux::residue::execute_volume_trim()
    }
    #[cfg(target_os = "macos")]
    {
        macos::residue::execute_volume_trim()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        TrimStatus {
            volume: "unknown".to_owned(),
            media_type: "Unknown".to_owned(),
            supported: false,
            executed: false,
            message: "Hardware TRIM execution is not supported on this platform".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::host::Platform;

    #[test]
    fn discovery_reports_the_running_platform() {
        assert_eq!(discover().platform, Platform::current());
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    #[test]
    fn an_unimplemented_platform_admits_it_knows_nothing() {
        // The property that keeps an unported platform honest: no fact is
        // guessed, so no control can evaluate to a pass.
        let host = discover();
        assert!(host.version.is_unknown());
        assert!(host.edition.is_unknown());
        assert!(host.elevated.is_unknown());
    }
}
