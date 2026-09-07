//! Windows host discovery.
//!
//! Establishes the facts controls are gated on. Every fact that cannot be
//! determined stays `Unknown`, which leaves dependent controls undetermined
//! rather than silently excluding them.
//!
//! Nothing here collects a stable identifier. Management detection reports only
//! whether an authority is present, never which one: enrollment identifiers,
//! security identifiers, and policy object identifiers are reduced to a boolean
//! inside this module and never exist further up the stack.

use crate::model::host::{
    Architecture, ContainerKind, Fact, HostFacts, OsVersion, Platform, SessionFacts, WriteModel,
};

use super::registry::{self, Hive, Target, View};

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

fn read_u32(value: &'static str) -> Option<u32> {
    let target = Target::new(Hive::LocalMachine, CURRENT_VERSION, value, View::Native);
    match registry::read(&target, crate::model::host::ManagementSource::Default) {
        crate::model::evidence::Evidence::Present { value, .. } => value.as_u32(),
        _ => None,
    }
}

/// The three outcomes of trying to read a string value.
///
/// Absent and unreadable are kept apart, because an absent domain name means
/// the host is not domain joined while an unreadable one means we cannot say.
enum Readable {
    Value(String),
    Absent,
    Unreadable,
}

/// Decode a registry string, which is stored as null-terminated UTF-16.
fn read_value_at(path: &'static str, value: &'static str) -> Readable {
    use crate::model::evidence::{Evidence, ValueKind};

    let target = Target::new(Hive::LocalMachine, path, value, View::Native);
    match registry::read(&target, crate::model::host::ManagementSource::Default) {
        Evidence::Present { value, .. } => {
            if value.kind != ValueKind::String {
                return Readable::Unreadable;
            }
            let units: Vec<u16> = value
                .bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|unit| *unit != 0)
                .collect();
            String::from_utf16(&units).map_or(Readable::Unreadable, Readable::Value)
        }
        Evidence::Absent { .. } => Readable::Absent,
        _ => Readable::Unreadable,
    }
}

fn read_string(value: &'static str) -> Option<String> {
    match read_value_at(CURRENT_VERSION, value) {
        Readable::Value(text) => Some(text),
        _ => None,
    }
}

/// Resolve the operating-system version.
///
/// Build number is read as a string because that is how Windows stores it, and
/// the update revision is appended so two hosts on the same build but different
/// patch levels are distinguishable.
fn version() -> Fact<OsVersion> {
    let major = read_u32("CurrentMajorVersionNumber");
    let minor = read_u32("CurrentMinorVersionNumber");
    let build = read_string("CurrentBuildNumber").and_then(|raw| raw.parse::<u32>().ok());

    match (major, minor, build) {
        (Some(major), Some(minor), Some(build)) => {
            let revision = read_u32("UBR").unwrap_or(0);
            let display = read_string("DisplayVersion").map_or_else(
                || format!("{major}.{minor}.{build}.{revision}"),
                |name| format!("{name} ({major}.{minor}.{build}.{revision})"),
            );
            Fact::Known(OsVersion::new(vec![major, minor, build, revision], display))
        }
        // A version we cannot read is unknown, never assumed current. A control
        // gated on a version range must not evaluate against a guess.
        _ => Fact::Unknown,
    }
}

/// Resolve the Windows edition, such as `Professional` or `Enterprise`.
///
/// Edition is load-bearing on Windows: several documented policies apply only
/// to a subset of editions and are silently inert elsewhere.
fn edition() -> Fact<String> {
    read_string("EditionID").map_or(Fact::Unknown, Fact::Known)
}

/// Resolve the native processor architecture.
///
/// The compile-time architecture is not authoritative, because a 32-bit process
/// on 64-bit Windows sees a translated environment. Windows exposes the native
/// architecture separately when that translation is in effect.
fn architecture() -> Fact<Architecture> {
    let native = std::env::var("PROCESSOR_ARCHITEW6432")
        .ok()
        .or_else(|| std::env::var("PROCESSOR_ARCHITECTURE").ok());

    match native.as_deref() {
        Some("AMD64") => Fact::Known(Architecture::X86_64),
        Some("ARM64") => Fact::Known(Architecture::Aarch64),
        Some("x86") => Fact::Known(Architecture::X86),
        Some(_) => Fact::Known(Architecture::Other),
        None => Fact::Unknown,
    }
}

/// Whether an external management authority governs this host.
///
/// Currently unknown, deliberately. Three plausible registry signals were
/// tried and all three produce a false positive on an ordinary unmanaged
/// machine:
///
/// - The Group Policy history key exists on essentially every installation,
///   because policy processing runs whether or not any policy is set.
/// - The internal policy manager device area is populated by Windows for its
///   own use, with no enrollment involved.
/// - Enrollment subkeys with an active enrollment state are created by Windows
///   provisioning. This machine carries 36 of them and is not managed.
///
/// A domain-name value under the network parameters is also unusable: it holds
/// the DNS suffix, which a home router can supply, not domain membership.
///
/// Reporting `Unknown` is the honest result until a signal is verified against
/// genuinely managed hosts. Claiming an unmanaged machine is managed would make
/// every control needlessly scan-only, and claiming the reverse would offer to
/// fight a policy that will simply reapply.
///
/// This does not weaken per-control reporting. A control determines its own
/// management source from whether its specific policy value is present, which
/// is a direct observation rather than an inference about the host.
fn managed() -> Fact<bool> {
    Fact::Unknown
}

/// Whether this process can make machine-scope changes.
fn elevated() -> Fact<bool> {
    registry::can_write_machine_scope().map_or(Fact::Unknown, Fact::Known)
}

/// Discover the facts this host presents.
pub fn discover() -> HostFacts {
    HostFacts {
        platform: Platform::Windows,
        version: version(),
        architecture: architecture(),
        edition: edition(),
        // Windows has no distribution concept.
        distribution: Fact::NotPresent,
        managed: managed(),
        // Windows system configuration is mutable in the sense this field
        // means: edits to machine state persist across reboots.
        write_model: Fact::Known(WriteModel::Mutable),
        container: Fact::Known(ContainerKind::None),
        // The desktop-session concept this field models is a Linux one.
        session: SessionFacts::not_present(),
        elevated: elevated(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_state_is_unknown_rather_than_guessed() {
        // Three registry signals that look like management and are not: the
        // Group Policy history key, the internal policy manager area, and
        // active enrollment subkeys. All three are present on ordinary
        // unmanaged machines. Until a signal is verified against a genuinely
        // managed host, the honest answer is that we do not know.
        assert!(discover().managed.is_unknown());
    }

    #[test]
    fn discovery_identifies_this_host() {
        let host = discover();

        assert_eq!(host.platform, Platform::Windows);
        assert_eq!(host.distribution, Fact::NotPresent);

        // These must be readable on any supported Windows installation. If one
        // is unknown here, discovery is broken rather than the host unusual.
        let version = host.version.known().expect("version is readable");
        assert!(version.components.len() >= 3);
        assert!(!version.display.is_empty());

        let edition = host.edition.known().expect("edition is readable");
        assert!(!edition.is_empty());

        assert!(host.architecture.known().is_some());
        assert!(host.elevated.known().is_some());
    }

    #[test]
    fn the_discovered_version_orders_correctly() {
        let host = discover();
        let version = host.version.known().expect("version is readable");

        // Every supported release is at least Windows 10.
        assert!(version.at_least(&OsVersion::new(vec![10, 0], "10.0")));
        // And none is beyond a clearly impossible future build.
        assert!(!version.at_least(&OsVersion::new(vec![99, 0], "99.0")));
    }

    #[test]
    fn discovery_exposes_no_identifiers() {
        // The rendered facts must not contain anything that identifies this
        // machine, account, or tenant. Only version, edition, architecture, and
        // booleans are permitted to escape this module.
        let host = discover();
        let rendered = serde_json::to_string(&host).expect("host facts serialize");

        for forbidden in ["S-1-5", "EnrollmentState", "-1-5-21"] {
            assert!(
                !rendered.contains(forbidden),
                "discovered facts leaked {forbidden}: {rendered}"
            );
        }
    }

    #[test]
    fn architecture_is_the_native_one_not_the_compiled_one() {
        // A translated 32-bit process must still report the native
        // architecture, so a control gated on ARM64 is not misled.
        let discovered = architecture();
        if std::env::var("PROCESSOR_ARCHITEW6432").is_ok() {
            assert_ne!(discovered, Fact::Known(Architecture::X86));
        }
        assert!(discovered.known().is_some());
    }
}
