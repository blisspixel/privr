//! Facts about the host that controls are gated on.
//!
//! This is the fixed structure that applicability predicates evaluate against.
//! It is deliberately designed against the hardest case on all three supported
//! platforms before any adapter exists, because a model shaped around one
//! platform makes the others permanently second-class.
//!
//! Every field that cannot be determined is `Unknown` rather than a default.
//! A missing fact must never resolve to "not applicable", because that would
//! silently exclude a control the operator expected to be evaluated.

use serde::{Deserialize, Serialize};

/// Which operating-system family the host belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

impl Platform {
    /// The platform this binary was compiled for.
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Linux
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
        }
    }
}

/// A fact that may not have been determined.
///
/// This exists instead of `Option` so that "we looked and could not tell" is
/// distinguishable from "this field does not apply here". Both are common, and
/// conflating them is how a check reports a confident wrong answer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
pub enum Fact<T> {
    /// Determined, with a value.
    Known(T),
    /// Does not exist on this platform. Windows editions on Linux, for example.
    NotPresent,
    /// Could not be determined. Applicability involving this fact is
    /// undetermined, never false.
    Unknown,
}

impl<T> Fact<T> {
    pub const fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            _ => None,
        }
    }

    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// A comparable operating-system version.
///
/// Windows uses build numbers, macOS uses major.minor.patch, and Linux
/// distributions use their own release numbering. All three are represented as
/// an ordered component list plus the vendor's own display string, so a control
/// can gate on order without the model needing to understand every scheme.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OsVersion {
    /// Ordered numeric components, most significant first.
    pub components: Vec<u32>,
    /// The vendor's own rendering, for display and evidence.
    pub display: String,
}

impl OsVersion {
    pub fn new(components: Vec<u32>, display: impl Into<String>) -> Self {
        Self {
            components,
            display: display.into(),
        }
    }

    /// Compare component-wise, treating a missing trailing component as zero.
    ///
    /// `10.0.26100` is at least `10.0`, and `10.0` is not at least `10.0.1`.
    pub fn at_least(&self, other: &Self) -> bool {
        let len = self.components.len().max(other.components.len());
        for index in 0..len {
            let mine = self.components.get(index).copied().unwrap_or(0);
            let theirs = other.components.get(index).copied().unwrap_or(0);
            if mine != theirs {
                return mine > theirs;
            }
        }
        true
    }
}

/// Processor architecture, which gates some controls on macOS and Windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86,
    X86_64,
    Aarch64,
    Other,
}

/// Which authority set a value, where that is determinable.
///
/// This is reduced to a coarse category at the probe boundary. Enrollment
/// identifiers, security identifiers, and policy object identifiers must never
/// travel further up the stack, because they are exactly the tenant and account
/// identifiers the privacy requirements forbid collecting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementSource {
    /// Set by the signed-in user or a user-scope preference.
    User,
    /// Set by local policy on this machine.
    LocalPolicy,
    /// Set by a directory-delivered policy.
    GroupPolicy,
    /// Set by a device-management authority.
    Mdm,
    /// Set by a macOS configuration profile.
    ConfigurationProfile,
    /// No explicit value; the platform's documented default governs.
    Default,
    /// A value exists but its authority could not be determined.
    Unknown,
}

impl ManagementSource {
    /// Whether an external authority governs this value.
    ///
    /// Managed hosts are scan-only by default. `privr` reports whether the
    /// managing authority's effective value passes or drifts, and does not
    /// enter a policy fight with it.
    pub const fn is_external(self) -> bool {
        matches!(
            self,
            Self::GroupPolicy | Self::Mdm | Self::ConfigurationProfile
        )
    }
}

/// How the system's configuration is expected to be modified.
///
/// A declarative or image-based system cannot be remediated by editing files in
/// place, so controls that assume a mutable filesystem must not apply there.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteModel {
    /// Ordinary read-write system configuration.
    Mutable,
    /// Image-based with a merged configuration directory.
    ImageMerged,
    /// Configuration is generated from a declaration and edits do not persist.
    Declarative,
    /// Changes are staged into a new snapshot and require a reboot.
    Transactional,
}

/// Whether the process is running inside a container or compatibility layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    None,
    Container,
    /// A Linux environment hosted by Windows, where desktop controls do not
    /// apply in the usual way.
    WindowsSubsystem,
}

/// Facts about the desktop session a user-scope control would act on.
///
/// A user-scope setting written without a live session, or written as root
/// against another user's session, can report success while changing nothing.
/// That is a documented false-pass source, so these facts gate user-scope work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionFacts {
    /// Whether the intended user has a live graphical or login session.
    pub live_session: Fact<bool>,
    /// Desktop environment identifier, lowercased, where one is present.
    pub desktop: Fact<String>,
    /// Session protocol, such as a display server name.
    pub session_type: Fact<String>,
    /// Whether the current process can act as the intended user.
    pub can_act_as_user: Fact<bool>,
}

impl SessionFacts {
    /// Facts for a platform where the session concept does not apply.
    pub const fn not_present() -> Self {
        Self {
            live_session: Fact::NotPresent,
            desktop: Fact::NotPresent,
            session_type: Fact::NotPresent,
            can_act_as_user: Fact::NotPresent,
        }
    }
}

/// The complete set of host facts a control may be gated on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostFacts {
    pub platform: Platform,
    pub version: Fact<OsVersion>,
    pub architecture: Fact<Architecture>,
    /// Windows edition, or distribution identifier on Linux. Lowercased.
    pub edition: Fact<String>,
    /// Distribution or product identifier where it differs from the platform.
    pub distribution: Fact<String>,
    /// Whether an external management authority is present at all.
    pub managed: Fact<bool>,
    pub write_model: Fact<WriteModel>,
    pub container: Fact<ContainerKind>,
    pub session: SessionFacts,
    /// Whether the current process is running with elevated privilege.
    pub elevated: Fact<bool>,
}

impl HostFacts {
    /// Facts for a host about which nothing has been determined.
    ///
    /// Every control evaluated against this is undetermined, never
    /// not-applicable. This is the correct starting point: discovery narrows it.
    pub fn unknown(platform: Platform) -> Self {
        Self {
            platform,
            version: Fact::Unknown,
            architecture: Fact::Unknown,
            edition: Fact::Unknown,
            distribution: Fact::Unknown,
            managed: Fact::Unknown,
            write_model: Fact::Unknown,
            container: Fact::Unknown,
            session: SessionFacts {
                live_session: Fact::Unknown,
                desktop: Fact::Unknown,
                session_type: Fact::Unknown,
                can_act_as_user: Fact::Unknown,
            },
            elevated: Fact::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(components: &[u32]) -> OsVersion {
        OsVersion::new(
            components.to_vec(),
            components
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join("."),
        )
    }

    #[test]
    fn version_comparison_treats_missing_components_as_zero() {
        assert!(version(&[10, 0, 26100]).at_least(&version(&[10, 0])));
        assert!(version(&[10, 0]).at_least(&version(&[10, 0, 0])));
        assert!(!version(&[10, 0]).at_least(&version(&[10, 0, 1])));
    }

    #[test]
    fn version_comparison_is_component_wise_not_lexical() {
        // A lexical comparison would place build 9600 above build 26100.
        assert!(version(&[10, 0, 26100]).at_least(&version(&[10, 0, 9600])));
        assert!(!version(&[10, 0, 9600]).at_least(&version(&[10, 0, 26100])));
    }

    #[test]
    fn equal_versions_satisfy_at_least() {
        assert!(version(&[15, 2]).at_least(&version(&[15, 2])));
    }

    #[test]
    fn unknown_host_leaves_every_fact_undetermined() {
        let host = HostFacts::unknown(Platform::Windows);
        assert!(host.version.is_unknown());
        assert!(host.edition.is_unknown());
        assert!(host.managed.is_unknown());
        assert!(host.elevated.is_unknown());
        assert!(host.session.live_session.is_unknown());
    }

    #[test]
    fn external_management_is_distinguished_from_local_authority() {
        assert!(ManagementSource::GroupPolicy.is_external());
        assert!(ManagementSource::Mdm.is_external());
        assert!(ManagementSource::ConfigurationProfile.is_external());

        assert!(!ManagementSource::User.is_external());
        assert!(!ManagementSource::LocalPolicy.is_external());
        assert!(!ManagementSource::Default.is_external());
        // An undetermined authority is not treated as external, because that
        // would silently make a control scan-only on a false premise.
        assert!(!ManagementSource::Unknown.is_external());
    }

    #[test]
    fn fact_distinguishes_absent_from_undetermined() {
        let absent: Fact<u32> = Fact::NotPresent;
        let undetermined: Fact<u32> = Fact::Unknown;

        assert!(!absent.is_unknown());
        assert!(undetermined.is_unknown());
        assert_eq!(absent.known(), None);
        assert_eq!(undetermined.known(), None);
        assert_eq!(Fact::Known(3).known(), Some(&3));
    }
}
