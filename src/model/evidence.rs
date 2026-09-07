//! Typed evidence returned by platform probes.
//!
//! A probe never returns a pass or a fail. It returns what it saw, including
//! the ways in which it failed to see. The adapter resolves evidence into an
//! effective state, because precedence is control-specific and there is no
//! universal ordering across policy, management, and preference sources.
//!
//! Raw values keep their exact platform type and bytes rather than a decoded
//! convenience value. Decoding early discards the type confusion these checks
//! exist to catch, and it makes an exact-preimage rollback impossible.

use serde::{Deserialize, Serialize};

use super::host::ManagementSource;

/// The platform storage type of an observed value.
///
/// The `Other` variant carries the raw discriminant so an unrecognized type is
/// preserved rather than coerced. A value of an unexpected type is malformed
/// evidence, not an absent value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "code")]
pub enum ValueKind {
    /// Windows REG_DWORD, or an equivalent fixed-width integer.
    U32,
    /// Windows REG_QWORD.
    U64,
    /// A text value.
    String,
    /// A multi-valued text list.
    StringList,
    /// Opaque bytes.
    Binary,
    /// A boolean, where the platform stores one natively.
    Bool,
    /// A type the adapter did not recognize, preserved by its raw code.
    Other(u32),
}

/// A value exactly as the platform stores it.
///
/// `bytes` is the authoritative content. A rollback restores these bytes and
/// this kind, not a re-encoded interpretation of them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawValue {
    pub kind: ValueKind,
    pub bytes: Vec<u8>,
}

impl RawValue {
    pub fn new(kind: ValueKind, bytes: Vec<u8>) -> Self {
        Self { kind, bytes }
    }

    /// A little-endian 32-bit value, the common Windows registry case.
    pub fn u32(value: u32) -> Self {
        Self::new(ValueKind::U32, value.to_le_bytes().to_vec())
    }

    /// Interpret as a 32-bit integer, if that is genuinely what this is.
    ///
    /// Returns `None` for any other kind or an incorrect byte length rather
    /// than guessing. A caller that cannot decode must report malformed
    /// evidence, never a default.
    pub fn as_u32(&self) -> Option<u32> {
        if self.kind != ValueKind::U32 || self.bytes.len() != 4 {
            return None;
        }
        Some(u32::from_le_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
        ]))
    }
}

/// Why a value could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// The caller lacks permission.
    Permission,
    /// Reading requires elevation the caller does not have.
    Elevation,
    /// The platform requires a capability grant that has not been made.
    CapabilityGrant,
}

/// Why an observation could not be determined.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndeterminedReason {
    /// A required host fact was not established.
    HostFactUnknown,
    /// The probe itself failed in a way that is not a denial.
    ProbeFailed,
    /// The platform reported success without a usable result.
    NoResult,
    /// The reading interface is present but its behavior is not verified on
    /// this platform version.
    UnverifiedInterface,
}

/// One piece of typed evidence from one source.
///
/// The variants are deliberately exhaustive over the ways an observation can
/// fail. Anything that is not `Present` or `Absent` carries uncertainty that
/// must remain visible in the result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "evidence")]
pub enum Evidence {
    /// A value exists and was read exactly.
    Present {
        source: ManagementSource,
        value: RawValue,
    },
    /// The location was readable and no value is set. The platform's documented
    /// default governs. This is a positive observation, not a failure.
    Absent { source: ManagementSource },
    /// Access was refused. This is never an absent value.
    Denied {
        source: ManagementSource,
        reason: DenialReason,
    },
    /// A value exists but is not the type the control expects.
    Malformed {
        source: ManagementSource,
        expected: ValueKind,
        found: ValueKind,
    },
    /// The reading interface does not exist on this host.
    Unsupported { source: ManagementSource },
    /// The probe could not reach a conclusion.
    Undetermined {
        source: ManagementSource,
        reason: UndeterminedReason,
    },
}

impl Evidence {
    /// Which authority this evidence came from.
    pub const fn source(&self) -> ManagementSource {
        match self {
            Self::Present { source, .. }
            | Self::Absent { source }
            | Self::Denied { source, .. }
            | Self::Malformed { source, .. }
            | Self::Unsupported { source }
            | Self::Undetermined { source, .. } => *source,
        }
    }

    /// Whether this evidence leaves the effective state in doubt.
    ///
    /// `Present` and `Absent` are conclusive. Everything else means the machine
    /// might be sharing data the operator believes is disabled, so a control
    /// resting on it can never report a pass.
    pub const fn is_conclusive(&self) -> bool {
        matches!(self, Self::Present { .. } | Self::Absent { .. })
    }
}

/// Everything a probe saw for one control, across every source it consulted.
///
/// Multiple sources are normal: a Windows setting commonly has a policy value
/// and a user preference, and which one governs is control-specific.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// Evidence in the order the adapter consulted it.
    pub evidence: Vec<Evidence>,
    /// Whether the platform can actually honor this setting on this host.
    ///
    /// A policy value that writes and reads back successfully on an edition
    /// that ignores it is the single most common false pass in this category.
    /// An adapter that knows the value is inert sets this to `false`, and the
    /// engine reports the control as not applicable rather than compliant.
    pub honored_by_platform: bool,
}

impl Observation {
    pub fn new(evidence: Vec<Evidence>) -> Self {
        Self {
            evidence,
            honored_by_platform: true,
        }
    }

    /// An observation for a setting this host writes but does not act on.
    pub fn inert(evidence: Vec<Evidence>) -> Self {
        Self {
            evidence,
            honored_by_platform: false,
        }
    }

    /// The first evidence from an external managing authority, if any.
    pub fn external_authority(&self) -> Option<&Evidence> {
        self.evidence
            .iter()
            .find(|item| item.source().is_external())
    }

    /// Whether any consulted source left the state in doubt.
    pub fn has_inconclusive_evidence(&self) -> bool {
        self.evidence.iter().any(|item| !item.is_conclusive())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_round_trips_through_exact_bytes() {
        let value = RawValue::u32(3);
        assert_eq!(value.kind, ValueKind::U32);
        assert_eq!(value.bytes, vec![3, 0, 0, 0]);
        assert_eq!(value.as_u32(), Some(3));
    }

    #[test]
    fn decoding_refuses_a_mismatched_kind() {
        // A string that happens to hold four bytes must not decode as a number.
        let value = RawValue::new(ValueKind::String, vec![1, 0, 0, 0]);
        assert_eq!(value.as_u32(), None);
    }

    #[test]
    fn decoding_refuses_a_wrong_length() {
        let value = RawValue::new(ValueKind::U32, vec![1, 0]);
        assert_eq!(value.as_u32(), None);
    }

    #[test]
    fn unrecognized_platform_types_are_preserved_not_coerced() {
        let value = RawValue::new(ValueKind::Other(11), vec![0xff]);
        assert_eq!(value.kind, ValueKind::Other(11));
        assert_eq!(value.as_u32(), None);
    }

    #[test]
    fn only_present_and_absent_are_conclusive() {
        let source = ManagementSource::User;

        assert!(
            Evidence::Present {
                source,
                value: RawValue::u32(0)
            }
            .is_conclusive()
        );
        assert!(Evidence::Absent { source }.is_conclusive());

        // Each of these means the state might differ from what a naive read
        // would suggest, so none may support a pass.
        assert!(
            !Evidence::Denied {
                source,
                reason: DenialReason::Permission
            }
            .is_conclusive()
        );
        assert!(
            !Evidence::Malformed {
                source,
                expected: ValueKind::U32,
                found: ValueKind::String
            }
            .is_conclusive()
        );
        assert!(!Evidence::Unsupported { source }.is_conclusive());
        assert!(
            !Evidence::Undetermined {
                source,
                reason: UndeterminedReason::ProbeFailed
            }
            .is_conclusive()
        );
    }

    #[test]
    fn observation_finds_an_external_authority() {
        let observation = Observation::new(vec![
            Evidence::Absent {
                source: ManagementSource::User,
            },
            Evidence::Present {
                source: ManagementSource::GroupPolicy,
                value: RawValue::u32(1),
            },
        ]);

        let external = observation.external_authority().expect("external evidence");
        assert_eq!(external.source(), ManagementSource::GroupPolicy);
    }

    #[test]
    fn observation_without_external_authority_reports_none() {
        let observation = Observation::new(vec![Evidence::Absent {
            source: ManagementSource::User,
        }]);
        assert!(observation.external_authority().is_none());
        assert!(!observation.has_inconclusive_evidence());
    }

    #[test]
    fn an_inert_setting_is_marked_even_when_evidence_is_clean() {
        // The Windows edition-gating case: the value is present and reads back
        // exactly as written, and the platform ignores it.
        let observation = Observation::inert(vec![Evidence::Present {
            source: ManagementSource::LocalPolicy,
            value: RawValue::u32(0),
        }]);

        assert!(!observation.has_inconclusive_evidence());
        assert!(!observation.honored_by_platform);
    }
}
