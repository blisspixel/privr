//! Typed, read-only Windows registry probing.
//!
//! Every target is a compiled constant. No path, key, or value name ever comes
//! from catalogue data, a policy file, or a caller, which is what keeps
//! catalogue content from being able to describe a new privileged operation.
//!
//! Reads preserve the exact stored type and bytes. Nothing is decoded here,
//! because decoding early discards the type confusion these checks exist to
//! catch and makes an exact-preimage rollback impossible.

use windows_registry::{CURRENT_USER, Key, LOCAL_MACHINE, Type};

use crate::model::evidence::{DenialReason, Evidence, RawValue, UndeterminedReason, ValueKind};
use crate::model::host::ManagementSource;

/// Win32 error codes, as returned in the low word of an `HRESULT`.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;

/// Which root key to read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

/// Which registry view to read.
///
/// A 32-bit and a 64-bit view of the same path can hold different values. A
/// probe that does not say which view it read is not reproducible, and a
/// rollback that restores into the wrong view has not restored anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum View {
    /// The view natural to the running process.
    Native,
    /// The 32-bit view, explicitly.
    Wow6432,
    /// The 64-bit view, explicitly.
    Wow6464,
}

/// A compiled registry target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Target {
    pub hive: Hive,
    pub path: &'static str,
    pub value: &'static str,
    pub view: View,
}

impl Target {
    pub const fn new(hive: Hive, path: &'static str, value: &'static str, view: View) -> Self {
        Self {
            hive,
            path,
            value,
            view,
        }
    }
}

/// Extract the originating Win32 code from a registry error.
///
/// The low word of a Win32-derived `HRESULT` holds the original code. Anything
/// that is not a recognized code stays undetermined rather than being guessed
/// at, because an unrecognized failure is not evidence of absence.
fn win32_code(error: &windows_result::Error) -> u32 {
    (error.code().0 as u32) & 0xFFFF
}

/// Translate a registry type into the platform-neutral value kind.
///
/// An unrecognized type keeps its raw code rather than being flattened into
/// bytes, so a control expecting a number can report malformed evidence instead
/// of silently accepting something else.
fn kind_of(ty: Type) -> ValueKind {
    match ty {
        Type::U32 => ValueKind::U32,
        Type::U64 => ValueKind::U64,
        Type::String | Type::ExpandString => ValueKind::String,
        Type::MultiString => ValueKind::StringList,
        Type::Bytes => ValueKind::Binary,
        Type::Other(code) => ValueKind::Other(code),
    }
}

/// Map a Windows error into evidence.
///
/// The distinction between "no value is set" and "we were not allowed to look"
/// is the whole point. Collapsing them into a single failure is how a tool
/// reports the documented default for a key it never read.
fn evidence_for_code(code: u32, source: ManagementSource) -> Evidence {
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Evidence::Absent { source },
        ERROR_ACCESS_DENIED => Evidence::Denied {
            source,
            reason: DenialReason::Permission,
        },
        _ => Evidence::Undetermined {
            source,
            reason: UndeterminedReason::ProbeFailed,
        },
    }
}

fn open(target: &Target) -> windows_registry::Result<Key> {
    let root = match target.hive {
        Hive::LocalMachine => LOCAL_MACHINE,
        Hive::CurrentUser => CURRENT_USER,
    };

    let mut options = root.options();
    options.read();
    match target.view {
        View::Native => {}
        View::Wow6432 => {
            options.wow64_32();
        }
        View::Wow6464 => {
            options.wow64_64();
        }
    }
    options.open(target.path)
}

/// Read one value, returning what was seen rather than a verdict.
pub fn read(target: &Target, source: ManagementSource) -> Evidence {
    let key = match open(target) {
        Ok(key) => key,
        Err(error) => return evidence_for_code(win32_code(&error), source),
    };

    match key.get_value(target.value) {
        Ok(value) => {
            let kind = kind_of(value.ty());
            // `Value` dereferences to the exact stored bytes.
            Evidence::Present {
                source,
                value: RawValue::new(kind, value.to_vec()),
            }
        }
        Err(error) => evidence_for_code(win32_code(&error), source),
    }
}

/// Whether this process can open a machine-scope key for writing.
///
/// This answers the question applicability actually needs, which is whether a
/// machine-scope change is possible, rather than inspecting token identity.
/// Opening for write changes nothing and never raises an elevation prompt: it
/// simply fails when the process lacks the right.
pub fn can_write_machine_scope() -> Option<bool> {
    let mut options = LOCAL_MACHINE.options();
    options.read().write();
    match options.open("SOFTWARE") {
        Ok(_) => Some(true),
        Err(error) => match win32_code(&error) {
            ERROR_ACCESS_DENIED => Some(false),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key that exists on every supported Windows installation.
    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    #[test]
    fn reads_a_real_value_with_its_exact_type() {
        let target = Target::new(
            Hive::LocalMachine,
            CURRENT_VERSION,
            "CurrentBuildNumber",
            View::Native,
        );

        match read(&target, ManagementSource::Default) {
            Evidence::Present { value, .. } => {
                assert_eq!(value.kind, ValueKind::String);
                assert!(!value.bytes.is_empty());
            }
            other => panic!("expected a present build number, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_value_is_absent_not_an_error() {
        let target = Target::new(
            Hive::LocalMachine,
            CURRENT_VERSION,
            "PrivrValueThatDoesNotExist",
            View::Native,
        );

        assert!(matches!(
            read(&target, ManagementSource::Default),
            Evidence::Absent { .. }
        ));
    }

    #[test]
    fn a_missing_key_is_absent_not_undetermined() {
        let target = Target::new(
            Hive::LocalMachine,
            r"SOFTWARE\PrivrKeyThatDoesNotExist",
            "Anything",
            View::Native,
        );

        assert!(matches!(
            read(&target, ManagementSource::Default),
            Evidence::Absent { .. }
        ));
    }

    #[test]
    fn absent_evidence_is_conclusive_and_denied_evidence_is_not() {
        // The property that matters downstream: an absent value lets a control
        // fall back to the documented default, a denied read never can.
        let absent = Evidence::Absent {
            source: ManagementSource::Default,
        };
        let denied = Evidence::Denied {
            source: ManagementSource::Default,
            reason: DenialReason::Permission,
        };

        assert!(absent.is_conclusive());
        assert!(!denied.is_conclusive());
    }

    #[test]
    fn both_registry_views_are_addressable() {
        for view in [View::Native, View::Wow6432, View::Wow6464] {
            let target = Target::new(
                Hive::LocalMachine,
                CURRENT_VERSION,
                "CurrentBuildNumber",
                view,
            );
            // The 32-bit view of this path is redirected on 64-bit Windows, so
            // the value may legitimately be absent there. What must not happen
            // is an undetermined result: the view is addressable either way.
            assert!(
                matches!(
                    read(&target, ManagementSource::Default),
                    Evidence::Present { .. } | Evidence::Absent { .. }
                ),
                "view {view:?} produced an inconclusive read"
            );
        }
    }

    #[test]
    fn unknown_registry_types_survive_translation() {
        assert_eq!(kind_of(Type::U32), ValueKind::U32);
        assert_eq!(kind_of(Type::MultiString), ValueKind::StringList);
        // An expandable string is still a string to the model, but a type the
        // crate does not know keeps its raw code so nothing is silently coerced.
        assert_eq!(kind_of(Type::ExpandString), ValueKind::String);
        assert_eq!(kind_of(Type::Other(11)), ValueKind::Other(11));
    }

    #[test]
    fn write_capability_probe_answers_without_prompting() {
        // Whatever the answer, it must be a definite one on a normal desktop,
        // and asking must not change anything or raise a prompt.
        let answer = can_write_machine_scope();
        assert!(answer.is_some());
    }
}
