//! Shared types for host facts, evidence, and results.
//!
//! These are deliberately designed against the hardest case on all three
//! supported platforms before any adapter exists. A model shaped around one
//! platform makes the others permanently second-class, and the evidence types
//! in particular have to express Windows policy precedence, macOS
//! forced-by-profile state, and Linux absent-schema and no-session states
//! without favouring any of them.
//!
//! Nothing here touches the operating system. The evaluation engine is a pure
//! function over these values, so fixtures are the same types a real probe
//! produces and there is no separate fake that can drift from reality.

pub mod applicability;
pub mod evidence;
pub mod host;
pub mod outcome;

pub use outcome::Reversibility;

pub use applicability::{Applicability, Applies, Predicate, Variant};
pub use evidence::{DenialReason, Evidence, Observation, RawValue, UndeterminedReason, ValueKind};
pub use host::{
    Architecture, ContainerKind, Fact, HostFacts, ManagementSource, OsVersion, Platform,
    SessionFacts, WriteModel,
};
pub use outcome::{
    ControlResult, Effect, Exception, Maturity, Outcome, Remediation, RemediationReason, Summary,
    Support,
};
