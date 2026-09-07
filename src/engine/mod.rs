//! The evaluation engine.
//!
//! The engine is a pure function over typed values. It never touches the
//! operating system, so fixtures are the same types a real probe produces and
//! there is no separate fake that can drift from reality.

pub mod evaluate;

pub use evaluate::{ControlSpec, Mode, Resolution, SemanticState, Uncertainty, evaluate};
