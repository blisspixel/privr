//! `privr` is a local-first privacy posture CLI.
//!
//! This crate is a concept build. It carries the shared model and the command
//! surface, and performs no platform observation or mutation yet.

#![forbid(unsafe_code)]

mod app;
mod cli;
pub mod engine;
pub mod model;

pub use app::run;
pub use cli::Cli;
pub use cli::{Command, OutputFormat, Platform, Profile};
