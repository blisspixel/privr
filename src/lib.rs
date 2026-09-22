//! `privr` is a local-first privacy posture CLI.
//!
//! Read-only observation is implemented for Windows, and experimentally for
//! Linux and macOS. Mutation is experimental and Windows user-scope only. See
//! the Current state section of `ROADMAP.md`.

#![forbid(unsafe_code)]

mod app;
pub mod catalog;
mod cli;
pub mod engine;
mod explain;
pub mod journal;
mod manifest;
pub mod model;
pub mod platform;
mod report;
pub mod ui;

pub use app::run;
pub use cli::Cli;
pub use cli::{Command, OutputFormat, Platform, Profile};
