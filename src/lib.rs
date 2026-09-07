//! `privr` is a local-first privacy posture CLI.
//!
//! This crate is a concept build. It carries the shared model and the command
//! surface, and performs no platform observation or mutation yet.

#![forbid(unsafe_code)]

mod app;
pub mod catalog;
mod cli;
pub mod engine;
mod explain;
mod manifest;
pub mod model;
pub mod platform;
mod report;
pub mod ui;

pub use app::run;
pub use cli::Cli;
pub use cli::{Command, OutputFormat, Platform, Profile};
