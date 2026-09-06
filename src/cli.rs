use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "privr",
    version,
    about = "Audit privacy settings, detect drift, apply a privacy-first baseline, and roll it back",
    long_about = None
)]
pub struct Cli {
    /// Output format for commands that produce reports.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check the current machine without changing it.
    #[command(visible_alias = "audit")]
    Check {
        /// Privacy policy profile to evaluate.
        #[arg(long, value_enum)]
        profile: Option<Profile>,
        /// Evaluate a custom local policy instead of a built-in profile.
        #[arg(long, conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Check only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
        /// Include passing controls in text output.
        #[arg(long)]
        all: bool,
    },
    /// Show the exact supported changes without applying them.
    Plan {
        /// Privacy policy profile to evaluate.
        #[arg(long, value_enum)]
        profile: Option<Profile>,
        /// Plan from a custom local policy instead of a built-in profile.
        #[arg(long, conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Plan only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
    },
    /// Recompute, confirm, apply, and verify supported changes.
    Apply {
        /// Privacy policy profile to apply.
        #[arg(long, value_enum)]
        profile: Option<Profile>,
        /// Apply a custom local policy instead of a built-in profile.
        #[arg(long, conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Compatibility alias for `privr plan`.
        #[arg(long)]
        dry_run: bool,
        /// Confirm the displayed standard-risk plan in noninteractive use.
        #[arg(long)]
        yes: bool,
        /// Apply only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
    },
    /// Roll back a transaction recorded by `privr apply`.
    #[command(visible_alias = "restore")]
    Rollback {
        /// Internal transaction ID shown by `privr history`.
        transaction_id: String,
        /// Confirm that settings may be restored.
        #[arg(long)]
        yes: bool,
    },
    /// List checks and their privacy-first expected values.
    List {
        /// Platform catalogue to list. Defaults to the current platform.
        #[arg(long, value_enum)]
        platform: Option<Platform>,
    },
    /// Explain one check, including impact and source.
    Explain {
        /// Exact check ID.
        id: String,
    },
    /// Check whether commands needed by the current platform are available.
    Doctor,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum Profile {
    /// Disable optional collection while retaining core security protections.
    #[default]
    PrivacyFirst,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivacyFirst => "privacy-first",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Platform {
    Auto,
    Windows,
    Macos,
    Linux,
    All,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::All => "all",
        }
    }
}
