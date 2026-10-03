use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "privr",
    version,
    about = "Audit privacy settings, detect drift, apply a reviewed baseline, and roll it back",
    long_about = None
)]
pub struct Cli {
    /// Output format for commands that produce reports.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// When to colorize output. An explicit choice overrides NO_COLOR.
    #[arg(long, global = true, value_enum, default_value_t = ColorWhen::Auto)]
    pub color: ColorWhen,
    #[command(subcommand)]
    pub command: Option<Command>,
}

pub use crate::model::posture::{FrictionTier, PostureDimension, WorkloadPersona};
pub use crate::model::profile::Profile;

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
        /// Check only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
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
        /// Plan only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
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
        /// Apply only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
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
    /// Recommend privacy posture improvements based on workload and friction budget.
    Recommend {
        /// Workload persona (general, developer, creative, mobile, high-assurance).
        #[arg(long, value_enum, default_value_t = WorkloadPersona::General)]
        workload: WorkloadPersona,
        /// Maximum tolerable friction tier.
        #[arg(long, value_enum)]
        max_friction: Option<FrictionTier>,
        /// Filter recommendations to a specific posture dimension.
        #[arg(long, value_enum)]
        dimension: Option<PostureDimension>,
    },
    /// Counterfactually simulate applying a profile or controls without modifying machine state.
    Simulate {
        /// Target policy profile to simulate.
        #[arg(long, value_enum, default_value_t = Profile::Baseline)]
        profile: Profile,
        /// Simulate only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
        /// Simulate only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
    },
    /// List the catalogue: every control this build can examine.
    List {
        /// Platform catalogue to list. Defaults to the current platform.
        #[arg(long, value_enum)]
        platform: Option<Platform>,
        /// Show only controls matching this text, in the identifier, title,
        /// section, or summary.
        #[arg(long)]
        query: Option<String>,
    },
    /// Explain one check, including impact and source.
    Explain {
        /// Exact check ID.
        id: String,
    },
    /// Check whether commands needed by the current platform are available.
    Doctor,
    /// Run a stdio Model Context Protocol (MCP) server for agent integration.
    Mcp {
        /// Expose mutation tools in tool discovery.
        #[arg(long)]
        allow_apply: bool,
    },
}

/// When to emit colour.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ColorWhen {
    /// Colour when writing to a terminal that supports it.
    #[default]
    Auto,
    /// Always colour, even when redirected.
    Always,
    /// Never colour.
    Never,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
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
