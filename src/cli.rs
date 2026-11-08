use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser, Default)]
#[command(
    name = "privr",
    version,
    about = "Audit privacy settings, detect drift, apply a reviewed baseline, and roll it back",
    long_about = "Audit privacy settings, detect drift, apply a reviewed baseline, and roll it back.\n\n\
                  privr is a local-first privacy posture and residue cleanup tool.\n\
                  It inspects effective privacy settings, explains scoring and evidence, plans and\n\
                  safely applies reviewed remediations with rollback journaling, and cleans\n\
                  disposable application and system caches.",
    after_help = "WORKFLOWS:\n  \
                    Audit & Remediate:   privr (or privr check) -> privr plan -> privr apply\n  \
                    Residue Cleanup:     privr clean --preview -> privr clean\n  \
                    Diagnostics:         privr doctor | privr explain | privr history\n\n\
                  COMMON EXAMPLES:\n  \
                    privr                             Run standard privacy audit\n  \
                    privr plan                        Show exact planned remediations (alias: privr diff)\n  \
                    privr apply                       Interactively apply safe remediations (alias: privr fix)\n  \
                    privr apply -e                    Apply machine-scope settings with elevation\n  \
                    privr clean                       Interactively review and clean caches (alias: privr purge)\n  \
                    privr clean -y                    Clean caches immediately without prompt\n  \
                    privr clean -c ai,browsers        Clean AI agent and web browser caches\n  \
                    privr rollback                    Undo the most recent applied changes (alias: privr undo)\n  \
                    privr doctor                      Verify environment and journal health\n\n\
                  Run 'privr <COMMAND> --help' for details and examples for any subcommand."
)]
pub struct Cli {
    /// Output format for commands that produce reports.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// When to colour output. An explicit choice overrides NO_COLOR.
    #[arg(long, global = true, value_enum, default_value_t = ColorWhen::Auto)]
    pub color: ColorWhen,
    /// Never prompt. Any operation that would require confirmation fails closed.
    #[arg(long = "no-input", global = true)]
    pub no_input: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

pub use crate::model::posture::{FrictionTier, PostureDimension, WorkloadPersona};
pub use crate::model::profile::Profile;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check the current machine without changing it.
    #[command(
        alias = "status",
        alias = "audit",
        alias = "scan",
        about = "Check the current machine without changing it",
        long_about = "Audit effective privacy settings on the local machine.\n\n\
                      Compares current machine state against a chosen baseline profile or workload\n\
                      persona without making any modifications. Reports compliant settings, drifted\n\
                      controls, and dimensional posture scores.\n\n\
                      Exit codes:\n  \
                        0  All evaluated controls pass\n  \
                        1  One or more evaluated controls drifted\n  \
                        2  Error or invalid argument\n\n\
                      Examples:\n  \
                        privr check                      Check baseline posture\n  \
                        privr check --all                Show passing, drifted, and not-selected controls\n  \
                        privr check --workload developer Audit against developer persona rules\n  \
                        privr check --section diagnostic Check only diagnostic telemetry controls\n  \
                        privr check --format json        Emit machine-readable JSON report"
    )]
    Check {
        /// Privacy policy profile to evaluate.
        #[arg(long, value_enum, conflicts_with = "workload")]
        profile: Option<Profile>,
        /// Evaluate a custom local policy instead of a built-in profile.
        #[arg(long, conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Workload persona to evaluate against (general, developer, creative, mobile, high-assurance).
        #[arg(long, value_enum, conflicts_with = "profile")]
        workload: Option<WorkloadPersona>,
        /// Check only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
        /// Check only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
        /// List passing, not applicable, and not selected controls in text output.
        #[arg(long)]
        all: bool,
        /// Compare this check against a saved historical JSON report to detect update regressions.
        #[arg(long = "compare", value_name = "SAVED_REPORT")]
        compare: Option<PathBuf>,
    },
    /// Show the exact supported changes without applying them.
    #[command(
        alias = "diff",
        about = "Show the exact supported changes without applying them",
        long_about = "Preview exact planned configuration changes without applying them.\n\n\
                      Compares current machine state against the target profile, calculates necessary\n\
                      remediations, and displays exact value transitions, friction tiers, and required\n\
                      privilege levels.\n\n\
                      Examples:\n  \
                        privr plan                       Preview baseline changes\n  \
                        privr plan --workload creative   Plan changes for creative/media workload\n  \
                        privr plan --section security    Preview only network and perimeter changes\n  \
                        privr plan --format json         Output planned changes as JSON"
    )]
    Plan {
        /// Privacy policy profile to evaluate.
        #[arg(long, value_enum, conflicts_with = "workload")]
        profile: Option<Profile>,
        /// Plan from a custom local policy instead of a built-in profile.
        #[arg(long, conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Workload persona to generate adaptive recommendations for (general, developer, creative, mobile, high-assurance).
        #[arg(long, value_enum)]
        workload: Option<WorkloadPersona>,
        /// Maximum tolerable friction tier for workload recommendations.
        #[arg(long, value_enum)]
        max_friction: Option<FrictionTier>,
        /// Plan only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
        /// Plan only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
    },
    /// Recompute, confirm, apply, and verify supported changes.
    #[command(
        alias = "fix",
        alias = "harden",
        about = "Recompute, confirm, apply, and verify supported changes",
        long_about = "Apply reviewed privacy baselines with safety verification and rollback journaling.\n\n\
                      Before modifying any setting, privr writes a local transaction journal with\n\
                      the prior state. After modification, it verifies authoritative state to ensure\n\
                      the change succeeded. If verification fails, the transaction is marked for rollback.\n\n\
                      Examples:\n  \
                        privr apply                      Interactively review and apply changes\n  \
                        privr apply -y                   Apply standard-risk changes noninteractively\n  \
                        privr apply -e                   Request elevation (UAC/sudo) to apply machine settings\n  \
                        privr apply --dry-run            Alias for 'privr plan'\n  \
                        privr apply --control windows.security.llmnr  Apply a single targeted control"
    )]
    Apply {
        /// Privacy policy profile to apply.
        #[arg(long, value_enum, conflicts_with = "workload")]
        profile: Option<Profile>,
        /// Apply a custom local policy instead of a built-in profile.
        #[arg(long, conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Workload persona to apply adaptive recommendations for (general, developer, creative, mobile, high-assurance).
        #[arg(long, value_enum)]
        workload: Option<WorkloadPersona>,
        /// Maximum tolerable friction tier for workload recommendations.
        #[arg(long, value_enum)]
        max_friction: Option<FrictionTier>,
        /// Compatibility alias for `privr plan`.
        #[arg(long)]
        dry_run: bool,
        /// Confirm the displayed standard-risk plan in noninteractive use.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Interactively review and approve planned changes section by section.
        #[arg(short = 'i', long = "interactive-sections", alias = "step")]
        interactive_sections: bool,
        /// Accept risk for specific high-friction or tradeoff controls in noninteractive apply. Repeatable.
        #[arg(long = "accept-risk", value_name = "CONTROL_ID")]
        accept_risk: Vec<String>,
        /// Force apply all eligible controls regardless of friction tier in noninteractive apply.
        #[arg(long)]
        force: bool,
        /// Apply only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
        /// Apply only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
        /// Request elevation (UAC on Windows, sudo on Unix) to apply machine-scope changes in-place.
        #[arg(short = 'e', long)]
        elevate: bool,
        /// Internal path used by elevated child process to return output to parent.
        #[arg(long, hide = true)]
        elevated_output: Option<PathBuf>,
    },
    /// Roll back a transaction recorded by `privr apply`.
    #[command(
        alias = "restore",
        alias = "undo",
        about = "Roll back a transaction recorded by privr apply",
        long_about = "Roll back settings to their prior state using recorded transaction journals.\n\n\
                      By default, rolls back the most recent transaction. Transactions are safely\n\
                      verified against current values before restoration.\n\n\
                      Examples:\n  \
                        privr rollback                   Interactively undo most recent transaction\n  \
                        privr rollback -y                Undo most recent transaction noninteractively\n  \
                        privr rollback -e                Roll back machine-scope settings with elevation\n  \
                        privr rollback <TRANSACTION_ID>  Roll back a specific transaction ID"
    )]
    Rollback {
        /// Internal transaction ID shown by `privr history` (defaults to most recent transaction).
        transaction_id: Option<String>,
        /// Roll back only controls in a specific section. Repeatable.
        #[arg(short = 's', long = "section")]
        sections: Vec<String>,
        /// Confirm that settings may be restored.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Request elevation (UAC on Windows, sudo on Unix) to rollback machine-scope changes in-place.
        #[arg(short = 'e', long)]
        elevate: bool,
        /// Internal path used by elevated child process to return output to parent.
        #[arg(long, hide = true)]
        elevated_output: Option<PathBuf>,
    },
    /// Show transaction history of applied changes.
    #[command(
        alias = "log",
        about = "Show transaction history of applied changes",
        long_about = "Display the chronological journal of past mutation transactions.\n\n\
                      Shows transaction IDs, timestamps, affected controls, and whether\n\
                      each transaction has been rolled back.\n\n\
                      Examples:\n  \
                        privr history                    List all transactions in text format\n  \
                        privr history --purge            Purge all transaction history files\n  \
                        privr history --purge -y         Purge history without prompting\n  \
                        privr history --format json      Emit transaction records as JSON"
    )]
    History {
        /// Purge and destroy all saved transaction history files.
        #[arg(long)]
        purge: bool,
        /// Confirm history purge without interactive prompting.
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Recommend confirmed drift changes across profiles, filtered by workload and friction.
    #[command(
        about = "Recommend confirmed drift changes across profiles, filtered by workload and friction",
        long_about = "Generate workload-tailored recommendations based on confirmed machine drift.\n\n\
                      Filters recommendations by persona (general, developer, creative, mobile,\n\
                      high-assurance) and caps tolerable friction tiers to avoid disrupting your\n\
                      daily workflow.\n\n\
                      Examples:\n  \
                        privr recommend                  Recommendations for general daily use\n  \
                        privr recommend --workload developer  Recommendations for software developers\n  \
                        privr recommend --max-friction tier1-cosmetic  Allow only cosmetic changes\n  \
                        privr recommend --dimension network-exposure   Focus on network perimeter"
    )]
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
    #[command(
        about = "Counterfactually simulate applying a profile or controls without modifying machine state",
        long_about = "Project privacy score and compliance outcomes if specific controls were applied.\n\n\
                      Allows testing hypothetical changes and evaluating compliance impact\n\
                      without altering any machine state. Posture dimension columns show\n\
                      c/d/c (compliant / drift / could not tell).\n\n\
                      Examples:\n  \
                        privr simulate --profile strict  Simulate applying strict profile\n  \
                        privr simulate --control windows.security.llmnr  Simulate one control"
    )]
    Simulate {
        /// Target policy profile to simulate.
        #[arg(long, value_enum, conflicts_with = "policy")]
        profile: Option<Profile>,
        /// Simulate applying a custom local policy.
        #[arg(long, conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Simulate only an exact control ID or documented ID prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
        /// Simulate only controls in a specific section. Repeatable.
        #[arg(long = "section")]
        sections: Vec<String>,
    },
    /// List the catalogue: every control this build can examine.
    #[command(
        about = "List the catalogue: every control this build can examine",
        long_about = "List all supported privacy controls compiled into this binary.\n\n\
                      Displays control identifiers, titles, sections, and supported platforms.\n\n\
                      Examples:\n  \
                        privr list                       List all controls for the current platform\n  \
                        privr list --query diagnostic    Search controls mentioning 'diagnostic'\n  \
                        privr list --platform all        List controls across all supported platforms"
    )]
    List {
        /// Platform catalogue to list. Defaults to the current platform.
        #[arg(long, value_enum)]
        platform: Option<Platform>,
        /// Show only controls matching this text, in the identifier, title,
        /// section, or summary.
        #[arg(long)]
        query: Option<String>,
    },
    /// Explain the posture scoring model and critical controls, or inspect one check in detail.
    #[command(
        about = "Explain the posture scoring model and critical controls, or inspect one check in detail",
        long_about = "Explain posture scoring, dimensions, critical controls, or inspect a specific check.\n\n\
                      Topics:\n  \
                        overview   Default summary of scoring and posture dimensions\n  \
                        score      Detailed scoring mathematics and weighting model\n  \
                        posture    Posture dimensions and compliance standards\n  \
                        critical   High-risk controls and priority remediations\n\n\
                      Examples:\n  \
                        privr explain                    Show posture scoring overview\n  \
                        privr explain score              Explain scoring calculations\n  \
                        privr explain critical           List and explain critical controls\n  \
                        privr explain windows.security.llmnr  Inspect a specific control's evidence"
    )]
    Explain {
        /// Exact check ID, or topic (score, posture, critical, overview). Defaults to overview.
        #[arg(value_name = "CONTROL_ID_OR_TOPIC")]
        id: Option<String>,
    },
    /// Report host facts, compiled adapters, and transaction storage checks.
    #[command(
        about = "Report host facts, compiled adapters, and transaction storage checks",
        long_about = "Run host environment diagnostics and check transaction storage.\n\n\
                      Validates operating system version, elevation capabilities, journal storage\n\
                      accessibility, and compiled platform adapters.\n\n\
                      Examples:\n  \
                        privr doctor                     Display environment health check\n  \
                        privr doctor --format json       Emit diagnostic facts as JSON"
    )]
    Doctor,
    /// Run a stdio Model Context Protocol (MCP) server for agent integration.
    Mcp {
        /// Expose mutation tools in tool discovery.
        #[arg(long)]
        allow_apply: bool,
    },
    /// Preview or clean disposable caches, temporary files, and residue.
    #[command(
        name = "clean",
        alias = "purge",
        about = "Clean disposable caches, temporary files, and activity residue",
        long_about = clean_help()
    )]
    Clean {
        /// Retain disruptive or costly-to-rebuild caches (e.g. thumbnail cache, recent items).
        #[arg(long)]
        polite: bool,
        /// Force preview only; never mutate even if confirmed.
        #[arg(long)]
        preview: bool,
        /// Compatibility alias for --preview.
        #[arg(long)]
        dry_run: bool,
        /// Confirm permanent cleanup of the selected scope, including supported history.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Filter by residue category: system, browsers, app, ai, dev, recent. Repeatable or comma-separated.
        #[arg(short = 'c', long = "category", value_delimiter = ',')]
        categories: Vec<String>,
        /// Clean only an exact target ID or prefix. Repeatable.
        #[arg(long = "control")]
        controls: Vec<String>,
        /// Explicitly acknowledge risk for a targeted category. Repeatable.
        #[arg(long = "accept-risk")]
        accept_risks: Vec<String>,
        /// Issue hardware TRIM / Deallocate to solid-state drives (SSDs/NVMe) to unmap free blocks and optimize write performance.
        #[arg(long)]
        trim: bool,
    },
}

fn clean_help() -> String {
    let mut help = String::from(
        "Clean supported local privacy residue with one preview and confirmation.\n\n\
         The thorough default includes supported command history and recent activity.\n\
         Deletion is permanent. Close affected applications first; open applications\n\
         can recreate records. Browser cookie and browsing-history adapters are not\n\
         implemented yet. Without a terminal, execution requires --yes.\n\n\
         Categories: available in this build (aliases share a row)\n",
    );
    let targets = crate::catalog::residue::compiled_residue_targets();
    for (selector, names) in [
        ("system", "system"),
        ("temp", "temp, temporary"),
        ("crash", "crash, dumps"),
        ("thumbnail", "thumbnail, thumbnails"),
        ("shader", "shader, shaders"),
        ("browser", "browser, browsers"),
        ("app", "app, apps"),
        ("ai", "ai, agent, agents"),
        ("recent", "recent, activity"),
        ("dev", "dev, developer, package, packages"),
    ] {
        let titles: Vec<_> = targets
            .iter()
            .filter(|target| {
                crate::catalog::residue::matches_category_filter(target.category, selector)
            })
            .map(|target| target.title.as_str())
            .collect();
        if !titles.is_empty() {
            help.push_str(&format!("  {names}: {}\n", titles.join(", ")));
        }
    }
    help.push_str(
        "\nExamples:\n  \
         privr clean                     Review and confirm thorough cleanup\n  \
         privr clean -y                  Permanently clean the default scope\n  \
         privr clean --preview           Inspect without deleting, even with --yes\n  \
         privr clean --polite            Reduce scope, retaining recent items and thumbnails\n  \
         privr clean --category app      Limit cleanup to application caches\n  \
         privr clean -c ai,browsers      Limit cleanup to these categories\n  \
         privr clean --trim              Also request hardware free-space maintenance",
    );
    help
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
