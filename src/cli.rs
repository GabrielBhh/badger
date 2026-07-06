use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "badger",
    version,
    about = "Clean, uninstall, analyze, optimize, and monitor your Arch system from the terminal",
    long_about = "A safety-first system cleaner for CachyOS and other Arch-based distros. \
badger finds reclaimable disk space, unused packages, and stale system state, \
shows exactly what it found, and touches nothing until you confirm — dry-run \
planning, a whitelist, risk tiers, trash-first deletion, and a full history \
journal are built in.",
    after_help = "docs: docs/RULES.md, https://github.com/GabrielBhh/badger",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub dry_run: bool,

    #[arg(long, global = true)]
    pub debug: bool,

    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Clean caches, logs, and other reclaimable space
    Clean {
        /// Actually delete Safe-tier selections (default just plans)
        #[arg(long)]
        yes: bool,
        /// Include experimental rules (orphaned config detection — may misidentify)
        #[arg(long)]
        experimental: bool,
    },
    /// Uninstall unused packages
    Uninstall,
    /// Optimize mirrors and system settings
    Optimize {
        /// Actually run pre-checked tasks (default just plans)
        #[arg(long)]
        yes: bool,
    },
    /// Show current system status (a live dashboard on a TTY)
    Status {
        /// CPU% a process must sustain to be flagged as a hog in the live
        /// dashboard's alerts panel
        #[arg(long, default_value_t = 80.0)]
        proc_cpu_threshold: f64,
        /// How many seconds a process must stay above the threshold to be
        /// flagged
        #[arg(long, default_value_t = 30)]
        proc_cpu_window: u64,
    },
    /// Aggressively purge reclaimable space
    Purge {
        /// Actually delete pre-checked (non-recent) selections (default just plans)
        #[arg(long)]
        yes: bool,
    },
    /// Analyze disk usage for a directory
    Analyze {
        /// Directory to analyze (defaults to your home)
        path: Option<PathBuf>,
    },
    /// Review past badger operations
    History {
        #[arg(long)]
        run: Option<String>,
    },
    /// Manage the safety whitelist
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },
    /// Generate shell completions
    Completion { shell: clap_complete::Shell },
    #[command(name = "__helper", hide = true)]
    Helper,
    #[command(name = "__mangen", hide = true)]
    Mangen { dir: std::path::PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum WhitelistAction {
    /// Add a pattern to the whitelist
    Add { pattern: String },
    /// Remove a pattern from the whitelist
    Remove { pattern: String },
    /// List whitelist entries
    List,
}
