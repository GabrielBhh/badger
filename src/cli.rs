use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "badger",
    version,
    about = "Clean, uninstall, analyze, optimize, and monitor your Arch system from the terminal",
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
    },
    /// Uninstall unused packages
    Uninstall,
    /// Optimize mirrors and system settings
    Optimize,
    /// Show current system status
    Status,
    /// Aggressively purge reclaimable space
    Purge,
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
