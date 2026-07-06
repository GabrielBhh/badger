use std::path::Path;

use anyhow::Context;
use clap::CommandFactory;

use crate::cli::Cli;

pub fn run(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;
    clap_mangen::generate_to(Cli::command(), dir)
        .with_context(|| format!("failed to generate man pages into {}", dir.display()))?;
    Ok(())
}
