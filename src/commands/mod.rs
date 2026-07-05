use anyhow::bail;
use clap::CommandFactory;

use crate::cli::{Cli, Command, WhitelistAction};

pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Completion { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Command::History { run: _ } => {
            bail!("`badger history` is not implemented yet — coming in a later phase")
        }
        Command::Whitelist { action } => match action {
            WhitelistAction::Add { pattern: _ }
            | WhitelistAction::Remove { pattern: _ }
            | WhitelistAction::List => {
                bail!("`badger whitelist` is not implemented yet — coming in a later phase")
            }
        },
        Command::Helper => {
            bail!("`badger __helper` must be invoked by badger itself")
        }
        Command::Clean => {
            bail!("`badger clean` is not implemented yet — coming in a later phase")
        }
        Command::Uninstall => {
            bail!("`badger uninstall` is not implemented yet — coming in a later phase")
        }
        Command::Optimize => {
            bail!("`badger optimize` is not implemented yet — coming in a later phase")
        }
        Command::Status => {
            bail!("`badger status` is not implemented yet — coming in a later phase")
        }
        Command::Purge => {
            bail!("`badger purge` is not implemented yet — coming in a later phase")
        }
        Command::Analyze { path: _ } => {
            bail!("`badger analyze` is not implemented yet — coming in a later phase")
        }
    }
}
