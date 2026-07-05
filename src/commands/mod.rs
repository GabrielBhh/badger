use anyhow::bail;
use clap::CommandFactory;

use crate::cli::{Cli, Command, WhitelistAction};

pub mod clean;
pub mod history;
pub mod whitelist;

pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Completion { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Command::History { run } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            history::run(&ctx.state_dir, run.as_deref(), mode)
        }
        Command::Whitelist { action } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            match action {
                WhitelistAction::List => {
                    println!("{}", whitelist::list(&ctx.config_dir)?);
                    Ok(())
                }
                WhitelistAction::Add { pattern } => {
                    println!("{}", whitelist::add(&ctx.config_dir, &pattern)?);
                    Ok(())
                }
                WhitelistAction::Remove { pattern } => {
                    println!("{}", whitelist::remove(&ctx.config_dir, &pattern)?);
                    Ok(())
                }
            }
        }
        Command::Helper => {
            crate::privilege::helper_main(std::io::stdin().lock(), std::io::stdout().lock())
        }
        Command::Clean { yes } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            let output = clean::run(&ctx, yes, cli.dry_run, mode)?;
            // Interactive cancel prints its own "nothing cleaned" note to
            // stderr and returns nothing to render — don't add a blank
            // stdout line on top of it.
            if !output.rendered.is_empty() {
                println!("{}", output.rendered);
            }
            Ok(())
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
