use std::io::IsTerminal;

use clap::CommandFactory;

use crate::cli::{Cli, Command, WhitelistAction};

pub mod analyze;
pub mod clean;
pub mod history;
pub mod mangen;
pub mod optimize;
pub mod purge;
pub(crate) mod shared;
pub mod status;
pub mod uninstall;
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
        Command::Mangen { dir } => mangen::run(&dir),
        Command::Clean { yes, experimental } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            let output = clean::run(&ctx, yes, cli.dry_run, mode, experimental)?;
            // Interactive cancel prints its own "nothing cleaned" note to
            // stderr and returns nothing to render — don't add a blank
            // stdout line on top of it.
            if !output.rendered.is_empty() {
                println!("{}", output.rendered);
            }
            Ok(())
        }
        Command::Uninstall { packages } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            let output = uninstall::run(&ctx, cli.dry_run, mode, packages)?;
            // Interactive cancel prints its own "nothing uninstalled" note
            // to stderr and returns nothing to render — don't add a blank
            // stdout line on top of it.
            if !output.rendered.is_empty() {
                println!("{}", output.rendered);
            }
            Ok(())
        }
        Command::Optimize { yes } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            let output = optimize::run(&ctx, yes, cli.dry_run, mode)?;
            // Interactive cancel prints its own "nothing run" note to
            // stderr and returns nothing to render — don't add a blank
            // stdout line on top of it.
            if !output.rendered.is_empty() {
                println!("{}", output.rendered);
            }
            Ok(())
        }
        Command::Status {
            proc_cpu_threshold,
            proc_cpu_window,
        } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            // Same gating as clean/purge/uninstall/analyze: only a real,
            // interactive terminal gets the live dashboard.
            if mode == crate::output::Mode::Human && std::io::stderr().is_terminal() {
                let output = status::run_dashboard(&ctx, proc_cpu_threshold, proc_cpu_window)?;
                if !output.rendered.is_empty() {
                    println!("{}", output.rendered);
                }
            } else {
                let output = status::run(&ctx, mode)?;
                println!("{}", output.rendered);
            }
            Ok(())
        }
        Command::Purge { yes } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            let output = purge::run(&ctx, yes, cli.dry_run, mode)?;
            // Interactive cancel prints its own "nothing purged" note to
            // stderr and returns nothing to render — don't add a blank
            // stdout line on top of it.
            if !output.rendered.is_empty() {
                println!("{}", output.rendered);
            }
            Ok(())
        }
        Command::Analyze { path } => {
            let ctx = crate::ctx::Ctx::resolve(
                cli.dry_run,
                cli.debug,
                crate::ctx::EnvOverrides::from_process(),
            )?;
            let mode = crate::output::current(cli.json);
            let output = analyze::run(&ctx, path, mode)?;
            // The interactive explorer renders nothing when the session
            // made no deletions — don't print a blank stdout line then.
            if !output.rendered.is_empty() {
                println!("{}", output.rendered);
            }
            Ok(())
        }
    }
}
