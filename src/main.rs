use badger::cli::Command;
use clap::Parser;

fn main() {
    let cli = badger::cli::Cli::parse();

    let yes = match &cli.command {
        Command::Clean { yes } | Command::Purge { yes } => Some(*yes),
        // `uninstall` has no `--yes` shortcut — it's always attempting the
        // interactive path unless mode/tty checks inside it say otherwise.
        Command::Uninstall => Some(false),
        _ => None,
    };
    if let Some(yes) = yes
        && badger::tui::is_interactive_now(cli.json, yes)
    {
        badger::tui::install_panic_hook();
    }

    if let Err(e) = badger::commands::dispatch(cli) {
        eprintln!("badger: {e:#}");
        std::process::exit(1);
    }
}
