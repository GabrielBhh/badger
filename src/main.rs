use badger::cli::Command;
use clap::Parser;

fn main() {
    let cli = badger::cli::Cli::parse();

    if let Command::Clean { yes } = &cli.command
        && badger::tui::is_interactive_now(cli.json, *yes)
    {
        badger::tui::install_panic_hook();
    }

    if let Err(e) = badger::commands::dispatch(cli) {
        eprintln!("badger: {e:#}");
        std::process::exit(1);
    }
}
