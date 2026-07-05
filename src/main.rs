use clap::Parser;

fn main() {
    let cli = badger::cli::Cli::parse();
    if let Err(e) = badger::commands::dispatch(cli) {
        eprintln!("badger: {e:#}");
        std::process::exit(1);
    }
}
