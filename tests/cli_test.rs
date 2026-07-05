use badger::cli::{Cli, WhitelistAction};
use clap::{CommandFactory, Parser};

fn parse(args: &[&str]) -> clap::error::Result<Cli> {
    Cli::try_parse_from(args)
}

#[test]
fn test_parses_clean_subcommand() {
    assert!(parse(&["badger", "clean"]).is_ok());
}

#[test]
fn test_parses_uninstall_subcommand() {
    assert!(parse(&["badger", "uninstall"]).is_ok());
}

#[test]
fn test_parses_optimize_subcommand() {
    assert!(parse(&["badger", "optimize"]).is_ok());
}

#[test]
fn test_parses_status_subcommand() {
    assert!(parse(&["badger", "status"]).is_ok());
}

#[test]
fn test_parses_purge_subcommand() {
    assert!(parse(&["badger", "purge"]).is_ok());
}

#[test]
fn test_parses_analyze_with_optional_path() {
    let cli = parse(&["badger", "analyze"]).unwrap();
    match cli.command {
        badger::cli::Command::Analyze { path } => assert!(path.is_none()),
        _ => panic!("expected Analyze"),
    }

    let cli = parse(&["badger", "analyze", "/tmp/foo"]).unwrap();
    match cli.command {
        badger::cli::Command::Analyze { path } => {
            assert_eq!(path, Some(std::path::PathBuf::from("/tmp/foo")))
        }
        _ => panic!("expected Analyze"),
    }
}

#[test]
fn test_parses_history_with_optional_run() {
    let cli = parse(&["badger", "history"]).unwrap();
    match cli.command {
        badger::cli::Command::History { run } => assert!(run.is_none()),
        _ => panic!("expected History"),
    }

    let cli = parse(&["badger", "history", "--run", "abc123"]).unwrap();
    match cli.command {
        badger::cli::Command::History { run } => assert_eq!(run, Some("abc123".to_string())),
        _ => panic!("expected History"),
    }
}

#[test]
fn test_parses_whitelist_add() {
    let cli = parse(&["badger", "whitelist", "add", "~/foo/*"]).unwrap();
    match cli.command {
        badger::cli::Command::Whitelist {
            action: WhitelistAction::Add { pattern },
        } => assert_eq!(pattern, "~/foo/*"),
        _ => panic!("expected Whitelist Add"),
    }
}

#[test]
fn test_parses_whitelist_remove() {
    let cli = parse(&["badger", "whitelist", "remove", "~/foo/*"]).unwrap();
    match cli.command {
        badger::cli::Command::Whitelist {
            action: WhitelistAction::Remove { pattern },
        } => assert_eq!(pattern, "~/foo/*"),
        _ => panic!("expected Whitelist Remove"),
    }
}

#[test]
fn test_parses_whitelist_list() {
    let cli = parse(&["badger", "whitelist", "list"]).unwrap();
    match cli.command {
        badger::cli::Command::Whitelist {
            action: WhitelistAction::List,
        } => {}
        _ => panic!("expected Whitelist List"),
    }
}

#[test]
fn test_parses_completion_shell() {
    let cli = parse(&["badger", "completion", "zsh"]).unwrap();
    match cli.command {
        badger::cli::Command::Completion { shell } => {
            assert_eq!(shell, clap_complete::Shell::Zsh)
        }
        _ => panic!("expected Completion"),
    }
}

#[test]
fn test_parses_hidden_helper_subcommand() {
    assert!(parse(&["badger", "__helper"]).is_ok());
}

#[test]
fn test_global_flags_parse_before_subcommand() {
    let cli = parse(&["badger", "--dry-run", "--json", "--debug", "clean"]).unwrap();
    assert!(cli.dry_run);
    assert!(cli.json);
    assert!(cli.debug);
}

#[test]
fn test_global_flags_parse_after_subcommand() {
    let cli = parse(&["badger", "clean", "--dry-run"]).unwrap();
    assert!(cli.dry_run);

    let cli = parse(&["badger", "clean", "--json"]).unwrap();
    assert!(cli.json);
}

#[test]
fn test_unknown_flag_errors() {
    assert!(parse(&["badger", "clean", "--not-a-real-flag"]).is_err());
}

#[test]
fn test_bare_invocation_errors() {
    assert!(parse(&["badger"]).is_err());
}

#[test]
fn test_help_lists_visible_subcommands_but_not_helper() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("clean"));
    assert!(!help.contains("__helper"));
}
