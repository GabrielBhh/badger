use badger::commands::uninstall;
use badger::config::Config;
use badger::ctx::Ctx;
use badger::output::Mode;

fn fixture_ctx() -> (tempfile::TempDir, Ctx) {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    std::fs::create_dir_all(&home).unwrap();
    let ctx = Ctx {
        root,
        home,
        config_dir: sandbox.path().join("config"),
        state_dir: sandbox.path().join("state"),
        dry_run: false,
        debug: false,
        config: Config::default(),
        sandboxed: true,
        available_commands: None,
        fake_command_output: None,
    };
    (sandbox, ctx)
}

/// `badger uninstall` is inherently interactive: no `--yes`, no `--json`
/// output mode. Asking for JSON (or running non-interactively) must fail
/// clearly rather than silently doing nothing.
#[test]
fn test_json_mode_is_rejected_as_non_interactive() {
    let (_sandbox, ctx) = fixture_ctx();
    let err = uninstall::run(&ctx, false, Mode::Json).unwrap_err();
    assert!(err.to_string().contains("interactive terminal"));
}

/// Thin end-to-end smoke test: drives the actual compiled binary (not just
/// the lib) with stdout/stderr piped (never a tty in a test process) to
/// catch wiring bugs in cli.rs/main.rs/dispatch that a lib-level call can't
/// see. `badger uninstall` has no non-interactive mode, so the only thing to
/// assert here is that it fails clearly instead of hanging or panicking.
#[test]
fn test_binary_uninstall_without_a_tty_exits_1_with_a_clear_error() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    std::fs::create_dir_all(&home).unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let output = std::process::Command::new(bin)
        .arg("uninstall")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal"),
        "stderr was: {stderr}"
    );
}
