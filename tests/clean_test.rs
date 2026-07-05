use badger::commands::clean;
use badger::config::Config;
use badger::ctx::Ctx;
use badger::output::Mode;

struct Fixture {
    _sandbox: tempfile::TempDir,
    ctx: Ctx,
}

fn fixture() -> Fixture {
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
    Fixture {
        _sandbox: sandbox,
        ctx,
    }
}

fn thumbnails_dir(ctx: &Ctx) -> std::path::PathBuf {
    let dir = ctx.home.join(".cache/thumbnails");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.png"), vec![0u8; 4096]).unwrap();
    dir
}

#[test]
fn test_default_plan_shows_candidate_and_does_not_touch_journal_or_filesystem() {
    let f = fixture();
    let dir = thumbnails_dir(&f.ctx);

    let output = clean::run(&f.ctx, false, false, Mode::Human, false).unwrap();

    assert!(output.rendered.contains("Thumbnail cache"));
    assert!(output.rendered.contains("[safe]"));
    assert!(output.rendered.contains("4.0 KiB"));
    assert!(output.rendered.contains("--dry-run"));
    assert!(output.rendered.contains("--yes"));
    assert!(dir.exists());
    assert!(!f.ctx.state_dir.join("history.jsonl").exists());
}

#[test]
fn test_dry_run_journals_and_leaves_filesystem_untouched() {
    let f = fixture();
    let dir = thumbnails_dir(&f.ctx);

    let output = clean::run(&f.ctx, false, true, Mode::Human, false).unwrap();

    assert!(output.rendered.contains("Would free 4.0 KiB"));
    assert!(output.rendered.contains("dry run"));
    assert!(dir.exists(), "dry run must not delete anything");

    let journal = badger::safety::journal::Journal::new(&f.ctx.state_dir);
    let (records, _) = journal.read_all().unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].dry_run);
    assert_eq!(records[0].rule, "user.thumbnails");
}

#[test]
fn test_yes_deletes_selected_candidate_and_journals_real_run() {
    let f = fixture();
    let dir = thumbnails_dir(&f.ctx);

    let output = clean::run(&f.ctx, true, false, Mode::Human, false).unwrap();

    assert!(output.rendered.contains("Freed 4.0 KiB"));
    assert!(!dir.exists(), "--yes must actually delete the candidate");

    let journal = badger::safety::journal::Journal::new(&f.ctx.state_dir);
    let (records, _) = journal.read_all().unwrap();
    assert_eq!(records.len(), 1);
    assert!(!records[0].dry_run);
    assert_eq!(records[0].outcome, "ok");
}

#[test]
fn test_dry_run_wins_over_yes() {
    let f = fixture();
    let dir = thumbnails_dir(&f.ctx);

    let output = clean::run(&f.ctx, true, true, Mode::Human, false).unwrap();

    assert!(output.rendered.contains("dry run"));
    assert!(dir.exists(), "--dry-run must win over --yes");
}

#[test]
fn test_moderate_group_is_shown_but_never_executed_by_yes() {
    let f = fixture();
    let dir = f.ctx.root.join("var/log/journal");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("system.journal"), vec![0u8; 4096]).unwrap();
    let mut ctx = f.ctx.clone();
    ctx.available_commands = Some(vec!["journalctl".to_string()]);

    let output = clean::run(&ctx, true, false, Mode::Human, false).unwrap();

    assert!(output.rendered.contains("systemd journal"));
    assert!(output.rendered.contains("needs manual opt-in"));
    assert!(dir.exists());
}

#[test]
fn test_json_mode_emits_parseable_groups_and_summary() {
    let f = fixture();
    thumbnails_dir(&f.ctx);

    let output = clean::run(&f.ctx, true, false, Mode::Json, false).unwrap();

    let value: serde_json::Value = serde_json::from_str(&output.rendered).unwrap();
    assert!(value["groups"].is_array());
    assert!(value["summary"]["bytes_freed"].as_u64().unwrap() > 0);
}

#[test]
fn test_nothing_to_clean_on_an_empty_home() {
    let f = fixture();
    let output = clean::run(&f.ctx, false, false, Mode::Human, false).unwrap();
    assert_eq!(output.rendered, "Nothing to clean.");
}

/// Thin end-to-end smoke test: drives the actual compiled binary (not just
/// the lib) to catch wiring bugs in cli.rs/main.rs/dispatch that a
/// lib-level call to `clean::run` can't see. Env vars are set only on the
/// spawned child, never the test process, so it's safe alongside the
/// parallel lib-level tests above. Captured (non-tty) stdout makes badger
/// fall back to JSON mode (see output::decide), so assertions parse JSON
/// rather than looking for human-readable text.
#[test]
fn test_binary_clean_plan_then_yes_via_real_process() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    let cache = home.join(".cache/thumbnails");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("a.png"), vec![0u8; 4096]).unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let plan = std::process::Command::new(bin)
        .arg("clean")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();
    assert!(plan.status.success(), "{:?}", plan);
    let plan_json: serde_json::Value =
        serde_json::from_slice(&plan.stdout).expect("plan stdout should be JSON");
    let groups = plan_json["groups"].as_array().unwrap();
    assert!(
        groups.iter().any(|g| g["rule_id"] == "user.thumbnails"
            && !g["candidates"].as_array().unwrap().is_empty())
    );
    assert!(plan_json["summary"].is_null());
    assert!(cache.exists());

    let clean = std::process::Command::new(bin)
        .arg("clean")
        .arg("--yes")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();
    assert!(clean.status.success(), "{:?}", clean);
    let clean_json: serde_json::Value =
        serde_json::from_slice(&clean.stdout).expect("clean stdout should be JSON");
    assert!(clean_json["summary"]["bytes_freed"].as_u64().unwrap() > 0);
    assert!(!cache.exists());
}
