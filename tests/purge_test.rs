use badger::commands::purge;
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
    let mut ctx = Ctx {
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
    ctx.config.purge.roots = vec!["~/dev".to_string()];
    Fixture {
        _sandbox: sandbox,
        ctx,
    }
}

/// An old (backdated) project with a `node_modules` next to its
/// `package.json` — the "boring, obviously reclaimable" case that a plain
/// `--yes` should actually delete.
fn old_node_project(ctx: &Ctx, name: &str) -> std::path::PathBuf {
    let project = ctx.home.join("dev").join(name);
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("package.json"), b"{}").unwrap();
    let node_modules = project.join("node_modules");
    std::fs::create_dir_all(&node_modules).unwrap();
    std::fs::write(node_modules.join("a.js"), vec![0u8; 4096]).unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86_400);
    std::fs::File::open(&project)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();
    node_modules
}

#[test]
fn test_default_plan_shows_candidate_and_does_not_touch_journal_or_filesystem() {
    let f = fixture();
    let dir = old_node_project(&f.ctx, "site");

    let output = purge::run(&f.ctx, false, false, Mode::Human).unwrap();

    assert!(output.rendered.contains("node_modules"));
    assert!(output.rendered.contains("4.0 KiB"));
    assert!(output.rendered.contains("--dry-run"));
    assert!(output.rendered.contains("--yes"));
    assert!(dir.exists());
    assert!(!f.ctx.state_dir.join("history.jsonl").exists());
}

#[test]
fn test_dry_run_journals_and_leaves_filesystem_untouched() {
    let f = fixture();
    let dir = old_node_project(&f.ctx, "site");

    let output = purge::run(&f.ctx, false, true, Mode::Human).unwrap();

    assert!(output.rendered.contains("Would free 4.0 KiB"));
    assert!(output.rendered.contains("dry run"));
    assert!(dir.exists(), "dry run must not delete anything");

    let journal = badger::safety::journal::Journal::new(&f.ctx.state_dir);
    let (records, _) = journal.read_all().unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].dry_run);
    assert_eq!(records[0].cmd, "purge");
}

#[test]
fn test_yes_deletes_pre_checked_candidate_and_journals_real_run() {
    let f = fixture();
    let dir = old_node_project(&f.ctx, "site");

    let output = purge::run(&f.ctx, true, false, Mode::Human).unwrap();

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
    let dir = old_node_project(&f.ctx, "site");

    let output = purge::run(&f.ctx, true, true, Mode::Human).unwrap();

    assert!(output.rendered.contains("dry run"));
    assert!(dir.exists(), "--dry-run must win over --yes");
}

#[test]
fn test_recent_project_is_shown_but_never_deleted_by_yes() {
    let f = fixture();
    let project = f.ctx.home.join("dev/freshsite");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("package.json"), b"{}").unwrap();
    let node_modules = project.join("node_modules");
    std::fs::create_dir_all(&node_modules).unwrap();
    // No backdating: the project was "just touched", so it starts unchecked.

    let output = purge::run(&f.ctx, true, false, Mode::Human).unwrap();

    assert!(output.rendered.contains("Freed 0 B"));
    assert!(node_modules.exists());
}

#[test]
fn test_json_mode_emits_parseable_groups_and_summary() {
    let f = fixture();
    old_node_project(&f.ctx, "site");

    let output = purge::run(&f.ctx, true, false, Mode::Json).unwrap();

    let value: serde_json::Value = serde_json::from_str(&output.rendered).unwrap();
    assert!(value["groups"].is_array());
    assert!(value["summary"]["bytes_freed"].as_u64().unwrap() > 0);
}

#[test]
fn test_nothing_to_purge_on_an_empty_home() {
    let f = fixture();
    let output = purge::run(&f.ctx, false, false, Mode::Human).unwrap();
    assert_eq!(output.rendered, "Nothing to purge.");
}

/// Thin end-to-end smoke test: drives the actual compiled binary (not just
/// the lib) to catch wiring bugs in cli.rs/main.rs/dispatch that a lib-level
/// call to `purge::run` can't see.
#[test]
fn test_binary_purge_plan_then_yes_via_real_process() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    let project = home.join("dev/site");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("package.json"), b"{}").unwrap();
    let node_modules = project.join("node_modules");
    std::fs::create_dir_all(&node_modules).unwrap();
    std::fs::write(node_modules.join("a.js"), vec![0u8; 4096]).unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86_400);
    std::fs::File::open(&project)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let plan = std::process::Command::new(bin)
        .arg("purge")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();
    assert!(plan.status.success(), "{:?}", plan);
    let plan_json: serde_json::Value =
        serde_json::from_slice(&plan.stdout).expect("plan stdout should be JSON");
    let groups = plan_json["groups"].as_array().unwrap();
    assert!(
        groups.iter().any(|g| g["rule_id"] == "purge.node_modules"
            && !g["candidates"].as_array().unwrap().is_empty())
    );
    assert!(plan_json["summary"].is_null());
    assert!(node_modules.exists());

    let clean = std::process::Command::new(bin)
        .arg("purge")
        .arg("--yes")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();
    assert!(clean.status.success(), "{:?}", clean);
    let clean_json: serde_json::Value =
        serde_json::from_slice(&clean.stdout).expect("purge --yes stdout should be JSON");
    assert!(clean_json["summary"]["bytes_freed"].as_u64().unwrap() > 0);
    assert!(!node_modules.exists());
}
