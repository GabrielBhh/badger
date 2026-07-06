use std::collections::HashMap;

use badger::commands::optimize;
use badger::config::Config;
use badger::core::runner::CmdOutput;
use badger::ctx::Ctx;
use badger::output::Mode;
use badger::safety::journal::Journal;

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

fn ok(stdout: &str) -> CmdOutput {
    CmdOutput {
        success: true,
        stdout: stdout.to_string(),
        stderr: String::new(),
    }
}

#[test]
fn test_default_plan_shows_prechecked_and_optin_tasks_and_touches_nothing() {
    let f = fixture();

    let output = optimize::run(&f.ctx, false, false, Mode::Human).unwrap();

    assert!(output.rendered.contains("Trim SSD free space"));
    assert!(output.rendered.contains("[safe, sudo]"));
    assert!(output.rendered.contains("Reset failed systemd units"));
    assert!(output.rendered.contains("pre-checked task"));
    assert!(output.rendered.contains("--dry-run"));
    assert!(output.rendered.contains("--yes"));
    assert!(!f.ctx.state_dir.join("history.jsonl").exists());
}

#[test]
fn test_default_plan_shows_optin_tasks_as_needing_manual_selection() {
    let mut f = fixture();
    f.ctx.available_commands = Some(vec!["pacman".to_string()]);

    let output = optimize::run(&f.ctx, false, false, Mode::Human).unwrap();

    assert!(output.rendered.contains("Refresh pacman file database"));
    assert!(output.rendered.contains("[moderate, sudo]"));
    assert!(output.rendered.contains("opt-in"));
}

#[test]
fn test_dry_run_journals_prechecked_tasks_without_running_anything_for_real() {
    let f = fixture();

    let output = optimize::run(&f.ctx, false, true, Mode::Human).unwrap();

    assert!(output.rendered.contains("Would run"));
    assert!(output.rendered.contains("dry run"));

    let journal = Journal::new(&f.ctx.state_dir);
    let (records, _) = journal.read_all().unwrap();
    // fstrim (1 spec) + reset-failed (2 specs) are the only Applicability::Always
    // tasks — nothing else is "available" in this bare fixture.
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|r| r.dry_run));
    assert!(records.iter().all(|r| r.outcome.starts_with("would run:")));
}

#[test]
fn test_yes_runs_only_prechecked_tasks_with_exact_argv_and_skips_opt_ins() {
    let mut f = fixture();
    let hicolor = f.ctx.home.join(".local/share/icons/hicolor");
    let mime = f.ctx.home.join(".local/share/mime");
    std::fs::create_dir_all(&hicolor).unwrap();
    std::fs::create_dir_all(&mime).unwrap();

    f.ctx.available_commands = Some(vec![
        "fc-cache".to_string(),
        "update-desktop-database".to_string(),
        "gtk-update-icon-cache".to_string(),
        "update-mime-database".to_string(),
        "updatedb".to_string(),
        // Opt-in tools are present too, to prove --yes still skips them.
        "pacman".to_string(),
        "reflector".to_string(),
    ]);

    let applications_dir = f.ctx.home.join(".local/share/applications");
    f.ctx.fake_command_output = Some(HashMap::from([
        (vec!["fc-cache".to_string(), "-f".to_string()], ok("")),
        (
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "reset-failed".to_string(),
            ],
            ok(""),
        ),
        (
            vec![
                "update-desktop-database".to_string(),
                applications_dir.display().to_string(),
            ],
            ok(""),
        ),
        (
            vec![
                "gtk-update-icon-cache".to_string(),
                "-f".to_string(),
                "-t".to_string(),
                hicolor.display().to_string(),
            ],
            ok(""),
        ),
        (
            vec![
                "update-mime-database".to_string(),
                mime.display().to_string(),
            ],
            ok(""),
        ),
    ]));

    let output = optimize::run(&f.ctx, true, false, Mode::Human).unwrap();
    assert!(output.rendered.contains("Ran 5 tasks · 3 skipped"));

    let journal = Journal::new(&f.ctx.state_dir);
    let (records, _) = journal.read_all().unwrap();

    let ran: Vec<&Vec<String>> = records
        .iter()
        .filter(|r| r.outcome == "ok")
        .filter_map(|r| r.argv.as_ref())
        .collect();
    assert!(ran.contains(&&vec!["fc-cache".to_string(), "-f".to_string()]));
    assert!(ran.contains(&&vec![
        "systemctl".to_string(),
        "--user".to_string(),
        "reset-failed".to_string()
    ]));
    assert!(ran.contains(&&vec![
        "update-desktop-database".to_string(),
        applications_dir.display().to_string()
    ]));
    assert!(ran.contains(&&vec![
        "gtk-update-icon-cache".to_string(),
        "-f".to_string(),
        "-t".to_string(),
        hicolor.display().to_string()
    ]));
    assert!(ran.contains(&&vec![
        "update-mime-database".to_string(),
        mime.display().to_string()
    ]));

    // Sudo tasks are visibly skipped rather than actually run, in a sandbox.
    let skipped_rules: Vec<&str> = records
        .iter()
        .filter(|r| r.outcome.starts_with("skipped"))
        .map(|r| r.rule.as_str())
        .collect();
    assert!(skipped_rules.contains(&"optimize.fstrim"));
    assert!(skipped_rules.contains(&"optimize.reset_failed"));
    assert!(skipped_rules.contains(&"optimize.updatedb"));

    // Opt-in tasks never ran, even though their tools are installed.
    assert!(!records.iter().any(|r| r.rule == "optimize.pacman_files"));
    assert!(!records.iter().any(|r| r.rule == "optimize.mirrors"));
}

#[test]
fn test_dry_run_wins_over_yes() {
    let f = fixture();
    let output = optimize::run(&f.ctx, true, true, Mode::Human).unwrap();
    assert!(output.rendered.contains("dry run"));
}

#[test]
fn test_json_mode_emits_parseable_groups_and_summary() {
    let f = fixture();
    let output = optimize::run(&f.ctx, true, false, Mode::Json).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output.rendered).unwrap();
    assert!(value["groups"].is_array());
    assert!(value["summary"]["actions"].as_u64().unwrap() > 0);
}

/// Thin end-to-end smoke test, same shape as `clean_test.rs`'s: drives the
/// actual compiled binary to catch wiring bugs in cli.rs/main.rs/dispatch.
#[test]
fn test_binary_optimize_plan_then_yes_via_real_process() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    std::fs::create_dir_all(&home).unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let plan = std::process::Command::new(bin)
        .arg("optimize")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();
    assert!(plan.status.success(), "{:?}", plan);
    let plan_json: serde_json::Value =
        serde_json::from_slice(&plan.stdout).expect("plan stdout should be JSON");
    let groups = plan_json["groups"].as_array().unwrap();
    assert!(groups.iter().any(|g| g["rule_id"] == "optimize.fstrim"));
    assert!(plan_json["summary"].is_null());

    let yes = std::process::Command::new(bin)
        .arg("optimize")
        .arg("--yes")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();
    assert!(yes.status.success(), "{:?}", yes);
    let yes_json: serde_json::Value =
        serde_json::from_slice(&yes.stdout).expect("yes stdout should be JSON");
    assert!(yes_json["summary"]["actions"].as_u64().unwrap() > 0);
}
