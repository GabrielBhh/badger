//! First real trigger of the Risky-tier typed-count confirmation
//! (`ConfirmState`/`handle_key` in src/tui/confirm.rs), which existed since
//! an earlier phase but had never been exercised by an actual Risky rule
//! until `snapshots.snapper_manual` landed. Drives the real pipeline
//! (scan -> ChecklistState -> ConfirmState -> handle_key) at the
//! state-struct level, no terminal involved.

use std::collections::HashMap;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Color;

use badger::config::Config;
use badger::core::item::{Group, Risk};
use badger::core::runner::CmdOutput;
use badger::core::scan::scan;
use badger::ctx::Ctx;
use badger::rules;
use badger::safety::whitelist;
use badger::tui::checklist::{self, ChecklistState};
use badger::tui::confirm::{ConfirmState, Outcome, handle_key};

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
        available_commands: Some(vec!["snapper".to_string(), "pacman".to_string()]),
        fake_command_output: None,
    };
    Fixture {
        _sandbox: sandbox,
        ctx,
    }
}

fn empty_whitelist() -> whitelist::Whitelist {
    whitelist::parse("", &PathBuf::from("/home/user")).unwrap()
}

fn cmd_output(stdout: &str) -> CmdOutput {
    CmdOutput {
        success: true,
        stdout: stdout.to_string(),
        stderr: String::new(),
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Runs the real scan through `rules::registry(false)` against a sandboxed
/// ctx wired so that: exactly one snapper config ("root") exists, it has
/// snapshots 0 (the pseudo "current system" snapshot), 4 (single), and 5
/// (single); `/proc/cmdline` says the booted snapshot is #5; and
/// limine-snapper-sync isn't installed. That leaves snapshot 0 excluded
/// (always) and 5 excluded (booted), so #4 is the lone manual-delete
/// candidate.
fn snapshot_groups() -> Vec<Group> {
    let mut f = fixture();
    std::fs::create_dir_all(f.ctx.root.join("proc")).unwrap();
    std::fs::write(
        f.ctx.root.join("proc/cmdline"),
        "BOOT_IMAGE=/vmlinuz rw subvol=@snapshots/5/snapshot quiet\n",
    )
    .unwrap();

    f.ctx.fake_command_output = Some(HashMap::from([
        (
            vec!["snapper".to_string(), "list-configs".to_string()],
            cmd_output("Config | Subvolume\n-------+----------\nroot   | /\n"),
        ),
        (
            vec![
                "snapper".to_string(),
                "-c".to_string(),
                "root".to_string(),
                "--jsonout".to_string(),
                "list".to_string(),
            ],
            cmd_output(r#"{"root": [{"number":0},{"number":4},{"number":5}]}"#),
        ),
        (
            vec![
                "systemctl".to_string(),
                "is-enabled".to_string(),
                "limine-snapper-sync.service".to_string(),
            ],
            cmd_output("not-found\n"),
        ),
    ]));

    scan(
        &rules::registry(false),
        &f.ctx,
        &f.ctx.config.clone(),
        &empty_whitelist(),
    )
    .unwrap()
}

#[test]
fn test_selecting_the_one_risky_snapshot_candidate_requires_typed_count_confirmation() {
    let groups = snapshot_groups();
    let manual_idx = groups
        .iter()
        .position(|g| g.rule_id == "snapshots.snapper_manual")
        .expect("snapshots.snapper_manual group must be present");
    let manual = &groups[manual_idx];
    assert_eq!(manual.risk, Risk::Risky);
    assert_eq!(manual.candidates.len(), 1, "only #4 should be offered");
    assert_eq!(manual.candidates[0].label, "root: #4");

    let mut checklist = ChecklistState::new(groups);
    loop {
        match checklist.cursor() {
            Some((gi, ci))
                if gi == manual_idx
                    && checklist.groups()[gi].candidates[ci].label == "root: #4" =>
            {
                break;
            }
            Some(_) => checklist.move_down(),
            None => panic!("cursor ran out before reaching the manual-delete candidate"),
        }
    }
    checklist.toggle();
    assert!(checklist.is_selected(manual_idx, 0));

    // First real-rule trigger of the Risky typed-count confirmation path.
    let mut confirm = ConfirmState::from_checklist(&checklist);
    assert!(confirm.requires_typed_confirmation());
    assert_eq!(confirm.risky_required_count(), 1);

    // The guard actually guards: plain 'y' must not proceed for a Risky
    // selection, a wrong typed count must not proceed, and the correct
    // count must.
    assert_eq!(
        handle_key(&mut confirm, key(KeyCode::Char('y'))),
        Outcome::None
    );
    handle_key(&mut confirm, key(KeyCode::Char('9')));
    assert_eq!(handle_key(&mut confirm, key(KeyCode::Enter)), Outcome::None);
    handle_key(&mut confirm, key(KeyCode::Backspace));
    handle_key(&mut confirm, key(KeyCode::Char('1')));
    assert_eq!(
        handle_key(&mut confirm, key(KeyCode::Enter)),
        Outcome::Proceed
    );
}

fn row_text(buffer: &Buffer, y: u16) -> String {
    (0..buffer.area.width)
        .map(|x| buffer.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
        .collect::<String>()
}

#[test]
fn test_checklist_renders_a_real_risky_groups_tag_in_red() {
    let groups = snapshot_groups();
    assert!(
        groups
            .iter()
            .any(|g| g.rule_id == "snapshots.snapper_manual" && g.risk == Risk::Risky)
    );

    let state = ChecklistState::new(groups);
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| checklist::render(f, &state, true))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();

    let y = (0..buffer.area.height)
        .find(|&y| row_text(&buffer, y).contains("[risky]"))
        .expect("a [risky] tag must be rendered");
    let x = row_text(&buffer, y).find("[risky]").unwrap() as u16;
    assert_eq!(buffer.cell((x, y)).unwrap().fg, Color::Red);
}
