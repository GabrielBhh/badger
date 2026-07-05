//! `badger uninstall`: pick one installed package (across whichever backends
//! are detected), remove it via that backend, then offer a review-and-delete
//! pass over whatever it left behind. Inherently interactive — there is no
//! `--yes`/JSON mode, since picking *which* package to remove is the whole
//! point and can't be scripted the way `clean`/`purge`'s pre-checked
//! defaults can.

use std::collections::HashSet;
use std::io::IsTerminal;

use crossterm::event::{Event, KeyEventKind};

use crate::commands::shared::{drive_selection, execution_notes};
use crate::core::exec::{DryRunEffector, Effector, RealEffector, Summary};
use crate::core::item::Group;
use crate::core::runner::RealRunner;
use crate::ctx::Ctx;
use crate::output::{Mode, humanize_bytes};
use crate::pkg::{Backend, InstalledPackage};
use crate::rules::CmdSpec;
use crate::safety::journal::{Journal, Record};
use crate::tui::{self, confirm, picker};
use crate::uninstall_leftovers;

#[derive(Debug)]
pub struct UninstallOutput {
    pub rendered: String,
}

/// `badger uninstall` only ever runs interactively: `--json`, a non-tty
/// stdout (both of which `output::current` already folds into `Mode::Json`),
/// or a non-tty stderr all mean there is no terminal to drive the picker on.
pub fn run(ctx: &Ctx, dry_run_flag: bool, mode: Mode) -> anyhow::Result<UninstallOutput> {
    if mode != Mode::Human || !std::io::stderr().is_terminal() {
        anyhow::bail!("badger uninstall requires an interactive terminal");
    }
    run_interactive(ctx, dry_run_flag)
}

fn run_interactive(ctx: &Ctx, dry_run_flag: bool) -> anyhow::Result<UninstallOutput> {
    eprintln!("Scanning installed packages — this can take a moment...");
    let packages = crate::pkg::list_installed(ctx);
    if packages.is_empty() {
        return Ok(UninstallOutput {
            rendered: "No installed packages found.".to_string(),
        });
    }

    let mut terminal = tui::init_terminal()?;
    let pick_result = drive_picker(&mut terminal, packages);
    let package = match pick_result {
        Ok(Some(package)) => package,
        Ok(None) => {
            tui::restore_terminal(&mut terminal)?;
            eprintln!("nothing uninstalled");
            return Ok(UninstallOutput {
                rendered: String::new(),
            });
        }
        Err(e) => {
            let _ = tui::restore_terminal(&mut terminal);
            return Err(e);
        }
    };

    let (argv, sudo) = remove_argv_for(&package);
    let confirm_lines = vec![
        format!(
            "About to remove {} ({}) via {}.",
            package.name,
            package.version,
            package.backend.label()
        ),
        format!(
            "Command: {}{}",
            if sudo { "sudo " } else { "" },
            argv.join(" ")
        ),
    ];
    let confirm_result = drive_plain_confirm(&mut terminal, confirm_lines);
    tui::restore_terminal(&mut terminal)?;
    if !confirm_result? {
        eprintln!("nothing uninstalled");
        return Ok(UninstallOutput {
            rendered: String::new(),
        });
    }

    let journal = Journal::new(&ctx.state_dir);
    let run_id = jiff::Timestamp::now().to_string();
    let leftover_group =
        uninstall_leftovers::scan(ctx, &package.name, &package.id, package.backend)?;

    let show_checklist =
        !leftover_group.candidates.is_empty() || !leftover_group.skipped.is_empty();
    let selection = if !show_checklist {
        HashSet::new()
    } else {
        let groups = vec![leftover_group.clone()];
        let mut terminal = tui::init_terminal()?;
        let selection_result = drive_selection(&mut terminal, groups.clone());
        tui::restore_terminal(&mut terminal)?;
        match selection_result? {
            Some(selection) => selection,
            None => {
                eprintln!("leftovers left untouched");
                HashSet::new()
            }
        }
    };

    let leftover_groups = vec![leftover_group];
    if dry_run_flag {
        let mut effector = DryRunEffector;
        render_after_removal_and_leftovers(
            ctx,
            &package,
            &leftover_groups,
            &selection,
            &mut effector,
            &journal,
            &run_id,
            true,
        )
    } else {
        let mut effector = RealEffector::new(ctx, Box::new(RealRunner));
        render_after_removal_and_leftovers(
            ctx,
            &package,
            &leftover_groups,
            &selection,
            &mut effector,
            &journal,
            &run_id,
            false,
        )
    }
}

/// The terminal-free seam: given the picked package, its (already-scanned)
/// leftover groups, and an already-made selection over them (as the
/// checklist would produce), runs the removal, then the selected leftover
/// deletes, and renders the final summary. No terminal involved, so tests
/// drive pick -> selection -> execute directly, the same way
/// `clean::render_after_selection` / `purge::render_after_selection` do.
#[allow(clippy::too_many_arguments)]
fn render_after_removal_and_leftovers(
    ctx: &Ctx,
    package: &InstalledPackage,
    leftover_groups: &[Group],
    leftover_selection: &HashSet<(usize, usize)>,
    effector: &mut dyn Effector,
    journal: &Journal,
    run_id: &str,
    dry_run: bool,
) -> anyhow::Result<UninstallOutput> {
    let (argv, sudo) = remove_argv_for(package);
    // Captured before removal for a future phase's leftover-guessing
    // heuristic; this phase's exact-name-match scan doesn't consult it, but
    // it's worth journaling now rather than losing it.
    let owned_files = (package.backend == Backend::Pacman)
        .then(|| crate::pkg::pacman::file_list(ctx, &package.id))
        .filter(|files| !files.is_empty());

    let removal_outcome = effector.run(&CmdSpec {
        argv: argv.clone(),
        sudo,
        label: format!("Remove {}", package.name),
    });
    if let Err(e) = journal.append(&Record::now(
        run_id.to_string(),
        "uninstall".to_string(),
        package.id.clone(),
        "cmd".to_string(),
        Some(argv),
        owned_files,
        sudo,
        dry_run,
        0,
        removal_outcome.outcome.clone(),
    )) {
        eprintln!("warning: failed to record audit trail: {e:#}");
    }

    if removal_outcome.outcome.starts_with("error") {
        anyhow::bail!(
            "failed to remove {}: {}",
            package.name,
            removal_outcome.outcome
        );
    }

    let mut rendered = removal_summary_line(package, dry_run);

    let any_leftover_candidates = leftover_groups.iter().any(|g| !g.candidates.is_empty());
    if any_leftover_candidates {
        let leftover_summary = execute_leftover_selection(
            leftover_groups,
            leftover_selection,
            ctx,
            effector,
            journal,
            run_id,
            dry_run,
        )?;
        for warning in &leftover_summary.journal_warnings {
            eprintln!("warning: {warning}");
        }
        if dry_run {
            rendered.push_str(&format!(
                "\nWould free {} from leftovers (dry run).",
                humanize_bytes(leftover_summary.bytes_freed)
            ));
        } else {
            rendered.push_str(&format!(
                "\nFreed {} from leftovers.",
                humanize_bytes(leftover_summary.bytes_freed)
            ));
        }
    }

    for note in execution_notes(journal, run_id)? {
        rendered.push_str(&format!("\n  {note}"));
    }

    Ok(UninstallOutput { rendered })
}

fn removal_summary_line(package: &InstalledPackage, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Would remove {} via {} (dry run).",
            package.name,
            package.backend.label()
        )
    } else {
        format!("Removed {} via {}.", package.name, package.backend.label())
    }
}

/// Deletes exactly the leftover candidates named in `selection`. Every
/// leftover is a plain, non-sudo directory/file delete validated against
/// `uninstall_leftovers::allowed_prefixes`, so — like `purge`'s
/// candidates — this drives `Effector::delete` directly rather than going
/// through the rule registry's `Action` dispatch (there is no static `Rule`
/// backing a leftover group).
#[allow(clippy::too_many_arguments)]
fn execute_leftover_selection(
    groups: &[Group],
    selection: &HashSet<(usize, usize)>,
    ctx: &Ctx,
    effector: &mut dyn Effector,
    journal: &Journal,
    run_id: &str,
    dry_run: bool,
) -> anyhow::Result<Summary> {
    let allowed = uninstall_leftovers::allowed_prefixes(ctx);
    let mut summary = Summary::default();
    for (gi, group) in groups.iter().enumerate() {
        for (ci, candidate) in group.candidates.iter().enumerate() {
            if !selection.contains(&(gi, ci)) {
                continue;
            }
            let Some(path) = &candidate.path else {
                continue;
            };
            let outcome = effector.delete(false, &allowed, path, candidate.bytes);
            summary.bytes_freed += outcome.bytes_freed;
            summary.actions += 1;
            if let Err(e) = journal.append(&Record::now(
                run_id.to_string(),
                "uninstall".to_string(),
                group.rule_id.clone(),
                "delete".to_string(),
                None,
                Some(vec![path.display().to_string()]),
                false,
                dry_run,
                outcome.bytes_freed,
                outcome.outcome,
            )) {
                summary
                    .journal_warnings
                    .push(format!("failed to record audit trail: {e:#}"));
            }
        }
    }
    Ok(summary)
}

fn remove_argv_for(package: &InstalledPackage) -> (Vec<String>, bool) {
    match package.backend {
        Backend::Pacman => (crate::pkg::pacman::remove_argv(&package.id), true),
        Backend::Flatpak => (crate::pkg::flatpak::remove_argv(&package.id), false),
        Backend::Snap => (crate::pkg::snap::remove_argv(&package.id), true),
    }
}

/// Drives the picker's key-handling loop against a real terminal. Returns
/// the chosen package, or `None` if the person cancelled.
fn drive_picker(
    terminal: &mut tui::Term,
    items: Vec<InstalledPackage>,
) -> anyhow::Result<Option<InstalledPackage>> {
    let mut state = picker::PickerState::new(items);
    let colors = tui::colors_enabled_now();
    loop {
        terminal.draw(|f| picker::render(f, &state, colors))?;

        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }

        match picker::map_key(key) {
            Some(picker::Action::Down) => state.move_down(),
            Some(picker::Action::Up) => state.move_up(),
            Some(picker::Action::Type(c)) => state.push_char(c),
            Some(picker::Action::Backspace) => state.backspace(),
            Some(picker::Action::Cancel) => return Ok(None),
            Some(picker::Action::Select) => {
                if let Some(package) = state.selected() {
                    return Ok(Some(package.clone()));
                }
            }
            None => {}
        }
    }
}

/// Drives the plain yes/no removal-confirm loop against a real terminal.
fn drive_plain_confirm(terminal: &mut tui::Term, lines: Vec<String>) -> anyhow::Result<bool> {
    let state = confirm::PlainConfirmState::new(lines);
    loop {
        terminal.draw(|f| confirm::render_plain(f, &state))?;

        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }

        match confirm::handle_plain_key(key) {
            confirm::Outcome::Proceed => return Ok(true),
            confirm::Outcome::Back => return Ok(false),
            confirm::Outcome::None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::core::item::{Candidate, Risk};
    use crate::core::runner::{CmdOutput, FakeRunner};

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

    fn flatpak_package() -> InstalledPackage {
        InstalledPackage {
            backend: Backend::Flatpak,
            id: "org.foo.App".to_string(),
            name: "Foo App".to_string(),
            version: "1.2.3".to_string(),
            size_bytes: None,
            aur: false,
        }
    }

    fn pacman_package() -> InstalledPackage {
        InstalledPackage {
            backend: Backend::Pacman,
            id: "foo".to_string(),
            name: "foo".to_string(),
            version: "1.0-1".to_string(),
            size_bytes: None,
            aur: false,
        }
    }

    #[test]
    fn test_run_bails_when_mode_is_not_human() {
        let f = fixture();
        let err = run(&f.ctx, false, Mode::Json).unwrap_err();
        assert!(err.to_string().contains("interactive terminal"));
    }

    #[test]
    fn test_remove_argv_for_pacman_is_sudo() {
        let (argv, sudo) = remove_argv_for(&pacman_package());
        assert!(sudo);
        assert_eq!(
            argv,
            vec![
                "pacman".to_string(),
                "-Rns".to_string(),
                "--noconfirm".to_string(),
                "foo".to_string(),
            ]
        );
    }

    #[test]
    fn test_remove_argv_for_flatpak_is_never_sudo() {
        let (_, sudo) = remove_argv_for(&flatpak_package());
        assert!(!sudo);
    }

    #[test]
    fn test_render_after_removal_runs_flatpak_uninstall_and_journals_it() {
        let f = fixture();
        let package = flatpak_package();
        let journal = Journal::new(&f.ctx.state_dir);
        let fake = FakeRunner::new().with(
            vec![
                "flatpak".to_string(),
                "uninstall".to_string(),
                "--delete-data".to_string(),
                "--noninteractive".to_string(),
                "org.foo.App".to_string(),
            ],
            CmdOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let mut effector = RealEffector::new(&f.ctx, Box::new(fake));

        let output = render_after_removal_and_leftovers(
            &f.ctx,
            &package,
            &[],
            &HashSet::new(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(output.rendered, "Removed Foo App via flatpak.");
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, "ok");
        assert!(!records[0].sudo);
    }

    #[test]
    fn test_removal_failure_bails_and_never_touches_leftovers() {
        let f = fixture();
        let package = flatpak_package();
        std::fs::create_dir_all(f.ctx.home.join(".config/Foo App")).unwrap();
        let journal = Journal::new(&f.ctx.state_dir);
        let fake = FakeRunner::new().with(
            vec![
                "flatpak".to_string(),
                "uninstall".to_string(),
                "--delete-data".to_string(),
                "--noninteractive".to_string(),
                "org.foo.App".to_string(),
            ],
            CmdOutput {
                success: false,
                stdout: String::new(),
                stderr: "error: not installed".to_string(),
            },
        );
        let mut effector = RealEffector::new(&f.ctx, Box::new(fake));

        let leftover_group =
            uninstall_leftovers::scan(&f.ctx, &package.name, &package.id, package.backend).unwrap();
        assert_eq!(
            leftover_group.candidates.len(),
            1,
            "sanity: a leftover exists"
        );
        let selection = HashSet::from([(0usize, 0usize)]);

        let err = render_after_removal_and_leftovers(
            &f.ctx,
            &package,
            &[leftover_group],
            &selection,
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap_err();

        assert!(err.to_string().contains("failed to remove"));
        assert!(
            f.ctx.home.join(".config/Foo App").exists(),
            "leftover must be untouched on removal failure"
        );
    }

    #[test]
    fn test_dry_run_journals_removal_and_leftovers_without_touching_disk() {
        let f = fixture();
        let package = flatpak_package();
        std::fs::create_dir_all(f.ctx.home.join(".config/Foo App")).unwrap();
        std::fs::write(
            f.ctx.home.join(".config/Foo App/settings.ini"),
            vec![0u8; 4096],
        )
        .unwrap();
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = DryRunEffector;

        let leftover_group =
            uninstall_leftovers::scan(&f.ctx, &package.name, &package.id, package.backend).unwrap();
        let selection = HashSet::from([(0usize, 0usize)]);

        let output = render_after_removal_and_leftovers(
            &f.ctx,
            &package,
            &[leftover_group],
            &selection,
            &mut effector,
            &journal,
            "run-1",
            true,
        )
        .unwrap();

        assert!(
            output
                .rendered
                .contains("Would remove Foo App via flatpak (dry run).")
        );
        assert!(
            output
                .rendered
                .contains("Would free 4.0 KiB from leftovers (dry run).")
        );
        assert!(f.ctx.home.join(".config/Foo App").exists());

        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.dry_run));
    }

    #[test]
    fn test_leftover_pipeline_deletes_only_the_selected_candidate() {
        let f = fixture();
        let package = flatpak_package();
        std::fs::create_dir_all(f.ctx.home.join(".config/Foo App")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cache/Foo App")).unwrap();
        let journal = Journal::new(&f.ctx.state_dir);
        let fake = FakeRunner::new().with(
            vec![
                "flatpak".to_string(),
                "uninstall".to_string(),
                "--delete-data".to_string(),
                "--noninteractive".to_string(),
                "org.foo.App".to_string(),
            ],
            CmdOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let mut effector = RealEffector::new(&f.ctx, Box::new(fake));

        let leftover_group =
            uninstall_leftovers::scan(&f.ctx, &package.name, &package.id, package.backend).unwrap();
        assert_eq!(leftover_group.candidates.len(), 2);
        // Only select whichever candidate sorts first (~/.cache/Foo App).
        let selection = HashSet::from([(0usize, 0usize)]);

        let output = render_after_removal_and_leftovers(
            &f.ctx,
            &package,
            &[leftover_group],
            &selection,
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert!(output.rendered.contains("Freed"));
        assert!(!f.ctx.home.join(".cache/Foo App").exists());
        assert!(
            f.ctx.home.join(".config/Foo App").exists(),
            "unselected leftover must survive"
        );
    }

    #[test]
    fn test_no_leftovers_omits_the_leftovers_line() {
        let f = fixture();
        let package = flatpak_package();
        let journal = Journal::new(&f.ctx.state_dir);
        let fake = FakeRunner::new().with(
            vec![
                "flatpak".to_string(),
                "uninstall".to_string(),
                "--delete-data".to_string(),
                "--noninteractive".to_string(),
                "org.foo.App".to_string(),
            ],
            CmdOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let mut effector = RealEffector::new(&f.ctx, Box::new(fake));

        let output = render_after_removal_and_leftovers(
            &f.ctx,
            &package,
            &[],
            &HashSet::new(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(output.rendered, "Removed Foo App via flatpak.");
    }

    #[test]
    fn test_execute_leftover_selection_ignores_a_candidate_not_in_the_selection() {
        let f = fixture();
        let dir = f.ctx.home.join(".config/foo");
        std::fs::create_dir_all(&dir).unwrap();
        let group = Group {
            rule_id: "uninstall.leftovers".to_string(),
            title: "Leftovers for foo".to_string(),
            risk: Risk::Moderate,
            requires_sudo: false,
            candidates: vec![Candidate::new(
                Some(dir.clone()),
                "~/.config/foo".to_string(),
                0,
                Risk::Moderate,
            )],
            skipped: Vec::new(),
        };
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute_leftover_selection(
            &[group],
            &HashSet::new(),
            &f.ctx,
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 0);
        assert!(dir.exists());
    }

    #[test]
    fn test_owned_files_are_captured_for_pacman_and_journaled() {
        let f = fixture();
        let mut ctx = f.ctx.clone();
        ctx.available_commands = Some(vec!["pacman".to_string()]);
        ctx.fake_command_output = Some(std::collections::HashMap::from([(
            vec!["pacman".to_string(), "-Qql".to_string(), "foo".to_string()],
            CmdOutput {
                success: true,
                stdout: "/usr/bin/foo\n".to_string(),
                stderr: String::new(),
            },
        )]));
        let package = pacman_package();
        let journal = Journal::new(&ctx.state_dir);
        let mut effector = RealEffector::new(&ctx, Box::new(FakeRunner::new()));

        // pacman removal is sudo, and ctx.sandboxed is true here, so the
        // real effector must skip running it — but the file list is still
        // captured and journaled beforehand.
        let output = render_after_removal_and_leftovers(
            &ctx,
            &package,
            &[],
            &HashSet::new(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert!(output.rendered.contains("note:"));
        assert!(output.rendered.contains("skipped"));
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records[0].paths, Some(vec!["/usr/bin/foo".to_string()]));
    }
}
