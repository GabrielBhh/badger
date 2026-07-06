use std::collections::HashSet;
use std::io::IsTerminal;

use crate::commands::shared::{JsonOutput, count_label, drive_selection, summarize_run};
use crate::core::exec::{DryRunEffector, RealEffector, Summary, execute, execute_selected};
use crate::core::item::{Group, Risk};
use crate::core::runner::RealRunner;
use crate::core::scan::scan;
use crate::ctx::Ctx;
use crate::output::{Mode, humanize_bytes};
use crate::rules::{self, Action, Rule};
use crate::safety::journal::Journal;
use crate::safety::whitelist::Whitelist;
use crate::tui;

pub struct CleanOutput {
    pub rendered: String,
}

pub fn run(
    ctx: &Ctx,
    yes: bool,
    dry_run_flag: bool,
    mode: Mode,
    experimental: bool,
) -> anyhow::Result<CleanOutput> {
    // Non-tty/--json/--yes behavior (below) is unchanged; the checklist only
    // shows up for a real, interactive `badger clean` with neither flag.
    if mode == Mode::Human && !yes && std::io::stderr().is_terminal() {
        return run_interactive(ctx, dry_run_flag, experimental);
    }

    let whitelist = Whitelist::load(&ctx.config_dir, &ctx.home)?;
    let rules = rules::registry(experimental);
    let groups = scan(&rules, ctx, &ctx.config, &whitelist)?;

    // --dry-run always wins over --yes: never risk a real delete on a preview request.
    let will_execute = yes || dry_run_flag;
    let is_dry_run = dry_run_flag || !yes;

    let journal = Journal::new(&ctx.state_dir);
    let run_id = jiff::Timestamp::now().to_string();

    let summary = if will_execute {
        Some(if is_dry_run {
            let mut effector = DryRunEffector;
            execute(
                &groups,
                &rules,
                ctx,
                &ctx.config,
                &mut effector,
                &journal,
                &run_id,
                true,
            )?
        } else {
            let mut effector = RealEffector::new(ctx, Box::new(RealRunner));
            execute(
                &groups,
                &rules,
                ctx,
                &ctx.config,
                &mut effector,
                &journal,
                &run_id,
                false,
            )?
        })
    } else {
        None
    };

    for warning in summary.iter().flat_map(|s| &s.journal_warnings) {
        eprintln!("warning: {warning}");
    }

    // Non-interactive `--yes` never re-read the journal for execution-time
    // outcomes: a TOCTOU refusal or delete error just silently shrank the
    // "Freed" total. Surface them the same way the interactive path does.
    let (ran, skipped, notes) = if will_execute {
        summarize_run(&journal, &run_id)?
    } else {
        (0, 0, Vec::new())
    };

    let mut rendered = match mode {
        Mode::Json => serde_json::to_string(&JsonOutput {
            groups: &groups,
            summary: summary.as_ref(),
            dry_run: is_dry_run,
        })?,
        Mode::Human => render_human(
            &groups,
            &rules,
            summary.as_ref(),
            will_execute,
            is_dry_run,
            ran,
            skipped,
        ),
    };
    if will_execute && mode == Mode::Human {
        for note in notes {
            rendered.push_str(&format!("\n  {note}"));
        }
    }
    Ok(CleanOutput { rendered })
}

/// Interactive `badger clean`: scan, show the checklist and risk-scaled
/// confirmation, then execute exactly what was selected.
fn run_interactive(
    ctx: &Ctx,
    dry_run_flag: bool,
    experimental: bool,
) -> anyhow::Result<CleanOutput> {
    let whitelist = Whitelist::load(&ctx.config_dir, &ctx.home)?;
    let rules = rules::registry(experimental);
    let groups = scan(&rules, ctx, &ctx.config, &whitelist)?;

    if !groups
        .iter()
        .any(|g| !g.candidates.is_empty() || !g.skipped.is_empty())
    {
        return Ok(CleanOutput {
            rendered: "Nothing to clean.".to_string(),
        });
    }

    let mut terminal = tui::init_terminal()?;
    let selection_result = drive_selection(
        &mut terminal,
        groups.clone(),
        tui::confirm::Verb::Delete,
        dry_run_flag,
    );
    // Leave the alternate screen before anything else happens: a sudo
    // prompt (during execution below) and the final summary (printed by our
    // caller once we return) both need a normal, scrollable terminal.
    tui::restore_terminal(&mut terminal)?;

    let Some(selection) = selection_result? else {
        eprintln!("nothing cleaned");
        return Ok(CleanOutput {
            rendered: String::new(),
        });
    };

    let journal = Journal::new(&ctx.state_dir);
    render_after_selection(&groups, &selection, &rules, ctx, &journal, dry_run_flag)
}

/// The terminal-free seam: given a scan's groups and an already-made
/// selection (as the checklist would produce), executes it and renders the
/// final summary. No terminal involved, so tests drive scan -> selection ->
/// execute directly.
fn render_after_selection(
    groups: &[Group],
    selection: &HashSet<(usize, usize)>,
    rules: &[Rule],
    ctx: &Ctx,
    journal: &Journal,
    dry_run: bool,
) -> anyhow::Result<CleanOutput> {
    let run_id = jiff::Timestamp::now().to_string();
    let summary = if dry_run {
        let mut effector = DryRunEffector;
        execute_selected(
            groups,
            selection,
            rules,
            ctx,
            &ctx.config,
            &mut effector,
            journal,
            &run_id,
            true,
        )?
    } else {
        let mut effector = RealEffector::new(ctx, Box::new(RealRunner));
        execute_selected(
            groups,
            selection,
            rules,
            ctx,
            &ctx.config,
            &mut effector,
            journal,
            &run_id,
            false,
        )?
    };

    for warning in &summary.journal_warnings {
        eprintln!("warning: {warning}");
    }

    let (ran, skipped, notes) = summarize_run(journal, &run_id)?;
    let mut out = if dry_run {
        format!(
            "Would free {} · {} · dry run — nothing deleted (recorded in history)",
            humanize_bytes(summary.bytes_freed),
            count_label(ran, "item")
        )
    } else {
        let mut line = format!(
            "Freed {} · {}",
            humanize_bytes(summary.bytes_freed),
            count_label(ran, "item")
        );
        if skipped > 0 {
            line.push_str(&format!(" · {skipped} skipped"));
        }
        line
    };

    for note in notes {
        out.push_str(&format!("\n  {note}"));
    }

    Ok(CleanOutput { rendered: out })
}

fn render_human(
    groups: &[Group],
    rules: &[Rule],
    summary: Option<&Summary>,
    will_execute: bool,
    is_dry_run: bool,
    ran: usize,
    skipped: usize,
) -> String {
    let mut out = render_plan(groups, rules);
    if out == "Nothing to clean." {
        return out;
    }
    match summary {
        Some(summary) if is_dry_run => out.push_str(&format!(
            "\n\nWould free {} · {} · dry run — nothing deleted (recorded in history)",
            humanize_bytes(summary.bytes_freed),
            count_label(ran, "item")
        )),
        Some(summary) => {
            out.push_str(&format!(
                "\n\nFreed {} · {}",
                humanize_bytes(summary.bytes_freed),
                count_label(ran, "item")
            ));
            if skipped > 0 {
                out.push_str(&format!(" · {skipped} skipped"));
            }
        }
        None if !will_execute => {
            out.push_str("\n\nRun with --dry-run for a journaled preview, or --yes to clean.")
        }
        None => {}
    }
    out
}

/// Renders the grouped plan: title, risk tag, per-candidate size, skip
/// reasons, and a "would free" total across Safe, directly-deletable,
/// non-sudo, selected candidates — the exact set `--yes` would act on.
fn render_plan(groups: &[Group], rules: &[Rule]) -> String {
    let shown: Vec<&Group> = groups
        .iter()
        .filter(|g| !g.candidates.is_empty() || !g.skipped.is_empty())
        .collect();
    if shown.is_empty() {
        return "Nothing to clean.".to_string();
    }

    let mut out = String::new();
    let mut total = 0u64;
    for group in shown {
        let risk_tag = match group.risk {
            Risk::Safe => "safe",
            Risk::Moderate => "moderate",
            Risk::Risky => "risky",
        };
        let sudo_tag = if group.requires_sudo { ", sudo" } else { "" };
        out.push_str(&format!("{} [{risk_tag}{sudo_tag}]\n", group.title));

        let is_delete_paths = rules
            .iter()
            .find(|r| r.id == group.rule_id)
            .is_some_and(|r| matches!(r.action, Action::DeletePaths));
        let contributes_to_total =
            group.risk == Risk::Safe && is_delete_paths && !group.requires_sudo;

        for candidate in &group.candidates {
            let tag = if candidate.whitelisted {
                " (whitelisted)"
            } else {
                ""
            };
            out.push_str(&format!(
                "  {}  {}{tag}\n",
                candidate.label,
                humanize_bytes(candidate.bytes)
            ));
            if contributes_to_total && candidate.selectable {
                total += candidate.bytes;
            }
        }
        for (label, reason) in &group.skipped {
            out.push_str(&format!("  {label}  skipped: {reason}\n"));
        }

        if group.risk != Risk::Safe {
            out.push_str("  (needs manual opt-in — not cleaned automatically)\n");
        } else if group.requires_sudo && is_delete_paths {
            out.push_str("  (needs root file deletion — not automated in this phase)\n");
        }
    }

    out.push_str(&format!("\nWould free: {}", humanize_bytes(total)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::item::Candidate;
    use crate::rules::{Applicability, CmdSpec, Detector};
    use std::path::PathBuf;

    fn safe_delete_rule(id: &'static str, requires_sudo: bool) -> Rule {
        Rule {
            id,
            title: "title placeholder",
            risk: Risk::Safe,
            requires_sudo,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        }
    }

    fn cmd_rule(id: &'static str) -> Rule {
        fn specs(_ctx: &Ctx, _config: &crate::config::Config) -> Vec<CmdSpec> {
            Vec::new()
        }
        Rule {
            id,
            title: "cmd rule",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::Cmd(specs),
            notes: "",
        }
    }

    #[test]
    fn test_render_plan_empty_groups_says_nothing_to_clean() {
        assert_eq!(render_plan(&[], &[]), "Nothing to clean.");
    }

    #[test]
    fn test_render_plan_shows_title_risk_and_size() {
        let group = Group {
            rule_id: "user.thumbnails".to_string(),
            title: "Thumbnail cache".to_string(),
            risk: Risk::Safe,
            requires_sudo: false,
            candidates: vec![Candidate::new(
                Some(PathBuf::from("/x")),
                "~/.cache/thumbnails".to_string(),
                2048,
                Risk::Safe,
            )],
            skipped: Vec::new(),
        };
        let rules = vec![safe_delete_rule("user.thumbnails", false)];
        let out = render_plan(&[group], &rules);
        assert!(out.contains("Thumbnail cache [safe]"));
        assert!(out.contains("~/.cache/thumbnails"));
        assert!(out.contains("2.0 KiB"));
        assert!(out.contains("Would free: 2.0 KiB"));
    }

    #[test]
    fn test_render_plan_shows_skip_reason() {
        let group = Group {
            rule_id: "user.thumbnails".to_string(),
            title: "Thumbnail cache".to_string(),
            risk: Risk::Safe,
            requires_sudo: false,
            candidates: Vec::new(),
            skipped: vec![("~/.ssh".to_string(), "protected path".to_string())],
        };
        let out = render_plan(&[group], &[safe_delete_rule("user.thumbnails", false)]);
        assert!(out.contains("~/.ssh"));
        assert!(out.contains("skipped: protected path"));
        assert!(out.contains("Would free: 0 B"));
    }

    #[test]
    fn test_render_plan_marks_whitelisted_candidate_and_excludes_from_total() {
        let mut candidate = Candidate::new(
            Some(PathBuf::from("/x")),
            "~/.cache/foo".to_string(),
            999,
            Risk::Safe,
        );
        candidate.whitelisted = true;
        candidate.selectable = false;
        let group = Group {
            rule_id: "user.cache_apps".to_string(),
            title: "Application caches".to_string(),
            risk: Risk::Safe,
            requires_sudo: false,
            candidates: vec![candidate],
            skipped: Vec::new(),
        };
        let out = render_plan(&[group], &[safe_delete_rule("user.cache_apps", false)]);
        assert!(out.contains("(whitelisted)"));
        assert!(out.contains("Would free: 0 B"));
    }

    #[test]
    fn test_render_plan_moderate_group_is_flagged_and_excluded_from_total() {
        let mut candidate = Candidate::new(
            Some(PathBuf::from("/x")),
            "/var/log/journal".to_string(),
            5000,
            Risk::Moderate,
        );
        candidate.selectable = true;
        let group = Group {
            rule_id: "system.journald".to_string(),
            title: "systemd journal".to_string(),
            risk: Risk::Moderate,
            requires_sudo: true,
            candidates: vec![candidate],
            skipped: Vec::new(),
        };
        let out = render_plan(&[group], &[cmd_rule("system.journald")]);
        assert!(out.contains("needs manual opt-in"));
        assert!(out.contains("Would free: 0 B"));
    }

    #[test]
    fn test_render_plan_sudo_delete_paths_group_is_flagged_and_excluded_from_total() {
        let mut candidate = Candidate::new(
            Some(PathBuf::from("/x")),
            "/var/cache/pacman/pkg/a.part".to_string(),
            123,
            Risk::Safe,
        );
        candidate.selectable = true;
        let group = Group {
            rule_id: "pacman.sync_partial".to_string(),
            title: "Partial pacman downloads".to_string(),
            risk: Risk::Safe,
            requires_sudo: true,
            candidates: vec![candidate],
            skipped: Vec::new(),
        };
        let out = render_plan(&[group], &[safe_delete_rule("pacman.sync_partial", true)]);
        assert!(out.contains("needs root file deletion"));
        assert!(out.contains("Would free: 0 B"));
    }

    // --- render_after_selection: the terminal-free seam behind the TUI ---

    struct ExecFixture {
        _sandbox: tempfile::TempDir,
        ctx: Ctx,
    }

    fn exec_fixture() -> ExecFixture {
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
            config: crate::config::Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output: None,
        };
        ExecFixture {
            _sandbox: sandbox,
            ctx,
        }
    }

    fn delete_rule_with_prefix(
        id: &'static str,
        requires_sudo: bool,
        allowed_prefixes: &'static [&'static str],
    ) -> Rule {
        Rule {
            id,
            title: "test rule",
            risk: Risk::Safe,
            requires_sudo,
            applicable: Applicability::Always,
            allowed_prefixes,
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        }
    }

    fn group_with_one_candidate(rule_id: &str, path: PathBuf, bytes: u64, risk: Risk) -> Group {
        Group {
            rule_id: rule_id.to_string(),
            title: "test group".to_string(),
            risk,
            requires_sudo: false,
            candidates: vec![Candidate::new(
                Some(path),
                "test candidate".to_string(),
                bytes,
                risk,
            )],
            skipped: Vec::new(),
        }
    }

    #[test]
    fn test_render_after_selection_executes_only_the_selected_candidate() {
        let f = exec_fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 4096]).unwrap();

        let rule = delete_rule_with_prefix("test.rule", false, &["~/.cache/target"]);
        let group = group_with_one_candidate("test.rule", target.clone(), 4096, Risk::Safe);
        let journal = Journal::new(&f.ctx.state_dir);
        let selection = HashSet::from([(0usize, 0usize)]);

        let output =
            render_after_selection(&[group], &selection, &[rule], &f.ctx, &journal, false).unwrap();

        assert_eq!(output.rendered, "Freed 4.0 KiB · 1 item");
        assert!(!target.exists());
    }

    #[test]
    fn test_render_after_selection_executes_a_selected_moderate_candidate() {
        let f = exec_fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 4096]).unwrap();

        let rule = delete_rule_with_prefix("test.moderate", false, &["~/.cache/target"]);
        let group = group_with_one_candidate("test.moderate", target.clone(), 4096, Risk::Moderate);
        let journal = Journal::new(&f.ctx.state_dir);
        let selection = HashSet::from([(0usize, 0usize)]);

        let output =
            render_after_selection(&[group], &selection, &[rule], &f.ctx, &journal, false).unwrap();

        assert_eq!(output.rendered, "Freed 4.0 KiB · 1 item");
        assert!(
            !target.exists(),
            "a selected Moderate candidate must actually execute via the TUI path"
        );
    }

    #[test]
    fn test_render_after_selection_dry_run_leaves_filesystem_untouched() {
        let f = exec_fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 2048]).unwrap();

        let rule = delete_rule_with_prefix("test.rule", false, &["~/.cache/target"]);
        let group = group_with_one_candidate("test.rule", target.clone(), 2048, Risk::Safe);
        let journal = Journal::new(&f.ctx.state_dir);
        let selection = HashSet::from([(0usize, 0usize)]);

        let output =
            render_after_selection(&[group], &selection, &[rule], &f.ctx, &journal, true).unwrap();

        assert!(output.rendered.contains("dry run — nothing deleted"));
        assert!(target.exists(), "dry run must not delete anything");
    }

    #[test]
    fn test_render_after_selection_surfaces_a_sandboxed_sudo_skip_as_a_note() {
        let f = exec_fixture();
        let target = f.ctx.root.join("var/cache/target");
        std::fs::create_dir_all(&target).unwrap();

        let rule = delete_rule_with_prefix("test.sudo_rule", true, &["/var/cache/target"]);
        let mut group = group_with_one_candidate("test.sudo_rule", target.clone(), 512, Risk::Safe);
        group.requires_sudo = true;
        let journal = Journal::new(&f.ctx.state_dir);
        let selection = HashSet::from([(0usize, 0usize)]);

        let output =
            render_after_selection(&[group], &selection, &[rule], &f.ctx, &journal, false).unwrap();

        assert!(output.rendered.contains("Freed 0 B · 0 items · 1 skipped"));
        assert!(output.rendered.contains("note:"));
        assert!(target.exists());
    }

    // Regression: the non-interactive `--yes` human path never re-read the
    // journal for execution-time outcomes (only the interactive TUI path
    // did via render_after_selection), so an execution-time refusal/skip just
    // silently shrank the "Freed" total instead of being surfaced as a note.
    #[test]
    fn test_run_yes_human_surfaces_an_execution_time_sudo_skip_as_a_note() {
        let f = exec_fixture();
        let mut ctx = f.ctx.clone();
        // `pacman.cache` only shows up once its command is "available"; its
        // Cmd action is sudo, and RealEffector::run() refuses to run sudo in
        // a sandbox — that refusal only happens at execution time, never at
        // scan time, so it's exactly the kind of note this fix must surface.
        ctx.available_commands = Some(vec!["paccache".to_string()]);

        let output = run(&ctx, true, false, Mode::Human, false).unwrap();

        assert!(
            output.rendered.contains("note:"),
            "execution-time sudo skip must be surfaced, got: {}",
            output.rendered
        );
        assert!(output.rendered.contains("skipped"));
    }
}
