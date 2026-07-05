//! `badger purge`: same UX contract as `badger clean` (plan by default,
//! `--dry-run` for a journaled preview, `--yes` to act non-interactively, an
//! interactive TTY gets the checklist+confirm TUI), but scanning
//! context-gated project build artifacts (`purge::scan`) instead of the
//! static rule registry. All purge candidates are plain, non-sudo path
//! deletes, so execution here drives `core::exec`'s `Effector` directly
//! rather than going through `Action`/`Rule` dispatch.

use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::PathBuf;

use serde::Serialize;

use crate::commands::shared::{drive_selection, execution_notes};
use crate::core::exec::{DryRunEffector, Effector, RealEffector, Summary};
use crate::core::item::Group;
use crate::core::runner::RealRunner;
use crate::ctx::Ctx;
use crate::output::{Mode, humanize_bytes};
use crate::purge;
use crate::rules::expand_path_spec;
use crate::safety::journal::{Journal, Record};
use crate::safety::whitelist::Whitelist;
use crate::tui;

pub struct PurgeOutput {
    pub rendered: String,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    groups: &'a [Group],
    summary: Option<&'a Summary>,
    dry_run: bool,
}

pub fn run(ctx: &Ctx, yes: bool, dry_run_flag: bool, mode: Mode) -> anyhow::Result<PurgeOutput> {
    // Same contract as `clean`: the checklist only shows up for a real,
    // interactive `badger purge` with neither `--json` nor `--yes`.
    if mode == Mode::Human && !yes && std::io::stderr().is_terminal() {
        return run_interactive(ctx, dry_run_flag);
    }

    let whitelist = Whitelist::load(&ctx.config_dir, &ctx.home)?;
    let groups = purge::scan(ctx, &ctx.config, &whitelist)?;

    // --dry-run always wins over --yes: never risk a real delete on a preview request.
    let will_execute = yes || dry_run_flag;
    let is_dry_run = dry_run_flag || !yes;

    let journal = Journal::new(&ctx.state_dir);
    let run_id = jiff::Timestamp::now().to_string();

    let summary = if will_execute {
        // The non-interactive default acts on exactly the pre-checked
        // (non-recent) candidates — the same set the checklist would start
        // with selected.
        let selection = default_selection(&groups);
        Some(if is_dry_run {
            let mut effector = DryRunEffector;
            execute_selection(
                &groups,
                &selection,
                ctx,
                &mut effector,
                &journal,
                &run_id,
                true,
            )?
        } else {
            let mut effector = RealEffector::new(ctx, Box::new(RealRunner));
            execute_selection(
                &groups,
                &selection,
                ctx,
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

    let mut rendered = match mode {
        Mode::Json => serde_json::to_string(&JsonOutput {
            groups: &groups,
            summary: summary.as_ref(),
            dry_run: is_dry_run,
        })?,
        Mode::Human => render_human(&groups, summary.as_ref(), will_execute, is_dry_run),
    };
    if will_execute && mode == Mode::Human {
        for note in execution_notes(&journal, &run_id)? {
            rendered.push_str(&format!("\n  {note}"));
        }
    }
    Ok(PurgeOutput { rendered })
}

/// Interactive `badger purge`: scan, show the checklist and confirmation,
/// then delete exactly what was selected.
fn run_interactive(ctx: &Ctx, dry_run_flag: bool) -> anyhow::Result<PurgeOutput> {
    let whitelist = Whitelist::load(&ctx.config_dir, &ctx.home)?;
    let groups = purge::scan(ctx, &ctx.config, &whitelist)?;

    if !groups
        .iter()
        .any(|g| !g.candidates.is_empty() || !g.skipped.is_empty())
    {
        return Ok(PurgeOutput {
            rendered: "Nothing to purge.".to_string(),
        });
    }

    let mut terminal = tui::init_terminal()?;
    let selection_result = drive_selection(&mut terminal, groups.clone());
    // Leave the alternate screen before anything else happens: the final
    // summary (printed by our caller once we return) needs a normal,
    // scrollable terminal.
    tui::restore_terminal(&mut terminal)?;

    let Some(selection) = selection_result? else {
        eprintln!("nothing purged");
        return Ok(PurgeOutput {
            rendered: String::new(),
        });
    };

    let journal = Journal::new(&ctx.state_dir);
    render_after_selection(&groups, &selection, ctx, &journal, dry_run_flag)
}

/// The terminal-free seam: given a scan's groups and an already-made
/// selection (as the checklist would produce), executes it and renders the
/// final summary.
fn render_after_selection(
    groups: &[Group],
    selection: &HashSet<(usize, usize)>,
    ctx: &Ctx,
    journal: &Journal,
    dry_run: bool,
) -> anyhow::Result<PurgeOutput> {
    let run_id = jiff::Timestamp::now().to_string();
    let summary = if dry_run {
        let mut effector = DryRunEffector;
        execute_selection(
            groups,
            selection,
            ctx,
            &mut effector,
            journal,
            &run_id,
            true,
        )?
    } else {
        let mut effector = RealEffector::new(ctx, Box::new(RealRunner));
        execute_selection(
            groups,
            selection,
            ctx,
            &mut effector,
            journal,
            &run_id,
            false,
        )?
    };

    for warning in &summary.journal_warnings {
        eprintln!("warning: {warning}");
    }

    let mut out = if dry_run {
        format!(
            "Would free {} — dry run — nothing deleted (recorded in history).",
            humanize_bytes(summary.bytes_freed)
        )
    } else {
        format!("Freed {}.", humanize_bytes(summary.bytes_freed))
    };

    for note in execution_notes(journal, &run_id)? {
        out.push_str(&format!("\n  {note}"));
    }

    Ok(PurgeOutput { rendered: out })
}

/// Every candidate the non-interactive default (`--yes`/`--dry-run`) acts on:
/// exactly the pre-checked ones (`selectable`), i.e. every non-recent
/// artifact. Recent ones need an explicit opt-in via the interactive
/// checklist, same as a Moderate clean candidate would.
fn default_selection(groups: &[Group]) -> HashSet<(usize, usize)> {
    groups
        .iter()
        .enumerate()
        .flat_map(|(gi, group)| {
            group
                .candidates
                .iter()
                .enumerate()
                .filter(|(_, c)| c.selectable)
                .map(move |(ci, _)| (gi, ci))
        })
        .collect()
}

/// Deletes exactly the candidates named in `selection`. All purge artifacts
/// are plain, non-sudo directory deletes validated against the configured
/// purge roots, so this drives `Effector::delete` directly rather than going
/// through the rule registry's `Action` dispatch.
fn execute_selection(
    groups: &[Group],
    selection: &HashSet<(usize, usize)>,
    ctx: &Ctx,
    effector: &mut dyn Effector,
    journal: &Journal,
    run_id: &str,
    dry_run: bool,
) -> anyhow::Result<Summary> {
    let allowed: Vec<PathBuf> = ctx
        .config
        .purge
        .roots
        .iter()
        .map(|r| expand_path_spec(r, ctx))
        .collect();

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
                "purge".to_string(),
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

fn render_human(
    groups: &[Group],
    summary: Option<&Summary>,
    will_execute: bool,
    is_dry_run: bool,
) -> String {
    let mut out = render_plan(groups);
    if out == "Nothing to purge." {
        return out;
    }
    match summary {
        Some(summary) if is_dry_run => out.push_str(&format!(
            "\n\nWould free {} (dry run — nothing was deleted; recorded in history).",
            humanize_bytes(summary.bytes_freed)
        )),
        Some(summary) => out.push_str(&format!(
            "\n\nFreed {}.",
            humanize_bytes(summary.bytes_freed)
        )),
        None if !will_execute => {
            out.push_str("\n\nRun with --dry-run for a journaled preview, or --yes to purge.")
        }
        None => {}
    }
    out
}

/// Renders the grouped plan: title, per-candidate size, skip reasons, and a
/// "would free" total across the pre-checked (non-recent) candidates — the
/// exact set `--yes` would act on.
fn render_plan(groups: &[Group]) -> String {
    let shown: Vec<&Group> = groups
        .iter()
        .filter(|g| !g.candidates.is_empty() || !g.skipped.is_empty())
        .collect();
    if shown.is_empty() {
        return "Nothing to purge.".to_string();
    }

    let mut out = String::new();
    let mut total = 0u64;
    for group in shown {
        out.push_str(&format!("{}\n", group.title));
        for candidate in &group.candidates {
            out.push_str(&format!(
                "  {}  {}\n",
                candidate.label,
                humanize_bytes(candidate.bytes)
            ));
            if candidate.selectable {
                total += candidate.bytes;
            }
        }
        for (label, reason) in &group.skipped {
            out.push_str(&format!("  {label}  skipped: {reason}\n"));
        }
    }

    out.push_str(&format!("\nWould free: {}", humanize_bytes(total)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

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

    fn project_with_node_modules(ctx: &Ctx, name: &str) -> std::path::PathBuf {
        let project = ctx.home.join("dev").join(name);
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("package.json"), b"{}").unwrap();
        let node_modules = project.join("node_modules");
        std::fs::create_dir_all(&node_modules).unwrap();
        std::fs::write(node_modules.join("a.js"), vec![0u8; 4096]).unwrap();
        // Backdate the project dir so it doesn't get the "(recent)" badge —
        // directories only need read access on Linux for `set_times`.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86_400);
        std::fs::File::open(&project)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        node_modules
    }

    fn empty_whitelist() -> Whitelist {
        crate::safety::whitelist::parse("", std::path::Path::new("/home/user")).unwrap()
    }

    #[test]
    fn test_default_plan_shows_candidate_and_does_not_touch_journal_or_filesystem() {
        let f = fixture();
        let dir = project_with_node_modules(&f.ctx, "site");

        let output = run(&f.ctx, false, false, Mode::Human).unwrap();

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
        let dir = project_with_node_modules(&f.ctx, "site");

        let output = run(&f.ctx, false, true, Mode::Human).unwrap();

        assert!(output.rendered.contains("Would free 4.0 KiB"));
        assert!(dir.exists(), "dry run must not delete anything");

        let journal = crate::safety::journal::Journal::new(&f.ctx.state_dir);
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].dry_run);
        assert_eq!(records[0].cmd, "purge");
    }

    #[test]
    fn test_yes_deletes_pre_checked_candidate_and_journals_real_run() {
        let f = fixture();
        let dir = project_with_node_modules(&f.ctx, "site");

        let output = run(&f.ctx, true, false, Mode::Human).unwrap();

        assert!(output.rendered.contains("Freed 4.0 KiB"));
        assert!(!dir.exists(), "--yes must delete the pre-checked candidate");
    }

    #[test]
    // Bug: purge's --yes path never consulted the user's
    // ~/.config/badger/whitelist, so a path explicitly marked "never touch
    // this" was deleted anyway. Root cause: purge::scan built candidates
    // directly, skipping the whitelist check core/scan.rs's
    // finish_deletable_candidates applies for `badger clean`.
    fn test_whitelisted_artifact_is_never_deleted_by_yes() {
        let f = fixture();
        let dir = project_with_node_modules(&f.ctx, "site");
        std::fs::create_dir_all(&f.ctx.config_dir).unwrap();
        std::fs::write(
            f.ctx.config_dir.join("whitelist"),
            "~/dev/site/node_modules\n",
        )
        .unwrap();

        let output = run(&f.ctx, true, false, Mode::Human).unwrap();

        assert!(output.rendered.contains("Freed 0 B"));
        assert!(dir.exists(), "whitelisted artifact must survive --yes");
    }

    #[test]
    fn test_recent_project_is_never_deleted_by_yes() {
        let f = fixture();
        let project = f.ctx.home.join("dev/freshsite");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("package.json"), b"{}").unwrap();
        let node_modules = project.join("node_modules");
        std::fs::create_dir_all(&node_modules).unwrap();
        // No backdating: this project is fresh, so its node_modules must stay
        // unchecked and untouched by --yes.

        let output = run(&f.ctx, true, false, Mode::Human).unwrap();

        assert!(output.rendered.contains("Freed 0 B"));
        assert!(node_modules.exists());
    }

    #[test]
    fn test_json_mode_emits_parseable_groups_and_summary() {
        let f = fixture();
        project_with_node_modules(&f.ctx, "site");

        let output = run(&f.ctx, true, false, Mode::Json).unwrap();

        let value: serde_json::Value = serde_json::from_str(&output.rendered).unwrap();
        assert!(value["groups"].is_array());
        assert!(value["summary"]["bytes_freed"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_nothing_to_purge_on_an_empty_home() {
        let f = fixture();
        let output = run(&f.ctx, false, false, Mode::Human).unwrap();
        assert_eq!(output.rendered, "Nothing to purge.");
    }

    #[test]
    fn test_render_after_selection_executes_only_the_selected_candidate() {
        let f = fixture();
        let dir = project_with_node_modules(&f.ctx, "site");
        let groups = purge::scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let journal = Journal::new(&f.ctx.state_dir);
        let selection = HashSet::from([(0usize, 0usize)]);

        let output = render_after_selection(&groups, &selection, &f.ctx, &journal, false).unwrap();

        assert_eq!(output.rendered, "Freed 4.0 KiB.");
        assert!(!dir.exists());
    }
}
