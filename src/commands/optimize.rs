//! `badger optimize`: same UX contract as `clean`/`purge` (plan by default,
//! `--dry-run` for a journaled preview, `--yes` runs pre-checked tasks
//! non-interactively, an interactive TTY gets the checklist+confirm TUI),
//! but over `rules::optimize::rules()` instead of the deletion registry.
//! Every task is `Action::Cmd` with a single, informational, zero-byte
//! candidate — there is nothing to report in bytes freed, so the summary
//! counts tasks run/skipped instead (see `summarize_run`).

use std::collections::HashSet;
use std::io::IsTerminal;

use crate::commands::shared::{JsonOutput, drive_selection};
use crate::core::exec::{DryRunEffector, RealEffector, execute, execute_selected};
use crate::core::item::{Group, Risk};
use crate::core::runner::runner_for;
use crate::core::scan::scan;
use crate::ctx::Ctx;
use crate::output::Mode;
use crate::rules::{self, Rule};
use crate::safety::journal::Journal;
use crate::safety::whitelist::Whitelist;
use crate::tui;

pub struct OptimizeOutput {
    pub rendered: String,
}

pub fn run(ctx: &Ctx, yes: bool, dry_run_flag: bool, mode: Mode) -> anyhow::Result<OptimizeOutput> {
    // Same gating as clean/purge: the checklist only shows up for a real,
    // interactive `badger optimize` with neither flag.
    if mode == Mode::Human && !yes && std::io::stderr().is_terminal() {
        return run_interactive(ctx, dry_run_flag);
    }

    let whitelist = Whitelist::load(&ctx.config_dir, &ctx.home)?;
    let rules = rules::optimize::rules();
    let groups = scan(&rules, ctx, &ctx.config, &whitelist)?;

    // --dry-run always wins over --yes: never risk a real run on a preview request.
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
            let mut effector = RealEffector::new(ctx, runner_for(ctx));
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
        Mode::Human => render_human(&groups, will_execute, is_dry_run, ran, skipped),
    };
    if will_execute && mode == Mode::Human {
        for note in notes {
            rendered.push_str(&format!("\n  {note}"));
        }
    }
    Ok(OptimizeOutput { rendered })
}

/// Interactive `badger optimize`: scan, show the checklist and risk-scaled
/// confirmation, then run exactly what was selected.
fn run_interactive(ctx: &Ctx, dry_run_flag: bool) -> anyhow::Result<OptimizeOutput> {
    let whitelist = Whitelist::load(&ctx.config_dir, &ctx.home)?;
    let rules = rules::optimize::rules();
    let groups = scan(&rules, ctx, &ctx.config, &whitelist)?;

    if !groups.iter().any(|g| !g.candidates.is_empty()) {
        return Ok(OptimizeOutput {
            rendered: "Nothing to optimize.".to_string(),
        });
    }

    let mut terminal = tui::init_terminal()?;
    let selection_result = drive_selection(&mut terminal, groups.clone());
    // Leave the alternate screen before anything else happens: a sudo
    // prompt (during execution below) and the final summary (printed by our
    // caller once we return) both need a normal, scrollable terminal.
    tui::restore_terminal(&mut terminal)?;

    let Some(selection) = selection_result? else {
        eprintln!("nothing run");
        return Ok(OptimizeOutput {
            rendered: String::new(),
        });
    };

    let journal = Journal::new(&ctx.state_dir);
    render_after_selection(&groups, &selection, &rules, ctx, &journal, dry_run_flag)
}

/// The terminal-free seam: given a scan's groups and an already-made
/// selection (as the checklist would produce), runs it and renders the
/// final summary. No terminal involved, so tests drive scan -> selection ->
/// execute directly.
fn render_after_selection(
    groups: &[Group],
    selection: &HashSet<(usize, usize)>,
    rules: &[Rule],
    ctx: &Ctx,
    journal: &Journal,
    dry_run: bool,
) -> anyhow::Result<OptimizeOutput> {
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
        let mut effector = RealEffector::new(ctx, runner_for(ctx));
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
        format!("Would run {ran} task(s) — dry run — nothing executed (recorded in history).")
    } else {
        format!("Ran {ran} task(s).")
    };
    if skipped > 0 {
        out.push_str(&format!(" {skipped} skipped."));
    }

    for note in notes {
        out.push_str(&format!("\n  {note}"));
    }

    Ok(OptimizeOutput { rendered: out })
}

/// Reads this run's journal records once and classifies all of them: how
/// many actually ran (or, in a dry run, would have), how many were skipped
/// (sudo in a sandbox), and "note: <rule> — <outcome>" lines for the
/// skipped/error/refused ones (same format as `commands::shared::
/// execution_notes`, inlined here so both counts and notes come from a
/// single journal read instead of two).
fn summarize_run(journal: &Journal, run_id: &str) -> anyhow::Result<(usize, usize, Vec<String>)> {
    let (records, _) = journal.read_all()?;
    let mut ran = 0;
    let mut skipped = 0;
    let mut notes = Vec::new();
    for record in records.iter().filter(|r| r.run_id == run_id) {
        if record.outcome.starts_with("skipped") {
            skipped += 1;
            notes.push(format!("note: {} — {}", record.rule, record.outcome));
        } else if record.outcome.starts_with("error") || record.outcome.starts_with("refused") {
            notes.push(format!("note: {} — {}", record.rule, record.outcome));
        } else {
            ran += 1;
        }
    }
    Ok((ran, skipped, notes))
}

fn render_human(
    groups: &[Group],
    will_execute: bool,
    is_dry_run: bool,
    ran: usize,
    skipped: usize,
) -> String {
    let mut out = render_plan(groups);
    if out == "Nothing to optimize." {
        return out;
    }
    if !will_execute {
        out.push_str(
            "\n\nRun with --dry-run for a journaled preview, or --yes to run pre-checked tasks.",
        );
        return out;
    }
    if is_dry_run {
        out.push_str(&format!(
            "\n\nWould run {ran} task(s) (dry run — nothing was executed; recorded in history)."
        ));
    } else {
        out.push_str(&format!("\n\nRan {ran} task(s)."));
    }
    if skipped > 0 {
        out.push_str(&format!(" {skipped} skipped."));
    }
    out
}

/// Renders the grouped plan: title, risk tag, and each task's one-line
/// description, flagging opt-in (Moderate) tasks as needing manual
/// selection. Unlike `clean`'s plan, there is no "would free" total —
/// every candidate here is informational (zero bytes).
fn render_plan(groups: &[Group]) -> String {
    let shown: Vec<&Group> = groups.iter().filter(|g| !g.candidates.is_empty()).collect();
    if shown.is_empty() {
        return "Nothing to optimize.".to_string();
    }

    let mut out = String::new();
    let mut precheck_count = 0;
    let mut optin_count = 0;
    for group in shown {
        let risk_tag = match group.risk {
            Risk::Safe => "safe",
            Risk::Moderate => "moderate",
            Risk::Risky => "risky",
        };
        let sudo_tag = if group.requires_sudo { ", sudo" } else { "" };
        out.push_str(&format!("{} [{risk_tag}{sudo_tag}]\n", group.title));
        for candidate in &group.candidates {
            out.push_str(&format!("  {}\n", candidate.label));
        }
        if group.risk == Risk::Safe {
            precheck_count += 1;
        } else {
            optin_count += 1;
            out.push_str("  (opt-in — not run automatically)\n");
        }
    }

    out.push_str(&format!(
        "\n{precheck_count} pre-checked task(s) will run with --yes; {optin_count} opt-in task(s) need manual selection."
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::item::Candidate;

    fn group(title: &str, rule_id: &str, risk: Risk, requires_sudo: bool, label: &str) -> Group {
        Group {
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            risk,
            requires_sudo,
            candidates: vec![Candidate::new(None, label.to_string(), 0, risk)],
            skipped: Vec::new(),
        }
    }

    #[test]
    fn test_render_plan_empty_groups_says_nothing_to_optimize() {
        assert_eq!(render_plan(&[]), "Nothing to optimize.");
    }

    #[test]
    fn test_render_plan_shows_prechecked_task_without_opt_in_note() {
        let g = group(
            "Trim SSD free space",
            "optimize.fstrim",
            Risk::Safe,
            true,
            "Trim free space on all mounted filesystems (fstrim -av)",
        );
        let out = render_plan(&[g]);
        assert!(out.contains("Trim SSD free space [safe, sudo]"));
        assert!(out.contains("fstrim -av"));
        assert!(!out.contains("not run automatically"));
        assert!(out.contains("1 pre-checked task(s) will run with --yes; 0 opt-in"));
    }

    #[test]
    fn test_render_plan_flags_moderate_task_as_opt_in() {
        let g = group(
            "Refresh pacman file database",
            "optimize.pacman_files",
            Risk::Moderate,
            true,
            "pacman -Fy",
        );
        let out = render_plan(&[g]);
        assert!(out.contains("[moderate, sudo]"));
        assert!(out.contains("opt-in — not run automatically"));
        assert!(out.contains("0 pre-checked task(s) will run with --yes; 1 opt-in"));
    }

    #[test]
    fn test_render_human_without_execution_points_at_dry_run_and_yes() {
        let g = group(
            "Trim SSD free space",
            "optimize.fstrim",
            Risk::Safe,
            true,
            "fstrim -av",
        );
        let out = render_human(&[g], false, true, 0, 0);
        assert!(out.contains("--dry-run"));
        assert!(out.contains("--yes"));
    }

    #[test]
    fn test_render_human_dry_run_reports_would_run_count() {
        let g = group(
            "Trim SSD free space",
            "optimize.fstrim",
            Risk::Safe,
            true,
            "fstrim -av",
        );
        let out = render_human(&[g], true, true, 2, 1);
        assert!(out.contains("Would run 2 task(s)"));
        assert!(out.contains("dry run"));
        assert!(out.contains("1 skipped"));
    }

    #[test]
    fn test_render_human_yes_reports_ran_count_and_omits_skipped_when_zero() {
        let g = group(
            "Trim SSD free space",
            "optimize.fstrim",
            Risk::Safe,
            true,
            "fstrim -av",
        );
        let out = render_human(&[g], true, false, 3, 0);
        assert!(out.contains("Ran 3 task(s)."));
        assert!(!out.contains("skipped"));
    }
}
