use serde::Serialize;

use crate::core::exec::{DryRunEffector, RealEffector, Summary, execute};
use crate::core::item::{Group, Risk};
use crate::core::runner::RealRunner;
use crate::core::scan::scan;
use crate::ctx::Ctx;
use crate::output::{Mode, humanize_bytes};
use crate::rules::{self, Action, Rule};
use crate::safety::journal::Journal;
use crate::safety::whitelist::Whitelist;

pub struct CleanOutput {
    pub rendered: String,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    groups: &'a [Group],
    summary: Option<&'a Summary>,
    dry_run: bool,
}

pub fn run(ctx: &Ctx, yes: bool, dry_run_flag: bool, mode: Mode) -> anyhow::Result<CleanOutput> {
    let whitelist = Whitelist::load(&ctx.config_dir, &ctx.home)?;
    let rules = rules::registry();
    let groups = scan(&rules, ctx, &ctx.config, &whitelist)?;

    // --dry-run always wins over --yes: never risk a real delete on a preview request.
    let will_execute = yes || dry_run_flag;
    let is_dry_run = dry_run_flag || !yes;

    let summary = if will_execute {
        let journal = Journal::new(&ctx.state_dir);
        let run_id = jiff::Timestamp::now().to_string();
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

    let rendered = match mode {
        Mode::Json => serde_json::to_string(&JsonOutput {
            groups: &groups,
            summary: summary.as_ref(),
            dry_run: is_dry_run,
        })?,
        Mode::Human => render_human(&groups, &rules, summary.as_ref(), will_execute, is_dry_run),
    };
    Ok(CleanOutput { rendered })
}

fn render_human(
    groups: &[Group],
    rules: &[Rule],
    summary: Option<&Summary>,
    will_execute: bool,
    is_dry_run: bool,
) -> String {
    let mut out = render_plan(groups, rules);
    if out == "Nothing to clean." {
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
}
