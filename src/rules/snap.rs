//! `snap.old_revisions`: disabled snap revisions snapd keeps around so
//! `snap revert` can roll back to them. Removing them frees space but gives
//! up that rollback option for the removed revisions.

use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::core::runner::runner_for;
use crate::ctx::Ctx;
use crate::rules::{Action, Applicability, CmdSelectedWithSkipsResult, CmdSpec, Detector, Rule};

pub fn rules() -> Vec<Rule> {
    vec![Rule {
        id: "snap.old_revisions",
        title: "Old snap revisions",
        risk: Risk::Risky,
        requires_sudo: true,
        applicable: Applicability::CommandExists("snap"),
        allowed_prefixes: &[],
        detector: Detector::Fn(old_revisions_detector),
        action: Action::CmdSelectedWithSkips(old_revisions_cmd),
        notes: "Disabled, superseded revisions snapd keeps around for rollback; removing them \
                frees space but removes the ability to `snap revert` to those revisions.",
    }]
}

/// `snap list --all`: one row per (snap, revision), header first. A row is a
/// candidate iff its Notes column (the last one), split on commas, contains
/// the exact token `disabled` — not a substring match, so `classic` alone
/// (or a hypothetical token merely containing "disabled") never matches.
fn old_revisions_detector(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let runner = runner_for(ctx);
    let Ok(res) = runner.run(&["snap".to_string(), "list".to_string(), "--all".to_string()]) else {
        return Vec::new();
    };
    if !res.success {
        return Vec::new();
    }

    let mut out = Vec::new();
    for line in res.stdout.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let name = cols[0];
        let rev = cols[2];
        let notes = cols[cols.len() - 1];
        if notes.split(',').any(|token| token == "disabled") {
            out.push(Candidate::new(
                None,
                format!("{name} (revision {rev})"),
                0,
                Risk::Risky,
            ));
        }
    }
    out
}

/// Parses a `"<name> (revision <rev>)"` label back into its parts. Mirrors
/// `snapshots.rs`'s label-parse-back approach.
fn parse_revision_label(label: &str) -> Option<(&str, &str)> {
    let (name, rest) = label.split_once(" (revision ")?;
    let rev = rest.strip_suffix(')')?;
    if name.is_empty() || rev.is_empty() {
        return None;
    }
    Some((name, rev))
}

/// snapd's own naming rule: non-empty, only ASCII lowercase letters/digits/
/// hyphens, starting with a letter or digit — so it can never be mistaken
/// for a flag.
fn is_valid_snap_name(name: &str) -> bool {
    let Some(first) = name.chars().next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Snap revisions are numbers (store snaps) or things like `x1` (locally
/// installed) — ASCII alphanumeric only.
fn is_valid_revision(rev: &str) -> bool {
    !rev.is_empty() && rev.chars().all(|c| c.is_ascii_alphanumeric())
}

fn old_revisions_cmd(
    _ctx: &Ctx,
    _config: &Config,
    selected: &[Candidate],
) -> CmdSelectedWithSkipsResult {
    let mut specs = Vec::new();
    let mut skips = Vec::new();

    for c in selected {
        let parsed = parse_revision_label(&c.label)
            .filter(|(name, rev)| is_valid_snap_name(name) && is_valid_revision(rev));
        match parsed {
            Some((name, rev)) => specs.push(CmdSpec {
                argv: vec![
                    "snap".to_string(),
                    "remove".to_string(),
                    name.to_string(),
                    "--revision".to_string(),
                    rev.to_string(),
                ],
                sudo: true,
                label: format!("Remove {name} revision {rev}"),
            }),
            None => skips.push((
                c.label.clone(),
                "could not be safely interpreted — not removed".to_string(),
            )),
        }
    }

    (specs, skips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::runner::CmdOutput;
    use crate::core::scan::scan;
    use crate::rules::moderate;
    use crate::safety::whitelist;
    use std::collections::HashMap;
    use std::path::PathBuf;

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

    fn list_all_argv() -> Vec<String> {
        vec!["snap".to_string(), "list".to_string(), "--all".to_string()]
    }

    const REAL_SHAPED_OUTPUT: &str = "\
Name      Version   Rev    Tracking       Publisher   Notes
firefox   129.0     4848   latest/stable  mozilla     -
firefox   128.0     4790   latest/stable  mozilla     disabled
firefox   127.0     4700   latest/stable  mozilla     disabled,classic
code      1.90      163    latest/stable  vscode      classic
";

    // --- gating ---

    #[test]
    fn test_old_revisions_group_absent_when_snap_command_missing() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "snap.old_revisions"));
    }

    #[test]
    fn test_old_revisions_group_present_and_does_not_collide_with_snap_cache() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["snap".to_string()]);
        f.ctx.fake_command_output = Some(HashMap::new());

        let mut all_rules = rules();
        all_rules.extend(moderate::rules());
        let groups = scan(
            &all_rules,
            &f.ctx,
            &f.ctx.config.clone(),
            &empty_whitelist(),
        )
        .unwrap();

        let old_revisions = groups
            .iter()
            .find(|g| g.rule_id == "snap.old_revisions")
            .unwrap();
        assert_eq!(old_revisions.risk, Risk::Risky);
        assert!(old_revisions.requires_sudo);

        let cache = groups.iter().find(|g| g.rule_id == "snap.cache").unwrap();
        assert_ne!(old_revisions.rule_id, cache.rule_id);
    }

    #[test]
    fn test_old_revisions_candidates_start_unselectable_via_scan() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["snap".to_string()]);
        f.ctx.fake_command_output = Some(HashMap::from([(
            list_all_argv(),
            cmd_output(REAL_SHAPED_OUTPUT),
        )]));

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "snap.old_revisions")
            .unwrap();
        assert_eq!(group.candidates.len(), 2);
        assert!(group.candidates.iter().all(|c| !c.selectable));
    }

    // --- detector ---

    #[test]
    fn test_detector_matches_exact_disabled_token_not_substring_or_plain_classic() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            list_all_argv(),
            cmd_output(REAL_SHAPED_OUTPUT),
        )]));

        let candidates = old_revisions_detector(&f.ctx, &f.ctx.config.clone());
        let labels: Vec<&str> = candidates.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(
            labels,
            vec!["firefox (revision 4790)", "firefox (revision 4700)"]
        );
        assert!(
            candidates.iter().all(|c| !c.selectable),
            "Risky starts unchecked"
        );
    }

    #[test]
    fn test_detector_empty_when_command_errors() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::new());
        let candidates = old_revisions_detector(&f.ctx, &f.ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_detector_empty_when_output_unsuccessful() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            list_all_argv(),
            CmdOutput {
                success: false,
                stdout: REAL_SHAPED_OUTPUT.to_string(),
                stderr: String::new(),
            },
        )]));
        let candidates = old_revisions_detector(&f.ctx, &f.ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_detector_skips_short_and_garbage_rows_without_panic() {
        let mut f = fixture();
        let output = "\
Name      Version   Rev    Tracking       Publisher   Notes
too short
firefox   128.0     4790   latest/stable  mozilla     disabled
";
        f.ctx.fake_command_output = Some(HashMap::from([(list_all_argv(), cmd_output(output))]));
        let candidates = old_revisions_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].label, "firefox (revision 4790)");
    }

    // --- builder ---

    #[test]
    fn test_builder_two_selected_candidates_build_two_specs() {
        let candidates = vec![
            Candidate::new(None, "firefox (revision 4790)".to_string(), 0, Risk::Risky),
            Candidate::new(None, "code (revision 163)".to_string(), 0, Risk::Risky),
        ];
        let (specs, skips) = old_revisions_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert!(skips.is_empty());
        assert_eq!(
            specs,
            vec![
                CmdSpec {
                    argv: vec![
                        "snap".to_string(),
                        "remove".to_string(),
                        "firefox".to_string(),
                        "--revision".to_string(),
                        "4790".to_string(),
                    ],
                    sudo: true,
                    label: "Remove firefox revision 4790".to_string(),
                },
                CmdSpec {
                    argv: vec![
                        "snap".to_string(),
                        "remove".to_string(),
                        "code".to_string(),
                        "--revision".to_string(),
                        "163".to_string(),
                    ],
                    sudo: true,
                    label: "Remove code revision 163".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_builder_local_install_style_revision_builds_normally() {
        let candidates = vec![Candidate::new(
            None,
            "myapp (revision x1)".to_string(),
            0,
            Risk::Risky,
        )];
        let (specs, skips) = old_revisions_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert!(skips.is_empty());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec![
                    "snap".to_string(),
                    "remove".to_string(),
                    "myapp".to_string(),
                    "--revision".to_string(),
                    "x1".to_string(),
                ],
                sudo: true,
                label: "Remove myapp revision x1".to_string(),
            }]
        );
    }

    #[test]
    fn test_builder_defense_checks_skip_unsafe_labels_but_still_build_the_valid_one() {
        let candidates = vec![
            Candidate::new(None, "garbage label".to_string(), 0, Risk::Risky),
            Candidate::new(None, "-flag (revision 123)".to_string(), 0, Risk::Risky),
            Candidate::new(
                None,
                "UPPER/CASE (revision 123)".to_string(),
                0,
                Risk::Risky,
            ),
            Candidate::new(None, "name (revision -1)".to_string(), 0, Risk::Risky),
            Candidate::new(None, "name (revision 1 2)".to_string(), 0, Risk::Risky),
            Candidate::new(None, "firefox (revision 4790)".to_string(), 0, Risk::Risky),
        ];
        let (specs, skips) = old_revisions_cmd(&fixture().ctx, &Config::default(), &candidates);

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].argv[2], "firefox");

        assert_eq!(skips.len(), 5);
        for (label, reason) in &skips {
            assert_eq!(reason, "could not be safely interpreted — not removed");
            assert_ne!(label, "firefox (revision 4790)");
        }
    }
}
