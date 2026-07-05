use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::core::item::{Candidate, Group, Risk};
use crate::core::runner::CommandRunner;
use crate::ctx::Ctx;
use crate::privilege;
use crate::rules::{Action, CmdSpec, Rule, expand_path_spec};
use crate::safety::deleter::delete_tree;
use crate::safety::journal::{Journal, Record};
use crate::safety::protected::{SafetyEnv, Tier, validate_deletable};

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteOutcome {
    pub bytes_freed: u64,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunOutcome {
    pub outcome: String,
    pub skipped: bool,
}

/// One path a Safe/Moderate-tier `DeletePaths` rule needs deleted with root
/// privilege, carrying the dev/ino snapshotted at selection time (for the
/// privileged helper's TOCTOU re-check) and the estimated size (for dry-run
/// reporting, which never talks to the helper at all).
#[derive(Debug, Clone, PartialEq)]
pub struct PrivilegedDelete {
    pub rule_id: String,
    pub path: PathBuf,
    pub expected_dev: u64,
    pub expected_ino: u64,
    pub estimated_bytes: u64,
}

/// Carries out one selected action. `DryRunEffector` only records what would
/// happen; `RealEffector` actually deletes/runs. `delete` takes
/// `requires_sudo`/`allowed_prefixes` directly (rather than a `&Rule`) so
/// callers with no static `Rule` of their own — `badger purge`'s
/// context-gated candidates, for instance — can drive the same effector.
pub trait Effector {
    fn delete(
        &mut self,
        requires_sudo: bool,
        allowed_prefixes: &[PathBuf],
        path: &Path,
        estimated_bytes: u64,
    ) -> DeleteOutcome;
    fn run(&mut self, spec: &CmdSpec) -> RunOutcome;
    /// Deletes paths that require root privilege via the privileged helper
    /// subprocess (see `privilege.rs`), one outcome per `op`, same order.
    fn delete_privileged(&mut self, run_id: &str, ops: &[PrivilegedDelete]) -> Vec<DeleteOutcome>;
}

pub struct DryRunEffector;

impl Effector for DryRunEffector {
    fn delete(
        &mut self,
        _requires_sudo: bool,
        _allowed_prefixes: &[PathBuf],
        _path: &Path,
        estimated_bytes: u64,
    ) -> DeleteOutcome {
        DeleteOutcome {
            bytes_freed: estimated_bytes,
            outcome: "would delete".to_string(),
        }
    }

    fn run(&mut self, spec: &CmdSpec) -> RunOutcome {
        RunOutcome {
            outcome: format!("would run: {}", spec.argv.join(" ")),
            skipped: false,
        }
    }

    fn delete_privileged(&mut self, _run_id: &str, ops: &[PrivilegedDelete]) -> Vec<DeleteOutcome> {
        ops.iter()
            .map(|op| DeleteOutcome {
                bytes_freed: op.estimated_bytes,
                outcome: "would delete".to_string(),
            })
            .collect()
    }
}

pub struct RealEffector<'a> {
    ctx: &'a Ctx,
    runner: Box<dyn CommandRunner>,
}

impl<'a> RealEffector<'a> {
    pub fn new(ctx: &'a Ctx, runner: Box<dyn CommandRunner>) -> RealEffector<'a> {
        RealEffector { ctx, runner }
    }
}

impl Effector for RealEffector<'_> {
    fn delete(
        &mut self,
        requires_sudo: bool,
        allowed_prefixes: &[PathBuf],
        path: &Path,
        _estimated_bytes: u64,
    ) -> DeleteOutcome {
        // Re-read /proc/self/mountinfo per candidate rather than caching it
        // once for the batch: mounts can change mid-run, and this is the
        // freshest possible TOCTOU state right before the delete.
        let env = match SafetyEnv::from_system(self.ctx) {
            Ok(env) => env,
            Err(e) => {
                return DeleteOutcome {
                    bytes_freed: 0,
                    outcome: format!("error: {e:#}"),
                };
            }
        };
        let tier = if requires_sudo {
            Tier::System
        } else {
            Tier::User
        };

        // Fresh re-check: the world can have changed since scan time (TOCTOU).
        if let Err(refusal) = validate_deletable(path, allowed_prefixes, tier, &env) {
            return DeleteOutcome {
                bytes_freed: 0,
                outcome: format!("refused: {refusal}"),
            };
        }

        let report = delete_tree(path);
        if report.errors.is_empty() {
            DeleteOutcome {
                bytes_freed: report.bytes_freed,
                outcome: "ok".to_string(),
            }
        } else {
            let detail = report
                .errors
                .iter()
                .map(|(p, e)| format!("{}: {e}", p.display()))
                .collect::<Vec<_>>()
                .join("; ");
            DeleteOutcome {
                bytes_freed: report.bytes_freed,
                outcome: format!("error: {detail}"),
            }
        }
    }

    fn run(&mut self, spec: &CmdSpec) -> RunOutcome {
        if spec.sudo && self.ctx.sandboxed {
            return RunOutcome {
                outcome: "skipped: sudo is never run in a sandbox".to_string(),
                skipped: true,
            };
        }

        let mut argv = spec.argv.clone();
        if spec.sudo {
            argv.insert(0, "sudo".to_string());
        }
        match self.runner.run(&argv) {
            Ok(out) if out.success => RunOutcome {
                outcome: "ok".to_string(),
                skipped: false,
            },
            Ok(out) => RunOutcome {
                outcome: format!("error: {}", out.stderr.trim()),
                skipped: false,
            },
            Err(e) => RunOutcome {
                outcome: format!("error: {e:#}"),
                skipped: false,
            },
        }
    }

    fn delete_privileged(&mut self, run_id: &str, ops: &[PrivilegedDelete]) -> Vec<DeleteOutcome> {
        if ops.is_empty() {
            return Vec::new();
        }
        if self.ctx.sandboxed {
            return ops
                .iter()
                .map(|_| DeleteOutcome {
                    bytes_freed: 0,
                    outcome: "skipped: sudo is never run in a sandbox".to_string(),
                })
                .collect();
        }

        let manifest = privilege::Manifest {
            run_id: run_id.to_string(),
            root: self.ctx.root.clone(),
            home: self.ctx.home.clone(),
            ops: ops
                .iter()
                .map(|op| privilege::HelperOp {
                    rule_id: op.rule_id.clone(),
                    path: op.path.clone(),
                    expected_dev: op.expected_dev,
                    expected_ino: op.expected_ino,
                })
                .collect(),
        };
        match privilege::run_helper(&manifest) {
            Ok(results) => results
                .into_iter()
                .map(|r| DeleteOutcome {
                    bytes_freed: r.bytes_freed,
                    outcome: r.outcome,
                })
                .collect(),
            Err(e) => ops
                .iter()
                .map(|_| DeleteOutcome {
                    bytes_freed: 0,
                    outcome: format!("error: {e:#}"),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
pub struct Summary {
    pub bytes_freed: u64,
    pub actions: usize,
    /// Journal-append failures encountered mid-batch. A failed audit-trail
    /// write must not abort execution (the delete/run already happened), so
    /// these are collected here instead of propagated via `?`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub journal_warnings: Vec<String>,
}

/// Appends `record` to `journal`; a failed audit-trail write must not abort
/// the batch (the delete/run it describes already happened), so it's
/// collected as a warning on `summary` instead of propagated with `?`.
fn append_or_warn(journal: &Journal, record: &Record, summary: &mut Summary) {
    if let Err(e) = journal.append(record) {
        summary
            .journal_warnings
            .push(format!("failed to record audit trail: {e:#}"));
    }
}

/// Runs and journals each of `specs` in turn; shared by `Action::Cmd` and
/// `Action::CmdSelected` in both `execute` and `execute_selected`.
#[allow(clippy::too_many_arguments)]
fn run_specs(
    specs: Vec<CmdSpec>,
    rule_id: &str,
    effector: &mut dyn Effector,
    journal: &Journal,
    run_id: &str,
    dry_run: bool,
    summary: &mut Summary,
) {
    for spec in specs {
        let outcome = effector.run(&spec);
        summary.actions += 1;
        append_or_warn(
            journal,
            &Record::now(
                run_id.to_string(),
                "clean".to_string(),
                rule_id.to_string(),
                "cmd".to_string(),
                Some(spec.argv.clone()),
                None,
                spec.sudo,
                dry_run,
                0,
                outcome.outcome,
            ),
            summary,
        );
    }
}

/// Executes every Safe-tier group's selected candidates (or, for
/// `Action::Cmd` rules, its commands). Moderate/Risky groups are never
/// auto-executed here — that's what `--yes` acts on non-interactively, and
/// it stays Safe-only by design. `DeletePaths` rules that themselves
/// require sudo are also left alone: this function has no privileged-
/// deletion path, only privileged *commands* (`Action::Cmd`) can run, via a
/// `sudo`-prefixed invocation. The TUI checklist's explicit per-item opt-in
/// (including Moderate and privileged deletes) is `execute_selected` below.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    groups: &[Group],
    rules: &[Rule],
    ctx: &Ctx,
    config: &Config,
    effector: &mut dyn Effector,
    journal: &Journal,
    run_id: &str,
    dry_run: bool,
) -> anyhow::Result<Summary> {
    let mut summary = Summary::default();
    for group in groups {
        if group.risk != Risk::Safe {
            continue;
        }
        let Some(rule) = rules.iter().find(|r| r.id == group.rule_id) else {
            continue;
        };

        match rule.action {
            Action::DeletePaths => {
                if rule.requires_sudo {
                    continue;
                }
                let allowed: Vec<PathBuf> = rule
                    .allowed_prefixes
                    .iter()
                    .map(|p| expand_path_spec(p, ctx))
                    .collect();
                for candidate in &group.candidates {
                    if !candidate.selectable {
                        continue;
                    }
                    let Some(path) = &candidate.path else {
                        continue;
                    };
                    let outcome =
                        effector.delete(rule.requires_sudo, &allowed, path, candidate.bytes);
                    summary.bytes_freed += outcome.bytes_freed;
                    summary.actions += 1;
                    append_or_warn(
                        journal,
                        &Record::now(
                            run_id.to_string(),
                            "clean".to_string(),
                            rule.id.to_string(),
                            "delete".to_string(),
                            None,
                            Some(vec![path.display().to_string()]),
                            false,
                            dry_run,
                            outcome.bytes_freed,
                            outcome.outcome,
                        ),
                        &mut summary,
                    );
                }
            }
            Action::Cmd(build_specs) => {
                run_specs(
                    build_specs(ctx, config),
                    rule.id,
                    effector,
                    journal,
                    run_id,
                    dry_run,
                    &mut summary,
                );
            }
            Action::CmdSelected(build_specs) => {
                let selected: Vec<Candidate> = group
                    .candidates
                    .iter()
                    .filter(|c| c.selectable)
                    .cloned()
                    .collect();
                if selected.is_empty() {
                    continue;
                }
                run_specs(
                    build_specs(ctx, config, &selected),
                    rule.id,
                    effector,
                    journal,
                    run_id,
                    dry_run,
                    &mut summary,
                );
            }
        }
    }
    Ok(summary)
}

/// Executes exactly the candidates named in `selection` (`(group_idx,
/// candidate_idx)` pairs into `groups`), regardless of the group's risk
/// tier — the TUI checklist is the explicit per-item opt-in, so unlike
/// `execute` (Safe-tier only, used by non-interactive `--yes`) this acts on
/// whatever the person checked, including Moderate/Risky candidates.
///
/// `DeletePaths` rules that require sudo are batched into one privileged
/// helper call (see `privilege.rs`) rather than deleted directly. A Cmd
/// rule's command(s) run iff at least one of its (informational) candidates
/// is selected.
#[allow(clippy::too_many_arguments)]
pub fn execute_selected(
    groups: &[Group],
    selection: &HashSet<(usize, usize)>,
    rules: &[Rule],
    ctx: &Ctx,
    config: &Config,
    effector: &mut dyn Effector,
    journal: &Journal,
    run_id: &str,
    dry_run: bool,
) -> anyhow::Result<Summary> {
    let mut summary = Summary::default();
    let mut privileged_ops: Vec<PrivilegedDelete> = Vec::new();

    for (gi, group) in groups.iter().enumerate() {
        let Some(rule) = rules.iter().find(|r| r.id == group.rule_id) else {
            continue;
        };

        match rule.action {
            Action::DeletePaths => {
                let allowed: Vec<PathBuf> = rule
                    .allowed_prefixes
                    .iter()
                    .map(|p| expand_path_spec(p, ctx))
                    .collect();
                for (ci, candidate) in group.candidates.iter().enumerate() {
                    if !selection.contains(&(gi, ci)) {
                        continue;
                    }
                    let Some(path) = &candidate.path else {
                        continue;
                    };

                    if !rule.requires_sudo {
                        let outcome =
                            effector.delete(rule.requires_sudo, &allowed, path, candidate.bytes);
                        summary.bytes_freed += outcome.bytes_freed;
                        summary.actions += 1;
                        append_or_warn(
                            journal,
                            &Record::now(
                                run_id.to_string(),
                                "clean".to_string(),
                                rule.id.to_string(),
                                "delete".to_string(),
                                None,
                                Some(vec![path.display().to_string()]),
                                false,
                                dry_run,
                                outcome.bytes_freed,
                                outcome.outcome,
                            ),
                            &mut summary,
                        );
                        continue;
                    }

                    match std::fs::symlink_metadata(path) {
                        Ok(metadata) => privileged_ops.push(PrivilegedDelete {
                            rule_id: rule.id.to_string(),
                            path: path.clone(),
                            expected_dev: metadata.dev(),
                            expected_ino: metadata.ino(),
                            estimated_bytes: candidate.bytes,
                        }),
                        Err(e) => {
                            summary.actions += 1;
                            append_or_warn(
                                journal,
                                &Record::now(
                                    run_id.to_string(),
                                    "clean".to_string(),
                                    rule.id.to_string(),
                                    "delete".to_string(),
                                    None,
                                    Some(vec![path.display().to_string()]),
                                    true,
                                    dry_run,
                                    0,
                                    format!("error: cannot stat {}: {e}", path.display()),
                                ),
                                &mut summary,
                            );
                        }
                    }
                }
            }
            Action::Cmd(build_specs) => {
                let any_selected = group
                    .candidates
                    .iter()
                    .enumerate()
                    .any(|(ci, _)| selection.contains(&(gi, ci)));
                if !any_selected {
                    continue;
                }
                run_specs(
                    build_specs(ctx, config),
                    rule.id,
                    effector,
                    journal,
                    run_id,
                    dry_run,
                    &mut summary,
                );
            }
            Action::CmdSelected(build_specs) => {
                let selected: Vec<Candidate> = group
                    .candidates
                    .iter()
                    .enumerate()
                    .filter(|(ci, _)| selection.contains(&(gi, *ci)))
                    .map(|(_, c)| c.clone())
                    .collect();
                if selected.is_empty() {
                    continue;
                }
                run_specs(
                    build_specs(ctx, config, &selected),
                    rule.id,
                    effector,
                    journal,
                    run_id,
                    dry_run,
                    &mut summary,
                );
            }
        }
    }

    if !privileged_ops.is_empty() {
        let outcomes = effector.delete_privileged(run_id, &privileged_ops);
        for (op, outcome) in privileged_ops.iter().zip(outcomes) {
            summary.bytes_freed += outcome.bytes_freed;
            summary.actions += 1;
            append_or_warn(
                journal,
                &Record::now(
                    run_id.to_string(),
                    "clean".to_string(),
                    op.rule_id.clone(),
                    "delete".to_string(),
                    None,
                    Some(vec![op.path.display().to_string()]),
                    true,
                    dry_run,
                    outcome.bytes_freed,
                    outcome.outcome,
                ),
                &mut summary,
            );
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::item::Candidate;
    use crate::core::runner::{CmdOutput, FakeRunner};
    use crate::rules::{Applicability, Detector};

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

    fn delete_rule(id: &'static str, requires_sudo: bool) -> Rule {
        Rule {
            id,
            title: "test rule",
            risk: Risk::Safe,
            requires_sudo,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.cache/target"],
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        }
    }

    fn group_with_one_candidate(rule_id: &str, path: PathBuf, bytes: u64) -> Group {
        Group {
            rule_id: rule_id.to_string(),
            title: "test rule".to_string(),
            risk: Risk::Safe,
            requires_sudo: false,
            candidates: vec![Candidate::new(
                Some(path),
                "target".to_string(),
                bytes,
                Risk::Safe,
            )],
            skipped: Vec::new(),
        }
    }

    #[test]
    fn test_dry_run_effector_journals_without_touching_filesystem() {
        let f = fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 4096]).unwrap();

        let rule = delete_rule("test.rule", false);
        let group = group_with_one_candidate("test.rule", target.clone(), 4096);
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = DryRunEffector;

        let summary = execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            true,
        )
        .unwrap();

        assert_eq!(summary.bytes_freed, 4096);
        assert!(target.exists(), "dry run must not touch the filesystem");
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].dry_run);
        assert_eq!(records[0].outcome, "would delete");
    }

    #[test]
    fn test_real_effector_deletes_and_journals() {
        let f = fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 4096]).unwrap();

        let rule = delete_rule("test.rule", false);
        let group = group_with_one_candidate("test.rule", target.clone(), 4096);
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert!(summary.bytes_freed > 0);
        assert!(!target.exists());
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records[0].outcome, "ok");
        assert!(!records[0].dry_run);
    }

    // Regression: a failing journal.append() used to abort execute() via `?`,
    // so a delete that had already happened went unjournaled and the caller
    // never got the freed-bytes summary. It must now continue and surface the
    // failure as a warning instead.
    #[test]
    fn test_execute_continues_and_warns_when_journal_append_fails() {
        let f = fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 4096]).unwrap();

        let rule = delete_rule("test.rule", false);
        let group = group_with_one_candidate("test.rule", target.clone(), 4096);

        // Make the journal's state dir itself a regular file, so `append`'s
        // `create_dir_all(parent)` fails deterministically (ENOTDIR),
        // regardless of user privileges.
        std::fs::write(&f.ctx.state_dir, b"not a directory").unwrap();
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert!(!target.exists(), "the delete must still happen");
        assert_eq!(summary.actions, 1);
        assert!(
            summary.bytes_freed > 0,
            "the freed-bytes summary must still be reported"
        );
        assert_eq!(
            summary.journal_warnings.len(),
            1,
            "the failed audit-trail write must be surfaced as a warning"
        );
    }

    #[test]
    fn test_sudo_delete_paths_rule_is_never_executed() {
        let f = fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();

        let rule = delete_rule("test.sudo_rule", true);
        let mut group = group_with_one_candidate("test.sudo_rule", target.clone(), 100);
        group.requires_sudo = true;
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 0);
        assert!(target.exists());
        let (records, _) = journal.read_all().unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_moderate_group_is_never_executed() {
        let f = fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();

        let rule = delete_rule("test.moderate_rule", false);
        let mut group = group_with_one_candidate("test.moderate_rule", target.clone(), 100);
        group.risk = Risk::Moderate;
        group.candidates[0].selectable = true;
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 0);
        assert!(target.exists());
    }

    #[test]
    fn test_cmd_action_sudo_spec_is_skipped_in_sandbox_with_a_note() {
        let f = fixture();
        assert!(f.ctx.sandboxed);

        fn build_specs(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
            vec![CmdSpec {
                argv: vec!["paccache".to_string(), "-rk2".to_string()],
                sudo: true,
                label: "test".to_string(),
            }]
        }

        let rule = Rule {
            id: "test.cmd_rule",
            title: "test cmd rule",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::Cmd(build_specs),
            notes: "",
        };
        let group = Group {
            rule_id: "test.cmd_rule".to_string(),
            title: "test cmd rule".to_string(),
            risk: Risk::Safe,
            requires_sudo: true,
            candidates: Vec::new(),
            skipped: Vec::new(),
        };
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 1);
        let (records, _) = journal.read_all().unwrap();
        assert!(records[0].outcome.contains("skipped"));
    }

    #[test]
    fn test_cmd_action_runs_via_command_runner_with_exact_argv() {
        let f = fixture();

        fn build_specs(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
            vec![CmdSpec {
                argv: vec!["paccache".to_string(), "-rk2".to_string()],
                sudo: false,
                label: "test".to_string(),
            }]
        }

        let rule = Rule {
            id: "test.cmd_rule",
            title: "test cmd rule",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::Cmd(build_specs),
            notes: "",
        };
        let group = Group {
            rule_id: "test.cmd_rule".to_string(),
            title: "test cmd rule".to_string(),
            risk: Risk::Safe,
            requires_sudo: false,
            candidates: Vec::new(),
            skipped: Vec::new(),
        };
        let journal = Journal::new(&f.ctx.state_dir);
        let fake = FakeRunner::new().with(
            vec!["paccache".to_string(), "-rk2".to_string()],
            CmdOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let mut effector = RealEffector::new(&f.ctx, Box::new(fake));

        execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        let (records, _) = journal.read_all().unwrap();
        assert_eq!(
            records[0].argv,
            Some(vec!["paccache".to_string(), "-rk2".to_string()])
        );
        assert_eq!(records[0].outcome, "ok");
    }

    // --- execute_selected: the TUI-driven path ---

    #[test]
    fn test_execute_selected_deletes_a_moderate_candidate_when_selected() {
        let f = fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 4096]).unwrap();

        let rule = delete_rule("test.moderate_rule", false);
        let mut group = group_with_one_candidate("test.moderate_rule", target.clone(), 4096);
        group.risk = Risk::Moderate;
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));
        let selection = HashSet::from([(0usize, 0usize)]);

        let summary = execute_selected(
            &[group],
            &selection,
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert!(summary.bytes_freed > 0);
        assert!(!target.exists(), "selected Moderate candidate must delete");
    }

    #[test]
    fn test_execute_selected_ignores_a_safe_candidate_not_in_the_selection() {
        let f = fixture();
        let target = f.ctx.home.join(".cache/target");
        std::fs::create_dir_all(&target).unwrap();

        let rule = delete_rule("test.rule", false);
        let group = group_with_one_candidate("test.rule", target.clone(), 100);
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute_selected(
            &[group],
            &HashSet::new(),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 0);
        assert!(target.exists());
    }

    fn cmd_rule_with_candidate(id: &'static str, requires_sudo: bool) -> (Rule, Group) {
        fn build_specs(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
            vec![CmdSpec {
                argv: vec!["journalctl".to_string(), "--vacuum-size=100M".to_string()],
                sudo: false,
                label: "test".to_string(),
            }]
        }
        let rule = Rule {
            id,
            title: "test cmd rule",
            risk: Risk::Moderate,
            requires_sudo,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::Cmd(build_specs),
            notes: "",
        };
        let group = Group {
            rule_id: id.to_string(),
            title: "test cmd rule".to_string(),
            risk: Risk::Moderate,
            requires_sudo,
            candidates: vec![Candidate::new(
                None,
                "informational".to_string(),
                4096,
                Risk::Moderate,
            )],
            skipped: Vec::new(),
        };
        (rule, group)
    }

    #[test]
    fn test_execute_selected_runs_cmd_rule_only_when_its_candidate_is_selected() {
        let f = fixture();
        let (rule, group) = cmd_rule_with_candidate("test.cmd_selected", false);
        let journal = Journal::new(&f.ctx.state_dir);
        let fake = FakeRunner::new().with(
            vec!["journalctl".to_string(), "--vacuum-size=100M".to_string()],
            CmdOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let mut effector = RealEffector::new(&f.ctx, Box::new(fake));

        let summary = execute_selected(
            &[group],
            &HashSet::from([(0usize, 0usize)]),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 1);
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records[0].outcome, "ok");
    }

    #[test]
    fn test_execute_selected_skips_cmd_rule_when_its_candidate_is_not_selected() {
        let f = fixture();
        let (rule, group) = cmd_rule_with_candidate("test.cmd_unselected", false);
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute_selected(
            &[group],
            &HashSet::new(),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 0);
    }

    fn sudo_delete_rule_and_group(target: PathBuf, bytes: u64) -> (Rule, Group) {
        let rule = Rule {
            id: "test.sudo_delete",
            title: "test sudo delete rule",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &["/var/cache/target"],
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        };
        let mut group = group_with_one_candidate("test.sudo_delete", target, bytes);
        group.requires_sudo = true;
        (rule, group)
    }

    #[test]
    fn test_execute_selected_dry_run_reports_privileged_delete_without_touching_disk() {
        let f = fixture();
        let target = f.ctx.root.join("var/cache/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), vec![0u8; 4096]).unwrap();
        let (rule, group) = sudo_delete_rule_and_group(target.clone(), 4096);

        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = DryRunEffector;

        let summary = execute_selected(
            &[group],
            &HashSet::from([(0usize, 0usize)]),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            true,
        )
        .unwrap();

        assert_eq!(summary.bytes_freed, 4096);
        assert!(target.exists(), "dry run must not touch the filesystem");
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records[0].outcome, "would delete");
        assert!(records[0].sudo);
        assert!(records[0].dry_run);
    }

    #[test]
    fn test_execute_selected_privileged_delete_is_skipped_with_a_note_when_sandboxed() {
        let f = fixture();
        assert!(f.ctx.sandboxed);
        let target = f.ctx.root.join("var/cache/target");
        std::fs::create_dir_all(&target).unwrap();
        let (rule, group) = sudo_delete_rule_and_group(target.clone(), 100);

        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute_selected(
            &[group],
            &HashSet::from([(0usize, 0usize)]),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 1);
        assert_eq!(summary.bytes_freed, 0);
        assert!(
            target.exists(),
            "sandboxed run must never touch real root paths"
        );
        let (records, _) = journal.read_all().unwrap();
        assert!(records[0].outcome.contains("skipped"));
        assert!(records[0].sudo);
    }

    // --- Action::CmdSelected ---

    fn cmd_selected_rule_and_group(id: &'static str) -> (Rule, Group) {
        fn build_specs(_ctx: &Ctx, _config: &Config, selected: &[Candidate]) -> Vec<CmdSpec> {
            let mut argv = vec![
                "pacman".to_string(),
                "-Rns".to_string(),
                "--noconfirm".to_string(),
            ];
            argv.extend(selected.iter().map(|c| c.label.clone()));
            vec![CmdSpec {
                argv,
                sudo: false,
                label: "Remove selected orphan packages".to_string(),
            }]
        }
        let rule = Rule {
            id,
            title: "test cmd_selected rule",
            risk: Risk::Moderate,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::CmdSelected(build_specs),
            notes: "",
        };
        let group = Group {
            rule_id: id.to_string(),
            title: "test cmd_selected rule".to_string(),
            risk: Risk::Moderate,
            requires_sudo: false,
            candidates: vec![
                Candidate::new(None, "pkg-a".to_string(), 0, Risk::Moderate),
                Candidate::new(None, "pkg-b".to_string(), 0, Risk::Moderate),
            ],
            skipped: Vec::new(),
        };
        (rule, group)
    }

    #[test]
    fn test_execute_selected_cmd_selected_builds_command_from_only_the_selected_candidates() {
        let f = fixture();
        let (rule, group) = cmd_selected_rule_and_group("test.cmd_selected");
        let journal = Journal::new(&f.ctx.state_dir);
        let expected_argv = vec![
            "pacman".to_string(),
            "-Rns".to_string(),
            "--noconfirm".to_string(),
            "pkg-b".to_string(),
        ];
        let fake = FakeRunner::new().with(
            expected_argv.clone(),
            CmdOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let mut effector = RealEffector::new(&f.ctx, Box::new(fake));

        // Only "pkg-b" (index 1) is selected — "pkg-a" must not appear in argv.
        let summary = execute_selected(
            &[group],
            &HashSet::from([(0usize, 1usize)]),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 1);
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records[0].argv, Some(expected_argv));
        assert_eq!(records[0].outcome, "ok");
    }

    #[test]
    fn test_execute_selected_cmd_selected_runs_nothing_when_selection_is_empty() {
        let f = fixture();
        let (rule, group) = cmd_selected_rule_and_group("test.cmd_selected_empty");
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute_selected(
            &[group],
            &HashSet::new(),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 0);
        let (records, _) = journal.read_all().unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_execute_selected_cmd_selected_dry_run_prints_exact_argv() {
        let f = fixture();
        let (rule, group) = cmd_selected_rule_and_group("test.cmd_selected_dry_run");
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = DryRunEffector;

        let summary = execute_selected(
            &[group],
            &HashSet::from([(0usize, 1usize)]),
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            true,
        )
        .unwrap();

        assert_eq!(summary.actions, 1);
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(
            records[0].outcome,
            "would run: pacman -Rns --noconfirm pkg-b"
        );
        assert!(records[0].dry_run);
    }

    #[test]
    fn test_execute_ignores_cmd_selected_when_no_candidate_is_selectable() {
        let f = fixture();
        let (rule, mut group) = cmd_selected_rule_and_group("test.cmd_selected_auto");
        // Moderate candidates default to non-selectable; `execute` (the
        // Safe-tier `--yes` path) must never run a CmdSelected command built
        // from an empty selection.
        assert!(group.candidates.iter().all(|c| !c.selectable));
        group.risk = Risk::Safe; // force past execute()'s risk gate to isolate this behavior
        let journal = Journal::new(&f.ctx.state_dir);
        let mut effector = RealEffector::new(&f.ctx, Box::new(FakeRunner::new()));

        let summary = execute(
            &[group],
            &[rule],
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 0);
    }
}
