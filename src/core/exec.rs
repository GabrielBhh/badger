use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::core::item::{Group, Risk};
use crate::core::runner::CommandRunner;
use crate::ctx::Ctx;
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

/// Carries out one selected action. `DryRunEffector` only records what would
/// happen; `RealEffector` actually deletes/runs.
pub trait Effector {
    fn delete(&mut self, rule: &Rule, path: &Path, estimated_bytes: u64) -> DeleteOutcome;
    fn run(&mut self, spec: &CmdSpec) -> RunOutcome;
}

pub struct DryRunEffector;

impl Effector for DryRunEffector {
    fn delete(&mut self, _rule: &Rule, _path: &Path, estimated_bytes: u64) -> DeleteOutcome {
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
    fn delete(&mut self, rule: &Rule, path: &Path, _estimated_bytes: u64) -> DeleteOutcome {
        let env = match SafetyEnv::from_system(self.ctx) {
            Ok(env) => env,
            Err(e) => {
                return DeleteOutcome {
                    bytes_freed: 0,
                    outcome: format!("error: {e:#}"),
                };
            }
        };
        let tier = if rule.requires_sudo {
            Tier::System
        } else {
            Tier::User
        };
        let allowed: Vec<PathBuf> = rule
            .allowed_prefixes
            .iter()
            .map(|p| expand_path_spec(p, self.ctx))
            .collect();

        // Fresh re-check: the world can have changed since scan time (TOCTOU).
        if let Err(refusal) = validate_deletable(path, &allowed, tier, &env) {
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
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
pub struct Summary {
    pub bytes_freed: u64,
    pub actions: usize,
}

/// Executes every Safe-tier group's selected candidates (or, for
/// `Action::Cmd` rules, its commands). Moderate/Risky groups are never
/// auto-executed — they need explicit opt-in from a later (TUI) phase.
/// `DeletePaths` rules that themselves require sudo are also left alone:
/// badger has no privileged-deletion path wired up yet in this phase (see
/// `privilege.rs`), only privileged *commands* (`Action::Cmd`) can run,
/// via a `sudo`-prefixed invocation.
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
                for candidate in &group.candidates {
                    if !candidate.selectable {
                        continue;
                    }
                    let Some(path) = &candidate.path else {
                        continue;
                    };
                    let outcome = effector.delete(rule, path, candidate.bytes);
                    summary.bytes_freed += outcome.bytes_freed;
                    summary.actions += 1;
                    journal.append(&Record::now(
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
                    ))?;
                }
            }
            Action::Cmd(build_specs) => {
                for spec in build_specs(ctx, config) {
                    let outcome = effector.run(&spec);
                    summary.actions += 1;
                    journal.append(&Record::now(
                        run_id.to_string(),
                        "clean".to_string(),
                        rule.id.to_string(),
                        "cmd".to_string(),
                        Some(spec.argv.clone()),
                        None,
                        spec.sudo,
                        dry_run,
                        0,
                        outcome.outcome,
                    ))?;
                }
            }
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
}
