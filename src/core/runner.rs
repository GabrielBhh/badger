use std::cell::RefCell;
use std::collections::HashMap;
use std::process::Command;

use anyhow::Context;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Abstracts "run this argv and tell me what happened" so effectors (and
/// their tests) never have to actually spawn `paccache`/`journalctl`/etc.
pub trait CommandRunner {
    fn run(&self, argv: &[String]) -> anyhow::Result<CmdOutput>;
}

pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, argv: &[String]) -> anyhow::Result<CmdOutput> {
        let [program, args @ ..] = argv else {
            anyhow::bail!("empty command");
        };
        let output = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to run {program}"))?;
        Ok(CmdOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Test double: returns a canned `CmdOutput` for an exact argv match and
/// records every call it received, so tests can assert exactly what would
/// have been run.
#[derive(Default)]
pub struct FakeRunner {
    canned: HashMap<Vec<String>, CmdOutput>,
    pub calls: RefCell<Vec<Vec<String>>>,
}

impl FakeRunner {
    pub fn new() -> FakeRunner {
        FakeRunner::default()
    }

    pub fn with(mut self, argv: Vec<String>, output: CmdOutput) -> FakeRunner {
        self.canned.insert(argv, output);
        self
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, argv: &[String]) -> anyhow::Result<CmdOutput> {
        self.calls.borrow_mut().push(argv.to_vec());
        self.canned
            .get(argv)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no canned response for {argv:?}"))
    }
}

/// The runner a command-based detector should use: a `RealRunner` on a real
/// system, or a `FakeRunner` seeded from `ctx.fake_command_output` while
/// sandboxed — so detection logic that shells out (pacman orphans, flatpak,
/// container images, ...) never actually spawns a subprocess in a test.
pub fn runner_for(ctx: &crate::ctx::Ctx) -> Box<dyn CommandRunner> {
    if ctx.sandboxed {
        let mut fake = FakeRunner::new();
        if let Some(canned) = &ctx.fake_command_output {
            for (argv, output) in canned {
                fake = fake.with(argv.clone(), output.clone());
            }
        }
        Box::new(fake)
    } else {
        Box::new(RealRunner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn sandboxed_ctx(
        fake_command_output: Option<HashMap<Vec<String>, CmdOutput>>,
    ) -> crate::ctx::Ctx {
        crate::ctx::Ctx {
            root: PathBuf::from("/root"),
            home: PathBuf::from("/root/home/user"),
            config_dir: PathBuf::new(),
            state_dir: PathBuf::new(),
            dry_run: false,
            debug: false,
            config: crate::config::Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output,
        }
    }

    #[test]
    fn test_runner_for_sandboxed_returns_canned_output_from_ctx() {
        let argv = vec!["pacman".to_string(), "-Qtdq".to_string()];
        let canned = HashMap::from([(
            argv.clone(),
            CmdOutput {
                success: true,
                stdout: "orphan-pkg\n".to_string(),
                stderr: String::new(),
            },
        )]);
        let ctx = sandboxed_ctx(Some(canned));
        let runner = runner_for(&ctx);
        let out = runner.run(&argv).unwrap();
        assert_eq!(out.stdout, "orphan-pkg\n");
    }

    #[test]
    fn test_runner_for_sandboxed_with_no_canned_output_errors_rather_than_running_for_real() {
        let ctx = sandboxed_ctx(None);
        let runner = runner_for(&ctx);
        assert!(
            runner
                .run(&["pacman".to_string(), "-Qtdq".to_string()])
                .is_err()
        );
    }

    #[test]
    fn test_real_runner_captures_stdout_and_success() {
        let out = RealRunner
            .run(&["echo".to_string(), "hello".to_string()])
            .unwrap();
        assert!(out.success);
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[test]
    fn test_real_runner_reports_failure_without_erroring() {
        let out = RealRunner.run(&["false".to_string()]).unwrap();
        assert!(!out.success);
    }

    #[test]
    fn test_fake_runner_returns_canned_output_and_records_call() {
        let argv = vec!["paccache".to_string(), "-rk2".to_string()];
        let fake = FakeRunner::new().with(
            argv.clone(),
            CmdOutput {
                success: true,
                stdout: "ok".to_string(),
                stderr: String::new(),
            },
        );

        let out = fake.run(&argv).unwrap();
        assert!(out.success);
        assert_eq!(fake.calls.borrow().as_slice(), &[argv]);
    }

    #[test]
    fn test_fake_runner_errors_on_unexpected_argv() {
        let fake = FakeRunner::new();
        assert!(fake.run(&["unexpected".to_string()]).is_err());
    }
}
