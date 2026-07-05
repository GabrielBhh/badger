//! CachyOS/kernel extras: kernel release, the `sched_ext` (scx) scheduler
//! state, and the failed-systemd-units count.

use crate::core::runner::runner_for;
use crate::ctx::Ctx;

/// Reads `<root>/proc/sys/kernel/osrelease` (e.g.
/// `7.1.3-1-cachyos`).
pub fn kernel_release(ctx: &Ctx) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(ctx.root.join("proc/sys/kernel/osrelease"))?;
    Ok(text.trim().to_string())
}

/// Reports the `sched_ext` scheduler state: `None` when the kernel has no
/// `sched_ext` support at all (no `/sys/kernel/sched_ext/state`); the raw
/// state (typically `"disabled"`) when not enabled; or the active
/// scheduler's name from `root/ops` when enabled and that file is present
/// and non-empty.
pub fn scx_scheduler(ctx: &Ctx) -> Option<String> {
    let state = std::fs::read_to_string(ctx.root.join("sys/kernel/sched_ext/state"))
        .ok()?
        .trim()
        .to_string();
    if state != "enabled" {
        return Some(state);
    }
    match std::fs::read_to_string(ctx.root.join("sys/kernel/sched_ext/root/ops")) {
        Ok(ops) if !ops.trim().is_empty() => Some(ops.trim().to_string()),
        _ => Some(state),
    }
}

/// Counts failed systemd units via `systemctl --failed --plain
/// --no-legend` (one non-blank line per failed unit). Uses the same
/// `CommandRunner` seam as the pacman/flatpak detectors: real system runs
/// it for real, a sandboxed `Ctx` only sees canned output from
/// `ctx.fake_command_output`. `None` when the command fails or isn't
/// available (a `FakeRunner` with no matching canned entry errors, which
/// this treats the same as `systemctl` being absent).
pub fn failed_units(ctx: &Ctx) -> Option<usize> {
    let runner = runner_for(ctx);
    let argv = [
        "systemctl".to_string(),
        "--failed".to_string(),
        "--plain".to_string(),
        "--no-legend".to_string(),
    ];
    let output = runner.run(&argv).ok()?;
    if !output.success {
        return None;
    }
    Some(
        output
            .stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::core::runner::CmdOutput;
    use std::collections::HashMap;
    use std::path::Path;

    fn fixture_ctx(root: &Path) -> Ctx {
        Ctx {
            root: root.to_path_buf(),
            home: root.join("home/user"),
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            dry_run: false,
            debug: false,
            config: Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output: None,
        }
    }

    // --- kernel_release ---

    #[test]
    fn test_kernel_release_trims_trailing_newline() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc/sys/kernel")).unwrap();
        std::fs::write(
            ctx.root.join("proc/sys/kernel/osrelease"),
            "7.1.3-1-cachyos\n",
        )
        .unwrap();

        assert_eq!(kernel_release(&ctx).unwrap(), "7.1.3-1-cachyos");
    }

    #[test]
    fn test_kernel_release_missing_file_is_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert!(kernel_release(&ctx).is_err());
    }

    // --- scx_scheduler ---

    #[test]
    fn test_scx_scheduler_absent_support_is_none() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert_eq!(scx_scheduler(&ctx), None);
    }

    #[test]
    fn test_scx_scheduler_disabled_state() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("sys/kernel/sched_ext")).unwrap();
        std::fs::write(ctx.root.join("sys/kernel/sched_ext/state"), "disabled\n").unwrap();

        assert_eq!(scx_scheduler(&ctx), Some("disabled".to_string()));
    }

    #[test]
    fn test_scx_scheduler_enabled_reads_ops_name() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("sys/kernel/sched_ext/root")).unwrap();
        std::fs::write(ctx.root.join("sys/kernel/sched_ext/state"), "enabled\n").unwrap();
        std::fs::write(
            ctx.root.join("sys/kernel/sched_ext/root/ops"),
            "scx_bpfland\n",
        )
        .unwrap();

        assert_eq!(scx_scheduler(&ctx), Some("scx_bpfland".to_string()));
    }

    #[test]
    fn test_scx_scheduler_enabled_without_ops_file_falls_back_to_state() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("sys/kernel/sched_ext")).unwrap();
        std::fs::write(ctx.root.join("sys/kernel/sched_ext/state"), "enabled\n").unwrap();

        assert_eq!(scx_scheduler(&ctx), Some("enabled".to_string()));
    }

    // --- failed_units ---

    #[test]
    fn test_failed_units_counts_nonblank_lines() {
        let sandbox = tempfile::tempdir().unwrap();
        let mut ctx = fixture_ctx(sandbox.path());
        let argv = vec![
            "systemctl".to_string(),
            "--failed".to_string(),
            "--plain".to_string(),
            "--no-legend".to_string(),
        ];
        ctx.fake_command_output = Some(HashMap::from([(
            argv,
            CmdOutput {
                success: true,
                stdout:
                    "foo.service loaded failed failed Foo\nbar.service loaded failed failed Bar\n"
                        .to_string(),
                stderr: String::new(),
            },
        )]));

        assert_eq!(failed_units(&ctx), Some(2));
    }

    #[test]
    fn test_failed_units_no_failures_is_zero() {
        let sandbox = tempfile::tempdir().unwrap();
        let mut ctx = fixture_ctx(sandbox.path());
        let argv = vec![
            "systemctl".to_string(),
            "--failed".to_string(),
            "--plain".to_string(),
            "--no-legend".to_string(),
        ];
        ctx.fake_command_output = Some(HashMap::from([(
            argv,
            CmdOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        )]));

        assert_eq!(failed_units(&ctx), Some(0));
    }

    #[test]
    fn test_failed_units_command_unavailable_is_none() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        // Sandboxed with no canned output at all: the FakeRunner errors,
        // same as `systemctl` not existing on the real system.
        assert_eq!(failed_units(&ctx), None);
    }
}
