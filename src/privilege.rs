use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::rules::{expand_path_spec_parts, registry};
use crate::safety::protected::{SafetyEnv, Tier, validate_deletable};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelperOp {
    pub rule_id: String,
    pub path: PathBuf,
    pub expected_dev: u64,
    pub expected_ino: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub run_id: String,
    pub ops: Vec<HelperOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelperResult {
    pub rule_id: String,
    pub path: PathBuf,
    pub bytes_freed: u64,
    pub outcome: String,
}

/// Re-validates one queued op right before a privileged delete: the dev/ino
/// recorded when it was selected must still match what's really at `path`
/// now (closing the TOCTOU window between selection and root-side
/// execution), and the path must still pass `validate_deletable` for its
/// owning rule's allowed prefixes.
pub fn helper_validate_op(op: &HelperOp, env: &SafetyEnv) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(&op.path)
        .map_err(|e| format!("cannot stat {}: {e}", op.path.display()))?;
    if metadata.dev() != op.expected_dev || metadata.ino() != op.expected_ino {
        return Err(format!(
            "{} changed since it was selected (dev/ino mismatch)",
            op.path.display()
        ));
    }

    let rule = registry()
        .into_iter()
        .find(|r| r.id == op.rule_id)
        .ok_or_else(|| format!("unknown rule id: {}", op.rule_id))?;
    let allowed: Vec<PathBuf> = rule
        .allowed_prefixes
        .iter()
        .map(|p| expand_path_spec_parts(p, &env.root, &env.home))
        .collect();
    validate_deletable(&op.path, &allowed, Tier::System, env).map_err(|r| r.to_string())
}

/// Reads a `Manifest` (one JSON object) from `stdin`, refuses unless running
/// as root, then for each op re-validates and deletes, writing one
/// `HelperResult` JSON line per op to `stdout`. Not unit-tested itself (the
/// euid check can't be exercised without actually being root); its per-op
/// logic is covered by `helper_validate_op`.
pub fn helper_main<R: Read, W: Write>(mut stdin: R, mut stdout: W) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("badger __helper must run as root (invoked internally via sudo)");
    }

    let mut text = String::new();
    stdin
        .read_to_string(&mut text)
        .context("failed to read manifest from stdin")?;
    let manifest: Manifest = serde_json::from_str(&text).context("failed to parse manifest")?;

    let ctx = crate::ctx::Ctx::resolve(false, false, crate::ctx::EnvOverrides::from_process())?;
    let env = SafetyEnv::from_system(&ctx)?;

    for op in &manifest.ops {
        let result = match helper_validate_op(op, &env) {
            Ok(()) => {
                let report = crate::safety::deleter::delete_tree(&op.path);
                if report.errors.is_empty() {
                    HelperResult {
                        rule_id: op.rule_id.clone(),
                        path: op.path.clone(),
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
                    HelperResult {
                        rule_id: op.rule_id.clone(),
                        path: op.path.clone(),
                        bytes_freed: report.bytes_freed,
                        outcome: format!("error: {detail}"),
                    }
                }
            }
            Err(reason) => HelperResult {
                rule_id: op.rule_id.clone(),
                path: op.path.clone(),
                bytes_freed: 0,
                outcome: format!("refused: {reason}"),
            },
        };
        writeln!(stdout, "{}", serde_json::to_string(&result)?)?;
    }
    Ok(())
}

/// Parent-side: primes the sudo credential cache, then spawns
/// `sudo /proc/self/exe __helper`, writes `manifest` to its stdin, and
/// parses one `HelperResult` per stdout line. Nothing in this phase calls
/// this yet — Phase 1's rules never need root file deletion; it exists so a
/// later phase has the plumbing ready.
pub fn run_helper(manifest: &Manifest) -> anyhow::Result<Vec<HelperResult>> {
    let status = std::process::Command::new("sudo")
        .arg("-v")
        .status()
        .context("failed to prime sudo credentials")?;
    anyhow::ensure!(status.success(), "sudo -v failed");

    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut child = std::process::Command::new("sudo")
        .arg(exe)
        .arg("__helper")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn privileged helper")?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("privileged helper's stdin was unavailable")?;
        stdin.write_all(serde_json::to_string(manifest)?.as_bytes())?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait for privileged helper")?;
    anyhow::ensure!(
        output.status.success(),
        "privileged helper exited with an error"
    );

    let mut results = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.trim().is_empty() {
            continue;
        }
        results.push(serde_json::from_str(line).context("failed to parse helper result line")?);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn env(root: &std::path::Path, home: &std::path::Path) -> SafetyEnv {
        SafetyEnv {
            root: root.to_path_buf(),
            home: home.to_path_buf(),
            mount_points: HashSet::new(),
            euid: nix::unistd::Uid::current().as_raw(),
        }
    }

    #[test]
    fn test_manifest_serde_round_trips() {
        let manifest = Manifest {
            run_id: "run-1".to_string(),
            ops: vec![HelperOp {
                rule_id: "dev.pip".to_string(),
                path: PathBuf::from("/home/user/.cache/pip"),
                expected_dev: 42,
                expected_ino: 7,
            }],
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let round_tripped: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, round_tripped);
    }

    #[test]
    fn test_helper_validate_op_refuses_dev_ino_mismatch() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let home = root.join("home/user");
        let pip_cache = home.join(".cache/pip");
        std::fs::create_dir_all(&pip_cache).unwrap();

        let metadata = std::fs::symlink_metadata(&pip_cache).unwrap();
        let op = HelperOp {
            rule_id: "dev.pip".to_string(),
            path: pip_cache,
            expected_dev: metadata.dev(),
            expected_ino: metadata.ino() + 1,
        };

        let e = env(&root, &home);
        let err = helper_validate_op(&op, &e).unwrap_err();
        assert!(err.contains("dev/ino mismatch"), "error was: {err}");
    }

    #[test]
    fn test_helper_validate_op_refuses_denylisted_path() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let home = root.join("home/user");
        let ssh_key = home.join(".ssh/id_rsa");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(&ssh_key, b"secret").unwrap();

        let metadata = std::fs::symlink_metadata(&ssh_key).unwrap();
        let op = HelperOp {
            rule_id: "user.thumbnails".to_string(),
            path: ssh_key,
            expected_dev: metadata.dev(),
            expected_ino: metadata.ino(),
        };

        let e = env(&root, &home);
        let err = helper_validate_op(&op, &e).unwrap_err();
        assert_eq!(
            err,
            crate::safety::protected::Refusal::DenyListed.to_string()
        );
    }

    #[test]
    fn test_helper_validate_op_accepts_a_legitimately_safe_path() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let home = root.join("home/user");
        let pip_cache = home.join(".cache/pip");
        std::fs::create_dir_all(&pip_cache).unwrap();

        let metadata = std::fs::symlink_metadata(&pip_cache).unwrap();
        let op = HelperOp {
            rule_id: "dev.pip".to_string(),
            path: pip_cache,
            expected_dev: metadata.dev(),
            expected_ino: metadata.ino(),
        };

        let e = env(&root, &home);
        assert_eq!(helper_validate_op(&op, &e), Ok(()));
    }

    #[test]
    fn test_helper_validate_op_refuses_unknown_rule_id() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let home = root.join("home/user");
        std::fs::create_dir_all(&home).unwrap();

        let metadata = std::fs::symlink_metadata(&home).unwrap();
        let op = HelperOp {
            rule_id: "no.such.rule".to_string(),
            path: home.clone(),
            expected_dev: metadata.dev(),
            expected_ino: metadata.ino(),
        };

        let e = env(&root, &home);
        let err = helper_validate_op(&op, &e).unwrap_err();
        assert!(err.contains("unknown rule id"), "error was: {err}");
    }
}
