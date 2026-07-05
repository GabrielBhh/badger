use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::rules::{Rule, expand_path_spec_parts, registry};
use crate::safety::protected::{SafetyEnv, Tier, parse_mountinfo, validate_deletable};

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
    /// The parent's resolved root/home, carried across the `sudo` boundary so
    /// the helper re-validates against the invoking user's paths rather than
    /// trusting its own (root-owned) process environment — see
    /// `safety_env_from_manifest`.
    pub root: PathBuf,
    pub home: PathBuf,
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
pub fn helper_validate_op(op: &HelperOp, rules: &[Rule], env: &SafetyEnv) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(&op.path)
        .map_err(|e| format!("cannot stat {}: {e}", op.path.display()))?;
    if metadata.dev() != op.expected_dev || metadata.ino() != op.expected_ino {
        return Err(format!(
            "{} changed since it was selected (dev/ino mismatch)",
            op.path.display()
        ));
    }

    let rule = rules
        .iter()
        .find(|r| r.id == op.rule_id)
        .ok_or_else(|| format!("unknown rule id: {}", op.rule_id))?;
    let allowed: Vec<PathBuf> = rule
        .allowed_prefixes
        .iter()
        .map(|p| expand_path_spec_parts(p, &env.root, &env.home))
        .collect();
    validate_deletable(&op.path, &allowed, Tier::System, env).map_err(|r| r.to_string())
}

/// Builds the `SafetyEnv` the helper re-validates against, using the root/home
/// carried in the manifest — never the helper process's own `$HOME`. `sudo`'s
/// default `env_reset` sets `HOME=/root` for the child, which is not the
/// invoking user's home; trusting it would check the home-relative deny list
/// and depth guard against the wrong tree.
fn safety_env_from_manifest(manifest: &Manifest) -> anyhow::Result<SafetyEnv> {
    let text = std::fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;
    Ok(SafetyEnv {
        root: manifest.root.clone(),
        home: manifest.home.clone(),
        mount_points: parse_mountinfo(&text),
        euid: nix::unistd::geteuid().as_raw(),
    })
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

    let env = safety_env_from_manifest(&manifest)?;
    // Rules for ops already selected and validated upstream may include
    // experimental ones — the helper only resolves rule ids to allowed
    // prefixes, so it must know every rule that could have produced an op.
    // (leftovers.orphan_configs' requires_sudo: false must never change — a heuristic guess must never gain root-deletion trust just by being resolvable here.)
    let rules = registry(true);

    for op in &manifest.ops {
        let result = match helper_validate_op(op, &rules, &env) {
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
        stdin
            .write_all(serde_json::to_string(manifest)?.as_bytes())
            .context("failed to write manifest to privileged helper's stdin")?;
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
            root: PathBuf::from("/"),
            home: PathBuf::from("/home/user"),
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

    // Regression: helper_main used to build its SafetyEnv via
    // Ctx::resolve(...) reading $HOME from the process env. Under `sudo`
    // (default env_reset) that resolves to /root, not the invoking user's
    // home, silently breaking the home-relative deny list (~/.ssh etc.) and
    // depth check on the root side. safety_env_from_manifest must build the
    // env from the manifest's carried root/home instead, never from $HOME.
    #[test]
    fn test_safety_env_from_manifest_uses_manifest_home_for_denylist_check() {
        let sandbox = tempfile::tempdir().unwrap();
        let manifest_root = sandbox.path().join("root");
        let manifest_home = manifest_root.join("home/realuser");
        let ssh_key = manifest_home.join(".ssh/id_rsa");
        std::fs::create_dir_all(manifest_home.join(".ssh")).unwrap();
        std::fs::write(&ssh_key, b"secret").unwrap();

        let manifest = Manifest {
            run_id: "run-1".to_string(),
            root: manifest_root.clone(),
            home: manifest_home.clone(),
            ops: Vec::new(),
        };

        let env = safety_env_from_manifest(&manifest).unwrap();
        assert_eq!(env.home, manifest_home, "must use manifest home, not $HOME");

        let metadata = std::fs::symlink_metadata(&ssh_key).unwrap();
        let op = HelperOp {
            rule_id: "user.thumbnails".to_string(),
            path: ssh_key,
            expected_dev: metadata.dev(),
            expected_ino: metadata.ino(),
        };
        let err = helper_validate_op(&op, &registry(false), &env).unwrap_err();
        assert_eq!(
            err,
            crate::safety::protected::Refusal::DenyListed.to_string()
        );
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
        let err = helper_validate_op(&op, &registry(false), &e).unwrap_err();
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
        let err = helper_validate_op(&op, &registry(false), &e).unwrap_err();
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
        assert_eq!(helper_validate_op(&op, &registry(false), &e), Ok(()));
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
        let err = helper_validate_op(&op, &registry(false), &e).unwrap_err();
        assert!(err.contains("unknown rule id"), "error was: {err}");
    }
}
