use std::path::PathBuf;

use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::ctx::Ctx;

pub mod command;
pub mod dev;
pub mod user;

/// Whether a rule even makes sense to run in the current environment.
#[derive(Debug, Clone, Copy)]
pub enum Applicability {
    Always,
    /// `name` must be found on `PATH` (or in `Ctx::available_commands` when
    /// sandboxed).
    CommandExists(&'static str),
    /// `~`-prefixed or root-relative path that must exist.
    PathExists(&'static str),
}

/// How a rule finds its candidates.
pub enum Detector {
    /// `~`-prefixed (ctx home) or root-relative (ctx root) path specs. A
    /// trailing wildcard in the last path component expands against that
    /// directory's entries; a bare spec is a single candidate.
    Globs(&'static [&'static str]),
    /// Escape hatch for rules whose candidate set needs custom logic (age
    /// filtering, exclusion lists, process checks, ...).
    Fn(fn(&Ctx, &Config) -> Vec<Candidate>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CmdSpec {
    pub argv: Vec<String>,
    pub sudo: bool,
    pub label: String,
}

/// What happens when a rule's selected candidates are executed.
pub enum Action {
    /// Delete each selected candidate path directly.
    DeletePaths,
    /// Run one or more external commands instead of deleting paths
    /// ourselves; the rule's candidates are informational sizing only.
    Cmd(fn(&Ctx, &Config) -> Vec<CmdSpec>),
    /// Like `Cmd`, but the command is built from exactly the candidates the
    /// person selected in this group (e.g. `pacman -Rns <ticked packages>`).
    /// Never invoked with an empty selection — nothing selected means no
    /// command runs at all.
    CmdSelected(fn(&Ctx, &Config, &[Candidate]) -> Vec<CmdSpec>),
}

pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub risk: Risk,
    pub requires_sudo: bool,
    pub applicable: Applicability,
    /// `~`/root-relative prefixes this rule is allowed to delete inside of;
    /// fed to `safety::protected::validate_deletable`. Unused by `Cmd`-action
    /// rules, whose candidates are informational only.
    pub allowed_prefixes: &'static [&'static str],
    pub detector: Detector,
    pub action: Action,
    pub notes: &'static str,
}

/// Root-relative or `~`-relative path spec to a real path, given a `Ctx`.
pub fn expand_path_spec(spec: &str, ctx: &Ctx) -> PathBuf {
    expand_path_spec_parts(spec, &ctx.root, &ctx.home)
}

/// Same as `expand_path_spec`, but for callers (like the privileged helper)
/// that have a root/home pair without a full `Ctx` to hand.
pub fn expand_path_spec_parts(
    spec: &str,
    root: &std::path::Path,
    home: &std::path::Path,
) -> PathBuf {
    if let Some(rest) = spec.strip_prefix("~/") {
        home.join(rest)
    } else if spec == "~" {
        home.to_path_buf()
    } else if let Some(rest) = spec.strip_prefix('/') {
        root.join(rest)
    } else {
        PathBuf::from(spec)
    }
}

pub fn registry() -> Vec<Rule> {
    let mut rules = Vec::new();
    rules.extend(user::rules());
    rules.extend(dev::rules());
    rules.extend(command::rules());
    rules
}

/// Real `/proc/*/comm` scan, always live (no sandboxing awareness) so it can
/// be exercised directly in tests against a spawned process.
fn is_process_running(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let pid = entry.file_name();
        if !pid.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm"))
            && comm.trim() == name
        {
            return true;
        }
    }
    false
}

/// Whether a process named `name` (exact `/proc/<pid>/comm` match) is
/// currently running. Always false while `ctx.sandboxed`, since tests must
/// never depend on — or be able to spoof — the real system's process table.
pub fn process_running(name: &str, ctx: &Ctx) -> bool {
    if ctx.sandboxed {
        return false;
    }
    is_process_running(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(root: PathBuf, home: PathBuf) -> Ctx {
        Ctx {
            root,
            home,
            config_dir: PathBuf::new(),
            state_dir: PathBuf::new(),
            dry_run: false,
            debug: false,
            config: Config::default(),
            sandboxed: true,
            available_commands: None,
        }
    }

    #[test]
    fn test_expand_home_relative_spec() {
        let c = ctx(PathBuf::from("/root"), PathBuf::from("/root/home/user"));
        assert_eq!(
            expand_path_spec("~/.cache/thumbnails", &c),
            PathBuf::from("/root/home/user/.cache/thumbnails")
        );
    }

    #[test]
    fn test_expand_bare_tilde() {
        let c = ctx(PathBuf::from("/root"), PathBuf::from("/root/home/user"));
        assert_eq!(expand_path_spec("~", &c), PathBuf::from("/root/home/user"));
    }

    #[test]
    fn test_expand_root_relative_spec() {
        let c = ctx(PathBuf::from("/root"), PathBuf::from("/root/home/user"));
        assert_eq!(
            expand_path_spec("/var/cache/pacman/pkg", &c),
            PathBuf::from("/root/var/cache/pacman/pkg")
        );
    }

    #[test]
    fn test_registry_ids_are_unique() {
        let rules = registry();
        assert!(!rules.is_empty());
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids, deduped, "duplicate rule id in registry()");
    }

    #[test]
    fn test_process_running_is_false_when_sandboxed_even_if_really_running() {
        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .spawn()
            .unwrap();
        let c = ctx(PathBuf::from("/root"), PathBuf::from("/root/home/user"));
        assert!(c.sandboxed);
        assert!(!process_running("sleep", &c));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn test_process_running_detects_a_real_running_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .spawn()
            .unwrap();
        let mut c = ctx(PathBuf::from("/root"), PathBuf::from("/root/home/user"));
        c.sandboxed = false;
        assert!(process_running("sleep", &c));
        let _ = child.kill();
        let _ = child.wait();
        assert!(!process_running("no-such-process-xyz", &c));
    }
}
