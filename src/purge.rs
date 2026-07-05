//! `badger purge` scanner: finds context-gated build/dependency artifacts
//! (`node_modules`, Rust `target/`, Python virtualenvs, ...) under the
//! configured project roots. Deliberately separate from `rules::registry()`
//! — these aren't static rules, they're a config-driven recursive walk, but
//! the result is shaped as the same `Group`/`Candidate` types so the rest of
//! the pipeline (TUI checklist, JSON output, journaling) needs no purge-
//! specific code.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::core::item::{Candidate, Group, Risk};
use crate::core::scan::display_label;
use crate::ctx::Ctx;
use crate::rules::expand_path_spec;
use crate::safety::protected::{SafetyEnv, Tier, validate_deletable};
use crate::safety::whitelist::Whitelist;
use crate::util::dirsize::dir_size;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    NodeModules,
    CargoTarget,
    PyVenv,
    DistBuild,
    NextBuild,
    Pycache,
    Gradle,
    MypyCache,
    PytestCache,
}

const ALL_KINDS: [ArtifactKind; 9] = [
    ArtifactKind::NodeModules,
    ArtifactKind::CargoTarget,
    ArtifactKind::PyVenv,
    ArtifactKind::DistBuild,
    ArtifactKind::NextBuild,
    ArtifactKind::Pycache,
    ArtifactKind::Gradle,
    ArtifactKind::MypyCache,
    ArtifactKind::PytestCache,
];

impl ArtifactKind {
    fn rule_id(self) -> &'static str {
        match self {
            ArtifactKind::NodeModules => "purge.node_modules",
            ArtifactKind::CargoTarget => "purge.cargo_target",
            ArtifactKind::PyVenv => "purge.py_venv",
            ArtifactKind::DistBuild => "purge.dist_build",
            ArtifactKind::NextBuild => "purge.next_build",
            ArtifactKind::Pycache => "purge.pycache",
            ArtifactKind::Gradle => "purge.gradle",
            ArtifactKind::MypyCache => "purge.mypy_cache",
            ArtifactKind::PytestCache => "purge.pytest_cache",
        }
    }

    fn title(self) -> &'static str {
        match self {
            ArtifactKind::NodeModules => "node_modules directories",
            ArtifactKind::CargoTarget => "Rust target/ directories",
            ArtifactKind::PyVenv => "Python virtualenvs",
            ArtifactKind::DistBuild => "dist/build directories",
            ArtifactKind::NextBuild => "Next.js build cache (.next)",
            ArtifactKind::Pycache => "Python __pycache__ directories",
            ArtifactKind::Gradle => "Gradle build cache (.gradle)",
            ArtifactKind::MypyCache => "mypy cache (.mypy_cache)",
            ArtifactKind::PytestCache => "pytest cache (.pytest_cache)",
        }
    }
}

/// Scans every configured `purge.roots` entry that exists and returns one
/// `Group` per artifact kind (always all nine, even if empty — same
/// convention `rules::registry()`'s groups follow). Missing roots are
/// skipped silently; the caller logs them under `--debug` if it wants to.
/// `whitelist` is the user's `~/.config/badger/whitelist` — a match greys the
/// candidate out exactly like `core::scan`'s rule-registry scan does.
pub fn scan(ctx: &Ctx, config: &Config, whitelist: &Whitelist) -> anyhow::Result<Vec<Group>> {
    let env = SafetyEnv::from_system(ctx)?;
    let allowed: Vec<PathBuf> = config
        .purge
        .roots
        .iter()
        .map(|r| expand_path_spec(r, ctx))
        .collect();

    let mut found: Vec<(ArtifactKind, PathBuf)> = Vec::new();
    for root in &allowed {
        if root.is_dir() {
            walk_dir(root, &mut found);
        }
    }

    let max_age = Duration::from_secs(u64::from(config.purge.recent_days) * 86_400);
    let cutoff = SystemTime::now().checked_sub(max_age);

    let mut groups: Vec<Group> = ALL_KINDS
        .iter()
        .map(|kind| Group {
            rule_id: kind.rule_id().to_string(),
            title: kind.title().to_string(),
            risk: Risk::Safe,
            requires_sudo: false,
            candidates: Vec::new(),
            skipped: Vec::new(),
        })
        .collect();

    for (kind, path) in found {
        let group = &mut groups[ALL_KINDS.iter().position(|k| *k == kind).unwrap()];
        if let Err(refusal) = validate_deletable(&path, &allowed, Tier::User, &env) {
            group
                .skipped
                .push((display_label(&path, ctx), refusal.to_string()));
            continue;
        }

        let bytes = dir_size(&path);
        let mut label = display_label(&path, ctx);
        let mut candidate = Candidate::new(Some(path.clone()), label.clone(), bytes, Risk::Safe);
        if whitelist.matches(&path) {
            candidate.whitelisted = true;
            candidate.selectable = false;
        }
        if is_recent(&path, cutoff) {
            candidate.selectable = false;
            label.push_str(" (recent)");
            candidate.label = label;
        }
        group.candidates.push(candidate);
    }

    Ok(groups)
}

/// "Recent" means the artifact's *parent* (the project directory) was
/// modified more recently than `config.purge.recent_days` ago — a project
/// someone touched this week probably isn't done with its build output yet.
fn is_recent(artifact_path: &Path, cutoff: Option<SystemTime>) -> bool {
    let Some(cutoff) = cutoff else { return false };
    let Some(parent) = artifact_path.parent() else {
        return false;
    };
    std::fs::symlink_metadata(parent)
        .and_then(|m| m.modified())
        .is_ok_and(|mtime| mtime > cutoff)
}

/// Recursively walks `dir`, collecting every context-gated artifact found.
/// Never descends into a matched artifact (no `node_modules` inside
/// `node_modules`) and never descends into a hidden directory that wasn't
/// itself a match — `__pycache__`/`.mypy_cache`/`.pytest_cache` are found at
/// any depth precisely because ordinary (non-hidden) project directories are
/// still walked all the way down.
fn walk_dir(dir: &Path, found: &mut Vec<(ArtifactKind, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();

        if let Some(kind) = classify(&path, &name, dir) {
            found.push((kind, path));
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        walk_dir(&path, found);
    }
}

/// Decides whether `path` (named `name`, living in `parent`) is one of our
/// known artifact kinds. Each kind is gated on the sibling/inner file that
/// makes it recognizable as a *project's* build output rather than a
/// coincidentally-named directory.
fn classify(path: &Path, name: &str, parent: &Path) -> Option<ArtifactKind> {
    match name {
        "node_modules" => {
            is_file(&parent.join("package.json")).then_some(ArtifactKind::NodeModules)
        }
        "target" => is_file(&parent.join("Cargo.toml")).then_some(ArtifactKind::CargoTarget),
        ".venv" | "venv" => is_file(&path.join("pyvenv.cfg")).then_some(ArtifactKind::PyVenv),
        "dist" | "build" => {
            let gated = is_file(&parent.join("package.json"))
                || is_file(&parent.join("setup.py"))
                || is_file(&parent.join("pyproject.toml"));
            gated.then_some(ArtifactKind::DistBuild)
        }
        ".next" => is_file(&parent.join("package.json")).then_some(ArtifactKind::NextBuild),
        "__pycache__" => Some(ArtifactKind::Pycache),
        ".gradle" => has_prefixed_sibling(parent, "build.gradle").then_some(ArtifactKind::Gradle),
        ".mypy_cache" => Some(ArtifactKind::MypyCache),
        ".pytest_cache" => Some(ArtifactKind::PytestCache),
        _ => None,
    }
}

fn is_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
}

fn has_prefixed_sibling(dir: &Path, prefix: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _sandbox: tempfile::TempDir,
        ctx: Ctx,
    }

    fn fixture() -> Fixture {
        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let home = root.join("home/user");
        std::fs::create_dir_all(&home).unwrap();
        let mut ctx = Ctx {
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
        ctx.config.purge.roots = vec!["~/dev".to_string()];
        Fixture {
            _sandbox: sandbox,
            ctx,
        }
    }

    fn group<'a>(groups: &'a [Group], rule_id: &str) -> &'a Group {
        groups.iter().find(|g| g.rule_id == rule_id).unwrap()
    }

    fn empty_whitelist() -> Whitelist {
        crate::safety::whitelist::parse("", Path::new("/home/user")).unwrap()
    }

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    /// Backdates `dir`'s mtime well past the default `recent_days` cutoff, so
    /// tests that aren't specifically about the recency badge don't have to
    /// account for "(recent)" showing up in freshly-created fixture dirs.
    /// Directories can only be opened read-only on Linux, but `set_times`
    /// doesn't need write access.
    fn age(dir: &Path) {
        let old = SystemTime::now() - Duration::from_secs(30 * 86_400);
        std::fs::File::open(dir)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
    }

    #[test]
    fn test_finds_node_modules_with_sibling_package_json() {
        let f = fixture();
        let project = f.ctx.home.join("dev/site");
        touch(&project.join("package.json"));
        std::fs::create_dir_all(project.join("node_modules/left-pad")).unwrap();
        age(&project);

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.node_modules");
        assert_eq!(g.candidates.len(), 1);
        assert_eq!(g.candidates[0].label, "~/dev/site/node_modules");
    }

    #[test]
    fn test_target_without_sibling_cargo_toml_is_not_matched() {
        let f = fixture();
        // A "target" dir with no Cargo.toml next to it — must not be picked up.
        std::fs::create_dir_all(f.ctx.home.join("dev/random/target")).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(group(&groups, "purge.cargo_target").candidates.is_empty());
    }

    #[test]
    fn test_finds_cargo_target_with_sibling_cargo_toml() {
        let f = fixture();
        let project = f.ctx.home.join("dev/rustapp");
        touch(&project.join("Cargo.toml"));
        std::fs::create_dir_all(project.join("target/debug")).unwrap();
        age(&project);

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.cargo_target");
        assert_eq!(g.candidates.len(), 1);
        assert_eq!(g.candidates[0].label, "~/dev/rustapp/target");
    }

    #[test]
    fn test_finds_venv_with_pyvenv_cfg_inside_but_not_without_it() {
        let f = fixture();
        let project = f.ctx.home.join("dev/pyapp");
        std::fs::create_dir_all(project.join(".venv")).unwrap();
        touch(&project.join(".venv/pyvenv.cfg"));
        std::fs::create_dir_all(project.join("other_venv_lookalike")).unwrap();
        age(&project);

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.py_venv");
        assert_eq!(g.candidates.len(), 1);
        assert_eq!(g.candidates[0].label, "~/dev/pyapp/.venv");
    }

    #[test]
    fn test_finds_dist_and_build_gated_by_setup_py_or_package_json() {
        let f = fixture();
        let node_project = f.ctx.home.join("dev/node-thing");
        touch(&node_project.join("package.json"));
        std::fs::create_dir_all(node_project.join("dist")).unwrap();
        age(&node_project);

        let py_project = f.ctx.home.join("dev/py-thing");
        touch(&py_project.join("setup.py"));
        std::fs::create_dir_all(py_project.join("build")).unwrap();
        age(&py_project);

        let ungated = f.ctx.home.join("dev/random-dir");
        std::fs::create_dir_all(ungated.join("dist")).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.dist_build");
        let mut labels: Vec<_> = g.candidates.iter().map(|c| c.label.clone()).collect();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                "~/dev/node-thing/dist".to_string(),
                "~/dev/py-thing/build".to_string(),
            ]
        );
    }

    #[test]
    fn test_finds_next_build_cache_with_sibling_package_json() {
        let f = fixture();
        let project = f.ctx.home.join("dev/nextapp");
        touch(&project.join("package.json"));
        std::fs::create_dir_all(project.join(".next")).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert_eq!(group(&groups, "purge.next_build").candidates.len(), 1);
    }

    #[test]
    fn test_finds_pycache_anywhere_without_gating() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join("dev/a/b/__pycache__")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join("dev/__pycache__")).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert_eq!(group(&groups, "purge.pycache").candidates.len(), 2);
    }

    #[test]
    fn test_finds_gradle_cache_with_sibling_build_gradle() {
        let f = fixture();
        let project = f.ctx.home.join("dev/gradleapp");
        touch(&project.join("build.gradle.kts"));
        std::fs::create_dir_all(project.join(".gradle")).unwrap();
        age(&project);

        let no_gradle_file = f.ctx.home.join("dev/notgradle");
        std::fs::create_dir_all(no_gradle_file.join(".gradle")).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.gradle");
        assert_eq!(g.candidates.len(), 1);
        assert_eq!(g.candidates[0].label, "~/dev/gradleapp/.gradle");
    }

    #[test]
    fn test_finds_mypy_and_pytest_caches() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join("dev/pyapp/.mypy_cache")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join("dev/pyapp/.pytest_cache")).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert_eq!(group(&groups, "purge.mypy_cache").candidates.len(), 1);
        assert_eq!(group(&groups, "purge.pytest_cache").candidates.len(), 1);
    }

    #[test]
    fn test_does_not_recurse_into_a_matched_node_modules() {
        let f = fixture();
        let project = f.ctx.home.join("dev/site");
        touch(&project.join("package.json"));
        // A nested node_modules-inside-node_modules must not be counted separately.
        std::fs::create_dir_all(project.join("node_modules/some-pkg/node_modules/inner")).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert_eq!(group(&groups, "purge.node_modules").candidates.len(), 1);
    }

    #[test]
    fn test_recent_project_is_badged_and_starts_unchecked() {
        let f = fixture();
        let project = f.ctx.home.join("dev/freshsite");
        touch(&project.join("package.json"));
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        // Default mtime (just created) is "now" — well within recent_days.

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.node_modules");
        assert_eq!(g.candidates.len(), 1);
        assert!(g.candidates[0].label.ends_with("(recent)"));
        assert!(
            !g.candidates[0].selectable,
            "recent artifacts start unchecked"
        );
    }

    #[test]
    fn test_old_project_has_no_badge_and_is_precheck() {
        let f = fixture();
        let project = f.ctx.home.join("dev/oldsite");
        touch(&project.join("package.json"));
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        age(&project);

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.node_modules");
        assert_eq!(g.candidates.len(), 1);
        assert!(!g.candidates[0].label.contains("(recent)"));
        assert!(
            g.candidates[0].selectable,
            "old artifacts start pre-checked"
        );
    }

    #[test]
    fn test_byte_count_reflects_directory_size() {
        let f = fixture();
        let project = f.ctx.home.join("dev/site");
        touch(&project.join("package.json"));
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        std::fs::write(project.join("node_modules/big.bin"), vec![0u8; 8192]).unwrap();

        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.node_modules");
        assert!(g.candidates[0].bytes > 0);
    }

    #[test]
    fn test_missing_root_yields_empty_groups_without_error() {
        let f = fixture();
        // ~/dev was never created.
        let groups = scan(&f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert_eq!(groups.len(), 9);
        assert!(groups.iter().all(|g| g.candidates.is_empty()));
    }

    #[test]
    fn test_too_shallow_candidate_is_recorded_as_skipped_not_silently_dropped() {
        let f = fixture();
        // Point a purge root directly at home itself, so a node_modules found
        // right under it trips validate_deletable's "too shallow" guard.
        let mut ctx = f.ctx.clone();
        ctx.config.purge.roots = vec!["~".to_string()];
        touch(&ctx.home.join("package.json"));
        std::fs::create_dir_all(ctx.home.join("node_modules")).unwrap();

        let groups = scan(&ctx, &ctx.config.clone(), &empty_whitelist()).unwrap();
        let g = group(&groups, "purge.node_modules");
        assert!(g.candidates.is_empty());
        assert_eq!(g.skipped.len(), 1);
    }

    #[test]
    // Bug: purge::scan never consulted the user's whitelist, so a
    // whitelisted artifact was offered as a normal, pre-checked deletable
    // candidate — the opposite of the whitelist's "never touch this"
    // contract. Root cause: finish_deletable_candidates in core/scan.rs
    // applies the whitelist, but purge::scan built candidates on its own and
    // skipped that step entirely.
    fn test_whitelisted_artifact_is_greyed_out_and_unselectable() {
        let f = fixture();
        let project = f.ctx.home.join("dev/site");
        touch(&project.join("package.json"));
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        age(&project);

        let wl = crate::safety::whitelist::parse("~/dev/site/node_modules", &f.ctx.home).unwrap();
        let groups = scan(&f.ctx, &f.ctx.config.clone(), &wl).unwrap();
        let g = group(&groups, "purge.node_modules");

        assert_eq!(g.candidates.len(), 1);
        assert!(g.candidates[0].whitelisted);
        assert!(!g.candidates[0].selectable);
    }
}
