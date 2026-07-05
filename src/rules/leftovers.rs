//! EXPERIMENTAL: `leftovers.orphan_configs` guesses at config/data/cache
//! directories left behind by an app that's since been uninstalled. This is
//! inherently a heuristic — there is no reliable way to prove a directory
//! "belongs" to nothing — so every one of the five conditions below is
//! deliberately fail-closed: any doubt (no package data, a short/ambiguous
//! name, an unreadable mtime, ...) keeps the directory rather than offering
//! it. Only reachable via `badger clean --experimental` (see
//! `rules::registry`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::core::runner::runner_for;
use crate::core::scan::display_label;
use crate::ctx::Ctx;
use crate::pkg::flatpak;
use crate::rules::{Action, Applicability, Detector, Rule};

/// Curated names under `~/.config`, `~/.local/share`, `~/.cache` that are
/// never orphan candidates regardless of package/desktop-file evidence —
/// shared infrastructure directories no single package "owns".
const KEEP_LIST: &[&str] = &[
    "gtk-2.0",
    "gtk-3.0",
    "gtk-4.0",
    "dconf",
    "pulse",
    "systemd",
    "fontconfig",
    "autostart",
    "applications",
    "icons",
    "themes",
    "fonts",
    "mime",
    "nvim",
    "trash",
    "badger",
    "pipewire",
    "wireplumber",
];

pub fn rules() -> Vec<Rule> {
    vec![Rule {
        id: "leftovers.orphan_configs",
        title: "Orphaned app leftovers (experimental)",
        risk: Risk::Risky,
        // Must stay false: a heuristic guess must never gain root-deletion trust via the helper's registry(true).
        requires_sudo: false,
        applicable: Applicability::CommandExists("pacman"),
        allowed_prefixes: &["~/.config", "~/.local/share", "~/.cache"],
        detector: Detector::Fn(orphan_configs_detector),
        action: Action::DeletePaths,
        notes: "Directories under ~/.config, ~/.local/share, and ~/.cache that look like they \
                belong to no installed package. This detection is a heuristic and can \
                misidentify — review every item before deleting. Only offered with \
                --experimental.",
    }]
}

/// Lowercased, leading-dots-stripped form used for every name comparison
/// below (package match, keep-list, desktop-file scan).
fn normalize(name: &str) -> String {
    name.trim_start_matches('.').to_lowercase()
}

/// Whether installed name `p` and candidate `name` refer to the same app.
/// Exact match always counts; a substring match only counts when the
/// *shorter* of the two is at least 3 chars — otherwise a short package name
/// like `bc` would "own" every directory that happens to contain those
/// letters (e.g. `abc`).
fn names_match(p: &str, name: &str) -> bool {
    if p == name {
        return true;
    }
    let shorter = p.len().min(name.len());
    shorter >= 3 && (p.contains(name) || name.contains(p))
}

fn package_matches(installed: &HashSet<String>, name: &str) -> bool {
    installed.iter().any(|p| names_match(p, name))
}

/// `pacman -Qq`, one installed package name per line. Returns `None` if the
/// command errors, fails, or succeeds with zero package names — a real Arch
/// system always has packages installed, so an empty result is itself a
/// signal that something's wrong (not a system with nothing on it) and must
/// fail closed exactly like the error path: condition 1 (no installed-package
/// evidence) means no guesses at all, so the whole detector bails out to zero
/// candidates.
fn installed_pacman_names(ctx: &Ctx) -> Option<HashSet<String>> {
    let runner = runner_for(ctx);
    let argv = vec!["pacman".to_string(), "-Qq".to_string()];
    match runner.run(&argv) {
        Ok(out) if out.success => {
            let names: HashSet<String> = out
                .stdout
                .lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty())
                .collect();
            if names.is_empty() { None } else { Some(names) }
        }
        _ => None,
    }
}

/// Flatpak app IDs, each contributing both the full id and its last
/// dot-segment (`org.mozilla.firefox` -> `org.mozilla.firefox`, `firefox`).
/// Flatpak simply being absent is not a failure here — condition 1's
/// fail-closed behavior is pacman-specific (see `installed_pacman_names`).
fn installed_flatpak_names(ctx: &Ctx) -> HashSet<String> {
    if !flatpak::is_available(ctx) {
        return HashSet::new();
    }
    let mut names = HashSet::new();
    for pkg in flatpak::list(ctx) {
        let id = pkg.id.to_lowercase();
        if let Some(last) = id.rsplit('.').next() {
            names.insert(last.to_string());
        }
        names.insert(id);
    }
    names
}

/// The two non-recursive `.desktop` directories checked for condition 2.
fn desktop_dirs(ctx: &Ctx) -> [PathBuf; 2] {
    [
        ctx.home.join(".local/share/applications"),
        ctx.root.join("usr/share/applications"),
    ]
}

/// Whether any `Exec=`/`Name=` line in a top-level `.desktop` file
/// (case-insensitively) references `name`. A name shorter than 3 chars is
/// too ambiguous to search for reliably, so it's treated as referenced
/// (fail closed: not offered) regardless of what's on disk.
fn referenced_in_desktop_files(name: &str, ctx: &Ctx) -> bool {
    if name.len() < 3 {
        return true;
    }
    for dir in desktop_dirs(ctx) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            let referenced = contents.lines().any(|line| {
                line.strip_prefix("Exec=")
                    .or_else(|| line.strip_prefix("Name="))
                    .is_some_and(|value| value.to_lowercase().contains(name))
            });
            if referenced {
                return true;
            }
        }
    }
    false
}

/// Condition 3: the curated keep-list plus hidden (dot-prefixed) directories,
/// which are never candidates regardless of package/desktop-file evidence.
fn is_kept(raw_name: &str, normalized: &str) -> bool {
    raw_name.starts_with('.')
        || raw_name == "Trash"
        || KEEP_LIST.contains(&normalized)
        || normalized.starts_with("kde")
        || normalized.starts_with("plasma")
}

/// Condition 4: mtime older than `min_age_days`. An unreadable mtime fails
/// closed (not a candidate) rather than guessing.
fn is_old_enough(path: &Path, min_age_days: u32) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified()) else {
        return false;
    };
    let max_age = Duration::from_secs(u64::from(min_age_days) * 86_400);
    match SystemTime::now().checked_sub(max_age) {
        Some(cutoff) => modified <= cutoff,
        None => false,
    }
}

/// Real `/proc` scan for condition 5, always live (no sandboxing awareness)
/// so it can be exercised directly against a spawned process — mirrors
/// `rules::is_process_running`'s split between a live scan and a
/// ctx-gated wrapper. `proc_dir` is parameterized (always `/proc` in
/// production) so the read-error path can be exercised in a test. An
/// unreadable `proc_dir` means process state is unknown, and unknown must
/// fail closed toward "in use" (keep the directory) rather than toward
/// deletion.
fn is_process_using_path(dir: &Path, proc_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(proc_dir) else {
        return true;
    };
    for entry in entries.flatten() {
        let pid = entry.file_name();
        if !pid.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        for link in ["cwd", "exe"] {
            if let Ok(target) = std::fs::read_link(entry.path().join(link))
                && target.starts_with(dir)
            {
                return true;
            }
        }
    }
    false
}

/// Whether some running process is using `dir` as its cwd or executable —
/// always false while `ctx.sandboxed`, since tests must never depend on the
/// real system's process table.
fn process_using_path(dir: &Path, ctx: &Ctx) -> bool {
    if ctx.sandboxed {
        return false;
    }
    is_process_using_path(dir, Path::new("/proc"))
}

fn orphan_configs_detector(ctx: &Ctx, config: &Config) -> Vec<Candidate> {
    let Some(mut installed) = installed_pacman_names(ctx) else {
        return Vec::new();
    };
    installed.extend(installed_flatpak_names(ctx));

    let trees = [
        ctx.home.join(".config"),
        ctx.home.join(".local/share"),
        ctx.home.join(".cache"),
    ];

    let mut out = Vec::new();
    for tree in &trees {
        let Ok(entries) = std::fs::read_dir(tree) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            // Files and symlinks (even ones pointing at a directory) are
            // never candidates — only real top-level directories are.
            if !metadata.is_dir() {
                continue;
            }

            let raw_name = entry.file_name().to_string_lossy().into_owned();
            let normalized = normalize(&raw_name);

            if is_kept(&raw_name, &normalized) {
                continue;
            }
            if package_matches(&installed, &normalized) {
                continue;
            }
            if referenced_in_desktop_files(&normalized, ctx) {
                continue;
            }
            if !is_old_enough(&path, config.clean.orphan_min_age_days) {
                continue;
            }
            if process_using_path(&path, ctx) {
                continue;
            }

            let label = format!("{} (experimental guess)", display_label(&path, ctx));
            out.push(Candidate::new(Some(path), label, 0, Risk::Risky));
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::runner::CmdOutput;
    use crate::core::scan::scan;
    use crate::safety::whitelist;
    use std::collections::HashMap;

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
        whitelist::parse("", std::path::Path::new("/home/user")).unwrap()
    }

    fn pacman_qq_argv() -> Vec<String> {
        vec!["pacman".to_string(), "-Qq".to_string()]
    }

    fn cmd_output(stdout: &str) -> CmdOutput {
        CmdOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn pacman_output(names: &[&str]) -> HashMap<Vec<String>, CmdOutput> {
        HashMap::from([(
            pacman_qq_argv(),
            cmd_output(&format!("{}\n", names.join("\n"))),
        )])
    }

    fn flatpak_list_argv() -> Vec<String> {
        vec![
            "flatpak".to_string(),
            "list".to_string(),
            "--app".to_string(),
            "--columns=application,name,version".to_string(),
        ]
    }

    /// Creates `~/.config/<name>` aged `days_old` days, returns its path.
    fn aged_dir(ctx: &Ctx, subtree: &str, name: &str, days_old: u64) -> PathBuf {
        let dir = ctx.home.join(subtree).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let old = SystemTime::now() - Duration::from_secs(days_old * 86_400);
        let f = std::fs::File::open(&dir).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        dir
    }

    fn labels(candidates: &[Candidate]) -> Vec<String> {
        candidates.iter().map(|c| c.label.clone()).collect()
    }

    // --- condition 1: package match ---

    #[test]
    fn test_unmatched_old_dir_is_a_candidate_labeled_with_experimental_guess_suffix() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert_eq!(
            labels(&candidates),
            vec!["~/.config/oldapp (experimental guess)".to_string()]
        );
    }

    #[test]
    fn test_exact_installed_package_name_excludes_the_dir() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["oldapp"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_substring_match_both_ways_excludes_the_dir() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["oldapp-extras"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_short_package_name_does_not_own_a_dir_via_substring() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "abc", 200);
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["bc"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert_eq!(
            labels(&candidates),
            vec!["~/.config/abc (experimental guess)".to_string()]
        );
    }

    #[test]
    fn test_flatpak_last_segment_match_excludes_the_dir() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let mut ctx = f.ctx;
        ctx.available_commands = Some(vec!["flatpak".to_string()]);
        ctx.fake_command_output = Some({
            let mut m = pacman_output(&["unrelated-pkg"]);
            m.insert(
                flatpak_list_argv(),
                cmd_output("org.foo.OldApp\tOld App\t1.0\n"),
            );
            m
        });

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_pacman_erroring_yields_zero_candidates_fail_closed() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(HashMap::new());

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_pacman_success_with_empty_stdout_yields_zero_candidates_fail_closed() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(HashMap::from([(pacman_qq_argv(), cmd_output(""))]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    // --- condition 2: desktop-file reference ---

    #[test]
    fn test_desktop_exec_reference_under_home_applications_excludes_the_dir() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let apps_dir = f.ctx.home.join(".local/share/applications");
        std::fs::create_dir_all(&apps_dir).unwrap();
        std::fs::write(apps_dir.join("oldapp.desktop"), "Exec=/opt/oldapp/run\n").unwrap();
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_desktop_reference_under_root_usr_share_applications_excludes_the_dir() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let apps_dir = f.ctx.root.join("usr/share/applications");
        std::fs::create_dir_all(&apps_dir).unwrap();
        std::fs::write(apps_dir.join("oldapp.desktop"), "Name=OldApp\n").unwrap();
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_unrelated_desktop_file_does_not_exclude_the_dir() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        let apps_dir = f.ctx.home.join(".local/share/applications");
        std::fs::create_dir_all(&apps_dir).unwrap();
        std::fs::write(apps_dir.join("other.desktop"), "Exec=/opt/other/run\n").unwrap();
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert_eq!(
            labels(&candidates),
            vec!["~/.config/oldapp (experimental guess)".to_string()]
        );
    }

    #[test]
    fn test_name_shorter_than_three_chars_is_never_a_candidate() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "ab", 200);
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    // --- condition 3: keep-list ---

    #[test]
    fn test_keep_list_and_hidden_dirs_are_never_candidates() {
        let f = fixture();
        for name in ["gtk-4.0", "kdeconnect", "plasmashell", ".hidden"] {
            aged_dir(&f.ctx, ".local/share", name, 200);
        }
        let trash = f.ctx.home.join(".local/share/Trash");
        std::fs::create_dir_all(&trash).unwrap();
        let old = SystemTime::now() - Duration::from_secs(200 * 86_400);
        std::fs::File::open(&trash)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        aged_dir(&f.ctx, ".config", "oldapp", 200);

        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert_eq!(
            labels(&candidates),
            vec!["~/.config/oldapp (experimental guess)".to_string()]
        );
    }

    // --- condition 4: age ---

    #[test]
    fn test_fresh_dir_is_not_a_candidate() {
        let f = fixture();
        let dir = f.ctx.home.join(".config/oldapp");
        std::fs::create_dir_all(&dir).unwrap();
        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_config_orphan_min_age_days_override_is_respected() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 20);
        let mut ctx = f.ctx;
        ctx.config.clean.orphan_min_age_days = 10;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        assert_eq!(
            labels(&candidates),
            vec!["~/.config/oldapp (experimental guess)".to_string()]
        );
    }

    // --- condition 5: process using the path ---

    #[test]
    fn test_is_process_using_path_detects_a_real_process_cwd() {
        let sandbox = tempfile::tempdir().unwrap();
        let used_dir = sandbox.path().join("used");
        std::fs::create_dir_all(&used_dir).unwrap();
        let unrelated_dir = sandbox.path().join("unrelated");
        std::fs::create_dir_all(&unrelated_dir).unwrap();

        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .current_dir(&used_dir)
            .spawn()
            .unwrap();

        let proc_dir = Path::new("/proc");
        assert!(is_process_using_path(&used_dir, proc_dir));
        assert!(!is_process_using_path(&unrelated_dir, proc_dir));

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn test_is_process_using_path_read_dir_error_fails_closed_as_in_use() {
        let f = fixture();
        let dir = f.ctx.home.join("somedir");
        std::fs::create_dir_all(&dir).unwrap();
        let missing_proc_dir = f.ctx.root.join("proc");

        assert!(is_process_using_path(&dir, &missing_proc_dir));
    }

    // --- registry gating (see also rules::mod tests) ---

    #[test]
    fn test_registry_true_includes_leftovers_rule() {
        let rules = crate::rules::registry(true);
        assert!(rules.iter().any(|r| r.id == "leftovers.orphan_configs"));
        let rules = crate::rules::registry(false);
        assert!(!rules.iter().any(|r| r.id == "leftovers.orphan_configs"));
    }

    // --- top-level-only, dirs-only ---

    #[test]
    fn test_file_nested_dir_and_symlink_are_never_candidates() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".config")).unwrap();
        std::fs::write(f.ctx.home.join(".config/stray.conf"), b"x").unwrap();

        let nested_target = f.ctx.home.join(".config/keep/nested-oldapp");
        std::fs::create_dir_all(&nested_target).unwrap();
        let old = SystemTime::now() - Duration::from_secs(200 * 86_400);
        std::fs::File::open(&nested_target)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();

        let real_dir = aged_dir(&f.ctx, ".config", "reallyold", 200);
        let symlink_path = f.ctx.home.join(".config/linked");
        std::os::unix::fs::symlink(&real_dir, &symlink_path).unwrap();

        let mut ctx = f.ctx;
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let candidates = orphan_configs_detector(&ctx, &ctx.config.clone());
        // Only the top-level "reallyold" and "keep" dirs are ever scanned;
        // "keep" itself doesn't match any exclusion so it also becomes a
        // candidate, but "nested-oldapp" (nested) and "linked" (symlink)
        // must never appear.
        assert!(!labels(&candidates).iter().any(|l| l.contains("linked")));
        assert!(
            !labels(&candidates)
                .iter()
                .any(|l| l.contains("nested-oldapp"))
        );
        assert!(!labels(&candidates).iter().any(|l| l.contains("stray")));
    }

    // --- end-to-end sandbox tree via full scan() ---

    #[test]
    fn test_full_scan_orphan_is_risky_unselectable_and_whitelisted_one_is_greyed() {
        let f = fixture();
        aged_dir(&f.ctx, ".config", "oldapp", 200);
        aged_dir(&f.ctx, ".config", "oldapp2", 200);

        let mut ctx = f.ctx;
        ctx.available_commands = Some(vec!["pacman".to_string()]);
        ctx.fake_command_output = Some(pacman_output(&["unrelated-pkg"]));

        let wl = whitelist::parse("~/.config/oldapp2", &ctx.home).unwrap();
        let groups = scan(
            &crate::rules::registry(true),
            &ctx,
            &ctx.config.clone(),
            &wl,
        )
        .unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "leftovers.orphan_configs")
            .unwrap();

        let orphan = group
            .candidates
            .iter()
            .find(|c| c.label.starts_with("~/.config/oldapp "))
            .unwrap();
        assert!(!orphan.selectable, "Risky defaults to unselectable");
        assert!(orphan.label.ends_with("(experimental guess)"));

        let whitelisted = group
            .candidates
            .iter()
            .find(|c| c.label.starts_with("~/.config/oldapp2"))
            .unwrap();
        assert!(whitelisted.whitelisted);
        assert!(!whitelisted.selectable);
    }

    #[test]
    fn test_orphan_rule_absent_without_pacman_command() {
        let f = fixture();
        let groups = scan(
            &crate::rules::registry(true),
            &f.ctx,
            &f.ctx.config.clone(),
            &empty_whitelist(),
        )
        .unwrap();
        assert!(
            !groups
                .iter()
                .any(|g| g.rule_id == "leftovers.orphan_configs")
        );
    }
}
