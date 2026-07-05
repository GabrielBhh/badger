use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::ctx::Ctx;
use crate::rules::{Action, Applicability, Detector, Rule, process_running};

/// `~/.cache` children owned by a more specific rule and never offered
/// generically here.
const CACHE_APPS_EXCLUDE: &[&str] = &["thumbnails", "paru", "pip", "go-build"];

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "user.cache_apps",
            title: "Application caches",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.cache"],
            detector: Detector::Fn(cache_apps_detector),
            action: Action::DeletePaths,
            notes: "Per-app caches under ~/.cache; apps rebuild these as needed.",
        },
        Rule {
            id: "user.thumbnails",
            title: "Thumbnail cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.cache/thumbnails"],
            detector: Detector::Globs(&["~/.cache/thumbnails"]),
            action: Action::DeletePaths,
            notes: "File managers regenerate thumbnails on demand.",
        },
        Rule {
            id: "user.trash",
            title: "Trash",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.local/share/Trash/files"],
            detector: Detector::Fn(trash_detector),
            action: Action::DeletePaths,
            notes: "Items older than the configured trash retention.",
        },
    ]
}

fn cache_apps_detector(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let cache_dir = ctx.home.join(".cache");
    let Ok(entries) = std::fs::read_dir(&cache_dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if CACHE_APPS_EXCLUDE.contains(&name.as_str()) {
            continue;
        }
        let mut candidate = Candidate::new(
            Some(entry.path()),
            format!("~/.cache/{name}"),
            0,
            Risk::Safe,
        );
        if process_running(&name, ctx) {
            candidate.selectable = false;
            candidate.label.push_str(" (app running)");
        }
        out.push(candidate);
    }
    out
}

fn trash_detector(ctx: &Ctx, config: &Config) -> Vec<Candidate> {
    let trash_dir = ctx.home.join(".local/share/Trash/files");
    let Ok(entries) = std::fs::read_dir(&trash_dir) else {
        return Vec::new();
    };

    let max_age = Duration::from_secs(u64::from(config.clean.trash_older_than_days) * 86_400);
    let cutoff = SystemTime::now().checked_sub(max_age);

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if let Some(cutoff) = cutoff
            && modified > cutoff
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        out.push(Candidate::new(
            Some(path),
            format!("~/.local/share/Trash/files/{name}"),
            0,
            Risk::Safe,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::scan;
    use crate::safety::whitelist;

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

    fn empty_whitelist() -> Whitelist {
        whitelist::parse("", std::path::Path::new("/home/user")).unwrap()
    }

    use crate::safety::whitelist::Whitelist;

    #[test]
    fn test_cache_apps_lists_generic_child_but_excludes_specific_ones() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".cache/some-browser")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cache/thumbnails")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cache/paru")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cache/pip")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cache/go-build")).unwrap();

        let candidates = cache_apps_detector(&f.ctx, &f.ctx.config.clone());
        let labels: Vec<_> = candidates.iter().map(|c| c.label.clone()).collect();
        assert_eq!(labels, vec!["~/.cache/some-browser"]);
    }

    #[test]
    fn test_thumbnails_rule_found_via_full_scan() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".cache/thumbnails")).unwrap();
        std::fs::write(f.ctx.home.join(".cache/thumbnails/a.png"), b"x").unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "user.thumbnails")
            .unwrap();
        assert_eq!(group.candidates.len(), 1);
    }

    #[test]
    fn test_trash_includes_old_entry_and_excludes_fresh_one() {
        let f = fixture();
        let trash = f.ctx.home.join(".local/share/Trash/files");
        std::fs::create_dir_all(&trash).unwrap();
        std::fs::write(trash.join("old.txt"), b"x").unwrap();
        std::fs::write(trash.join("fresh.txt"), b"x").unwrap();

        let old = SystemTime::now() - Duration::from_secs(40 * 86_400);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(trash.join("old.txt"))
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();

        let candidates = trash_detector(&f.ctx, &f.ctx.config.clone());
        let labels: Vec<_> = candidates.iter().map(|c| c.label.clone()).collect();
        assert_eq!(
            labels,
            vec!["~/.local/share/Trash/files/old.txt".to_string()]
        );
    }
}
