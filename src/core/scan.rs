use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::core::item::{Candidate, Group};
use crate::ctx::Ctx;
use crate::rules::{Action, Applicability, Detector, Rule, command_exists, expand_path_spec};
use crate::safety::protected::{SafetyEnv, Tier, validate_deletable};
use crate::safety::whitelist::Whitelist;
use crate::util::dirsize::dir_size;

/// Scans every applicable rule and returns one `Group` per rule that applies
/// to this system. Rules whose `Applicability` doesn't hold are omitted
/// entirely — there is nothing to plan or show for them.
pub fn scan(
    rules: &[Rule],
    ctx: &Ctx,
    config: &Config,
    whitelist: &Whitelist,
) -> anyhow::Result<Vec<Group>> {
    let env = SafetyEnv::from_system(ctx)?;
    Ok(rules
        .iter()
        .filter(|rule| is_applicable(rule.applicable, ctx))
        .map(|rule| scan_rule(rule, ctx, config, whitelist, &env))
        .collect())
}

fn is_applicable(applicable: Applicability, ctx: &Ctx) -> bool {
    match applicable {
        Applicability::Always => true,
        Applicability::CommandExists(name) => command_exists(name, ctx),
        Applicability::CommandExistsAny(names) => {
            names.iter().any(|name| command_exists(name, ctx))
        }
        Applicability::PathExists(spec) => expand_path_spec(spec, ctx).exists(),
    }
}

fn scan_rule(
    rule: &Rule,
    ctx: &Ctx,
    config: &Config,
    whitelist: &Whitelist,
    env: &SafetyEnv,
) -> Group {
    let raw = raw_candidates(rule, ctx, config);
    let (candidates, skipped) = match rule.action {
        Action::DeletePaths => finish_deletable_candidates(rule, raw, ctx, whitelist, env),
        Action::Cmd(_) | Action::CmdSelected(_) => (size_only(raw), Vec::new()),
    };

    Group {
        rule_id: rule.id.to_string(),
        title: rule.title.to_string(),
        risk: rule.risk,
        requires_sudo: rule.requires_sudo,
        candidates,
        skipped,
    }
}

fn raw_candidates(rule: &Rule, ctx: &Ctx, config: &Config) -> Vec<Candidate> {
    match &rule.detector {
        Detector::Globs(patterns) => patterns
            .iter()
            .flat_map(|pattern| expand_glob_spec(pattern, ctx))
            .map(|path| {
                let label = display_label(&path, ctx);
                Candidate::new(Some(path), label, 0, rule.risk)
            })
            .collect(),
        Detector::Fn(f) => f(ctx, config),
    }
}

fn finish_deletable_candidates(
    rule: &Rule,
    raw: Vec<Candidate>,
    ctx: &Ctx,
    whitelist: &Whitelist,
    env: &SafetyEnv,
) -> (Vec<Candidate>, Vec<(String, String)>) {
    let tier = if rule.requires_sudo {
        Tier::System
    } else {
        Tier::User
    };
    let allowed: Vec<PathBuf> = rule
        .allowed_prefixes
        .iter()
        .map(|p| expand_path_spec(p, ctx))
        .collect();

    let mut candidates = Vec::new();
    let mut skipped = Vec::new();
    for mut candidate in raw {
        let Some(path) = candidate.path.clone() else {
            continue;
        };
        if let Err(refusal) = validate_deletable(&path, &allowed, tier, env) {
            skipped.push((candidate.label.clone(), refusal.to_string()));
            continue;
        }
        if whitelist.matches(&path) {
            candidate.whitelisted = true;
            candidate.selectable = false;
        }
        candidate.bytes = dir_size(&path);
        candidates.push(candidate);
    }
    (candidates, skipped)
}

/// `Cmd`-action candidates are informational sizing only — never passed to
/// `validate_deletable` or whitelist-checked, since the rule's command (not
/// badger) decides what actually gets removed.
fn size_only(raw: Vec<Candidate>) -> Vec<Candidate> {
    raw.into_iter()
        .map(|mut candidate| {
            if let Some(path) = &candidate.path {
                candidate.bytes = dir_size(path);
            }
            candidate
        })
        .collect()
}

/// Renders `path` as a `~/`-relative or root-relative display label. Shared
/// with `purge::scan`, whose candidates come from a config-driven walk
/// rather than the static rule registry but want the same display format.
pub(crate) fn display_label(path: &Path, ctx: &Ctx) -> String {
    if let Ok(rel) = path.strip_prefix(&ctx.home) {
        if rel.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rel.display())
        }
    } else if let Ok(rel) = path.strip_prefix(&ctx.root) {
        format!("/{}", rel.display())
    } else {
        path.display().to_string()
    }
}

/// Expands one glob spec into concrete, existing paths. A spec with no `*`
/// is a single candidate (only if it exists — a non-match is not a
/// candidate at all, not a refusal). A spec with a `*` in its last path
/// component expands against that directory's entries.
fn expand_glob_spec(spec: &str, ctx: &Ctx) -> Vec<PathBuf> {
    if !spec.contains('*') {
        let path = expand_path_spec(spec, ctx);
        return if std::fs::symlink_metadata(&path).is_ok() {
            vec![path]
        } else {
            Vec::new()
        };
    }

    let Some((dir_spec, file_glob)) = spec.rsplit_once('/') else {
        return Vec::new();
    };
    let dir = expand_path_spec(dir_spec, ctx);
    let Ok(glob) = globset::Glob::new(file_glob) else {
        return Vec::new();
    };
    let matcher = glob.compile_matcher();

    let mut out: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .flatten()
            .filter(|entry| matcher.is_match(entry.file_name()))
            .map(|entry| entry.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::item::Risk;
    use crate::rules::CmdSpec;
    use crate::safety::protected::Refusal;

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
        crate::safety::whitelist::parse("", Path::new("/home/user")).unwrap()
    }

    fn glob_rule() -> Rule {
        Rule {
            id: "test.thumbnails",
            title: "Thumbnail cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.cache"],
            detector: Detector::Globs(&["~/.cache/thumbnails"]),
            action: Action::DeletePaths,
            notes: "",
        }
    }

    #[test]
    fn test_scan_finds_a_glob_candidate_with_correct_bytes() {
        let f = fixture();
        let dir = f.ctx.home.join(".cache/thumbnails");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.png"), vec![0u8; 4096]).unwrap();

        let groups = scan(
            &[glob_rule()],
            &f.ctx,
            &f.ctx.config.clone(),
            &empty_whitelist(),
        )
        .unwrap();

        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.rule_id, "test.thumbnails");
        assert_eq!(group.candidates.len(), 1);
        assert!(group.candidates[0].bytes > 0);
        assert!(group.candidates[0].selectable);
        assert!(group.skipped.is_empty());
    }

    #[test]
    fn test_scan_omits_candidate_when_glob_target_missing() {
        let f = fixture();
        let groups = scan(
            &[glob_rule()],
            &f.ctx,
            &f.ctx.config.clone(),
            &empty_whitelist(),
        )
        .unwrap();
        assert_eq!(groups[0].candidates.len(), 0);
        assert_eq!(groups[0].skipped.len(), 0);
    }

    #[test]
    fn test_scan_wildcard_glob_expands_matching_entries_only() {
        let f = fixture();
        let dir = f.ctx.home.join("pkgcache");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.part"), b"x").unwrap();
        std::fs::write(dir.join("b.part"), b"yy").unwrap();
        std::fs::write(dir.join("keep.txt"), b"zzz").unwrap();

        let rule = Rule {
            id: "test.partials",
            title: "Partial downloads",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/pkgcache"],
            detector: Detector::Globs(&["~/pkgcache/*.part"]),
            action: Action::DeletePaths,
            notes: "",
        };

        let groups = scan(&[rule], &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let mut labels: Vec<_> = groups[0]
            .candidates
            .iter()
            .map(|c| c.label.clone())
            .collect();
        labels.sort();
        assert_eq!(labels, vec!["~/pkgcache/a.part", "~/pkgcache/b.part"]);
    }

    #[test]
    fn test_scan_refuses_denylisted_path_and_records_reason() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".ssh")).unwrap();
        std::fs::write(f.ctx.home.join(".ssh/id_rsa"), b"secret").unwrap();

        let rule = Rule {
            id: "test.ssh",
            title: "SSH (should never be offered)",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~"],
            detector: Detector::Globs(&["~/.ssh"]),
            action: Action::DeletePaths,
            notes: "",
        };

        let groups = scan(&[rule], &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(groups[0].candidates.is_empty());
        assert_eq!(groups[0].skipped.len(), 1);
        assert_eq!(groups[0].skipped[0].0, "~/.ssh");
        assert_eq!(groups[0].skipped[0].1, Refusal::DenyListed.to_string());
    }

    #[test]
    fn test_scan_greys_out_whitelisted_candidate() {
        let f = fixture();
        let dir = f.ctx.home.join(".cache/thumbnails");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.png"), b"x").unwrap();

        let wl = crate::safety::whitelist::parse("~/.cache/thumbnails", &f.ctx.home).unwrap();
        let groups = scan(&[glob_rule()], &f.ctx, &f.ctx.config.clone(), &wl).unwrap();

        assert_eq!(groups[0].candidates.len(), 1);
        assert!(groups[0].candidates[0].whitelisted);
        assert!(!groups[0].candidates[0].selectable);
    }

    #[test]
    fn test_scan_omits_rule_when_not_applicable() {
        let f = fixture();
        let rule = Rule {
            id: "test.needs-cmd",
            title: "Needs a command",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::CommandExists("does-not-exist-anywhere"),
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        };
        let groups = scan(&[rule], &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn test_scan_command_exists_true_when_listed_in_sandboxed_override() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["paccache".to_string()]);
        let rule = Rule {
            id: "test.paccache",
            title: "Needs paccache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::CommandExists("paccache"),
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        };
        let groups = scan(&[rule], &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn test_scan_command_exists_any_matches_on_the_second_of_several_names() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["docker".to_string()]);
        let rule = Rule {
            id: "test.podman_or_docker",
            title: "Needs podman or docker",
            risk: Risk::Moderate,
            requires_sudo: false,
            applicable: Applicability::CommandExistsAny(&["podman", "docker"]),
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        };
        let groups = scan(&[rule], &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn test_scan_command_exists_any_omits_rule_when_none_present() {
        let f = fixture();
        let rule = Rule {
            id: "test.podman_or_docker_absent",
            title: "Needs podman or docker",
            risk: Risk::Moderate,
            requires_sudo: false,
            applicable: Applicability::CommandExistsAny(&["podman", "docker"]),
            allowed_prefixes: &[],
            detector: Detector::Globs(&[]),
            action: Action::DeletePaths,
            notes: "",
        };
        let groups = scan(&[rule], &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn test_cmd_action_candidate_is_sized_but_never_safety_checked_or_whitelisted() {
        let f = fixture();
        let dir = f.ctx.home.join("varcache");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pkg.tar"), vec![0u8; 4096]).unwrap();

        fn cmd_action(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
            vec![]
        }

        let rule = Rule {
            id: "test.cmd",
            title: "Cache cleaned by a command",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Globs(&["~/varcache"]),
            action: Action::Cmd(cmd_action),
            notes: "",
        };

        // Whitelist everything so we can prove Cmd candidates ignore it.
        let wl = crate::safety::whitelist::parse("~/varcache", &f.ctx.home).unwrap();
        let groups = scan(&[rule], &f.ctx, &f.ctx.config.clone(), &wl).unwrap();
        assert_eq!(groups[0].candidates.len(), 1);
        assert!(groups[0].candidates[0].bytes > 0);
        assert!(!groups[0].candidates[0].whitelisted);
        assert!(groups[0].skipped.is_empty());
    }
}
