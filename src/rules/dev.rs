use crate::core::item::Risk;
use crate::rules::{Action, Applicability, Detector, Rule};

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "dev.pip",
            title: "pip cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.cache/pip"],
            detector: Detector::Globs(&["~/.cache/pip"]),
            action: Action::DeletePaths,
            notes: "pip re-downloads/rebuilds wheels as needed.",
        },
        Rule {
            id: "dev.npm",
            title: "npm cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.npm/_cacache"],
            detector: Detector::Globs(&["~/.npm/_cacache"]),
            action: Action::DeletePaths,
            notes: "npm re-downloads packages as needed.",
        },
        Rule {
            id: "dev.pnpm",
            title: "pnpm store",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.local/share/pnpm/store"],
            detector: Detector::Globs(&["~/.local/share/pnpm/store"]),
            action: Action::DeletePaths,
            notes: "pnpm rebuilds its content-addressed store as needed.",
        },
        Rule {
            id: "dev.go",
            title: "Go build cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.cache/go-build"],
            detector: Detector::Globs(&["~/.cache/go-build"]),
            action: Action::DeletePaths,
            notes: "go rebuilds this cache as needed.",
        },
        Rule {
            id: "dev.cargo_registry",
            title: "Cargo registry cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.cargo/registry/cache"],
            detector: Detector::Globs(&["~/.cargo/registry/cache"]),
            action: Action::DeletePaths,
            notes: "Only the extracted-crate cache; registry git/index metadata is untouched.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::core::scan::scan;
    use crate::ctx::Ctx;
    use crate::safety::whitelist;
    use std::path::PathBuf;

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
        whitelist::parse("", &PathBuf::from("/home/user")).unwrap()
    }

    #[test]
    fn test_cargo_registry_rule_only_covers_the_cache_subdir() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".cargo/registry/cache")).unwrap();
        std::fs::write(f.ctx.home.join(".cargo/registry/cache/crate.crate"), b"x").unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cargo/registry/git")).unwrap();
        std::fs::write(f.ctx.home.join(".cargo/registry/git/keep.pack"), b"x").unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "dev.cargo_registry")
            .unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert_eq!(group.candidates[0].label, "~/.cargo/registry/cache");
    }

    #[test]
    fn test_all_dev_rules_are_absent_when_their_dirs_dont_exist() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        for group in &groups {
            assert!(
                group.candidates.is_empty(),
                "{} unexpectedly found a candidate",
                group.rule_id
            );
        }
    }

    #[test]
    fn test_npm_and_pnpm_and_go_caches_are_found_when_present() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".npm/_cacache")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".local/share/pnpm/store")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cache/go-build")).unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        for id in ["dev.npm", "dev.pnpm", "dev.go"] {
            let group = groups.iter().find(|g| g.rule_id == id).unwrap();
            assert_eq!(group.candidates.len(), 1, "{id} should have found its dir");
        }
    }
}
