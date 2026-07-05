use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::ctx::Ctx;
use crate::rules::{Action, Applicability, CmdSpec, Detector, Rule, expand_path_spec};

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "pacman.cache",
            title: "Pacman package cache",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::CommandExists("paccache"),
            allowed_prefixes: &[],
            detector: Detector::Fn(pacman_cache_size),
            action: Action::Cmd(pacman_cache_cmd),
            notes: "Size shown is before cleaning; paccache decides what actually goes.",
        },
        Rule {
            id: "pacman.sync_partial",
            title: "Partial pacman downloads",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &["/var/cache/pacman/pkg"],
            detector: Detector::Globs(&["/var/cache/pacman/pkg/*.part"]),
            action: Action::DeletePaths,
            notes: "Interrupted package downloads; safe to remove and re-fetch.",
        },
        Rule {
            id: "aur.paru",
            title: "paru cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::CommandExists("paru"),
            allowed_prefixes: &["~/.cache/paru"],
            detector: Detector::Globs(&["~/.cache/paru"]),
            action: Action::DeletePaths,
            notes: "paru re-clones AUR packages as needed.",
        },
        Rule {
            id: "system.journald",
            title: "systemd journal",
            risk: Risk::Moderate,
            requires_sudo: true,
            applicable: Applicability::CommandExists("journalctl"),
            allowed_prefixes: &[],
            detector: Detector::Fn(journald_size),
            action: Action::Cmd(journald_cmd),
            notes: "Vacuums the journal down to the configured size cap.",
        },
    ]
}

fn pacman_cache_size(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let dir = expand_path_spec("/var/cache/pacman/pkg", ctx);
    vec![Candidate::new(
        Some(dir),
        "/var/cache/pacman/pkg".to_string(),
        0,
        Risk::Safe,
    )]
}

fn pacman_cache_cmd(_ctx: &Ctx, config: &Config) -> Vec<CmdSpec> {
    vec![
        CmdSpec {
            argv: vec![
                "paccache".to_string(),
                format!("-rk{}", config.clean.paccache_keep),
            ],
            sudo: true,
            label: "Remove old cached package versions".to_string(),
        },
        CmdSpec {
            argv: vec!["paccache".to_string(), "-ruk0".to_string()],
            sudo: true,
            label: "Remove cache for uninstalled packages".to_string(),
        },
    ]
}

fn journald_size(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let dir = expand_path_spec("/var/log/journal", ctx);
    vec![Candidate::new(
        Some(dir),
        "/var/log/journal".to_string(),
        0,
        Risk::Moderate,
    )]
}

fn journald_cmd(_ctx: &Ctx, config: &Config) -> Vec<CmdSpec> {
    vec![CmdSpec {
        argv: vec![
            "journalctl".to_string(),
            format!("--vacuum-size={}", config.clean.journal_max_size),
        ],
        sudo: true,
        label: "Vacuum systemd journal".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::scan;
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
    fn test_pacman_cache_cmd_uses_configured_keep_count_and_sudo() {
        let mut config = Config::default();
        config.clean.paccache_keep = 5;
        let specs = pacman_cache_cmd(&Fixture::dummy_ctx(), &config);
        assert_eq!(
            specs,
            vec![
                CmdSpec {
                    argv: vec!["paccache".to_string(), "-rk5".to_string()],
                    sudo: true,
                    label: "Remove old cached package versions".to_string(),
                },
                CmdSpec {
                    argv: vec!["paccache".to_string(), "-ruk0".to_string()],
                    sudo: true,
                    label: "Remove cache for uninstalled packages".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_journald_cmd_uses_configured_max_size_and_sudo() {
        let mut config = Config::default();
        config.clean.journal_max_size = "150M".to_string();
        let specs = journald_cmd(&Fixture::dummy_ctx(), &config);
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec!["journalctl".to_string(), "--vacuum-size=150M".to_string()],
                sudo: true,
                label: "Vacuum systemd journal".to_string(),
            }]
        );
    }

    impl Fixture {
        fn dummy_ctx() -> Ctx {
            Ctx {
                root: PathBuf::from("/root"),
                home: PathBuf::from("/root/home/user"),
                config_dir: PathBuf::new(),
                state_dir: PathBuf::new(),
                dry_run: false,
                debug: false,
                config: Config::default(),
                sandboxed: true,
                available_commands: None,
                fake_command_output: None,
            }
        }
    }

    #[test]
    fn test_pacman_cache_group_absent_without_paccache_and_present_with_it() {
        let mut f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "pacman.cache"));

        f.ctx.available_commands = Some(vec!["paccache".to_string()]);
        std::fs::create_dir_all(f.ctx.root.join("var/cache/pacman/pkg")).unwrap();
        std::fs::write(
            f.ctx.root.join("var/cache/pacman/pkg/foo.pkg.tar.zst"),
            vec![0u8; 4096],
        )
        .unwrap();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups.iter().find(|g| g.rule_id == "pacman.cache").unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert!(group.candidates[0].bytes > 0);
        assert!(group.requires_sudo);
    }

    #[test]
    fn test_pacman_sync_partial_only_matches_dot_part_files() {
        let f = fixture();
        let dir = f.ctx.root.join("var/cache/pacman/pkg");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.pkg.tar.zst.part"), b"x").unwrap();
        std::fs::write(dir.join("keep.pkg.tar.zst"), b"x").unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "pacman.sync_partial")
            .unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert_eq!(
            group.candidates[0].label,
            "/var/cache/pacman/pkg/a.pkg.tar.zst.part"
        );
    }

    #[test]
    fn test_aur_paru_group_requires_paru_command() {
        let mut f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".cache/paru")).unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "aur.paru"));

        f.ctx.available_commands = Some(vec!["paru".to_string()]);
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups.iter().find(|g| g.rule_id == "aur.paru").unwrap();
        assert_eq!(group.candidates.len(), 1);
    }
}
