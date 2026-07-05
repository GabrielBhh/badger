use std::collections::HashMap;

use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::core::runner::runner_for;
use crate::ctx::Ctx;
use crate::rules::{Action, Applicability, CmdSpec, Detector, Rule, expand_path_spec};
use crate::util::parse_human_size;

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
        Rule {
            id: "pacman.orphans",
            title: "Orphaned packages",
            risk: Risk::Moderate,
            requires_sudo: true,
            applicable: Applicability::CommandExists("pacman"),
            allowed_prefixes: &[],
            detector: Detector::Fn(pacman_orphans_detector),
            action: Action::CmdSelected(pacman_orphans_cmd),
            notes: "No longer required by any explicitly installed package. Some may be \
                    optional dependencies you still want — review before removing.",
        },
    ]
}

/// One `pacman -Qtdq` (orphans) followed by one `pacman -Qi <names>` (sizes,
/// best-effort) — both via the detection-only `CommandRunner` seam so tests
/// never shell out for real. A package `pacman -Qi` has no parseable
/// "Installed Size" for is still offered, just with bytes 0 and a label
/// noting the size is unknown.
fn pacman_orphans_detector(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let runner = runner_for(ctx);
    let names: Vec<String> = match runner.run(&["pacman".to_string(), "-Qtdq".to_string()]) {
        Ok(out) => out.stdout.lines().map(str::to_string).collect(),
        Err(_) => Vec::new(),
    };
    if names.is_empty() {
        return Vec::new();
    }

    let mut qi_argv = vec!["pacman".to_string(), "-Qi".to_string()];
    qi_argv.extend(names.iter().cloned());
    let sizes = match runner.run(&qi_argv) {
        Ok(out) => parse_pacman_installed_sizes(&out.stdout),
        Err(_) => HashMap::new(),
    };

    names
        .into_iter()
        .map(|name| match sizes.get(&name) {
            Some(&bytes) => Candidate::new(None, name, bytes, Risk::Moderate),
            None => Candidate::new(None, format!("{name} (size unknown)"), 0, Risk::Moderate),
        })
        .collect()
}

/// Parses `pacman -Qi`'s "Name" / "Installed Size" fields into a
/// name -> bytes map. Tolerant of formatting quirks: an entry whose size
/// can't be parsed is simply omitted (the caller falls back to "unknown").
/// `pub(crate)`: also reused by `pkg::pacman::list` to size installed
/// packages for `badger uninstall`'s picker.
pub(crate) fn parse_pacman_installed_sizes(text: &str) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let mut current_name: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Name") {
            current_name = rest.split_once(':').map(|(_, v)| v.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Installed Size") {
            let Some(name) = &current_name else { continue };
            let Some((_, value)) = rest.split_once(':') else {
                continue;
            };
            if let Some(bytes) = parse_human_size(value.trim()) {
                out.insert(name.clone(), bytes);
            }
        }
    }
    out
}

/// Extracts the bare package name from a candidate's label, stripping any
/// " (size unknown)" suffix the detector appended for display.
fn pacman_orphans_cmd(_ctx: &Ctx, _config: &Config, selected: &[Candidate]) -> Vec<CmdSpec> {
    let mut argv = vec![
        "pacman".to_string(),
        "-Rns".to_string(),
        "--noconfirm".to_string(),
    ];
    argv.extend(selected.iter().map(|c| {
        c.label
            .split_whitespace()
            .next()
            .unwrap_or(&c.label)
            .to_string()
    }));
    vec![CmdSpec {
        argv,
        sudo: true,
        label: "Remove selected orphan packages".to_string(),
    }]
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

    // --- pacman.orphans ---

    fn cmd_output(stdout: &str) -> crate::core::runner::CmdOutput {
        crate::core::runner::CmdOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn test_pacman_orphans_group_requires_pacman_command() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "pacman.orphans"));
    }

    #[test]
    fn test_pacman_orphans_detector_returns_empty_when_no_orphans() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["pacman".to_string()]);
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec!["pacman".to_string(), "-Qtdq".to_string()],
            cmd_output(""),
        )]));

        let candidates = pacman_orphans_detector(&f.ctx, &f.ctx.config.clone());
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_pacman_orphans_detector_parses_installed_size_per_package() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["pacman".to_string()]);
        let qi_output = "Name            : foo-lib\n\
                          Installed Size  : 1024.00 KiB\n\
                          \n\
                          Name            : bar-lib\n\
                          Installed Size  : 2.00 MiB\n";
        f.ctx.fake_command_output = Some(HashMap::from([
            (
                vec!["pacman".to_string(), "-Qtdq".to_string()],
                cmd_output("foo-lib\nbar-lib\n"),
            ),
            (
                vec![
                    "pacman".to_string(),
                    "-Qi".to_string(),
                    "foo-lib".to_string(),
                    "bar-lib".to_string(),
                ],
                cmd_output(qi_output),
            ),
        ]));

        let candidates = pacman_orphans_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].label, "foo-lib");
        assert_eq!(candidates[0].bytes, 1024 * 1024);
        assert_eq!(candidates[1].label, "bar-lib");
        assert_eq!(candidates[1].bytes, 2 * 1024 * 1024);
        assert!(
            candidates.iter().all(|c| !c.selectable),
            "Moderate starts unchecked"
        );
    }

    #[test]
    fn test_pacman_orphans_detector_notes_size_unknown_when_qi_has_no_entry() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["pacman".to_string()]);
        f.ctx.fake_command_output = Some(HashMap::from([
            (
                vec!["pacman".to_string(), "-Qtdq".to_string()],
                cmd_output("mystery-pkg\n"),
            ),
            (
                vec![
                    "pacman".to_string(),
                    "-Qi".to_string(),
                    "mystery-pkg".to_string(),
                ],
                cmd_output(""),
            ),
        ]));

        let candidates = pacman_orphans_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].label, "mystery-pkg (size unknown)");
        assert_eq!(candidates[0].bytes, 0);
    }

    #[test]
    fn test_pacman_orphans_cmd_builds_remove_argv_from_selected_candidates_only() {
        let selected = vec![
            crate::core::item::Candidate::new(None, "bar-lib".to_string(), 0, Risk::Moderate),
            crate::core::item::Candidate::new(
                None,
                "mystery-pkg (size unknown)".to_string(),
                0,
                Risk::Moderate,
            ),
        ];
        let specs = pacman_orphans_cmd(&Fixture::dummy_ctx(), &Config::default(), &selected);
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec![
                    "pacman".to_string(),
                    "-Rns".to_string(),
                    "--noconfirm".to_string(),
                    "bar-lib".to_string(),
                    "mystery-pkg".to_string(),
                ],
                sudo: true,
                label: "Remove selected orphan packages".to_string(),
            }]
        );
    }
}
