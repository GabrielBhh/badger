use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::core::runner::runner_for;
use crate::ctx::Ctx;
use crate::rules::{Action, Applicability, CmdSpec, Detector, Rule, command_exists};
use crate::util::parse_human_size;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "flatpak.unused",
            title: "Unused flatpak runtimes",
            risk: Risk::Moderate,
            requires_sudo: false,
            applicable: Applicability::CommandExists("flatpak"),
            allowed_prefixes: &[],
            detector: Detector::Fn(flatpak_unused_detector),
            action: Action::Cmd(flatpak_unused_cmd),
            notes: "Runtimes/extensions no installed app currently depends on; flatpak \
                    re-fetches them if something needs them again.",
        },
        Rule {
            id: "flatpak.app_caches",
            title: "Flatpak app caches",
            risk: Risk::Moderate,
            requires_sudo: false,
            applicable: Applicability::Always,
            allowed_prefixes: &["~/.var/app"],
            detector: Detector::Fn(flatpak_app_caches_detector),
            action: Action::DeletePaths,
            notes: "Per-app cache directories under Flatpak's sandboxed data dir; apps \
                    rebuild these as needed.",
        },
        Rule {
            id: "containers.prune",
            title: "Unused containers and images",
            risk: Risk::Moderate,
            requires_sudo: false,
            applicable: Applicability::CommandExistsAny(&["podman", "docker"]),
            allowed_prefixes: &[],
            detector: Detector::Fn(containers_prune_detector),
            action: Action::CmdSelected(containers_prune_cmd),
            notes: "Dangling images and exited containers only — review names before \
                    removing anything you meant to keep. Never runs a full system prune.",
        },
        Rule {
            id: "system.coredumps",
            title: "systemd coredumps",
            risk: Risk::Moderate,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &["/var/lib/systemd/coredump"],
            detector: Detector::Globs(&["/var/lib/systemd/coredump/*"]),
            action: Action::DeletePaths,
            notes: "Crash dumps kept for debugging; safe to remove once you've inspected \
                    any you need.",
        },
        Rule {
            id: "snap.cache",
            title: "snapd cache",
            risk: Risk::Moderate,
            requires_sudo: true,
            applicable: Applicability::CommandExists("snap"),
            allowed_prefixes: &["/var/lib/snapd/cache"],
            detector: Detector::Globs(&["/var/lib/snapd/cache/*"]),
            action: Action::DeletePaths,
            notes: "Cached snap revisions; snapd re-downloads as needed.",
        },
    ]
}

fn flatpak_unused_detector(_ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    vec![Candidate::new(
        None,
        "unused flatpak runtimes".to_string(),
        0,
        Risk::Moderate,
    )]
}

fn flatpak_unused_cmd(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    vec![CmdSpec {
        // No sudo: this only ever touches the user's own flatpak installation;
        // system-wide runtimes are handled by flatpak's own polkit prompt.
        argv: vec![
            "flatpak".to_string(),
            "uninstall".to_string(),
            "--unused".to_string(),
            "--noninteractive".to_string(),
        ],
        sudo: false,
        label: "Remove unused flatpak runtimes".to_string(),
    }]
}

/// Globs can't express a wildcard in a *middle* path component (only the
/// engine's supported form: fixed dir + wildcard last segment), so
/// `~/.var/app/*/cache` is walked by hand here instead of via
/// `Detector::Globs`.
fn flatpak_app_caches_detector(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let apps_dir = ctx.home.join(".var/app");
    let Ok(entries) = std::fs::read_dir(&apps_dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let cache_dir = entry.path().join("cache");
        if std::fs::symlink_metadata(&cache_dir).is_ok() {
            let app_id = entry.file_name().to_string_lossy().into_owned();
            out.push(Candidate::new(
                Some(cache_dir),
                format!("~/.var/app/{app_id}/cache"),
                0,
                Risk::Moderate,
            ));
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    out
}

/// Picks the container tool this system actually has, podman preferred —
/// `Applicability::CommandExistsAny` already guarantees at least one exists
/// by the time this runs.
fn container_tool(ctx: &Ctx) -> &'static str {
    if command_exists("podman", ctx) {
        "podman"
    } else {
        "docker"
    }
}

fn containers_prune_detector(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let tool = container_tool(ctx);
    let runner = runner_for(ctx);
    let mut out = Vec::new();

    let images_argv = vec![
        tool.to_string(),
        "images".to_string(),
        "-f".to_string(),
        "dangling=true".to_string(),
        "--format".to_string(),
        "{{.ID}} {{.Repository}} {{.Size}}".to_string(),
    ];
    if let Ok(res) = runner.run(&images_argv) {
        for line in res.stdout.lines() {
            let mut parts = line.splitn(3, ' ');
            let (Some(id), Some(repo), Some(size)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let bytes = parse_human_size(size).unwrap_or(0);
            out.push(Candidate::new(
                None,
                format!("image {repo} ({id})"),
                bytes,
                Risk::Moderate,
            ));
        }
    }

    let ps_argv = vec![
        tool.to_string(),
        "ps".to_string(),
        "-a".to_string(),
        "--filter".to_string(),
        "status=exited".to_string(),
        "--format".to_string(),
        "{{.ID}} {{.Names}}".to_string(),
    ];
    if let Ok(res) = runner.run(&ps_argv) {
        for line in res.stdout.lines() {
            let Some((id, name)) = line.split_once(' ') else {
                continue;
            };
            out.push(Candidate::new(
                None,
                format!("container {name} ({id})"),
                0,
                Risk::Moderate,
            ));
        }
    }

    out
}

/// Extracts the `(id)` trailing a candidate's `"image <repo> (<id>)"` or
/// `"container <name> (<id>)"` label.
fn extract_id(rest: &str) -> Option<String> {
    let start = rest.rfind('(')?;
    let end = rest.rfind(')')?;
    (end > start + 1).then(|| rest[start + 1..end].to_string())
}

fn containers_prune_cmd(ctx: &Ctx, _config: &Config, selected: &[Candidate]) -> Vec<CmdSpec> {
    let tool = container_tool(ctx);
    let mut image_ids = Vec::new();
    let mut container_ids = Vec::new();
    for c in selected {
        if let Some(rest) = c.label.strip_prefix("image ") {
            image_ids.extend(extract_id(rest));
        } else if let Some(rest) = c.label.strip_prefix("container ") {
            container_ids.extend(extract_id(rest));
        }
    }

    let mut specs = Vec::new();
    if !image_ids.is_empty() {
        let mut argv = vec![tool.to_string(), "rmi".to_string()];
        argv.extend(image_ids);
        specs.push(CmdSpec {
            argv,
            sudo: false,
            label: "Remove selected dangling images".to_string(),
        });
    }
    if !container_ids.is_empty() {
        let mut argv = vec![tool.to_string(), "rm".to_string()];
        argv.extend(container_ids);
        specs.push(CmdSpec {
            argv,
            sudo: false,
            label: "Remove selected stopped containers".to_string(),
        });
    }
    specs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::runner::CmdOutput;
    use crate::core::scan::scan;
    use crate::safety::whitelist;
    use std::collections::HashMap;
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

    fn cmd_output(stdout: &str) -> CmdOutput {
        CmdOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    // --- flatpak.unused ---

    #[test]
    fn test_flatpak_unused_group_requires_flatpak_command() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "flatpak.unused"));
    }

    #[test]
    fn test_flatpak_unused_present_with_one_informational_candidate() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["flatpak".to_string()]);
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "flatpak.unused")
            .unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert!(!group.requires_sudo);
        assert!(!group.candidates[0].selectable, "Moderate starts unchecked");
    }

    #[test]
    fn test_flatpak_unused_cmd_is_noninteractive_and_not_sudo() {
        let specs = flatpak_unused_cmd(&Fixture::dummy_ctx(), &Config::default());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec![
                    "flatpak".to_string(),
                    "uninstall".to_string(),
                    "--unused".to_string(),
                    "--noninteractive".to_string(),
                ],
                sudo: false,
                label: "Remove unused flatpak runtimes".to_string(),
            }]
        );
    }

    // --- flatpak.app_caches ---

    #[test]
    fn test_flatpak_app_caches_finds_cache_dir_per_app_and_skips_apps_without_one() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".var/app/org.foo.App/cache")).unwrap();
        std::fs::write(
            f.ctx.home.join(".var/app/org.foo.App/cache/f.bin"),
            vec![0u8; 4096],
        )
        .unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".var/app/org.bar.App/data")).unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "flatpak.app_caches")
            .unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert_eq!(group.candidates[0].label, "~/.var/app/org.foo.App/cache");
        assert!(group.candidates[0].bytes > 0);
    }

    #[test]
    fn test_flatpak_app_caches_empty_when_var_app_missing() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "flatpak.app_caches")
            .unwrap();
        assert!(group.candidates.is_empty());
    }

    // --- containers.prune ---

    #[test]
    fn test_containers_prune_group_requires_podman_or_docker() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "containers.prune"));
    }

    #[test]
    fn test_containers_prune_prefers_podman_when_both_present() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["podman".to_string(), "docker".to_string()]);
        assert_eq!(container_tool(&f.ctx), "podman");
    }

    #[test]
    fn test_containers_prune_falls_back_to_docker_when_podman_absent() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["docker".to_string()]);
        assert_eq!(container_tool(&f.ctx), "docker");
    }

    #[test]
    fn test_containers_prune_detector_lists_dangling_images_and_exited_containers() {
        let mut f = fixture();
        // The machine-real case: podman present, docker absent.
        f.ctx.available_commands = Some(vec!["podman".to_string()]);
        f.ctx.fake_command_output = Some(HashMap::from([
            (
                vec![
                    "podman".to_string(),
                    "images".to_string(),
                    "-f".to_string(),
                    "dangling=true".to_string(),
                    "--format".to_string(),
                    "{{.ID}} {{.Repository}} {{.Size}}".to_string(),
                ],
                cmd_output("abc123 <none> 128MB\n"),
            ),
            (
                vec![
                    "podman".to_string(),
                    "ps".to_string(),
                    "-a".to_string(),
                    "--filter".to_string(),
                    "status=exited".to_string(),
                    "--format".to_string(),
                    "{{.ID}} {{.Names}}".to_string(),
                ],
                cmd_output("def456 old-build\n"),
            ),
        ]));

        let candidates = containers_prune_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].label, "image <none> (abc123)");
        assert_eq!(candidates[0].bytes, 128 * 1024 * 1024);
        assert_eq!(candidates[1].label, "container old-build (def456)");
        assert_eq!(candidates[1].bytes, 0);
    }

    #[test]
    fn test_containers_prune_cmd_builds_separate_rmi_and_rm_for_selected_candidates() {
        let selected = vec![
            Candidate::new(None, "image <none> (abc123)".to_string(), 0, Risk::Moderate),
            Candidate::new(
                None,
                "container old-build (def456)".to_string(),
                0,
                Risk::Moderate,
            ),
        ];
        let mut ctx = Fixture::dummy_ctx();
        ctx.available_commands = Some(vec!["podman".to_string()]);

        let specs = containers_prune_cmd(&ctx, &Config::default(), &selected);
        assert_eq!(
            specs,
            vec![
                CmdSpec {
                    argv: vec![
                        "podman".to_string(),
                        "rmi".to_string(),
                        "abc123".to_string()
                    ],
                    sudo: false,
                    label: "Remove selected dangling images".to_string(),
                },
                CmdSpec {
                    argv: vec!["podman".to_string(), "rm".to_string(), "def456".to_string()],
                    sudo: false,
                    label: "Remove selected stopped containers".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_containers_prune_cmd_omits_rm_spec_when_only_images_selected() {
        let selected = vec![Candidate::new(
            None,
            "image <none> (abc123)".to_string(),
            0,
            Risk::Moderate,
        )];
        let mut ctx = Fixture::dummy_ctx();
        ctx.available_commands = Some(vec!["podman".to_string()]);

        let specs = containers_prune_cmd(&ctx, &Config::default(), &selected);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].label, "Remove selected dangling images");
    }

    // --- system.coredumps ---

    #[test]
    fn test_system_coredumps_matches_files_under_the_coredump_dir() {
        let f = fixture();
        let dir = f.ctx.root.join("var/lib/systemd/coredump");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("core.foo.1000.1"), vec![0u8; 4096]).unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "system.coredumps")
            .unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert!(group.requires_sudo);
        assert!(!group.candidates[0].selectable);
    }

    // --- snap.cache ---

    #[test]
    fn test_snap_cache_group_requires_snap_command() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "snap.cache"));
    }

    #[test]
    fn test_snap_cache_matches_files_under_the_cache_dir_when_snap_present() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["snap".to_string()]);
        let dir = f.ctx.root.join("var/lib/snapd/cache");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("abcd1234"), vec![0u8; 4096]).unwrap();

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups.iter().find(|g| g.rule_id == "snap.cache").unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert!(group.requires_sudo);
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
}
