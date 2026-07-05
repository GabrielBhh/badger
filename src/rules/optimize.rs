//! `badger optimize` task registry. Unlike `rules::registry()` (caches/logs
//! `clean` deletes), every task here is an action with no deletable
//! candidate of its own — one informational `Candidate` describing what the
//! task does, and an `Action::Cmd` that runs it. Deliberately **not** folded
//! into `rules::registry()`: these never delete a path, so they have no
//! business in the privileged-helper's path allowlist (see `privilege.rs`),
//! and `badger clean`/`purge` must never show them.
//!
//! Deliberate exclusions (not tasks here, and not planned for a later phase
//! either): `mkinitcpio -P` (regenerating initramfs is destructive if it goes
//! wrong and has no useful "preview" — a kernel/microcode update already
//! triggers it via pacman hooks), sysctl tuning (irreversible, environment-
//! specific, not "maintenance"), and RAM-booster/"free the cache" scripts
//! (freeing reclaimable page cache is not a real optimization — the kernel
//! already reclaims it on demand, and forcing it just causes more disk I/O
//! later). See `docs/RULES.md` for the same list with more detail.

use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::ctx::Ctx;
use crate::rules::{Action, Applicability, CmdSpec, Detector, Rule, command_exists};

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "optimize.fstrim",
            title: "Trim SSD free space",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Fn(fstrim_detector),
            action: Action::Cmd(fstrim_cmd),
            notes: "Discards unused blocks on every mounted, trim-capable filesystem. Most \
                    Arch installs already run this weekly via `fstrim.timer` — this is a \
                    manual top-up, not a substitute for it.",
        },
        Rule {
            id: "optimize.reset_failed",
            title: "Reset failed systemd units",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::Always,
            allowed_prefixes: &[],
            detector: Detector::Fn(reset_failed_detector),
            action: Action::Cmd(reset_failed_cmd),
            notes: "Clears the failed-unit counters systemd keeps for both the system and \
                    user managers. Purely cosmetic bookkeeping — does not restart, stop, or \
                    otherwise touch any unit.",
        },
        Rule {
            id: "optimize.font_cache",
            title: "Rebuild font cache",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::CommandExists("fc-cache"),
            allowed_prefixes: &[],
            detector: Detector::Fn(font_cache_detector),
            action: Action::Cmd(font_cache_cmd),
            notes: "Rescans installed fonts so new/removed fonts show up correctly.",
        },
        Rule {
            id: "optimize.desktop_db",
            title: "Refresh desktop entry, icon, and MIME databases",
            risk: Risk::Safe,
            requires_sudo: false,
            applicable: Applicability::CommandExistsAny(&[
                "update-desktop-database",
                "gtk-update-icon-cache",
                "update-mime-database",
            ]),
            allowed_prefixes: &[],
            detector: Detector::Fn(desktop_db_detector),
            action: Action::Cmd(desktop_db_cmd),
            notes: "Keeps app launchers, file-manager icons, and file-type associations in \
                    sync after installing/removing desktop apps. Each sub-command only runs \
                    if it's installed (and, for the icon/MIME caches, only if the matching \
                    `~/.local/share` directory already exists).",
        },
        Rule {
            id: "optimize.pacman_files",
            title: "Refresh pacman file database",
            risk: Risk::Moderate,
            requires_sudo: true,
            applicable: Applicability::CommandExists("pacman"),
            allowed_prefixes: &[],
            detector: Detector::Fn(pacman_files_detector),
            action: Action::Cmd(pacman_files_cmd),
            notes: "`pacman -Fy` downloads the full file-list database (used by `pacman -F` \
                    to find \"which package owns this file\"). Opt-in: it's a sizeable \
                    download most people never need.",
        },
        Rule {
            id: "optimize.mirrors",
            title: "Refresh mirror list",
            risk: Risk::Moderate,
            requires_sudo: true,
            applicable: Applicability::Fn(mirrors_applicable),
            allowed_prefixes: &[],
            detector: Detector::Fn(mirrors_detector),
            action: Action::Cmd(mirrors_cmd),
            notes: "Re-ranks pacman's mirror list for speed, via whichever of \
                    cachyos-rate-mirrors / rate-mirrors / reflector is installed (in that \
                    preference order), or the tool named in `optimize.mirror_tool` if set. \
                    Opt-in: it rewrites /etc/pacman.d/mirrorlist and takes a while to run. \
                    Set `optimize.mirror_tool = \"off\"` to hide this task entirely.",
        },
        Rule {
            id: "optimize.updatedb",
            title: "Update locate database",
            risk: Risk::Safe,
            requires_sudo: true,
            applicable: Applicability::CommandExists("updatedb"),
            allowed_prefixes: &[],
            detector: Detector::Fn(updatedb_detector),
            action: Action::Cmd(updatedb_cmd),
            notes: "Refreshes the mlocate/plocate database `locate` searches against.",
        },
    ]
}

fn fstrim_detector(_ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    vec![Candidate::new(
        None,
        "Trim free space on all mounted filesystems (fstrim -av)".to_string(),
        0,
        Risk::Safe,
    )]
}

fn fstrim_cmd(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    vec![CmdSpec {
        argv: vec!["fstrim".to_string(), "-av".to_string()],
        sudo: true,
        label: "Trim SSD free space".to_string(),
    }]
}

fn reset_failed_detector(_ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    vec![Candidate::new(
        None,
        "Clear failed-unit counters (system + user)".to_string(),
        0,
        Risk::Safe,
    )]
}

fn reset_failed_cmd(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    vec![
        CmdSpec {
            argv: vec!["systemctl".to_string(), "reset-failed".to_string()],
            sudo: true,
            label: "Reset failed system units".to_string(),
        },
        CmdSpec {
            argv: vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "reset-failed".to_string(),
            ],
            sudo: false,
            label: "Reset failed user units".to_string(),
        },
    ]
}

fn font_cache_detector(_ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    vec![Candidate::new(
        None,
        "Rebuild the fontconfig cache (fc-cache -f)".to_string(),
        0,
        Risk::Safe,
    )]
}

fn font_cache_cmd(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    vec![CmdSpec {
        argv: vec!["fc-cache".to_string(), "-f".to_string()],
        sudo: false,
        label: "Rebuild font cache".to_string(),
    }]
}

fn desktop_db_detector(_ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    vec![Candidate::new(
        None,
        "Refresh desktop entry, icon, and MIME databases".to_string(),
        0,
        Risk::Safe,
    )]
}

/// Each sub-command is independently gated: the binary must exist, and (for
/// the icon/MIME caches, which error on a missing directory) the target
/// `~/.local/share` directory must already exist too.
fn desktop_db_cmd(ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    let mut specs = Vec::new();

    if command_exists("update-desktop-database", ctx) {
        let dir = ctx.home.join(".local/share/applications");
        specs.push(CmdSpec {
            argv: vec![
                "update-desktop-database".to_string(),
                dir.display().to_string(),
            ],
            sudo: false,
            label: "Refresh desktop entry database".to_string(),
        });
    }

    let hicolor = ctx.home.join(".local/share/icons/hicolor");
    if command_exists("gtk-update-icon-cache", ctx) && hicolor.is_dir() {
        specs.push(CmdSpec {
            argv: vec![
                "gtk-update-icon-cache".to_string(),
                "-f".to_string(),
                "-t".to_string(),
                hicolor.display().to_string(),
            ],
            sudo: false,
            label: "Refresh hicolor icon cache".to_string(),
        });
    }

    let mime = ctx.home.join(".local/share/mime");
    if command_exists("update-mime-database", ctx) && mime.is_dir() {
        specs.push(CmdSpec {
            argv: vec![
                "update-mime-database".to_string(),
                mime.display().to_string(),
            ],
            sudo: false,
            label: "Refresh MIME database".to_string(),
        });
    }

    specs
}

fn pacman_files_detector(_ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    vec![Candidate::new(
        None,
        "Refresh pacman's file-list database (pacman -Fy) — large download".to_string(),
        0,
        Risk::Moderate,
    )]
}

fn pacman_files_cmd(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    vec![CmdSpec {
        argv: vec!["pacman".to_string(), "-Fy".to_string()],
        sudo: true,
        label: "Refresh pacman file database".to_string(),
    }]
}

const MIRROR_TOOLS_IN_PREFERENCE_ORDER: &[&str] =
    &["cachyos-rate-mirrors", "rate-mirrors", "reflector"];

/// The mirror tool this task would use, honoring `optimize.mirror_tool`:
/// `"off"` disables the task; one of the three tool names pins that tool
/// (regardless of what else is installed); anything else (including the
/// default `"auto"`) auto-detects in preference order. Returns `None` when
/// disabled or when the pinned/auto-detected tool isn't actually installed.
fn mirror_tool(ctx: &Ctx) -> Option<&'static str> {
    let configured = ctx.config.optimize.mirror_tool.as_str();
    if configured == "off" {
        return None;
    }
    // A recognized tool name pins that tool (only if it's actually
    // installed); anything else, including the default "auto", auto-detects
    // in preference order.
    if let Some(&pinned) = MIRROR_TOOLS_IN_PREFERENCE_ORDER
        .iter()
        .find(|&&name| name == configured)
    {
        return command_exists(pinned, ctx).then_some(pinned);
    }
    MIRROR_TOOLS_IN_PREFERENCE_ORDER
        .iter()
        .copied()
        .find(|&name| command_exists(name, ctx))
}

fn mirrors_applicable(ctx: &Ctx) -> bool {
    mirror_tool(ctx).is_some()
}

fn mirrors_detector(ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    let tool = mirror_tool(ctx).unwrap_or("reflector");
    vec![Candidate::new(
        None,
        format!("Refresh mirror list via {tool}"),
        0,
        Risk::Moderate,
    )]
}

fn mirrors_cmd(ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    let tool = mirror_tool(ctx).unwrap_or("reflector");
    let argv = if tool == "reflector" {
        vec![
            "reflector".to_string(),
            "--latest".to_string(),
            "20".to_string(),
            "--protocol".to_string(),
            "https".to_string(),
            "--sort".to_string(),
            "rate".to_string(),
            "--save".to_string(),
            "/etc/pacman.d/mirrorlist".to_string(),
        ]
    } else {
        vec![tool.to_string()]
    };
    vec![CmdSpec {
        argv,
        sudo: true,
        label: format!("Refresh mirror list via {tool}"),
    }]
}

fn updatedb_detector(_ctx: &Ctx, _config: &Config) -> Vec<Candidate> {
    vec![Candidate::new(
        None,
        "Update the mlocate/plocate search database (updatedb)".to_string(),
        0,
        Risk::Safe,
    )]
}

fn updatedb_cmd(_ctx: &Ctx, _config: &Config) -> Vec<CmdSpec> {
    vec![CmdSpec {
        argv: vec!["updatedb".to_string()],
        sudo: true,
        label: "Update locate database".to_string(),
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

    #[test]
    fn test_registry_ids_are_unique_and_do_not_collide_with_the_clean_registry() {
        let mut ids: Vec<&str> = rules().iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids, deduped);
        assert!(ids.iter().all(|id| id.starts_with("optimize.")));
    }

    // --- optimize.fstrim ---

    #[test]
    fn test_fstrim_is_always_present_and_prechecked() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "optimize.fstrim")
            .unwrap();
        assert!(group.requires_sudo);
        assert!(group.candidates[0].selectable, "Safe tasks start checked");
    }

    #[test]
    fn test_fstrim_cmd_is_sudo_fstrim_av() {
        let specs = fstrim_cmd(&dummy_ctx(), &Config::default());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec!["fstrim".to_string(), "-av".to_string()],
                sudo: true,
                label: "Trim SSD free space".to_string(),
            }]
        );
    }

    // --- optimize.reset_failed ---

    #[test]
    fn test_reset_failed_is_always_present_and_prechecked() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "optimize.reset_failed")
            .unwrap();
        assert!(group.candidates[0].selectable);
    }

    #[test]
    fn test_reset_failed_cmd_sudos_the_system_scope_only() {
        let specs = reset_failed_cmd(&dummy_ctx(), &Config::default());
        assert_eq!(
            specs,
            vec![
                CmdSpec {
                    argv: vec!["systemctl".to_string(), "reset-failed".to_string()],
                    sudo: true,
                    label: "Reset failed system units".to_string(),
                },
                CmdSpec {
                    argv: vec![
                        "systemctl".to_string(),
                        "--user".to_string(),
                        "reset-failed".to_string(),
                    ],
                    sudo: false,
                    label: "Reset failed user units".to_string(),
                },
            ]
        );
    }

    // --- optimize.font_cache ---

    #[test]
    fn test_font_cache_group_requires_fc_cache_command() {
        let mut f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "optimize.font_cache"));

        f.ctx.available_commands = Some(vec!["fc-cache".to_string()]);
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "optimize.font_cache")
            .unwrap();
        assert!(!group.requires_sudo);
        assert!(group.candidates[0].selectable);
    }

    #[test]
    fn test_font_cache_cmd_is_not_sudo() {
        let specs = font_cache_cmd(&dummy_ctx(), &Config::default());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec!["fc-cache".to_string(), "-f".to_string()],
                sudo: false,
                label: "Rebuild font cache".to_string(),
            }]
        );
    }

    // --- optimize.desktop_db ---

    #[test]
    fn test_desktop_db_group_requires_at_least_one_of_the_three_commands() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "optimize.desktop_db"));
    }

    #[test]
    fn test_desktop_db_cmd_only_includes_update_desktop_database_when_that_alone_exists() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec!["update-desktop-database".to_string()]);
        let specs = desktop_db_cmd(&ctx, &Config::default());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec![
                    "update-desktop-database".to_string(),
                    ctx.home
                        .join(".local/share/applications")
                        .display()
                        .to_string(),
                ],
                sudo: false,
                label: "Refresh desktop entry database".to_string(),
            }]
        );
    }

    #[test]
    fn test_desktop_db_cmd_skips_icon_and_mime_caches_when_their_dirs_are_missing() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec![
            "gtk-update-icon-cache".to_string(),
            "update-mime-database".to_string(),
        ]);
        let specs = desktop_db_cmd(&ctx, &Config::default());
        assert!(specs.is_empty(), "neither target dir exists in this ctx");
    }

    #[test]
    fn test_desktop_db_cmd_includes_icon_and_mime_caches_when_their_dirs_exist() {
        let sandbox = tempfile::tempdir().unwrap();
        let home = sandbox.path().join("home/user");
        std::fs::create_dir_all(home.join(".local/share/icons/hicolor")).unwrap();
        std::fs::create_dir_all(home.join(".local/share/mime")).unwrap();
        let mut ctx = dummy_ctx();
        ctx.home = home.clone();
        ctx.available_commands = Some(vec![
            "gtk-update-icon-cache".to_string(),
            "update-mime-database".to_string(),
        ]);

        let specs = desktop_db_cmd(&ctx, &Config::default());
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].label, "Refresh hicolor icon cache");
        assert_eq!(specs[1].label, "Refresh MIME database");
    }

    // --- optimize.pacman_files ---

    #[test]
    fn test_pacman_files_group_requires_pacman_command_and_starts_unchecked() {
        let mut f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "optimize.pacman_files"));

        f.ctx.available_commands = Some(vec!["pacman".to_string()]);
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "optimize.pacman_files")
            .unwrap();
        assert!(
            !group.candidates[0].selectable,
            "opt-in task must start unchecked"
        );
    }

    #[test]
    fn test_pacman_files_cmd_is_sudo_pacman_fy() {
        let specs = pacman_files_cmd(&dummy_ctx(), &Config::default());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec!["pacman".to_string(), "-Fy".to_string()],
                sudo: true,
                label: "Refresh pacman file database".to_string(),
            }]
        );
    }

    // --- optimize.updatedb ---

    #[test]
    fn test_updatedb_group_requires_updatedb_command_and_is_prechecked() {
        let mut f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "optimize.updatedb"));

        f.ctx.available_commands = Some(vec!["updatedb".to_string()]);
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "optimize.updatedb")
            .unwrap();
        assert!(group.candidates[0].selectable);
    }

    // --- optimize.mirrors ---

    #[test]
    fn test_mirrors_absent_when_no_mirror_tool_is_installed() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "optimize.mirrors"));
    }

    #[test]
    fn test_mirrors_absent_when_config_sets_mirror_tool_off() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["reflector".to_string()]);
        f.ctx.config.optimize.mirror_tool = "off".to_string();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(!groups.iter().any(|g| g.rule_id == "optimize.mirrors"));
    }

    #[test]
    fn test_mirrors_prefers_cachyos_rate_mirrors_over_the_others_when_auto() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec![
            "cachyos-rate-mirrors".to_string(),
            "rate-mirrors".to_string(),
            "reflector".to_string(),
        ]);
        assert_eq!(mirror_tool(&ctx), Some("cachyos-rate-mirrors"));
    }

    #[test]
    fn test_mirrors_falls_back_to_rate_mirrors_then_reflector() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec!["rate-mirrors".to_string(), "reflector".to_string()]);
        assert_eq!(mirror_tool(&ctx), Some("rate-mirrors"));

        ctx.available_commands = Some(vec!["reflector".to_string()]);
        assert_eq!(mirror_tool(&ctx), Some("reflector"));
    }

    #[test]
    fn test_mirrors_config_override_pins_a_specific_tool() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec![
            "cachyos-rate-mirrors".to_string(),
            "reflector".to_string(),
        ]);
        ctx.config.optimize.mirror_tool = "reflector".to_string();
        assert_eq!(mirror_tool(&ctx), Some("reflector"));
    }

    #[test]
    fn test_mirrors_config_override_to_an_uninstalled_tool_yields_none() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec!["cachyos-rate-mirrors".to_string()]);
        ctx.config.optimize.mirror_tool = "reflector".to_string();
        assert_eq!(mirror_tool(&ctx), None);
    }

    #[test]
    fn test_mirrors_group_starts_unchecked() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["reflector".to_string()]);
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let group = groups
            .iter()
            .find(|g| g.rule_id == "optimize.mirrors")
            .unwrap();
        assert!(!group.candidates[0].selectable);
    }

    #[test]
    fn test_mirrors_cmd_uses_reflector_argv() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec!["reflector".to_string()]);
        let specs = mirrors_cmd(&ctx, &Config::default());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec![
                    "reflector".to_string(),
                    "--latest".to_string(),
                    "20".to_string(),
                    "--protocol".to_string(),
                    "https".to_string(),
                    "--sort".to_string(),
                    "rate".to_string(),
                    "--save".to_string(),
                    "/etc/pacman.d/mirrorlist".to_string(),
                ],
                sudo: true,
                label: "Refresh mirror list via reflector".to_string(),
            }]
        );
    }

    #[test]
    fn test_mirrors_cmd_runs_cachyos_rate_mirrors_bare() {
        let mut ctx = dummy_ctx();
        ctx.available_commands = Some(vec!["cachyos-rate-mirrors".to_string()]);
        let specs = mirrors_cmd(&ctx, &Config::default());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec!["cachyos-rate-mirrors".to_string()],
                sudo: true,
                label: "Refresh mirror list via cachyos-rate-mirrors".to_string(),
            }]
        );
    }
}
