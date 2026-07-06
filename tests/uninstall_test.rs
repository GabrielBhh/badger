use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use badger::commands::uninstall;
use badger::config::Config;
use badger::core::runner::CmdOutput;
use badger::ctx::Ctx;
use badger::output::Mode;
use badger::pkg::{self, Backend, InstalledPackage};
use badger::tui::picker::{PickerState, View};

fn fixture_ctx() -> (tempfile::TempDir, Ctx) {
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
    (sandbox, ctx)
}

/// `badger uninstall` is inherently interactive: no `--yes`, no `--json`
/// output mode. Asking for JSON (or running non-interactively) must fail
/// clearly rather than silently doing nothing.
#[test]
fn test_json_mode_is_rejected_as_non_interactive() {
    let (_sandbox, ctx) = fixture_ctx();
    let err = uninstall::run(&ctx, false, Mode::Json, false).unwrap_err();
    assert!(err.to_string().contains("interactive terminal"));
}

/// Thin end-to-end smoke test: drives the actual compiled binary (not just
/// the lib) with stdout/stderr piped (never a tty in a test process) to
/// catch wiring bugs in cli.rs/main.rs/dispatch that a lib-level call can't
/// see. `badger uninstall` has no non-interactive mode, so the only thing to
/// assert here is that it fails clearly instead of hanging or panicking.
#[test]
fn test_binary_uninstall_without_a_tty_exits_1_with_a_clear_error() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    std::fs::create_dir_all(&home).unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let output = std::process::Command::new(bin)
        .arg("uninstall")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal"),
        "stderr was: {stderr}"
    );
}

/// End-to-end for issue #16: a `.desktop` tree (system pacman-owned entry +
/// flatpak export) plus a canned `pacman -Qo`, run through the real
/// `pkg::applications` seam and then into `PickerState`, mirrors what
/// `commands::uninstall::run_interactive` wires together — the picker must
/// default to the Applications view, showing friendly names, mapped back to
/// the right underlying package.
#[test]
fn test_applications_view_is_built_from_desktop_entries_and_defaults_the_picker_to_it() {
    let (_sandbox, mut ctx) = fixture_ctx();

    let system_apps = ctx.root.join("usr/share/applications");
    std::fs::create_dir_all(&system_apps).unwrap();
    std::fs::write(
        system_apps.join("firefox.desktop"),
        "[Desktop Entry]\nName=Firefox\n",
    )
    .unwrap();
    let firefox_desktop_file = system_apps.join("firefox.desktop");

    let flatpak_exports = ctx.root.join("var/lib/flatpak/exports/share/applications");
    std::fs::create_dir_all(&flatpak_exports).unwrap();
    std::fs::write(
        flatpak_exports.join("org.gimp.GIMP.desktop"),
        "[Desktop Entry]\nName=GIMP\nX-Flatpak=org.gimp.GIMP\n",
    )
    .unwrap();

    ctx.fake_command_output = Some(HashMap::from([(
        vec![
            "pacman".to_string(),
            "-Qo".to_string(),
            "--".to_string(),
            firefox_desktop_file.display().to_string(),
        ],
        CmdOutput {
            success: true,
            stdout: format!(
                "{} is owned by firefox 121.0-1\n",
                firefox_desktop_file.display()
            ),
            stderr: String::new(),
        },
    )]));

    let packages = vec![
        InstalledPackage {
            backend: Backend::Pacman,
            id: "firefox".to_string(),
            name: "firefox".to_string(),
            version: "121.0-1".to_string(),
            size_bytes: None,
            aur: false,
        },
        InstalledPackage {
            backend: Backend::Flatpak,
            id: "org.gimp.GIMP".to_string(),
            name: "org.gimp.GIMP".to_string(),
            version: "2.10.36".to_string(),
            size_bytes: None,
            aur: false,
        },
        // Never referenced by any .desktop entry — must not show up in the
        // Applications view, only in the raw Packages view.
        InstalledPackage {
            backend: Backend::Pacman,
            id: "lib32-gcc-libs".to_string(),
            name: "lib32-gcc-libs".to_string(),
            version: "13.2.1-1".to_string(),
            size_bytes: None,
            aur: false,
        },
    ];

    let apps = pkg::applications(&ctx, &packages);
    assert_eq!(apps.len(), 2, "firefox and GIMP, not lib32-gcc-libs");

    let state = PickerState::new(packages, apps);
    assert_eq!(
        state.view(),
        View::Apps,
        "must default to Applications view"
    );
    let names: Vec<&str> = state.visible().iter().map(|r| r.display_name).collect();
    assert_eq!(names, vec!["Firefox", "GIMP"]);
    assert!(
        !names.contains(&"lib32-gcc-libs"),
        "raw package with no desktop entry must not appear in the Applications view"
    );

    let selected = state.selected().unwrap();
    assert_eq!(
        selected.id, "firefox",
        "cursor starts on the first (alphabetical) app, mapped to its package"
    );
}

/// End-to-end for issue #21: a cross-backend duplicate (pacman + flatpak
/// Firefox) and an app with only a stale `~/.cache` dir, run through the
/// real `pkg::applications` + `pkg::recommend` seams and into
/// `PickerState`, mirrors what `commands::uninstall::run_interactive` wires
/// together — both must carry a recommendation, an unflagged app must not,
/// and the `r`-toggled recommended-only filter must show exactly the
/// flagged three (both Firefox rows plus the unused one).
#[test]
fn test_picker_state_carries_duplicate_and_unused_recommendations_and_r_filters_to_them() {
    let (_sandbox, mut ctx) = fixture_ctx();

    let system_apps = ctx.root.join("usr/share/applications");
    std::fs::create_dir_all(&system_apps).unwrap();
    std::fs::write(
        system_apps.join("firefox.desktop"),
        "[Desktop Entry]\nName=Firefox\n",
    )
    .unwrap();
    std::fs::write(
        system_apps.join("oldapp.desktop"),
        "[Desktop Entry]\nName=OldApp\n",
    )
    .unwrap();
    std::fs::write(
        system_apps.join("plainapp.desktop"),
        "[Desktop Entry]\nName=PlainApp\n",
    )
    .unwrap();
    let firefox_file = system_apps.join("firefox.desktop");
    let oldapp_file = system_apps.join("oldapp.desktop");
    let plainapp_file = system_apps.join("plainapp.desktop");

    let flatpak_exports = ctx.root.join("var/lib/flatpak/exports/share/applications");
    std::fs::create_dir_all(&flatpak_exports).unwrap();
    std::fs::write(
        flatpak_exports.join("org.mozilla.firefox.desktop"),
        "[Desktop Entry]\nName=Firefox\nX-Flatpak=org.mozilla.firefox\n",
    )
    .unwrap();

    // oldapp's own cache dir, untouched well past the default 90-day
    // unused_days threshold — the only signal `recommend::unused` needs.
    let oldapp_cache = ctx.home.join(".cache/oldapp");
    std::fs::create_dir_all(&oldapp_cache).unwrap();
    let stale = SystemTime::now() - Duration::from_secs(200 * 86_400);
    std::fs::File::open(&oldapp_cache)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(stale))
        .unwrap();

    ctx.fake_command_output = Some(HashMap::from([(
        vec![
            "pacman".to_string(),
            "-Qo".to_string(),
            "--".to_string(),
            firefox_file.display().to_string(),
            oldapp_file.display().to_string(),
            plainapp_file.display().to_string(),
        ],
        CmdOutput {
            success: true,
            stdout: format!(
                "{} is owned by firefox 121.0-1\n{} is owned by oldapp 1.0-1\n{} is owned by plainapp 1.0-1\n",
                firefox_file.display(),
                oldapp_file.display(),
                plainapp_file.display(),
            ),
            stderr: String::new(),
        },
    )]));

    let packages = vec![
        InstalledPackage {
            backend: Backend::Pacman,
            id: "firefox".to_string(),
            name: "firefox".to_string(),
            version: "121.0-1".to_string(),
            size_bytes: None,
            aur: false,
        },
        InstalledPackage {
            backend: Backend::Flatpak,
            id: "org.mozilla.firefox".to_string(),
            name: "Firefox".to_string(),
            version: "121.0".to_string(),
            size_bytes: None,
            aur: false,
        },
        InstalledPackage {
            backend: Backend::Pacman,
            id: "oldapp".to_string(),
            name: "oldapp".to_string(),
            version: "1.0-1".to_string(),
            size_bytes: None,
            aur: false,
        },
        InstalledPackage {
            backend: Backend::Pacman,
            id: "plainapp".to_string(),
            name: "plainapp".to_string(),
            version: "1.0-1".to_string(),
            size_bytes: None,
            aur: false,
        },
    ];

    let apps = pkg::applications(&ctx, &packages);
    assert_eq!(apps.len(), 4, "both Firefox entries, OldApp, PlainApp");
    let desktop_apps = pkg::desktop::scan(&ctx);
    let recommendations =
        pkg::recommend::recommendations(&apps, &packages, &desktop_apps, &ctx, &ctx.config);

    let mut state = PickerState::new(packages, apps);
    state.set_recommendations(recommendations);

    assert!(state.has_any_recommendation());
    assert!(
        !state.recommendations_for(0).is_empty(),
        "pacman firefox must carry the duplicate badge"
    );
    assert!(
        !state.recommendations_for(1).is_empty(),
        "flatpak firefox must carry the duplicate badge"
    );
    assert!(
        !state.recommendations_for(2).is_empty(),
        "oldapp must carry the unused badge"
    );
    assert!(
        state.recommendations_for(3).is_empty(),
        "plainapp has neither a duplicate nor a stale cache/config dir"
    );

    state.toggle_recommended_only();
    let names: Vec<&str> = state.visible().iter().map(|r| r.display_name).collect();
    assert_eq!(
        names,
        vec!["Firefox", "Firefox", "OldApp"],
        "recommended-only shows exactly the flagged apps, duplicates before unused"
    );
}
