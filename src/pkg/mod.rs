//! Installed-package backends for `badger uninstall`: enumerating what's
//! installed (pacman/AUR, flatpak, snap) and the argv each backend's removal
//! takes. Every backend goes through `core::runner`'s `CommandRunner` seam —
//! nothing here ever shells out directly — so tests never run real pacman/
//! flatpak/snap.

pub mod desktop;
pub mod flatpak;
pub mod pacman;
pub mod snap;

use std::collections::HashMap;
use std::path::PathBuf;

use crate::ctx::Ctx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Pacman,
    Flatpak,
    Snap,
}

impl Backend {
    /// Display label for the picker's `[pacman|aur|flatpak|snap]` badge.
    /// `aur` itself is not a `Backend` variant — it's `Pacman` with
    /// `InstalledPackage::aur` set, and callers that want the "aur" badge
    /// check that flag themselves before falling back to this label.
    pub fn label(self) -> &'static str {
        match self {
            Backend::Pacman => "pacman",
            Backend::Flatpak => "flatpak",
            Backend::Snap => "snap",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstalledPackage {
    pub backend: Backend,
    /// The identifier the backend's own remove command takes: a pacman
    /// package name, a flatpak application ID, or a snap name.
    pub id: String,
    pub name: String,
    pub version: String,
    pub size_bytes: Option<u64>,
    /// `true` for a pacman package installed from the AUR (foreign,
    /// `pacman -Qm`). Always `false` for flatpak/snap.
    pub aur: bool,
}

/// Every installed package across whichever backends are actually present on
/// this system (`CommandExists`-gated per backend) — an absent backend is
/// skipped silently rather than erroring.
pub fn list_installed(ctx: &Ctx) -> Vec<InstalledPackage> {
    let mut all = Vec::new();
    if pacman::is_available(ctx) {
        all.extend(pacman::list(ctx));
    }
    if flatpak::is_available(ctx) {
        all.extend(flatpak::list(ctx));
    }
    if snap::is_available(ctx) {
        all.extend(snap::list(ctx));
    }
    all
}

/// One friendly-named application for the uninstall picker's Applications
/// view, mapped back to `packages` via `index`.
#[derive(Debug, Clone, PartialEq)]
pub struct AppEntry {
    pub display_name: String,
    pub package_index: usize,
}

/// Maps every scanned `.desktop` entry back to whichever of `packages` owns
/// it — flatpak entries by app ID, pacman-owned entries via one batched
/// `pacman -Qo` call — for the uninstall picker's Applications view. An
/// entry whose owning package isn't in `packages` is dropped. Multiple
/// `.desktop` entries owned by the same package collapse into a single
/// `AppEntry`, keeping the shortest display name. Sorted by display name,
/// case-insensitively.
pub fn applications(ctx: &Ctx, packages: &[InstalledPackage]) -> Vec<AppEntry> {
    let desktop_apps = desktop::scan(ctx);

    let flatpak_index: HashMap<&str, usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.backend == Backend::Flatpak)
        .map(|(i, p)| (p.id.as_str(), i))
        .collect();
    let pacman_index: HashMap<&str, usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.backend == Backend::Pacman)
        .map(|(i, p)| (p.id.as_str(), i))
        .collect();

    // Sorted so the batched pacman -Qo call (and any test asserting its
    // exact argv) doesn't depend on `read_dir`'s unspecified entry order.
    let mut pacman_files: Vec<PathBuf> = desktop_apps
        .iter()
        .filter(|a| a.flatpak_id.is_none())
        .map(|a| a.desktop_file.clone())
        .collect();
    pacman_files.sort();
    let owners = pacman::owners(ctx, &pacman_files);

    let mut by_package: HashMap<usize, String> = HashMap::new();
    for app in &desktop_apps {
        let package_index = match &app.flatpak_id {
            Some(id) => flatpak_index.get(id.as_str()).copied(),
            None => owners
                .get(&app.desktop_file)
                .and_then(|pkg| pacman_index.get(pkg.as_str()).copied()),
        };
        let Some(package_index) = package_index else {
            continue;
        };
        by_package
            .entry(package_index)
            .and_modify(|existing| {
                if app.display_name.len() < existing.len() {
                    *existing = app.display_name.clone();
                }
            })
            .or_insert_with(|| app.display_name.clone());
    }

    let mut out: Vec<AppEntry> = by_package
        .into_iter()
        .map(|(package_index, display_name)| AppEntry {
            display_name,
            package_index,
        })
        .collect();
    out.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    fn ctx() -> Ctx {
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
    fn test_list_installed_is_empty_when_no_backend_is_available() {
        assert!(list_installed(&ctx()).is_empty());
    }
}

#[cfg(test)]
mod applications_tests {
    use super::*;
    use crate::config::Config;
    use crate::core::runner::CmdOutput;
    use std::path::Path;

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

    fn write_desktop(dir: &Path, filename: &str, contents: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(filename), contents).unwrap();
    }

    fn pacman_pkg(name: &str) -> InstalledPackage {
        InstalledPackage {
            backend: Backend::Pacman,
            id: name.to_string(),
            name: name.to_string(),
            version: "1.0-1".to_string(),
            size_bytes: None,
            aur: false,
        }
    }

    fn flatpak_pkg(id: &str) -> InstalledPackage {
        InstalledPackage {
            backend: Backend::Flatpak,
            id: id.to_string(),
            name: id.to_string(),
            version: "1.0".to_string(),
            size_bytes: None,
            aur: false,
        }
    }

    #[test]
    fn test_applications_maps_flatpak_entry_by_app_id() {
        let f = fixture();
        let dir = f
            .ctx
            .root
            .join("var/lib/flatpak/exports/share/applications");
        write_desktop(
            &dir,
            "org.foo.App.desktop",
            "[Desktop Entry]\nName=Foo App\nX-Flatpak=org.foo.App\n",
        );
        let packages = vec![flatpak_pkg("org.foo.App")];

        let apps = applications(&f.ctx, &packages);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].display_name, "Foo App");
        assert_eq!(apps[0].package_index, 0);
    }

    #[test]
    fn test_applications_maps_pacman_owned_desktop_entry_via_batched_qo() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "firefox.desktop", "[Desktop Entry]\nName=Firefox\n");
        let desktop_file = dir.join("firefox.desktop");
        let mut c = f.ctx.clone();
        c.fake_command_output = Some(HashMap::from([(
            vec![
                "pacman".to_string(),
                "-Qo".to_string(),
                "--".to_string(),
                desktop_file.display().to_string(),
            ],
            CmdOutput {
                success: true,
                stdout: format!("{} is owned by firefox 121.0-1\n", desktop_file.display()),
                stderr: String::new(),
            },
        )]));
        let packages = vec![pacman_pkg("firefox")];

        let apps = applications(&c, &packages);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].display_name, "Firefox");
        assert_eq!(apps[0].package_index, 0);
    }

    #[test]
    fn test_applications_drops_entry_whose_owning_package_is_not_installed() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "ghost.desktop", "[Desktop Entry]\nName=Ghost\n");
        let desktop_file = dir.join("ghost.desktop");
        let mut c = f.ctx.clone();
        c.fake_command_output = Some(HashMap::from([(
            vec![
                "pacman".to_string(),
                "-Qo".to_string(),
                "--".to_string(),
                desktop_file.display().to_string(),
            ],
            CmdOutput {
                success: true,
                stdout: format!("{} is owned by ghost-pkg 1.0-1\n", desktop_file.display()),
                stderr: String::new(),
            },
        )]));

        // ghost-pkg is never in the installed list, so the entry is dropped.
        let apps = applications(&c, &[]);
        assert!(apps.is_empty());
    }

    #[test]
    fn test_applications_tolerates_partial_qo_failure() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "firefox.desktop", "[Desktop Entry]\nName=Firefox\n");
        write_desktop(&dir, "orphaned.desktop", "[Desktop Entry]\nName=Orphaned\n");
        let firefox_file = dir.join("firefox.desktop");
        let orphaned_file = dir.join("orphaned.desktop");
        let mut c = f.ctx.clone();
        let mut files = vec![
            firefox_file.display().to_string(),
            orphaned_file.display().to_string(),
        ];
        files.sort();
        let mut argv = vec!["pacman".to_string(), "-Qo".to_string(), "--".to_string()];
        argv.extend(files);
        c.fake_command_output = Some(HashMap::from([(
            argv,
            CmdOutput {
                success: false,
                stdout: format!("{} is owned by firefox 121.0-1\n", firefox_file.display()),
                stderr: format!("error: No package owns {}\n", orphaned_file.display()),
            },
        )]));
        let packages = vec![pacman_pkg("firefox")];

        let apps = applications(&c, &packages);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].display_name, "Firefox");
    }

    #[test]
    fn test_applications_dedupes_multiple_desktop_entries_to_one_package_keeping_shortest_name() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "foo.desktop", "[Desktop Entry]\nName=Foo\n");
        write_desktop(
            &dir,
            "foo-alt.desktop",
            "[Desktop Entry]\nName=Foo Alternate Launcher\n",
        );
        let foo_file = dir.join("foo.desktop");
        let alt_file = dir.join("foo-alt.desktop");
        let mut c = f.ctx.clone();
        let mut files = vec![
            foo_file.display().to_string(),
            alt_file.display().to_string(),
        ];
        files.sort();
        let mut argv = vec!["pacman".to_string(), "-Qo".to_string(), "--".to_string()];
        argv.extend(files);
        c.fake_command_output = Some(HashMap::from([(
            argv,
            CmdOutput {
                success: true,
                stdout: format!(
                    "{} is owned by foo 1.0-1\n{} is owned by foo 1.0-1\n",
                    foo_file.display(),
                    alt_file.display()
                ),
                stderr: String::new(),
            },
        )]));
        let packages = vec![pacman_pkg("foo")];

        let apps = applications(&c, &packages);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].display_name, "Foo");
    }

    #[test]
    fn test_applications_sorts_by_display_name_case_insensitively() {
        let f = fixture();
        let dir = f.ctx.home.join(".local/share/applications");
        write_desktop(&dir, "zzz.desktop", "[Desktop Entry]\nName=zeta\n");
        write_desktop(&dir, "aaa.desktop", "[Desktop Entry]\nName=Alpha\n");
        let zeta_file = dir.join("zzz.desktop");
        let alpha_file = dir.join("aaa.desktop");
        let mut c = f.ctx.clone();
        let mut files = vec![
            zeta_file.display().to_string(),
            alpha_file.display().to_string(),
        ];
        files.sort();
        let mut argv = vec!["pacman".to_string(), "-Qo".to_string(), "--".to_string()];
        argv.extend(files);
        c.fake_command_output = Some(HashMap::from([(
            argv,
            CmdOutput {
                success: true,
                stdout: format!(
                    "{} is owned by zeta-pkg 1.0-1\n{} is owned by alpha-pkg 1.0-1\n",
                    zeta_file.display(),
                    alpha_file.display()
                ),
                stderr: String::new(),
            },
        )]));
        let packages = vec![pacman_pkg("zeta-pkg"), pacman_pkg("alpha-pkg")];

        let apps = applications(&c, &packages);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].display_name, "Alpha");
        assert_eq!(apps[1].display_name, "zeta");
    }
}
