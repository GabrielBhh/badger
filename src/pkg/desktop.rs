//! `.desktop` launcher scanner for the uninstall picker's Applications view:
//! parses installed `.desktop` entries (system, user, and flatpak exports)
//! into friendly display names, later mapped back to installed packages by
//! `pkg::applications`.

use std::path::{Path, PathBuf};

use crate::ctx::Ctx;

/// One parsed `.desktop` launcher entry, kept only when it should actually be
/// shown to a person (not `NoDisplay`/`Hidden`, and has a plain `Name=`).
#[derive(Debug, Clone, PartialEq)]
pub struct DesktopApp {
    pub display_name: String,
    pub desktop_file: PathBuf,
    /// The flatpak application ID, when this entry is a flatpak export —
    /// read from `X-Flatpak=` if present, else derived from the file's own
    /// name (flatpak exports one `<app-id>.desktop` per app).
    pub flatpak_id: Option<String>,
    /// The first entry in `Categories=` that belongs to the fixed "main
    /// category" set below, if any — feeds `pkg::recommend`'s category-
    /// overlap hint. Categories outside the set (`GTK`, `Utility`, ...) are
    /// skipped in favor of the next one.
    pub main_category: Option<Category>,
}

/// The fixed set of `.desktop` `Categories=` entries `pkg::recommend` groups
/// apps by for its overlap hint — deliberately small and user-facing rather
/// than the full freedesktop category list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    WebBrowser,
    Email,
    AudioVideo,
    Audio,
    Video,
    TextEditor,
    IDE,
    FileManager,
    TerminalEmulator,
    Graphics,
    Game,
}

impl Category {
    fn parse(raw: &str) -> Option<Category> {
        match raw {
            "WebBrowser" => Some(Category::WebBrowser),
            "Email" => Some(Category::Email),
            "AudioVideo" => Some(Category::AudioVideo),
            "Audio" => Some(Category::Audio),
            "Video" => Some(Category::Video),
            "TextEditor" => Some(Category::TextEditor),
            "IDE" => Some(Category::IDE),
            "FileManager" => Some(Category::FileManager),
            "TerminalEmulator" => Some(Category::TerminalEmulator),
            "Graphics" => Some(Category::Graphics),
            "Game" => Some(Category::Game),
            _ => None,
        }
    }
}

/// The first `;`-separated entry of a `Categories=` value that's in the
/// fixed main-category set, in the file's own order — an unrecognized entry
/// (e.g. `GTK`, `Utility`) is skipped rather than stopping the search.
fn main_category(categories: &str) -> Option<Category> {
    categories
        .split(';')
        .find_map(|c| Category::parse(c.trim()))
}

/// Scans every `.desktop` entry under the well-known application
/// directories: system (`/usr/share/applications`), user
/// (`~/.local/share/applications`), and flatpak exports (system + user).
/// Files that don't parse as a displayable app (missing `[Desktop Entry]`,
/// missing `Name=`, `NoDisplay=true`, `Hidden=true`) are skipped silently.
pub fn scan(ctx: &Ctx) -> Vec<DesktopApp> {
    dirs(ctx)
        .iter()
        .flat_map(|(dir, is_flatpak_export)| scan_dir(dir, *is_flatpak_export))
        .collect()
}

fn dirs(ctx: &Ctx) -> Vec<(PathBuf, bool)> {
    vec![
        (ctx.root.join("usr/share/applications"), false),
        (ctx.home.join(".local/share/applications"), false),
        (
            ctx.root.join("var/lib/flatpak/exports/share/applications"),
            true,
        ),
        (
            ctx.home
                .join(".local/share/flatpak/exports/share/applications"),
            true,
        ),
    ]
}

fn scan_dir(dir: &Path, is_flatpak_export: bool) -> Vec<DesktopApp> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "desktop"))
        .filter_map(|entry| parse_desktop_file(&entry.path(), is_flatpak_export))
        .collect()
}

fn parse_desktop_file(path: &Path, is_flatpak_export: bool) -> Option<DesktopApp> {
    let text = std::fs::read_to_string(path).ok()?;
    let entry = parse_entry(&text)?;
    if entry.no_display || entry.hidden {
        return None;
    }
    let flatpak_id = entry.x_flatpak.or_else(|| {
        is_flatpak_export
            .then(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .flatten()
    });
    Some(DesktopApp {
        display_name: entry.name?,
        desktop_file: path.to_path_buf(),
        flatpak_id,
        main_category: entry.categories.as_deref().and_then(main_category),
    })
}

#[derive(Default)]
struct ParsedEntry {
    name: Option<String>,
    no_display: bool,
    hidden: bool,
    x_flatpak: Option<String>,
    categories: Option<String>,
}

/// Parses just the `[Desktop Entry]` section: plain `Name=` (localized
/// `Name[xx]=` variants are a different key and so ignored), `NoDisplay=`,
/// `Hidden=`, `X-Flatpak=`, `Categories=`. Stops applying keys once a later
/// `[...]` section header is seen. Returns `None` when the file never had a
/// `[Desktop Entry]` section at all (malformed — skipped silently by the
/// caller).
fn parse_entry(text: &str) -> Option<ParsedEntry> {
    let mut entry = ParsedEntry::default();
    let mut in_section = false;
    let mut saw_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == "[Desktop Entry]";
            saw_section = saw_section || in_section;
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "Name" => entry.name = Some(value.trim().to_string()),
            "NoDisplay" => entry.no_display = value.trim().eq_ignore_ascii_case("true"),
            "Hidden" => entry.hidden = value.trim().eq_ignore_ascii_case("true"),
            "X-Flatpak" => entry.x_flatpak = Some(value.trim().to_string()),
            "Categories" => entry.categories = Some(value.trim().to_string()),
            _ => {}
        }
    }
    saw_section.then_some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

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

    #[test]
    fn test_scan_finds_a_normal_system_entry() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(
            &dir,
            "firefox.desktop",
            "[Desktop Entry]\nName=Firefox\nExec=firefox\n",
        );

        let apps = scan(&f.ctx);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].display_name, "Firefox");
        assert_eq!(apps[0].desktop_file, dir.join("firefox.desktop"));
        assert_eq!(apps[0].flatpak_id, None);
    }

    #[test]
    fn test_scan_skips_no_display_entries() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(
            &dir,
            "helper.desktop",
            "[Desktop Entry]\nName=Helper\nNoDisplay=true\n",
        );

        assert!(scan(&f.ctx).is_empty());
    }

    #[test]
    fn test_scan_skips_hidden_entries() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(
            &dir,
            "old.desktop",
            "[Desktop Entry]\nName=Old\nHidden=true\n",
        );

        assert!(scan(&f.ctx).is_empty());
    }

    #[test]
    fn test_scan_skips_entries_missing_name() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "noname.desktop", "[Desktop Entry]\nExec=noname\n");

        assert!(scan(&f.ctx).is_empty());
    }

    #[test]
    fn test_scan_ignores_localized_name_variants() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(
            &dir,
            "app.desktop",
            "[Desktop Entry]\nName[fr]=Le Foo\nName=Foo\n",
        );

        let apps = scan(&f.ctx);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].display_name, "Foo");
    }

    #[test]
    fn test_scan_finds_user_entry() {
        let f = fixture();
        let dir = f.ctx.home.join(".local/share/applications");
        write_desktop(&dir, "myapp.desktop", "[Desktop Entry]\nName=My App\n");

        let apps = scan(&f.ctx);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].display_name, "My App");
    }

    #[test]
    fn test_scan_flatpak_export_reads_x_flatpak_key() {
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

        let apps = scan(&f.ctx);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].flatpak_id, Some("org.foo.App".to_string()));
    }

    #[test]
    fn test_scan_flatpak_export_falls_back_to_filename_for_id() {
        let f = fixture();
        let dir = f
            .ctx
            .home
            .join(".local/share/flatpak/exports/share/applications");
        write_desktop(
            &dir,
            "org.bar.App.desktop",
            "[Desktop Entry]\nName=Bar App\n",
        );

        let apps = scan(&f.ctx);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].flatpak_id, Some("org.bar.App".to_string()));
    }

    #[test]
    fn test_scan_ignores_non_desktop_files() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "readme.txt", "not a desktop file");

        assert!(scan(&f.ctx).is_empty());
    }

    #[test]
    fn test_scan_missing_dirs_yield_no_apps() {
        let f = fixture();
        assert!(scan(&f.ctx).is_empty());
    }

    #[test]
    fn test_scan_skips_malformed_file_without_desktop_entry_section() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "broken.desktop", "not an ini file at all\n");

        assert!(scan(&f.ctx).is_empty());
    }

    // --- Categories= / main_category ---

    #[test]
    fn test_scan_parses_a_recognized_category() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(
            &dir,
            "firefox.desktop",
            "[Desktop Entry]\nName=Firefox\nCategories=Network;WebBrowser;\n",
        );

        let apps = scan(&f.ctx);
        assert_eq!(apps[0].main_category, Some(Category::WebBrowser));
    }

    #[test]
    fn test_scan_picks_the_first_recognized_category_skipping_unknown_ones() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(
            &dir,
            "app.desktop",
            "[Desktop Entry]\nName=App\nCategories=GTK;Utility;Video;AudioVideo;\n",
        );

        let apps = scan(&f.ctx);
        assert_eq!(apps[0].main_category, Some(Category::Video));
    }

    #[test]
    fn test_scan_no_categories_line_yields_no_main_category() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(&dir, "app.desktop", "[Desktop Entry]\nName=App\n");

        let apps = scan(&f.ctx);
        assert_eq!(apps[0].main_category, None);
    }

    #[test]
    fn test_scan_categories_with_no_recognized_entries_yields_no_main_category() {
        let f = fixture();
        let dir = f.ctx.root.join("usr/share/applications");
        write_desktop(
            &dir,
            "app.desktop",
            "[Desktop Entry]\nName=App\nCategories=GTK;Utility;\n",
        );

        let apps = scan(&f.ctx);
        assert_eq!(apps[0].main_category, None);
    }
}
