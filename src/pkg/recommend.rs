//! Advisory recommendation badges for the uninstall picker's Applications
//! view: hints about which installed apps might be worth removing. Every
//! recommendation is a *guess*, never an auto-selection — badges are
//! display-only (see `tui::picker`) and never change what actually gets
//! removed.
//!
//! Three independent heuristics, each conservative about false positives:
//! - `Duplicate` (reliable): the same app installed via >=2 different
//!   backends, matched by normalized display name / flatpak app-id.
//! - `Unused` (heuristic): the app's own `~/.cache`/`~/.config` directories
//!   haven't been touched in a while. Absence of evidence is never treated
//!   as evidence of non-use — an app with no matching directories at all
//!   gets no recommendation, not an "unused" guess.
//! - `Overlap`: three or more installed apps share the same `.desktop`
//!   main category (e.g. three web browsers).

use std::collections::HashMap;
use std::time::SystemTime;

use crate::config::Config;
use crate::ctx::Ctx;
use crate::pkg::desktop::{Category, DesktopApp};
use crate::pkg::{AppEntry, Backend, InstalledPackage};

/// One advisory hint for the package at `package_index` — an index into the
/// same `packages` slice `AppEntry::package_index` already points into.
#[derive(Debug, Clone, PartialEq)]
pub struct Recommendation {
    pub package_index: usize,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    /// The same app is also installed via `other_backend`.
    Duplicate { other_backend: Backend },
    /// Its cache/config directories haven't been touched in roughly this
    /// many months.
    Unused { months: u32 },
    /// One of `count` installed apps sharing `category`. `most_used` marks
    /// the group member with the freshest activity signal (see
    /// `activity_ages_days`) — recency of the app's own cache/config files,
    /// not launch counts, so it's an honest proxy rather than a measurement.
    /// If no member of the group has any matching cache/config directory at
    /// all, nobody is marked. Ties are broken by first occurrence in the
    /// caller's `apps` order.
    Overlap {
        category: Category,
        count: usize,
        most_used: bool,
    },
}

/// Builds every recommendation for `apps`, each keyed back to its package via
/// `package_index`. Pure aside from the cache/config directory mtime checks
/// under `ctx.home` — no command execution, so this never needs a runner.
pub fn recommendations(
    apps: &[AppEntry],
    packages: &[InstalledPackage],
    desktop_apps: &[DesktopApp],
    ctx: &Ctx,
    config: &Config,
) -> Vec<Recommendation> {
    let mut out = duplicates(apps, packages);
    out.extend(unused(apps, packages, ctx, config));
    out.extend(overlaps(apps, packages, desktop_apps, ctx));
    out
}

/// Lowercased with whitespace, `-`, and `_` stripped — the identity
/// `Duplicate` matches on, so "Foo App", "foo-app", and "foo_app" are all
/// one identity.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// The identity `Duplicate` groups an app by: a flatpak's app-id last
/// dot-segment (`org.mozilla.firefox` -> `firefox`), normalized the same way
/// as every other backend's own display name — so a pacman `firefox` and a
/// flatpak `org.mozilla.firefox` land in the same group.
fn identity(app: &AppEntry, packages: &[InstalledPackage]) -> String {
    let package = &packages[app.package_index];
    if package.backend == Backend::Flatpak {
        let last = package.id.rsplit('.').next().unwrap_or(&package.id);
        normalize(last)
    } else {
        normalize(&app.display_name)
    }
}

/// Same normalized identity appearing via >=2 different backends: every app
/// in that group gets `Duplicate`, badged with one of the *other* backends
/// present (arbitrary but deterministic when more than two are involved).
fn duplicates(apps: &[AppEntry], packages: &[InstalledPackage]) -> Vec<Recommendation> {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, app) in apps.iter().enumerate() {
        groups.entry(identity(app, packages)).or_default().push(i);
    }

    let mut out = Vec::new();
    for members in groups.values() {
        let backends: Vec<Backend> = members
            .iter()
            .map(|&i| packages[apps[i].package_index].backend)
            .collect();
        let mut distinct: Vec<Backend> = Vec::new();
        for &b in &backends {
            if !distinct.contains(&b) {
                distinct.push(b);
            }
        }
        if distinct.len() < 2 {
            continue;
        }
        for (&member, &own_backend) in members.iter().zip(backends.iter()) {
            // distinct.len() >= 2 (checked above) and own_backend is itself
            // one of distinct's members, so some other entry always exists;
            // if that invariant ever breaks, skip rather than panic.
            let Some(other_backend) = distinct.iter().copied().find(|&b| b != own_backend) else {
                continue;
            };
            out.push(Recommendation {
                package_index: apps[member].package_index,
                kind: Kind::Duplicate { other_backend },
            });
        }
    }
    out
}

/// Age in days since `modified`, or `None` if the clock is somehow before
/// `modified` (a future mtime — never treated as "old").
fn age_days(modified: SystemTime) -> Option<f64> {
    SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|d| d.as_secs_f64() / 86_400.0)
}

/// The mtime ages (in days) of whichever of `~/.cache/<name>`/`~/.config/<name>`
/// exist for `package`, using the same name-variant logic
/// `uninstall_leftovers::scan` uses (only those two dirs — not the full
/// leftover scan's systemd/autostart globs). Empty if none exist — the
/// shared probe `unused()` and `overlaps()`'s most-used marker both build on.
///
/// Heuristic, not proof — a directory's mtime is a coarse signal:
/// - A top-level dir's mtime only changes when an entry is added or removed
///   directly inside it, not when a file already inside it is rewritten in
///   place. An app touched daily via files nested under its config dir can
///   still look untouched here.
/// - A symlinked cache/config dir reports the *link's* mtime, not the target's
///   — a long-lived symlink pointing at actively-used data can still look old.
fn activity_ages_days(package: &InstalledPackage, ctx: &Ctx) -> Vec<f64> {
    let variants = crate::uninstall_leftovers::name_variants(&package.name);
    let mut ages = Vec::new();
    for variant in &variants {
        for base in [".cache", ".config"] {
            let path = ctx.home.join(base).join(variant);
            if let Ok(meta) = std::fs::symlink_metadata(&path)
                && let Ok(modified) = meta.modified()
                && let Some(age) = age_days(modified)
            {
                ages.push(age);
            }
        }
    }
    ages
}

/// At least one of `activity_ages_days` must exist, and every one that exists
/// must be at least `config.uninstall.unused_days` old, before this offers a
/// guess at all. Absence of evidence (no matching dirs) is never treated as
/// evidence of non-use.
///
/// Both false-positive modes documented on `activity_ages_days` can produce a
/// false "unused" guess, which is why this is advisory only and never
/// auto-selects anything.
fn unused(
    apps: &[AppEntry],
    packages: &[InstalledPackage],
    ctx: &Ctx,
    config: &Config,
) -> Vec<Recommendation> {
    let threshold_days = f64::from(config.uninstall.unused_days);
    let mut out = Vec::new();
    for app in apps {
        let package = &packages[app.package_index];
        let ages = activity_ages_days(package, ctx);
        if ages.is_empty() {
            continue; // no evidence either way — never guess "unused"
        }
        if !ages.iter().all(|&age| age >= threshold_days) {
            continue;
        }
        // The least-old (most recently touched) of the existing directories
        // pins "how long unused": it's the last time anything about this
        // app was touched at all.
        let freshest = ages.iter().cloned().fold(f64::INFINITY, f64::min);
        let months = (freshest / 30.0).round() as u32;
        out.push(Recommendation {
            package_index: app.package_index,
            kind: Kind::Unused { months },
        });
    }
    out
}

/// Three or more apps sharing the same `.desktop` main category (matched to
/// each `AppEntry` by its display name, the same string `pkg::applications`
/// chose from among that package's `.desktop` entries) each get `Overlap`.
/// Within each such group, the member with the freshest `activity_ages_days`
/// (smallest minimum age) is marked `most_used`; a tie keeps whichever member
/// was found first while iterating `apps` in the caller's own order — an
/// arbitrary but deterministic pick, not a claim that it's truly the busier
/// app.
fn overlaps(
    apps: &[AppEntry],
    packages: &[InstalledPackage],
    desktop_apps: &[DesktopApp],
    ctx: &Ctx,
) -> Vec<Recommendation> {
    // Sorted by desktop_file first, matching `pkg::applications`' convention,
    // so that when two entries share a display name but disagree on
    // category, the first one in path order deterministically wins rather
    // than depending on `read_dir`'s unspecified entry order.
    let mut sorted_desktop_apps: Vec<&DesktopApp> = desktop_apps.iter().collect();
    sorted_desktop_apps.sort_by(|a, b| a.desktop_file.cmp(&b.desktop_file));

    let mut category_by_name: HashMap<&str, Category> = HashMap::new();
    for d in &sorted_desktop_apps {
        if let Some(category) = d.main_category {
            category_by_name
                .entry(d.display_name.as_str())
                .or_insert(category);
        }
    }

    let categories: Vec<Option<Category>> = apps
        .iter()
        .map(|app| category_by_name.get(app.display_name.as_str()).copied())
        .collect();

    let mut counts: HashMap<Category, usize> = HashMap::new();
    for cat in categories.iter().flatten() {
        *counts.entry(*cat).or_insert(0) += 1;
    }

    // For each category that will actually get an `Overlap` badge, find the
    // freshest member (see doc comment above for the tie rule). `best_age`
    // and `most_used_index` are only ever set together, one entry per
    // category.
    let mut best_age: HashMap<Category, f64> = HashMap::new();
    let mut most_used_index: HashMap<Category, usize> = HashMap::new();
    for (i, cat) in categories.iter().enumerate() {
        let Some(cat) = cat else { continue };
        match counts.get(cat) {
            Some(&count) if count >= 3 => {}
            _ => continue,
        }
        let ages = activity_ages_days(&packages[apps[i].package_index], ctx);
        if ages.is_empty() {
            continue; // no evidence for this member — never counts as freshest
        }
        let freshest = ages.iter().cloned().fold(f64::INFINITY, f64::min);
        let is_fresher = match best_age.get(cat) {
            Some(&current_best) => freshest < current_best,
            None => true,
        };
        if is_fresher {
            best_age.insert(*cat, freshest);
            most_used_index.insert(*cat, i);
        }
    }

    apps.iter()
        .enumerate()
        .zip(categories)
        .filter_map(|((i, app), cat)| {
            let cat = cat?;
            let count = *counts.get(&cat)?;
            (count >= 3).then_some(Recommendation {
                package_index: app.package_index,
                kind: Kind::Overlap {
                    category: cat,
                    count,
                    most_used: most_used_index.get(&cat) == Some(&i),
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;
    use std::time::Duration;

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

    fn flatpak_pkg(id: &str, name: &str) -> InstalledPackage {
        InstalledPackage {
            backend: Backend::Flatpak,
            id: id.to_string(),
            name: name.to_string(),
            version: "1.0".to_string(),
            size_bytes: None,
            aur: false,
        }
    }

    fn app(display_name: &str, package_index: usize) -> AppEntry {
        AppEntry {
            display_name: display_name.to_string(),
            package_index,
        }
    }

    fn desktop_app(display_name: &str, category: Option<Category>) -> DesktopApp {
        DesktopApp {
            display_name: display_name.to_string(),
            desktop_file: PathBuf::from(format!("/usr/share/applications/{display_name}.desktop")),
            flatpak_id: None,
            main_category: category,
        }
    }

    fn aged_dir(ctx: &Ctx, subtree: &str, name: &str, days_old: u64) -> PathBuf {
        let dir = ctx.home.join(subtree).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let old = SystemTime::now() - Duration::from_secs(days_old * 86_400);
        std::fs::File::open(&dir)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        dir
    }

    fn kinds_for(recs: &[Recommendation], package_index: usize) -> Vec<Kind> {
        recs.iter()
            .filter(|r| r.package_index == package_index)
            .map(|r| r.kind)
            .collect()
    }

    // --- Duplicate ---

    #[test]
    fn test_flatpak_and_pacman_firefox_are_flagged_as_duplicates_of_each_other() {
        let f = fixture();
        let packages = vec![
            pacman_pkg("firefox"),
            flatpak_pkg("org.mozilla.firefox", "Firefox"),
        ];
        let apps = vec![app("Firefox", 0), app("Firefox", 1)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert_eq!(
            kinds_for(&recs, 0),
            vec![Kind::Duplicate {
                other_backend: Backend::Flatpak
            }]
        );
        assert_eq!(
            kinds_for(&recs, 1),
            vec![Kind::Duplicate {
                other_backend: Backend::Pacman
            }]
        );
    }

    #[test]
    fn test_name_normalization_ignores_case_spaces_dashes_and_underscores() {
        let f = fixture();
        let packages = vec![
            pacman_pkg("foo-app"),
            flatpak_pkg("org.example.foo_app", "Foo App"),
        ];
        let apps = vec![app("foo-app", 0), app("Foo App", 1)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert_eq!(
            kinds_for(&recs, 0).len(),
            1,
            "must match despite formatting"
        );
        assert_eq!(kinds_for(&recs, 1).len(), 1);
    }

    #[test]
    fn test_two_backends_but_different_identity_are_not_duplicates() {
        let f = fixture();
        let packages = vec![pacman_pkg("firefox"), flatpak_pkg("org.gimp.GIMP", "GIMP")];
        let apps = vec![app("Firefox", 0), app("GIMP", 1)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert!(kinds_for(&recs, 0).is_empty());
        assert!(kinds_for(&recs, 1).is_empty());
    }

    #[test]
    fn test_same_identity_same_backend_is_not_a_duplicate() {
        let f = fixture();
        // Two distinct pacman packages that happen to normalize the same —
        // a single backend can't be "duplicated" against itself.
        let packages = vec![pacman_pkg("foo"), pacman_pkg("foo-alt")];
        let apps = vec![app("Foo", 0), app("Foo", 1)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert!(kinds_for(&recs, 0).is_empty());
        assert!(kinds_for(&recs, 1).is_empty());
    }

    // --- Unused ---

    #[test]
    fn test_unused_recommended_when_only_the_cache_dir_exists_and_is_stale() {
        let f = fixture();
        aged_dir(&f.ctx, ".cache", "foo", 180);
        let packages = vec![pacman_pkg("foo")];
        let apps = vec![app("Foo", 0)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert_eq!(kinds_for(&recs, 0), vec![Kind::Unused { months: 6 }]);
    }

    #[test]
    fn test_no_cache_or_config_dir_yields_no_unused_recommendation() {
        let f = fixture();
        let packages = vec![pacman_pkg("foo")];
        let apps = vec![app("Foo", 0)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert!(kinds_for(&recs, 0).is_empty());
    }

    #[test]
    fn test_a_recently_touched_dir_blocks_the_unused_recommendation_even_if_another_is_stale() {
        let f = fixture();
        aged_dir(&f.ctx, ".cache", "foo", 200);
        aged_dir(&f.ctx, ".config", "foo", 1);
        let packages = vec![pacman_pkg("foo")];
        let apps = vec![app("Foo", 0)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert!(kinds_for(&recs, 0).is_empty());
    }

    #[test]
    fn test_unused_days_config_override_is_respected() {
        let f = fixture();
        aged_dir(&f.ctx, ".cache", "foo", 20);
        let packages = vec![pacman_pkg("foo")];
        let apps = vec![app("Foo", 0)];
        let mut config = f.ctx.config.clone();
        config.uninstall.unused_days = 10;

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &config);

        assert_eq!(kinds_for(&recs, 0), vec![Kind::Unused { months: 1 }]);
    }

    #[test]
    fn test_unused_at_exactly_the_threshold_day_boundary_is_recommended() {
        // The doc says "at least N days old" and the code checks `>=`, not
        // `>` — a dir exactly at the threshold must still be recommended.
        let f = fixture();
        let threshold_days = f.ctx.config.uninstall.unused_days;
        aged_dir(&f.ctx, ".cache", "foo", u64::from(threshold_days));
        let packages = vec![pacman_pkg("foo")];
        let apps = vec![app("Foo", 0)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert!(!kinds_for(&recs, 0).is_empty());
    }

    #[test]
    fn test_fresh_dir_under_the_threshold_yields_no_recommendation() {
        let f = fixture();
        aged_dir(&f.ctx, ".cache", "foo", 5);
        let packages = vec![pacman_pkg("foo")];
        let apps = vec![app("Foo", 0)];

        let recs = recommendations(&apps, &packages, &[], &f.ctx, &f.ctx.config.clone());

        assert!(kinds_for(&recs, 0).is_empty());
    }

    // --- Overlap ---

    #[test]
    fn test_exactly_three_apps_in_a_category_all_get_overlap() {
        let f = fixture();
        let packages = vec![pacman_pkg("a"), pacman_pkg("b"), pacman_pkg("c")];
        let apps = vec![app("Alpha", 0), app("Beta", 1), app("Gamma", 2)];
        let desktop_apps = vec![
            desktop_app("Alpha", Some(Category::WebBrowser)),
            desktop_app("Beta", Some(Category::WebBrowser)),
            desktop_app("Gamma", Some(Category::WebBrowser)),
        ];

        let recs = recommendations(
            &apps,
            &packages,
            &desktop_apps,
            &f.ctx,
            &f.ctx.config.clone(),
        );

        for i in 0..3 {
            assert_eq!(
                kinds_for(&recs, i),
                vec![Kind::Overlap {
                    category: Category::WebBrowser,
                    count: 3,
                    most_used: false,
                }],
                "no cache/config dirs exist for any member, so nobody is most_used"
            );
        }
    }

    #[test]
    fn test_only_two_apps_in_a_category_get_no_overlap() {
        let f = fixture();
        let packages = vec![pacman_pkg("a"), pacman_pkg("b")];
        let apps = vec![app("Alpha", 0), app("Beta", 1)];
        let desktop_apps = vec![
            desktop_app("Alpha", Some(Category::WebBrowser)),
            desktop_app("Beta", Some(Category::WebBrowser)),
        ];

        let recs = recommendations(
            &apps,
            &packages,
            &desktop_apps,
            &f.ctx,
            &f.ctx.config.clone(),
        );

        assert!(recs.is_empty());
    }

    #[test]
    fn test_app_with_no_known_category_never_gets_overlap() {
        let f = fixture();
        let packages = vec![pacman_pkg("a"), pacman_pkg("b"), pacman_pkg("c")];
        let apps = vec![app("Alpha", 0), app("Beta", 1), app("Gamma", 2)];
        let desktop_apps = vec![
            desktop_app("Alpha", Some(Category::WebBrowser)),
            desktop_app("Beta", Some(Category::WebBrowser)),
            desktop_app("Gamma", None),
        ];

        let recs = recommendations(
            &apps,
            &packages,
            &desktop_apps,
            &f.ctx,
            &f.ctx.config.clone(),
        );

        assert!(kinds_for(&recs, 2).is_empty());
    }

    #[test]
    fn test_overlap_category_for_a_duplicated_display_name_is_independent_of_input_order() {
        // Two .desktop entries share a display name but disagree on category;
        // their paths sort "a.desktop" before "b.desktop" so the fix (sort by
        // desktop_file, first wins) always picks the WebBrowser one below,
        // regardless of which order they're passed in.
        let entry_a = DesktopApp {
            display_name: "Ambiguous".to_string(),
            desktop_file: PathBuf::from("/usr/share/applications/a.desktop"),
            flatpak_id: None,
            main_category: Some(Category::WebBrowser),
        };
        let entry_b = DesktopApp {
            display_name: "Ambiguous".to_string(),
            desktop_file: PathBuf::from("/usr/share/applications/b.desktop"),
            flatpak_id: None,
            main_category: Some(Category::Email),
        };
        let others = [
            desktop_app("Beta", Some(Category::WebBrowser)),
            desktop_app("Gamma", Some(Category::WebBrowser)),
        ];
        let apps = vec![app("Ambiguous", 0), app("Beta", 1), app("Gamma", 2)];
        let packages = vec![
            pacman_pkg("ambiguous"),
            pacman_pkg("beta"),
            pacman_pkg("gamma"),
        ];
        let f = fixture();

        let mut desktop_apps_1 = vec![entry_a.clone(), entry_b.clone()];
        desktop_apps_1.extend(others.iter().cloned());
        let recs_1 = overlaps(&apps, &packages, &desktop_apps_1, &f.ctx);

        let mut desktop_apps_2 = vec![entry_b, entry_a];
        desktop_apps_2.extend(others.iter().cloned());
        let recs_2 = overlaps(&apps, &packages, &desktop_apps_2, &f.ctx);

        assert_eq!(kinds_for(&recs_1, 0), kinds_for(&recs_2, 0));
        assert_eq!(
            kinds_for(&recs_1, 0),
            vec![Kind::Overlap {
                category: Category::WebBrowser,
                count: 3,
                most_used: false,
            }]
        );
    }

    #[test]
    fn test_most_used_marks_the_group_member_with_the_freshest_activity() {
        let f = fixture();
        aged_dir(&f.ctx, ".cache", "alpha", 100);
        aged_dir(&f.ctx, ".cache", "beta", 10); // freshest (smallest age)
        aged_dir(&f.ctx, ".cache", "gamma", 200);
        let packages = vec![pacman_pkg("alpha"), pacman_pkg("beta"), pacman_pkg("gamma")];
        let apps = vec![app("Alpha", 0), app("Beta", 1), app("Gamma", 2)];
        let desktop_apps = vec![
            desktop_app("Alpha", Some(Category::WebBrowser)),
            desktop_app("Beta", Some(Category::WebBrowser)),
            desktop_app("Gamma", Some(Category::WebBrowser)),
        ];

        // Calls `overlaps` directly (not `recommendations`) so the ages
        // chosen to pin freshness ordering don't also trip the unrelated
        // `unused` heuristic at its own (much lower) default threshold.
        let recs = overlaps(&apps, &packages, &desktop_apps, &f.ctx);

        assert_eq!(
            kinds_for(&recs, 1),
            vec![Kind::Overlap {
                category: Category::WebBrowser,
                count: 3,
                most_used: true,
            }]
        );
        for i in [0, 2] {
            assert_eq!(
                kinds_for(&recs, i),
                vec![Kind::Overlap {
                    category: Category::WebBrowser,
                    count: 3,
                    most_used: false,
                }]
            );
        }
    }

    #[test]
    fn test_most_used_tie_goes_to_the_first_member_in_apps_order() {
        let f = fixture();
        // A single shared timestamp for both dirs, rather than two separate
        // `aged_dir` calls (each reads its own `SystemTime::now()`), so the
        // two ages are exactly equal instead of merely close.
        let old = SystemTime::now() - Duration::from_secs(50 * 86_400);
        for name in ["alpha", "beta"] {
            let dir = f.ctx.home.join(".cache").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::File::open(&dir)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(old))
                .unwrap();
        }
        // gamma has no cache/config dir at all.
        let packages = vec![pacman_pkg("alpha"), pacman_pkg("beta"), pacman_pkg("gamma")];
        let apps = vec![app("Alpha", 0), app("Beta", 1), app("Gamma", 2)];
        let desktop_apps = vec![
            desktop_app("Alpha", Some(Category::WebBrowser)),
            desktop_app("Beta", Some(Category::WebBrowser)),
            desktop_app("Gamma", Some(Category::WebBrowser)),
        ];

        let recs = overlaps(&apps, &packages, &desktop_apps, &f.ctx);

        assert_eq!(
            kinds_for(&recs, 0),
            vec![Kind::Overlap {
                category: Category::WebBrowser,
                count: 3,
                most_used: true,
            }],
            "alpha comes first in apps order, so it wins the tie over beta"
        );
        assert_eq!(
            kinds_for(&recs, 1),
            vec![Kind::Overlap {
                category: Category::WebBrowser,
                count: 3,
                most_used: false,
            }]
        );
    }

    // --- combined ---

    #[test]
    fn test_recommendations_is_empty_for_no_apps() {
        let f = fixture();
        assert!(recommendations(&[], &[], &[], &f.ctx, &f.ctx.config.clone()).is_empty());
    }
}
