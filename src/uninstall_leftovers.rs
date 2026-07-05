//! Leftover scan for `badger uninstall`: once a package's own backend has
//! removed it, this looks for the config/cache/state it left behind under
//! well-known per-app locations. Matching is deliberately exact (the
//! package's own name, case-sensitive and lowercased) — no fuzzy guessing.
//! That heuristic belongs to a later phase; this one only ever offers what
//! it can name with confidence. Results are shaped as a `Group` of
//! Moderate-tier `Candidate`s so they run through the same checklist/confirm/
//! execute pipeline every other command already uses.

use std::path::{Path, PathBuf};

use crate::core::item::{Candidate, Group, Risk};
use crate::core::scan::display_label;
use crate::ctx::Ctx;
use crate::pkg::Backend;
use crate::safety::protected::{SafetyEnv, Tier, validate_deletable};
use crate::safety::whitelist::Whitelist;
use crate::util::dirsize::dir_size;

/// The locations this scan ever looks under — also the `validate_deletable`
/// allowed-prefixes list, and reused as-is by `commands::uninstall` when it
/// later deletes exactly what was selected from this scan's candidates.
pub fn allowed_prefixes(ctx: &Ctx) -> Vec<PathBuf> {
    vec![
        ctx.home.join(".config"),
        ctx.home.join(".local/share"),
        ctx.home.join(".cache"),
        ctx.home.join(".var/app"),
    ]
}

/// Scans for leftovers of a just-removed package. `name` is the package's
/// display name (used for the per-app directories and glob prefixes); `id`
/// is its backend identifier (used only for flatpak's `~/.var/app/<id>`,
/// since that directory is keyed by app ID, not name). `whitelist` is the
/// user's `~/.config/badger/whitelist` — a match marks the candidate
/// whitelisted (permanently unselectable in the checklist) exactly like
/// `core::scan`'s rule-registry scan does.
pub fn scan(
    ctx: &Ctx,
    name: &str,
    id: &str,
    backend: Backend,
    whitelist: &Whitelist,
) -> anyhow::Result<Group> {
    let env = SafetyEnv::from_system(ctx)?;
    let allowed = allowed_prefixes(ctx);

    let name_variants = name_variants(name);
    let mut found: Vec<PathBuf> = Vec::new();

    for variant in &name_variants {
        push_if_exists(&mut found, ctx.home.join(".config").join(variant));
        push_if_exists(&mut found, ctx.home.join(".local/share").join(variant));
        push_if_exists(&mut found, ctx.home.join(".cache").join(variant));
    }
    if backend == Backend::Flatpak {
        push_if_exists(&mut found, ctx.home.join(".var/app").join(id));
    }

    found.extend(glob_prefix(
        &ctx.home.join(".config/systemd/user"),
        &name_variants,
        "",
    ));
    found.extend(glob_prefix(
        &ctx.home.join(".local/share/applications"),
        &name_variants,
        ".desktop",
    ));
    found.extend(glob_prefix(
        &ctx.home.join(".config/autostart"),
        &name_variants,
        ".desktop",
    ));

    found.sort();
    found.dedup();

    let mut candidates = Vec::new();
    let mut skipped = Vec::new();
    for path in found {
        if let Err(refusal) = validate_deletable(&path, &allowed, Tier::User, &env) {
            skipped.push((display_label(&path, ctx), refusal.to_string()));
            continue;
        }
        let bytes = dir_size(&path);
        let label = display_label(&path, ctx);
        let mut candidate = Candidate::new(Some(path.clone()), label, bytes, Risk::Moderate);
        if whitelist.matches(&path) {
            candidate.whitelisted = true;
            candidate.selectable = false;
        }
        candidates.push(candidate);
    }

    Ok(Group {
        rule_id: "uninstall.leftovers".to_string(),
        title: format!("Leftovers for {name}"),
        risk: Risk::Moderate,
        requires_sudo: false,
        candidates,
        skipped,
    })
}

/// The package name as-is, plus its lowercased form if that differs — many
/// packages install per-app directories lowercased even when the package
/// name itself has mixed case.
fn name_variants(name: &str) -> Vec<String> {
    let lower = name.to_lowercase();
    if lower == name {
        vec![name.to_string()]
    } else {
        vec![name.to_string(), lower]
    }
}

fn push_if_exists(found: &mut Vec<PathBuf>, path: PathBuf) {
    if std::fs::symlink_metadata(&path).is_ok() {
        found.push(path);
    }
}

/// Every entry directly under `dir` whose file name is one of
/// `name_variants` at a genuine word boundary (see `matches_name_boundary`)
/// and ends with `suffix` (`""` means no suffix constraint) — e.g.
/// `foo.service`/`foo@x.service` under `~/.config/systemd/user`, or
/// `foo.desktop` under `~/.local/share/applications`. A same-prefix
/// lookalike like `github-desktop.service` for name `git`, or
/// `code-oss.desktop` for name `code`, is intentionally excluded: a bare
/// `starts_with` would wrongly match those.
fn glob_prefix(dir: &Path, name_variants: &[String], suffix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            name_variants
                .iter()
                .any(|n| matches_name_boundary(&file_name, n))
                && file_name.ends_with(suffix)
        })
        .map(|entry| entry.path())
        .collect()
}

/// True when `file_name` is exactly `name`, or `name` immediately followed
/// by `.` or `@` — the only two ways a unit/desktop file name legitimately
/// extends a package's own name (`name.service`, `name.desktop`,
/// `name@instance.service`). Excludes same-prefix lookalikes such as
/// `code-oss.desktop` or `github-desktop.service`.
fn matches_name_boundary(file_name: &str, name: &str) -> bool {
    let Some(remainder) = file_name.strip_prefix(name) else {
        return false;
    };
    remainder.is_empty() || remainder.starts_with('.') || remainder.starts_with('@')
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

    fn empty_whitelist() -> Whitelist {
        crate::safety::whitelist::parse("", Path::new("/home/user")).unwrap()
    }

    #[test]
    fn test_finds_config_local_share_and_cache_dirs_by_exact_name() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".config/foo")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".local/share/foo")).unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".cache/foo")).unwrap();
        std::fs::write(f.ctx.home.join(".cache/foo/data.bin"), vec![0u8; 4096]).unwrap();

        let group = scan(&f.ctx, "foo", "foo", Backend::Pacman, &empty_whitelist()).unwrap();
        let mut labels: Vec<_> = group.candidates.iter().map(|c| c.label.clone()).collect();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                "~/.cache/foo".to_string(),
                "~/.config/foo".to_string(),
                "~/.local/share/foo".to_string(),
            ]
        );
        assert!(
            group.candidates.iter().all(|c| !c.selectable),
            "Moderate starts unchecked"
        );
        assert!(
            group
                .candidates
                .iter()
                .find(|c| c.label == "~/.cache/foo")
                .unwrap()
                .bytes
                > 0
        );
    }

    #[test]
    fn test_partial_name_match_is_not_offered() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".config/firefoxx")).unwrap();

        let group = scan(
            &f.ctx,
            "firefox",
            "firefox",
            Backend::Pacman,
            &empty_whitelist(),
        )
        .unwrap();
        assert!(group.candidates.is_empty());
    }

    #[test]
    fn test_matches_lowercased_variant_of_a_mixed_case_name() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".config/foo-app")).unwrap();

        let group = scan(
            &f.ctx,
            "Foo-App",
            "Foo-App",
            Backend::Pacman,
            &empty_whitelist(),
        )
        .unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert_eq!(group.candidates[0].label, "~/.config/foo-app");
    }

    #[test]
    fn test_finds_flatpak_var_app_dir_by_id() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".var/app/org.foo.App")).unwrap();

        let group = scan(
            &f.ctx,
            "Foo App",
            "org.foo.App",
            Backend::Flatpak,
            &empty_whitelist(),
        )
        .unwrap();
        assert!(
            group
                .candidates
                .iter()
                .any(|c| c.label == "~/.var/app/org.foo.App")
        );
    }

    #[test]
    fn test_non_flatpak_backend_never_checks_var_app() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".var/app/foo")).unwrap();

        let group = scan(&f.ctx, "foo", "foo", Backend::Pacman, &empty_whitelist()).unwrap();
        assert!(group.candidates.is_empty());
    }

    #[test]
    fn test_finds_systemd_user_unit_by_name_prefix() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".config/systemd/user")).unwrap();
        std::fs::write(
            f.ctx.home.join(".config/systemd/user/foo.service"),
            b"[Unit]",
        )
        .unwrap();
        std::fs::write(
            f.ctx.home.join(".config/systemd/user/unrelated.service"),
            b"[Unit]",
        )
        .unwrap();

        let group = scan(&f.ctx, "foo", "foo", Backend::Pacman, &empty_whitelist()).unwrap();
        assert_eq!(group.candidates.len(), 1);
        assert_eq!(
            group.candidates[0].label,
            "~/.config/systemd/user/foo.service"
        );
    }

    #[test]
    fn test_finds_desktop_entry_and_autostart_entry_by_name_prefix() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".local/share/applications")).unwrap();
        std::fs::write(
            f.ctx.home.join(".local/share/applications/foo.desktop"),
            b"[Desktop Entry]",
        )
        .unwrap();
        std::fs::create_dir_all(f.ctx.home.join(".config/autostart")).unwrap();
        std::fs::write(
            f.ctx.home.join(".config/autostart/foo.desktop"),
            b"[Desktop Entry]",
        )
        .unwrap();

        let group = scan(&f.ctx, "foo", "foo", Backend::Pacman, &empty_whitelist()).unwrap();
        let mut labels: Vec<_> = group.candidates.iter().map(|c| c.label.clone()).collect();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                "~/.config/autostart/foo.desktop".to_string(),
                "~/.local/share/applications/foo.desktop".to_string(),
            ]
        );
    }

    #[test]
    fn test_no_leftovers_yields_empty_group() {
        let f = fixture();
        let group = scan(
            &f.ctx,
            "nothing-here",
            "nothing-here",
            Backend::Pacman,
            &empty_whitelist(),
        )
        .unwrap();
        assert!(group.candidates.is_empty());
        assert!(group.skipped.is_empty());
        assert_eq!(group.risk, Risk::Moderate);
    }

    #[test]
    // Bug: glob_prefix used file_name.starts_with(name), so uninstalling
    // "git" would offer github-desktop.service (a same-prefix lookalike
    // service, not git's own leftover) as a deletable candidate. Root cause:
    // no boundary check after the prefix match.
    fn test_github_desktop_service_is_not_matched_for_git() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".config/systemd/user")).unwrap();
        std::fs::write(
            f.ctx
                .home
                .join(".config/systemd/user/github-desktop.service"),
            b"[Unit]",
        )
        .unwrap();

        let group = scan(&f.ctx, "git", "git", Backend::Pacman, &empty_whitelist()).unwrap();
        assert!(group.candidates.is_empty());
    }

    #[test]
    // Bug: glob_prefix used file_name.starts_with(name), so uninstalling
    // "code" would offer code-oss.desktop (a different, still-installed
    // package's desktop entry) as a deletable candidate. Root cause: no
    // boundary check after the prefix match.
    fn test_code_oss_desktop_is_not_matched_for_code() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".local/share/applications")).unwrap();
        std::fs::write(
            f.ctx
                .home
                .join(".local/share/applications/code-oss.desktop"),
            b"[Desktop Entry]",
        )
        .unwrap();

        let group = scan(&f.ctx, "code", "code", Backend::Pacman, &empty_whitelist()).unwrap();
        assert!(group.candidates.is_empty());
    }

    #[test]
    fn test_denylisted_leftover_is_recorded_as_skipped_not_silently_dropped() {
        let f = fixture();
        // ~/.config/badger is on the safety deny list (it's badger's own
        // config dir) — a package that happened to be named "badger" must
        // never have it silently offered as a deletable leftover.
        std::fs::create_dir_all(f.ctx.home.join(".config/badger")).unwrap();

        let group = scan(
            &f.ctx,
            "badger",
            "badger",
            Backend::Pacman,
            &empty_whitelist(),
        )
        .unwrap();
        assert!(group.candidates.is_empty());
        assert_eq!(group.skipped.len(), 1);
        assert_eq!(group.skipped[0].0, "~/.config/badger");
    }

    #[test]
    // Bug: uninstall_leftovers::scan never consulted the user's whitelist,
    // so a whitelisted leftover directory was left toggleable in the
    // checklist like any other Moderate candidate. Root cause: only
    // core/scan.rs's finish_deletable_candidates applied the whitelist;
    // this scan built candidates on its own and skipped that step.
    fn test_whitelisted_leftover_is_marked_whitelisted_and_unselectable() {
        let f = fixture();
        std::fs::create_dir_all(f.ctx.home.join(".config/foo")).unwrap();

        let wl = crate::safety::whitelist::parse("~/.config/foo", &f.ctx.home).unwrap();
        let group = scan(&f.ctx, "foo", "foo", Backend::Pacman, &wl).unwrap();

        assert_eq!(group.candidates.len(), 1);
        assert!(group.candidates[0].whitelisted);
        assert!(!group.candidates[0].selectable);
    }
}
