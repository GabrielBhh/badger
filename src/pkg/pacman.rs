use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::core::runner::runner_for;
use crate::ctx::Ctx;
use crate::pkg::{Backend, InstalledPackage};
use crate::rules::{command::parse_pacman_installed_sizes, command_exists};

pub fn is_available(ctx: &Ctx) -> bool {
    command_exists("pacman", ctx)
}

/// Every explicitly-and-dependency installed package (`pacman -Q`), badged
/// `aur` when it also shows up in `pacman -Qm` (foreign/AUR packages), sized
/// via a single best-effort `pacman -Qi <names...>` call.
pub fn list(ctx: &Ctx) -> Vec<InstalledPackage> {
    let runner = runner_for(ctx);
    let installed = match runner.run(&["pacman".to_string(), "-Q".to_string()]) {
        Ok(out) => parse_name_version_lines(&out.stdout),
        Err(_) => return Vec::new(),
    };
    if installed.is_empty() {
        return Vec::new();
    }

    let aur_names: HashSet<String> = match runner.run(&["pacman".to_string(), "-Qm".to_string()]) {
        Ok(out) => parse_name_version_lines(&out.stdout)
            .into_iter()
            .map(|(name, _)| name)
            .collect(),
        Err(_) => HashSet::new(),
    };

    let mut qi_argv = vec!["pacman".to_string(), "-Qi".to_string()];
    qi_argv.extend(installed.iter().map(|(name, _)| name.clone()));
    let sizes = match runner.run(&qi_argv) {
        Ok(out) => parse_pacman_installed_sizes(&out.stdout),
        Err(_) => Default::default(),
    };

    installed
        .into_iter()
        .map(|(name, version)| InstalledPackage {
            backend: Backend::Pacman,
            aur: aur_names.contains(&name),
            size_bytes: sizes.get(&name).copied(),
            id: name.clone(),
            name,
            version,
        })
        .collect()
}

/// Parses `pacman -Q`/`pacman -Qm`'s `<name> <version>` lines.
fn parse_name_version_lines(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(name, version)| (name.to_string(), version.trim().to_string()))
        .collect()
}

/// `pacman -Rns --noconfirm -- <id>` — always run via sudo. The `--`
/// separates pacman's own options from `id` (a package name out of pacman's
/// database), so a name that happens to start with `-` is never
/// misinterpreted as a flag.
pub fn remove_argv(id: &str) -> Vec<String> {
    vec![
        "pacman".to_string(),
        "-Rns".to_string(),
        "--noconfirm".to_string(),
        "--".to_string(),
        id.to_string(),
    ]
}

/// Every file the package owns, captured with `pacman -Qql` before removal
/// — plumbing for a future phase's leftover-guessing heuristic; unused by
/// this phase's exact-name-match leftover scan.
pub fn file_list(ctx: &Ctx, id: &str) -> Vec<String> {
    let runner = runner_for(ctx);
    match runner.run(&["pacman".to_string(), "-Qql".to_string(), id.to_string()]) {
        Ok(out) => out.stdout.lines().map(str::to_string).collect(),
        Err(_) => Vec::new(),
    }
}

/// Batched `pacman -Qo -- <file1> <file2> ...` to map each of `files` to its
/// owning package name in one call — used to map installed `.desktop`
/// launchers back to the package that owns them. A file pacman doesn't own
/// produces an error line on stderr and a nonzero exit; that's tolerated
/// here — whatever parses on stdout is kept regardless of the exit status.
/// If the command fails to run at all (or `files` is empty), the map is
/// simply empty.
pub fn owners(ctx: &Ctx, files: &[PathBuf]) -> HashMap<PathBuf, String> {
    if files.is_empty() {
        return HashMap::new();
    }
    let runner = runner_for(ctx);
    let mut argv = vec!["pacman".to_string(), "-Qo".to_string(), "--".to_string()];
    argv.extend(files.iter().map(|f| f.display().to_string()));
    match runner.run(&argv) {
        Ok(out) => parse_owners(&out.stdout),
        Err(_) => HashMap::new(),
    }
}

/// Parses `pacman -Qo`'s `<path> is owned by <pkg> <version>` lines.
fn parse_owners(text: &str) -> HashMap<PathBuf, String> {
    text.lines()
        .filter_map(|line| {
            let (path, rest) = line.split_once(" is owned by ")?;
            let pkg = rest.split_whitespace().next()?;
            Some((PathBuf::from(path.trim()), pkg.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::core::runner::CmdOutput;
    use std::collections::HashMap;
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

    fn cmd_output(stdout: &str) -> CmdOutput {
        CmdOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn test_is_available_requires_pacman_command() {
        let mut c = ctx();
        assert!(!is_available(&c));
        c.available_commands = Some(vec!["pacman".to_string()]);
        assert!(is_available(&c));
    }

    #[test]
    fn test_list_is_empty_without_canned_output() {
        assert!(list(&ctx()).is_empty());
    }

    #[test]
    fn test_list_parses_names_versions_aur_badge_and_sizes() {
        let mut c = ctx();
        let qi = "Name            : foo\n\
                  Installed Size  : 1024.00 KiB\n\
                  \n\
                  Name            : bar-aur\n\
                  Installed Size  : 2.00 MiB\n";
        c.fake_command_output = Some(HashMap::from([
            (
                vec!["pacman".to_string(), "-Q".to_string()],
                cmd_output("foo 1.0-1\nbar-aur 2.0-1\n"),
            ),
            (
                vec!["pacman".to_string(), "-Qm".to_string()],
                cmd_output("bar-aur 2.0-1\n"),
            ),
            (
                vec![
                    "pacman".to_string(),
                    "-Qi".to_string(),
                    "foo".to_string(),
                    "bar-aur".to_string(),
                ],
                cmd_output(qi),
            ),
        ]));

        let packages = list(&c);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[0].version, "1.0-1");
        assert_eq!(packages[0].id, "foo");
        assert!(!packages[0].aur);
        assert_eq!(packages[0].size_bytes, Some(1024 * 1024));
        assert_eq!(packages[0].backend, Backend::Pacman);

        assert_eq!(packages[1].name, "bar-aur");
        assert!(packages[1].aur, "must be badged AUR via pacman -Qm");
        assert_eq!(packages[1].size_bytes, Some(2 * 1024 * 1024));
    }

    #[test]
    fn test_list_handles_missing_qi_size_as_none() {
        let mut c = ctx();
        c.fake_command_output = Some(HashMap::from([
            (
                vec!["pacman".to_string(), "-Q".to_string()],
                cmd_output("mystery 1.0-1\n"),
            ),
            (
                vec!["pacman".to_string(), "-Qm".to_string()],
                cmd_output(""),
            ),
            (
                vec![
                    "pacman".to_string(),
                    "-Qi".to_string(),
                    "mystery".to_string(),
                ],
                cmd_output(""),
            ),
        ]));

        let packages = list(&c);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].size_bytes, None);
    }

    #[test]
    fn test_remove_argv_is_exact() {
        assert_eq!(
            remove_argv("foo"),
            vec![
                "pacman".to_string(),
                "-Rns".to_string(),
                "--noconfirm".to_string(),
                "--".to_string(),
                "foo".to_string(),
            ]
        );
    }

    // Regression: a package name is an identifier from pacman's own database,
    // but nothing stopped it from being interpreted as a pacman flag if it
    // happened to start with a dash. `--` (end-of-options) must separate
    // pacman's own flags from the name, no matter what the name looks like.
    #[test]
    fn test_remove_argv_inserts_end_of_options_separator_before_a_dash_prefixed_name() {
        assert_eq!(
            remove_argv("-suspicious"),
            vec![
                "pacman".to_string(),
                "-Rns".to_string(),
                "--noconfirm".to_string(),
                "--".to_string(),
                "-suspicious".to_string(),
            ]
        );
    }

    #[test]
    fn test_owners_parses_qo_output_into_a_path_to_package_map() {
        let mut c = ctx();
        let files = vec![PathBuf::from("/usr/share/applications/foo.desktop")];
        c.fake_command_output = Some(HashMap::from([(
            vec![
                "pacman".to_string(),
                "-Qo".to_string(),
                "--".to_string(),
                "/usr/share/applications/foo.desktop".to_string(),
            ],
            cmd_output("/usr/share/applications/foo.desktop is owned by foo 1.0-1\n"),
        )]));

        let owners = owners(&c, &files);
        assert_eq!(owners.get(&files[0]), Some(&"foo".to_string()));
    }

    #[test]
    fn test_owners_is_empty_for_empty_file_list() {
        assert!(owners(&ctx(), &[]).is_empty());
    }

    #[test]
    fn test_owners_tolerates_partial_failure_and_keeps_what_parsed() {
        let mut c = ctx();
        let files = vec![
            PathBuf::from("/usr/share/applications/foo.desktop"),
            PathBuf::from("/usr/share/applications/unowned.desktop"),
        ];
        c.fake_command_output = Some(HashMap::from([(
            vec![
                "pacman".to_string(),
                "-Qo".to_string(),
                "--".to_string(),
                "/usr/share/applications/foo.desktop".to_string(),
                "/usr/share/applications/unowned.desktop".to_string(),
            ],
            CmdOutput {
                success: false,
                stdout: "/usr/share/applications/foo.desktop is owned by foo 1.0-1\n".to_string(),
                stderr: "error: No package owns /usr/share/applications/unowned.desktop\n"
                    .to_string(),
            },
        )]));

        let owners = owners(&c, &files);
        assert_eq!(owners.len(), 1);
        assert_eq!(owners.get(&files[0]), Some(&"foo".to_string()));
    }

    #[test]
    fn test_owners_is_empty_when_the_whole_command_fails_to_run() {
        // No canned output for this argv -> the runner errors, and that's
        // tolerated as "no owners found" rather than propagated.
        let files = vec![PathBuf::from("/usr/share/applications/foo.desktop")];
        assert!(owners(&ctx(), &files).is_empty());
    }

    #[test]
    fn test_file_list_parses_qql_lines() {
        let mut c = ctx();
        c.fake_command_output = Some(HashMap::from([(
            vec!["pacman".to_string(), "-Qql".to_string(), "foo".to_string()],
            cmd_output("/usr/bin/foo\n/usr/share/foo/data\n"),
        )]));
        assert_eq!(
            file_list(&c, "foo"),
            vec![
                "/usr/bin/foo".to_string(),
                "/usr/share/foo/data".to_string()
            ]
        );
    }
}
