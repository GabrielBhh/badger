use std::path::PathBuf;

use crate::core::runner::runner_for;
use crate::ctx::Ctx;
use crate::pkg::{Backend, InstalledPackage};
use crate::rules::command_exists;

pub fn is_available(ctx: &Ctx) -> bool {
    command_exists("flatpak", ctx)
}

/// `flatpak list --app --columns=application,name,version` — tab-separated
/// columns, one app per line. No size column: flatpak doesn't offer a cheap
/// per-app installed size the way `pacman -Qi` does.
pub fn list(ctx: &Ctx) -> Vec<InstalledPackage> {
    let runner = runner_for(ctx);
    let argv = vec![
        "flatpak".to_string(),
        "list".to_string(),
        "--app".to_string(),
        "--columns=application,name,version".to_string(),
    ];
    match runner.run(&argv) {
        Ok(out) => out.stdout.lines().filter_map(parse_line).collect(),
        Err(_) => Vec::new(),
    }
}

fn parse_line(line: &str) -> Option<InstalledPackage> {
    let mut cols = line.splitn(3, '\t');
    let id = cols.next()?.trim();
    if id.is_empty() {
        return None;
    }
    let name = cols.next().unwrap_or(id).trim();
    let version = cols.next().unwrap_or("").trim();
    Some(InstalledPackage {
        backend: Backend::Flatpak,
        id: id.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        size_bytes: None,
        aur: false,
    })
}

/// `flatpak uninstall --delete-data --noninteractive <id>` — never sudo:
/// this only ever touches the invoking user's own flatpak installation.
pub fn remove_argv(id: &str) -> Vec<String> {
    vec![
        "flatpak".to_string(),
        "uninstall".to_string(),
        "--delete-data".to_string(),
        "--noninteractive".to_string(),
        id.to_string(),
    ]
}

/// The sandboxed per-app data directory flatpak keeps even after
/// `uninstall` unless `--delete-data` also removed it — kept as a leftover
/// candidate location.
pub fn data_dir(ctx: &Ctx, id: &str) -> PathBuf {
    ctx.home.join(".var/app").join(id)
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

    #[test]
    fn test_is_available_requires_flatpak_command() {
        let mut c = ctx();
        assert!(!is_available(&c));
        c.available_commands = Some(vec!["flatpak".to_string()]);
        assert!(is_available(&c));
    }

    #[test]
    fn test_list_parses_tab_separated_columns() {
        let mut c = ctx();
        c.fake_command_output = Some(HashMap::from([(
            vec![
                "flatpak".to_string(),
                "list".to_string(),
                "--app".to_string(),
                "--columns=application,name,version".to_string(),
            ],
            CmdOutput {
                success: true,
                stdout: "org.foo.App\tFoo App\t1.2.3\n".to_string(),
                stderr: String::new(),
            },
        )]));

        let packages = list(&c);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].id, "org.foo.App");
        assert_eq!(packages[0].name, "Foo App");
        assert_eq!(packages[0].version, "1.2.3");
        assert_eq!(packages[0].backend, Backend::Flatpak);
        assert!(!packages[0].aur);
        assert_eq!(packages[0].size_bytes, None);
    }

    #[test]
    fn test_remove_argv_is_exact_and_never_sudo() {
        assert_eq!(
            remove_argv("org.foo.App"),
            vec![
                "flatpak".to_string(),
                "uninstall".to_string(),
                "--delete-data".to_string(),
                "--noninteractive".to_string(),
                "org.foo.App".to_string(),
            ]
        );
    }

    #[test]
    fn test_data_dir_is_var_app_id() {
        let c = ctx();
        assert_eq!(
            data_dir(&c, "org.foo.App"),
            c.home.join(".var/app/org.foo.App")
        );
    }
}
