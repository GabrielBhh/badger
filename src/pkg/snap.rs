use crate::core::runner::runner_for;
use crate::ctx::Ctx;
use crate::pkg::{Backend, InstalledPackage};
use crate::rules::command_exists;

/// Absent on the dev machine — only ever exercised via `FakeRunner`-canned
/// output in tests, never for real.
pub fn is_available(ctx: &Ctx) -> bool {
    command_exists("snap", ctx)
}

/// `snap list` — a header line (`Name  Version  Rev  Tracking  Publisher
/// Notes`) followed by one whitespace-separated row per installed snap. No
/// per-snap size is offered by this command, so `size_bytes` is always
/// `None`.
pub fn list(ctx: &Ctx) -> Vec<InstalledPackage> {
    let runner = runner_for(ctx);
    match runner.run(&["snap".to_string(), "list".to_string()]) {
        Ok(out) => parse_snap_list(&out.stdout),
        Err(_) => Vec::new(),
    }
}

fn parse_snap_list(text: &str) -> Vec<InstalledPackage> {
    text.lines()
        .skip(1) // header row
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let name = cols.next()?;
            let version = cols.next().unwrap_or("").to_string();
            Some(InstalledPackage {
                backend: Backend::Snap,
                id: name.to_string(),
                name: name.to_string(),
                version,
                size_bytes: None,
                aur: false,
            })
        })
        .collect()
}

/// `snap remove -- <name>` — always run via sudo. The `--` separates snap's
/// own options from `name` (an identifier out of snapd's own database), so a
/// name that happens to start with `-` is never misinterpreted as a flag.
pub fn remove_argv(name: &str) -> Vec<String> {
    vec![
        "snap".to_string(),
        "remove".to_string(),
        "--".to_string(),
        name.to_string(),
    ]
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
    fn test_is_available_requires_snap_command() {
        let mut c = ctx();
        assert!(!is_available(&c));
        c.available_commands = Some(vec!["snap".to_string()]);
        assert!(is_available(&c));
    }

    #[test]
    fn test_list_skips_header_and_parses_name_and_version() {
        let mut c = ctx();
        c.fake_command_output = Some(HashMap::from([(
            vec!["snap".to_string(), "list".to_string()],
            CmdOutput {
                success: true,
                stdout: "Name    Version   Rev    Tracking       Publisher   Notes\n\
                         hello   2.10      1234   latest/stable  canonical   -\n"
                    .to_string(),
                stderr: String::new(),
            },
        )]));

        let packages = list(&c);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "hello");
        assert_eq!(packages[0].id, "hello");
        assert_eq!(packages[0].version, "2.10");
        assert_eq!(packages[0].backend, Backend::Snap);
        assert_eq!(packages[0].size_bytes, None);
    }

    #[test]
    fn test_remove_argv_is_exact() {
        assert_eq!(
            remove_argv("hello"),
            vec![
                "snap".to_string(),
                "remove".to_string(),
                "--".to_string(),
                "hello".to_string()
            ]
        );
    }

    // Regression: a snap name is an identifier from snapd's own database, but
    // nothing stopped it from being interpreted as a snap flag if it happened
    // to start with a dash. `--` (end-of-options) must separate snap's own
    // flags from the name, no matter what the name looks like.
    #[test]
    fn test_remove_argv_inserts_end_of_options_separator_before_a_dash_prefixed_name() {
        assert_eq!(
            remove_argv("-suspicious"),
            vec![
                "snap".to_string(),
                "remove".to_string(),
                "--".to_string(),
                "-suspicious".to_string()
            ]
        );
    }
}
