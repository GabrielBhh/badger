use std::collections::HashSet;

use anyhow::Context;

use crate::core::runner::runner_for;
use crate::ctx::Ctx;

pub struct SnapperConfig {
    pub name: String,
    pub subvolume: String,
}

/// Runs `snapper list-configs` via `runner_for(ctx)` and parses its
/// `Config | Subvolume` table (a header row, a `---+---`-style separator
/// row of only dashes/pluses, then one `name | subvolume` row per config).
/// Both columns are trimmed. Empty/blank lines are skipped. Never errors on
/// its own parsing — an unexpected line is just skipped; only a genuine
/// command failure propagates as `Err`.
pub fn list_configs(ctx: &Ctx) -> anyhow::Result<Vec<SnapperConfig>> {
    let runner = runner_for(ctx);
    let out = runner
        .run(&["snapper".to_string(), "list-configs".to_string()])
        .context("failed to run snapper list-configs")?;

    let mut configs = Vec::new();
    let mut seen_separator = false;
    for line in out.stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !seen_separator {
            if !line.is_empty() && line.chars().all(|c| c == '-' || c == '+') {
                seen_separator = true;
            }
            continue;
        }
        let Some((name, subvolume)) = line.split_once('|') else {
            continue;
        };
        configs.push(SnapperConfig {
            name: name.trim().to_string(),
            subvolume: subvolume.trim().to_string(),
        });
    }
    Ok(configs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapType {
    Single,
    Pre,
    Post,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub number: u64,
    pub snap_type: SnapType,
    /// Only meaningful (Some) for a Post snapshot: the paired Pre snapshot's number.
    pub pre_number: Option<u64>,
    pub date: Option<String>,
    pub description: String,
}

/// Runs `snapper -c <cfg> --jsonout list` via `runner_for(ctx)` and parses
/// snapper's JSON: a top-level JSON object keyed by config name, mapping to
/// an array of snapshot objects. Parsed leniently via `serde_json::Value` so
/// unrecognized fields (`default`, `active`, `user`, `cleanup`, `userdata`,
/// ...) never break parsing. An entry missing the required `number` field is
/// skipped, not an error for the whole call. An unrecognized `type` string is
/// treated as `Single`. Genuinely malformed top-level JSON, or JSON whose top
/// level has no array under key `cfg`, is an `Err`.
pub fn list_snapshots(ctx: &Ctx, cfg: &str) -> anyhow::Result<Vec<Snapshot>> {
    let runner = runner_for(ctx);
    let out = runner
        .run(&[
            "snapper".to_string(),
            "-c".to_string(),
            cfg.to_string(),
            "--jsonout".to_string(),
            "list".to_string(),
        ])
        .with_context(|| format!("failed to run snapper -c {cfg} --jsonout list"))?;

    let value: serde_json::Value = serde_json::from_str(&out.stdout)
        .with_context(|| format!("failed to parse snapper JSON output for config {cfg}"))?;
    let entries = value
        .get(cfg)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("no snapshot array found for config {cfg}"))?;

    let mut snapshots = Vec::new();
    for entry in entries {
        let Some(number) = entry.get("number").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let snap_type = match entry.get("type").and_then(serde_json::Value::as_str) {
            Some("pre") => SnapType::Pre,
            Some("post") => SnapType::Post,
            _ => SnapType::Single,
        };
        let pre_number = entry.get("pre-number").and_then(serde_json::Value::as_u64);
        let date = entry
            .get("date")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let description = entry
            .get("description")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        snapshots.push(Snapshot {
            number,
            snap_type,
            pre_number,
            date,
            description,
        });
    }
    Ok(snapshots)
}

/// Parses `/proc/cmdline` (read from `ctx.root.join("proc/cmdline")`, so
/// this is testable via a sandboxed ctx) for the currently booted snapshot
/// number. Recognizes any of: `subvol=@snapshots/<N>/snapshot`,
/// `subvol=/@snapshots/<N>/snapshot`, and the openSUSE-style `.snapshots`
/// prefix instead of `@snapshots` (all four combinations of leading-slash x
/// @-vs-dot-prefix). Returns None if the file is missing/unreadable, no
/// `subvol=` token is present at all (e.g. rootflags uses `subvolid=`
/// instead — the booted snapshot number is then unknowable from cmdline),
/// or the `subvol=` token doesn't match the snapshot pattern.
pub fn booted_snapshot_from_cmdline(ctx: &Ctx) -> Option<u64> {
    let text = std::fs::read_to_string(ctx.root.join("proc/cmdline")).ok()?;
    extract_snapshot_number_from_cmdline(&text)
}

/// Scans whitespace-delimited `text` for a token containing `subvol=`
/// (covering both a bare `subvol=...` token and `rootflags=subvol=...`
/// combined into one token), then runs `extract_snapshot_number` on just the
/// value after `subvol=` in that one token. Anchoring to the token this way
/// means an unrelated argument that happens to contain "snapshots/<N>/
/// snapshot" (e.g. some other path) is never mistaken for the boot
/// subvolume, and a cmdline using `subvolid=` (no `subvol=` path argument at
/// all) correctly yields `None` here regardless of anything else on the
/// line.
fn extract_snapshot_number_from_cmdline(text: &str) -> Option<u64> {
    text.split_whitespace()
        .find_map(|tok| tok.split_once("subvol=").map(|(_, value)| value))
        .and_then(extract_snapshot_number)
}

/// Runs `btrfs subvolume get-default /` via `runner_for(ctx)` and parses the
/// snapshot number out of a `... path @snapshots/<N>/snapshot` (or
/// `.snapshots/<N>/snapshot`) line in its stdout. None if the command fails,
/// doesn't succeed, or its output doesn't contain that pattern (e.g. the
/// default subvolume is the real root, not a snapshot).
pub fn default_snapshot_from_btrfs(ctx: &Ctx) -> Option<u64> {
    let runner = runner_for(ctx);
    let out = runner
        .run(&[
            "btrfs".to_string(),
            "subvolume".to_string(),
            "get-default".to_string(),
            "/".to_string(),
        ])
        .ok()?;
    if !out.success {
        return None;
    }
    extract_snapshot_number(&out.stdout)
}

/// The set of snapshot numbers that must never be offered for manual
/// deletion: the union of `booted_snapshot_from_cmdline` and
/// `default_snapshot_from_btrfs`. Returns `None` ONLY when *neither* source
/// resolved a number at all — meaning badger has zero booted-snapshot
/// knowledge, and a later rule must refuse all manual snapshot deletion in
/// that case. Returns `Some` (a one- or two-element set) as soon as at
/// least one source resolved something, even if the other didn't.
pub fn protected_snapshot_numbers(ctx: &Ctx) -> Option<HashSet<u64>> {
    let booted = booted_snapshot_from_cmdline(ctx);
    let default = default_snapshot_from_btrfs(ctx);
    if booted.is_none() && default.is_none() {
        return None;
    }
    Some(booted.into_iter().chain(default).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimineState {
    Present { active: bool },
    Absent,
}

/// Runs `systemctl is-enabled limine-snapper-sync.service` via
/// `runner_for(ctx)`. If its stdout (trimmed) is exactly "not-found" (the
/// case when the unit file doesn't exist at all) OR the command errors,
/// returns `Absent` without running anything else. Otherwise (the unit
/// exists in some enabled/disabled/static/masked state) runs
/// `systemctl is-active limine-snapper-sync.service` and returns
/// `Present { active: <stdout.trim() == "active"> }` (command error while
/// checking active => active: false, never propagated as an Err from this
/// function — this is a detection helper, not fallible plumbing).
pub fn limine_sync_state(ctx: &Ctx) -> LimineState {
    let runner = runner_for(ctx);
    let enabled = runner.run(&[
        "systemctl".to_string(),
        "is-enabled".to_string(),
        "limine-snapper-sync.service".to_string(),
    ]);
    let Ok(enabled) = enabled else {
        return LimineState::Absent;
    };
    if enabled.stdout.trim() == "not-found" {
        return LimineState::Absent;
    }

    let active = runner
        .run(&[
            "systemctl".to_string(),
            "is-active".to_string(),
            "limine-snapper-sync.service".to_string(),
        ])
        .map(|out| out.stdout.trim() == "active")
        .unwrap_or(false);
    LimineState::Present { active }
}

/// Scans `text` for every occurrence of `"snapshots/"`, and for each
/// occurrence takes the digits immediately following it; if those digits are
/// non-empty AND immediately followed by `"/snapshot"`, parses and returns
/// the first such number found. Naturally covers `@snapshots/`,
/// `.snapshots/`, and leading-slash-or-not, since it doesn't care what
/// precedes the `"snapshots/"` substring.
fn extract_snapshot_number(text: &str) -> Option<u64> {
    let mut search_start = 0;
    while let Some(idx) = text[search_start..].find("snapshots/") {
        let after = search_start + idx + "snapshots/".len();
        let digits_end = text[after..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| after + i)
            .unwrap_or(text.len());
        let digits = &text[after..digits_end];
        if !digits.is_empty()
            && text[digits_end..].starts_with("/snapshot")
            && let Ok(number) = digits.parse::<u64>()
        {
            return Some(number);
        }
        search_start = after;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::core::runner::CmdOutput;
    use std::collections::HashMap;

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

    fn cmd_output(stdout: &str) -> CmdOutput {
        CmdOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn write_cmdline(f: &Fixture, contents: &str) {
        std::fs::create_dir_all(f.ctx.root.join("proc")).unwrap();
        std::fs::write(f.ctx.root.join("proc/cmdline"), contents).unwrap();
    }

    // --- list_configs ---

    #[test]
    fn test_list_configs_parses_realistic_table_with_two_configs() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec!["snapper".to_string(), "list-configs".to_string()],
            cmd_output(
                "Config | Subvolume\n\
                 -------+-----------\n\
                 root   | /\n\
                 home   | /home\n",
            ),
        )]));

        let configs = list_configs(&f.ctx).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].name, "root");
        assert_eq!(configs[0].subvolume, "/");
        assert_eq!(configs[1].name, "home");
        assert_eq!(configs[1].subvolume, "/home");
    }

    #[test]
    fn test_list_configs_returns_empty_vec_for_empty_stdout() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec!["snapper".to_string(), "list-configs".to_string()],
            cmd_output(""),
        )]));

        let configs = list_configs(&f.ctx).unwrap();
        assert!(configs.is_empty());
    }

    #[test]
    fn test_list_configs_parses_table_with_irregular_spacing() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec!["snapper".to_string(), "list-configs".to_string()],
            cmd_output("Config|Subvolume\n---+---\nroot|   /\n   home    |/home   \n"),
        )]));

        let configs = list_configs(&f.ctx).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].name, "root");
        assert_eq!(configs[0].subvolume, "/");
        assert_eq!(configs[1].name, "home");
        assert_eq!(configs[1].subvolume, "/home");
    }

    // --- list_snapshots ---

    #[test]
    fn test_list_snapshots_parses_single_pre_post_and_defaulted_entries_with_extra_fields() {
        let mut f = fixture();
        let json = r#"{
            "root": [
                {"number": 1, "type": "single", "date": "2024-01-01 00:00:00", "description": "single snap"},
                {"number": 2, "type": "pre", "date": "2024-01-02 00:00:00", "description": "before update", "cleanup": "number"},
                {"number": 3, "type": "post", "pre-number": 2, "date": "2024-01-02 00:05:00", "description": "after update"},
                {"number": 4, "date": "2024-01-03 00:00:00"}
            ]
        }"#;
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec![
                "snapper".to_string(),
                "-c".to_string(),
                "root".to_string(),
                "--jsonout".to_string(),
                "list".to_string(),
            ],
            cmd_output(json),
        )]));

        let snapshots = list_snapshots(&f.ctx, "root").unwrap();
        assert_eq!(snapshots.len(), 4);

        assert_eq!(snapshots[0].number, 1);
        assert_eq!(snapshots[0].snap_type, SnapType::Single);
        assert_eq!(snapshots[0].pre_number, None);
        assert_eq!(snapshots[0].date.as_deref(), Some("2024-01-01 00:00:00"));
        assert_eq!(snapshots[0].description, "single snap");

        assert_eq!(snapshots[1].number, 2);
        assert_eq!(snapshots[1].snap_type, SnapType::Pre);
        assert_eq!(snapshots[1].pre_number, None);
        assert_eq!(snapshots[1].date.as_deref(), Some("2024-01-02 00:00:00"));
        assert_eq!(snapshots[1].description, "before update");

        assert_eq!(snapshots[2].number, 3);
        assert_eq!(snapshots[2].snap_type, SnapType::Post);
        assert_eq!(snapshots[2].pre_number, Some(2));
        assert_eq!(snapshots[2].date.as_deref(), Some("2024-01-02 00:05:00"));
        assert_eq!(snapshots[2].description, "after update");

        assert_eq!(snapshots[3].number, 4);
        assert_eq!(snapshots[3].snap_type, SnapType::Single);
        assert_eq!(snapshots[3].pre_number, None);
        assert_eq!(snapshots[3].date.as_deref(), Some("2024-01-03 00:00:00"));
        assert_eq!(snapshots[3].description, "");
    }

    #[test]
    fn test_list_snapshots_skips_entry_missing_number() {
        let mut f = fixture();
        let json = r#"{
            "root": [
                {"type": "single", "description": "no number here"},
                {"number": 10, "description": "valid"}
            ]
        }"#;
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec![
                "snapper".to_string(),
                "-c".to_string(),
                "root".to_string(),
                "--jsonout".to_string(),
                "list".to_string(),
            ],
            cmd_output(json),
        )]));

        let snapshots = list_snapshots(&f.ctx, "root").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].number, 10);
    }

    #[test]
    fn test_list_snapshots_errors_on_malformed_json() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec![
                "snapper".to_string(),
                "-c".to_string(),
                "root".to_string(),
                "--jsonout".to_string(),
                "list".to_string(),
            ],
            cmd_output("not json"),
        )]));

        assert!(list_snapshots(&f.ctx, "root").is_err());
    }

    #[test]
    fn test_list_snapshots_errors_when_no_array_for_config() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            vec![
                "snapper".to_string(),
                "-c".to_string(),
                "root".to_string(),
                "--jsonout".to_string(),
                "list".to_string(),
            ],
            cmd_output(r#"{"other-config": [{"number": 1}]}"#),
        )]));

        assert!(list_snapshots(&f.ctx, "root").is_err());
    }

    // --- booted_snapshot_from_cmdline ---

    #[test]
    fn test_booted_snapshot_from_cmdline_at_snapshots_no_leading_slash() {
        let f = fixture();
        write_cmdline(
            &f,
            "BOOT_IMAGE=/vmlinuz rw subvol=@snapshots/5/snapshot quiet\n",
        );
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), Some(5));
    }

    #[test]
    fn test_booted_snapshot_from_cmdline_at_snapshots_leading_slash() {
        let f = fixture();
        write_cmdline(
            &f,
            "BOOT_IMAGE=/vmlinuz rw subvol=/@snapshots/5/snapshot quiet\n",
        );
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), Some(5));
    }

    #[test]
    fn test_booted_snapshot_from_cmdline_dot_snapshots_no_leading_slash() {
        let f = fixture();
        write_cmdline(
            &f,
            "BOOT_IMAGE=/vmlinuz rw subvol=.snapshots/5/snapshot quiet\n",
        );
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), Some(5));
    }

    #[test]
    fn test_booted_snapshot_from_cmdline_dot_snapshots_leading_slash() {
        let f = fixture();
        write_cmdline(
            &f,
            "BOOT_IMAGE=/vmlinuz rw subvol=/.snapshots/5/snapshot quiet\n",
        );
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), Some(5));
    }

    #[test]
    fn test_booted_snapshot_from_cmdline_none_when_no_snapshot_pattern() {
        let f = fixture();
        write_cmdline(&f, "BOOT_IMAGE=/vmlinuz rw subvol=@ quiet\n");
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), None);
    }

    #[test]
    fn test_booted_snapshot_from_cmdline_none_when_file_missing() {
        let f = fixture();
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), None);
    }

    #[test]
    fn test_booted_snapshot_from_cmdline_none_when_only_subvolid_present() {
        let f = fixture();
        write_cmdline(&f, "BOOT_IMAGE=/vmlinuz rw rootflags=subvolid=256 quiet\n");
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), None);
    }

    // Regression: a bare substring scan for "snapshots/" over the whole
    // cmdline picks up any argument that happens to contain that text, even
    // one with nothing to do with the boot subvolume (here, rootflags uses
    // subvolid= with no subvol= path at all). The scan must be anchored to a
    // subvol= token so this unrelated argument is ignored.
    #[test]
    fn test_booted_snapshot_from_cmdline_ignores_snapshot_like_substring_not_anchored_to_subvol() {
        let f = fixture();
        write_cmdline(
            &f,
            "BOOT_IMAGE=/vmlinuz rw rootflags=subvolid=256 \
             initrd=/boot/snapshots/5/snapshot-initrd quiet\n",
        );
        assert_eq!(booted_snapshot_from_cmdline(&f.ctx), None);
    }

    // --- default_snapshot_from_btrfs ---

    fn btrfs_argv() -> Vec<String> {
        vec![
            "btrfs".to_string(),
            "subvolume".to_string(),
            "get-default".to_string(),
            "/".to_string(),
        ]
    }

    #[test]
    fn test_default_snapshot_from_btrfs_parses_snapshot_number() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            btrfs_argv(),
            cmd_output("ID 344 gen 89201 top level 5 path @snapshots/5/snapshot\n"),
        )]));
        assert_eq!(default_snapshot_from_btrfs(&f.ctx), Some(5));
    }

    #[test]
    fn test_default_snapshot_from_btrfs_none_for_non_snapshot_default() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            btrfs_argv(),
            cmd_output("ID 5 gen 100 top level 5 path <FS_TREE>\n"),
        )]));
        assert_eq!(default_snapshot_from_btrfs(&f.ctx), None);
    }

    #[test]
    fn test_default_snapshot_from_btrfs_none_when_command_errors() {
        let f = fixture();
        assert_eq!(default_snapshot_from_btrfs(&f.ctx), None);
    }

    // --- protected_snapshot_numbers ---

    #[test]
    fn test_protected_snapshot_numbers_none_when_neither_source_resolves() {
        let f = fixture();
        assert_eq!(protected_snapshot_numbers(&f.ctx), None);
    }

    #[test]
    fn test_protected_snapshot_numbers_cmdline_only() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/5/snapshot\n");
        f.ctx.fake_command_output = Some(HashMap::new());
        assert_eq!(protected_snapshot_numbers(&f.ctx), Some(HashSet::from([5])));
    }

    #[test]
    fn test_protected_snapshot_numbers_btrfs_only() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            btrfs_argv(),
            cmd_output("ID 344 gen 89201 top level 5 path @snapshots/7/snapshot\n"),
        )]));
        assert_eq!(protected_snapshot_numbers(&f.ctx), Some(HashSet::from([7])));
    }

    #[test]
    fn test_protected_snapshot_numbers_both_equal() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/5/snapshot\n");
        f.ctx.fake_command_output = Some(HashMap::from([(
            btrfs_argv(),
            cmd_output("ID 344 gen 89201 top level 5 path @snapshots/5/snapshot\n"),
        )]));
        assert_eq!(protected_snapshot_numbers(&f.ctx), Some(HashSet::from([5])));
    }

    #[test]
    fn test_protected_snapshot_numbers_both_different_mid_rollback() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/5/snapshot\n");
        f.ctx.fake_command_output = Some(HashMap::from([(
            btrfs_argv(),
            cmd_output("ID 344 gen 89201 top level 5 path @snapshots/7/snapshot\n"),
        )]));
        assert_eq!(
            protected_snapshot_numbers(&f.ctx),
            Some(HashSet::from([5, 7]))
        );
    }

    // --- limine_sync_state ---

    fn is_enabled_argv() -> Vec<String> {
        vec![
            "systemctl".to_string(),
            "is-enabled".to_string(),
            "limine-snapper-sync.service".to_string(),
        ]
    }

    fn is_active_argv() -> Vec<String> {
        vec![
            "systemctl".to_string(),
            "is-active".to_string(),
            "limine-snapper-sync.service".to_string(),
        ]
    }

    #[test]
    fn test_limine_sync_state_present_and_active() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([
            (is_enabled_argv(), cmd_output("enabled\n")),
            (is_active_argv(), cmd_output("active\n")),
        ]));
        assert_eq!(
            limine_sync_state(&f.ctx),
            LimineState::Present { active: true }
        );
    }

    #[test]
    fn test_limine_sync_state_present_and_inactive() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([
            (is_enabled_argv(), cmd_output("disabled\n")),
            (is_active_argv(), cmd_output("inactive\n")),
        ]));
        assert_eq!(
            limine_sync_state(&f.ctx),
            LimineState::Present { active: false }
        );
    }

    // Regression seam: is-enabled == "not-found" must short-circuit without
    // consulting is-active at all. No canned response is provided for
    // is-active here, so if the implementation wrongly fell through and
    // called it anyway, the FakeRunner's error would surface as
    // `Present { active: false }` instead of the expected `Absent`.
    #[test]
    fn test_limine_sync_state_absent_when_not_found_skips_is_active() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::from([(
            is_enabled_argv(),
            cmd_output("not-found\n"),
        )]));
        assert_eq!(limine_sync_state(&f.ctx), LimineState::Absent);
    }

    #[test]
    fn test_limine_sync_state_absent_when_is_enabled_command_errors() {
        let f = fixture();
        assert_eq!(limine_sync_state(&f.ctx), LimineState::Absent);
    }
}
