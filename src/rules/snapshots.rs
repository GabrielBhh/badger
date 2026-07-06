//! The two most dangerous rules in badger: btrfs snapshot deletion via
//! `snapper`. `snapshots.snapper_cleanup` runs snapper's own retention
//! algorithm per config; `snapshots.snapper_manual` lets a person delete
//! specific snapshots, with hard exclusions (booted snapshot, default
//! snapshot, snapshot 0, unpaired pre/post) enforced in the detector and
//! builder rather than left to `validate_deletable` (these candidates carry
//! no `path` at all — there is nothing on disk for the safety module to
//! check; the exclusion logic here *is* the safety net).

use std::collections::{BTreeMap, HashSet};

use crate::config::Config;
use crate::core::item::{Candidate, Risk};
use crate::ctx::Ctx;
use crate::rules::{
    Action, Applicability, CmdSelectedWithSkipsResult, CmdSpec, Detector, DetectorResult, Rule,
    Skip, command_exists,
};
use crate::snapper::{self, LimineState, SnapType, Snapshot};

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "snapshots.snapper_cleanup",
            title: "Snapper snapshot cleanup",
            risk: Risk::Risky,
            requires_sudo: true,
            applicable: Applicability::Fn(snapper_applicable),
            allowed_prefixes: &[],
            detector: Detector::FnWithSkips(cleanup_detector),
            action: Action::CmdSelected(cleanup_cmd),
            notes: "Runs snapper's own 'number' cleanup algorithm per config, respecting each \
                    config's own retention settings — this is the recommended way to reclaim \
                    snapshot space. If limine-snapper-sync is active, boot entries re-sync \
                    automatically afterwards; if it's installed but inactive, run it manually \
                    after cleanup.",
        },
        Rule {
            id: "snapshots.snapper_manual",
            title: "Snapper snapshots (manual delete)",
            risk: Risk::Risky,
            requires_sudo: true,
            applicable: Applicability::Fn(snapper_applicable),
            allowed_prefixes: &[],
            detector: Detector::FnWithSkips(manual_detector),
            action: Action::CmdSelectedWithSkips(manual_cmd),
            notes: "Deletes exactly the snapshots you select. Snapshot 0 (snapper's 'current \
                    system' pseudo-snapshot), the booted snapshot, and the current default \
                    subvolume snapshot are never offered. A pre/post pair must be selected \
                    together, or that whole config is refused — nothing partial is ever \
                    deleted. Same limine-snapper-sync guidance as the cleanup rule above. \
                    Booted-snapshot detection is still pending verification on a real \
                    machine/VM.",
        },
    ]
}

fn snapper_applicable(ctx: &Ctx) -> bool {
    command_exists("snapper", ctx) && ctx.config.snapshots.manage
}

/// A snapper config name must be a safe token before it's ever placed into
/// `snapper -c <name> ...` argv: non-empty, ASCII alphanumeric/`-`/`_`/`.`
/// only, and never starting with `-` (so it can never be mistaken for a
/// flag). Mirrors `snap::is_valid_snap_name`'s charset-check style.
fn is_valid_config_name(name: &str) -> bool {
    let Some(first) = name.chars().next() else {
        return false;
    };
    first != '-'
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// `(label, reason)` skip note for a config name that failed
/// `is_valid_config_name` — reported instead of ever being offered as a
/// candidate.
fn invalid_config_name_skip(name: &str) -> Skip {
    (
        format!("snapper config {name}"),
        "config name contains characters unsafe to pass to snapper — skipped".to_string(),
    )
}

// --- snapshots.snapper_cleanup ---

fn limine_cleanup_suffix(ctx: &Ctx) -> &'static str {
    match snapper::limine_sync_state(ctx) {
        LimineState::Present { active: true } => " — limine boot entries re-sync automatically",
        LimineState::Present { active: false } => {
            " — WARNING: limine-snapper-sync inactive, run it manually afterwards"
        }
        LimineState::Absent => "",
    }
}

fn cleanup_detector(ctx: &Ctx, _config: &Config) -> DetectorResult {
    let Ok(configs) = snapper::list_configs(ctx) else {
        return (Vec::new(), Vec::new());
    };
    let suffix = limine_cleanup_suffix(ctx);

    let mut candidates = Vec::new();
    let mut skips = Vec::new();
    for cfg in configs {
        if !is_valid_config_name(&cfg.name) {
            skips.push(invalid_config_name_skip(&cfg.name));
            continue;
        }
        let count = snapper::list_snapshots(ctx, &cfg.name)
            .map(|snapshots| snapshots.len())
            .unwrap_or(0);
        let label = format!(
            "run snapper cleanup 'number' for config {} ({count} snapshots){suffix}",
            cfg.name
        );
        candidates.push(Candidate::new(None, label, 0, Risk::Risky));
    }
    (candidates, skips)
}

/// Extracts the config name between `for config ` and the following ` (` in
/// a `cleanup_detector` candidate label. Mirrors `moderate::extract_id`'s
/// label-parsing precedent.
fn extract_config_name(label: &str) -> Option<String> {
    let start = label.find("for config ")? + "for config ".len();
    let rest = &label[start..];
    let end = rest.find(" (")?;
    Some(rest[..end].to_string())
}

fn cleanup_cmd(_ctx: &Ctx, _config: &Config, selected: &[Candidate]) -> Vec<CmdSpec> {
    selected
        .iter()
        .filter_map(|c| extract_config_name(&c.label))
        .map(|name| CmdSpec {
            argv: vec![
                "snapper".to_string(),
                "-c".to_string(),
                name.clone(),
                "cleanup".to_string(),
                "number".to_string(),
            ],
            sudo: true,
            label: format!("Run snapper cleanup 'number' for {name}"),
        })
        .collect()
}

// --- snapshots.snapper_manual ---

const NO_BOOTED_KNOWLEDGE_LABEL: &str = "manual snapshot deletion";
const NO_BOOTED_KNOWLEDGE_REASON: &str = "cannot identify the booted snapshot — not offering \
                                           per-snapshot deletion (the cleanup rule above still \
                                           works)";
const LIMINE_INACTIVE_LABEL: &str = "limine-snapper-sync";
const LIMINE_INACTIVE_REASON: &str = "installed but inactive — run it manually after deleting \
                                       snapshots so boot entries stay in sync";

fn manual_label(config: &str, snap: &Snapshot) -> String {
    let mut label = format!("{config}: #{}", snap.number);
    match snap.snap_type {
        SnapType::Pre => label.push_str(" [pre]"),
        SnapType::Post => match snap.pre_number {
            Some(n) => label.push_str(&format!(" [post of #{n}]")),
            None => label.push_str(" [post]"),
        },
        SnapType::Single => {}
    }
    if let Some(date) = &snap.date {
        label.push(' ');
        label.push_str(date);
    }
    if !snap.description.is_empty() {
        label.push_str(" — ");
        label.push_str(&snap.description);
    }
    label
}

fn manual_limine_skips(ctx: &Ctx) -> Vec<Skip> {
    match snapper::limine_sync_state(ctx) {
        LimineState::Present { active: false } => vec![(
            LIMINE_INACTIVE_LABEL.to_string(),
            LIMINE_INACTIVE_REASON.to_string(),
        )],
        _ => Vec::new(),
    }
}

fn manual_detector(ctx: &Ctx, _config: &Config) -> DetectorResult {
    let Some(protected) = snapper::protected_snapshot_numbers(ctx) else {
        return (
            Vec::new(),
            vec![(
                NO_BOOTED_KNOWLEDGE_LABEL.to_string(),
                NO_BOOTED_KNOWLEDGE_REASON.to_string(),
            )],
        );
    };

    let mut candidates = Vec::new();
    let mut skips = manual_limine_skips(ctx);
    if let Ok(configs) = snapper::list_configs(ctx) {
        for cfg in configs {
            if !is_valid_config_name(&cfg.name) {
                skips.push(invalid_config_name_skip(&cfg.name));
                continue;
            }
            let Ok(snapshots) = snapper::list_snapshots(ctx, &cfg.name) else {
                continue;
            };
            for snap in snapshots {
                if snap.number == 0 || protected.contains(&snap.number) {
                    continue;
                }
                candidates.push(Candidate::new(
                    None,
                    manual_label(&cfg.name, &snap),
                    0,
                    Risk::Risky,
                ));
            }
        }
    }

    (candidates, skips)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedKind {
    Single,
    Pre,
    Post(Option<u64>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedLabel {
    config: String,
    number: u64,
    kind: ParsedKind,
}

/// Parses a `manual_label`-shaped candidate label back into its config,
/// number, and pre/post marker. The machine-parsed tokens sit at the front
/// of the label (`<config>: #<number>` then an optional `[pre]` / `[post of
/// #<n>]` / `[post]` marker immediately after), before any free-text
/// date/description, so a hostile description can never change what gets
/// parsed here. Splits on the LAST `": #"` occurrence (not the first) so a
/// config name that itself contains `": #"` can't redirect parsing to that
/// earlier, hostile occurrence instead of the real number that follows the
/// config name. Returns `None` for anything that doesn't match, and also for
/// number `0` (defense in depth — `0` must never reach an argv).
fn parse_manual_label(label: &str) -> Option<ParsedLabel> {
    let (config, rest) = label.rsplit_once(": #")?;
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if digits_end == 0 {
        return None;
    }
    let number: u64 = rest[..digits_end].parse().ok()?;
    if number == 0 {
        return None;
    }

    let after_number = &rest[digits_end..];
    let kind = if after_number.starts_with(" [pre]") {
        ParsedKind::Pre
    } else if let Some(post_rest) = after_number.strip_prefix(" [post of #") {
        let end = post_rest.find(']')?;
        let pre_number: u64 = post_rest[..end].parse().ok()?;
        ParsedKind::Post(Some(pre_number))
    } else if after_number.starts_with(" [post]") {
        ParsedKind::Post(None)
    } else {
        ParsedKind::Single
    };

    Some(ParsedLabel {
        config: config.to_string(),
        number,
        kind,
    })
}

/// Reconstructs the minimal, machine-parsed-only form of a label (no
/// date/description) for naming a pre/post pairing violation in a skip note.
fn minimal_label(config: &str, parsed: &ParsedLabel) -> String {
    match parsed.kind {
        ParsedKind::Pre => format!("{config}: #{} [pre]", parsed.number),
        ParsedKind::Post(Some(pre_number)) => {
            format!("{config}: #{} [post of #{pre_number}]", parsed.number)
        }
        ParsedKind::Post(None) => format!("{config}: #{} [post]", parsed.number),
        ParsedKind::Single => format!("{config}: #{}", parsed.number),
    }
}

fn manual_cmd(_ctx: &Ctx, _config: &Config, selected: &[Candidate]) -> CmdSelectedWithSkipsResult {
    let mut skips: Vec<Skip> = Vec::new();
    let mut by_config: BTreeMap<String, Vec<ParsedLabel>> = BTreeMap::new();

    for c in selected {
        match parse_manual_label(&c.label) {
            Some(parsed) => by_config
                .entry(parsed.config.clone())
                .or_default()
                .push(parsed),
            None => skips.push((
                c.label.clone(),
                "could not be safely interpreted — not deleted".to_string(),
            )),
        }
    }

    let mut specs = Vec::new();
    for (config, parsed) in by_config {
        let selected_numbers: HashSet<u64> = parsed.iter().map(|p| p.number).collect();
        let mut violations: Vec<Skip> = Vec::new();

        for p in &parsed {
            match p.kind {
                ParsedKind::Pre => {
                    let has_post = parsed
                        .iter()
                        .any(|q| matches!(q.kind, ParsedKind::Post(Some(n)) if n == p.number));
                    if !has_post {
                        violations.push((
                            minimal_label(&config, p),
                            format!(
                                "selected without its paired post snapshot — deselect it or \
                                 select the pair; nothing was deleted for config {config}"
                            ),
                        ));
                    }
                }
                ParsedKind::Post(pre_number) => {
                    let paired = matches!(pre_number, Some(n) if selected_numbers.contains(&n));
                    if !paired {
                        violations.push((
                            minimal_label(&config, p),
                            format!(
                                "selected without its paired pre snapshot — deselect it or \
                                 select the pair; nothing was deleted for config {config}"
                            ),
                        ));
                    }
                }
                ParsedKind::Single => {}
            }
        }

        if !violations.is_empty() {
            skips.extend(violations);
            continue;
        }

        let mut numbers: Vec<u64> = selected_numbers.into_iter().collect();
        numbers.sort_unstable();
        let mut argv = vec![
            "snapper".to_string(),
            "-c".to_string(),
            config.clone(),
            "delete".to_string(),
        ];
        argv.extend(numbers.iter().map(u64::to_string));
        specs.push(CmdSpec {
            argv,
            sudo: true,
            label: format!("Delete {} snapshot(s) from config {config}", numbers.len()),
        });
    }

    (specs, skips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::exec::{DryRunEffector, execute_selected};
    use crate::core::runner::CmdOutput;
    use crate::core::scan::scan;
    use crate::safety::journal::Journal;
    use crate::safety::whitelist;
    use std::collections::HashMap;
    use std::collections::HashSet as StdHashSet;
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

    fn cmd_output(stdout: &str) -> CmdOutput {
        CmdOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn list_configs_argv() -> Vec<String> {
        vec!["snapper".to_string(), "list-configs".to_string()]
    }

    fn list_configs_output(names: &[&str]) -> CmdOutput {
        let mut out = "Config | Subvolume\n-------+----------\n".to_string();
        for name in names {
            out.push_str(&format!("{name} | /\n"));
        }
        cmd_output(&out)
    }

    fn list_snapshots_argv(cfg: &str) -> Vec<String> {
        vec![
            "snapper".to_string(),
            "-c".to_string(),
            cfg.to_string(),
            "--jsonout".to_string(),
            "list".to_string(),
        ]
    }

    fn snapshot_json(entries: &[String]) -> String {
        format!("{{\"root\": [{}]}}", entries.join(","))
    }

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

    fn btrfs_argv() -> Vec<String> {
        vec![
            "btrfs".to_string(),
            "subvolume".to_string(),
            "get-default".to_string(),
            "/".to_string(),
        ]
    }

    fn write_cmdline(f: &Fixture, contents: &str) {
        std::fs::create_dir_all(f.ctx.root.join("proc")).unwrap();
        std::fs::write(f.ctx.root.join("proc/cmdline"), contents).unwrap();
    }

    fn limine_absent() -> HashMap<Vec<String>, CmdOutput> {
        HashMap::new()
    }

    fn limine_active() -> HashMap<Vec<String>, CmdOutput> {
        HashMap::from([
            (is_enabled_argv(), cmd_output("enabled\n")),
            (is_active_argv(), cmd_output("active\n")),
        ])
    }

    fn limine_inactive() -> HashMap<Vec<String>, CmdOutput> {
        HashMap::from([
            (is_enabled_argv(), cmd_output("disabled\n")),
            (is_active_argv(), cmd_output("inactive\n")),
        ])
    }

    fn merge(maps: Vec<HashMap<Vec<String>, CmdOutput>>) -> HashMap<Vec<String>, CmdOutput> {
        let mut out = HashMap::new();
        for m in maps {
            out.extend(m);
        }
        out
    }

    // --- is_valid_config_name ---

    #[test]
    fn test_is_valid_config_name_rejects_leading_dash_and_unsafe_chars() {
        assert!(is_valid_config_name("root"));
        assert!(is_valid_config_name("my-config_1.bak"));
        assert!(!is_valid_config_name("-evil"));
        assert!(!is_valid_config_name("has space"));
        assert!(!is_valid_config_name(""));
    }

    // --- gating ---

    #[test]
    fn test_snapshots_rules_absent_when_snapper_command_missing() {
        let f = fixture();
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn test_snapshots_rules_absent_when_manage_is_false() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["snapper".to_string()]);
        f.ctx.config.snapshots.manage = false;
        f.ctx.fake_command_output = Some(HashMap::new());
        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn test_snapshots_rules_present_when_snapper_and_manage_true() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["snapper".to_string()]);
        assert!(f.ctx.config.snapshots.manage);
        f.ctx.fake_command_output = Some(HashMap::new());

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let cleanup = groups
            .iter()
            .find(|g| g.rule_id == "snapshots.snapper_cleanup")
            .unwrap();
        let manual = groups
            .iter()
            .find(|g| g.rule_id == "snapshots.snapper_manual")
            .unwrap();
        assert!(cleanup.requires_sudo);
        assert_eq!(cleanup.risk, Risk::Risky);
        assert!(manual.requires_sudo);
        assert_eq!(manual.risk, Risk::Risky);
    }

    // --- cleanup detector ---

    #[test]
    fn test_cleanup_detector_lists_one_candidate_per_config_with_counts() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&["root", "home"]))]),
            HashMap::from([(
                vec![
                    "snapper".to_string(),
                    "-c".to_string(),
                    "root".to_string(),
                    "--jsonout".to_string(),
                    "list".to_string(),
                ],
                cmd_output(r#"{"root": [{"number":1},{"number":2},{"number":3}]}"#),
            )]),
            HashMap::from([(
                vec![
                    "snapper".to_string(),
                    "-c".to_string(),
                    "home".to_string(),
                    "--jsonout".to_string(),
                    "list".to_string(),
                ],
                cmd_output(r#"{"home": [{"number":1}]}"#),
            )]),
            limine_absent(),
        ]));

        let (candidates, _skips) = cleanup_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].label,
            "run snapper cleanup 'number' for config root (3 snapshots)"
        );
        assert_eq!(
            candidates[1].label,
            "run snapper cleanup 'number' for config home (1 snapshots)"
        );
        assert!(!candidates[0].selectable);
        assert!(!candidates[1].selectable);
    }

    #[test]
    fn test_cleanup_detector_limine_active_suffix() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&["root"]))]),
            HashMap::from([(list_snapshots_argv("root"), cmd_output(&snapshot_json(&[])))]),
            limine_active(),
        ]));
        let (candidates, _skips) = cleanup_detector(&f.ctx, &f.ctx.config.clone());
        assert!(
            candidates[0]
                .label
                .ends_with(" — limine boot entries re-sync automatically")
        );
    }

    #[test]
    fn test_cleanup_detector_limine_inactive_suffix() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&["root"]))]),
            HashMap::from([(list_snapshots_argv("root"), cmd_output(&snapshot_json(&[])))]),
            limine_inactive(),
        ]));
        let (candidates, _skips) = cleanup_detector(&f.ctx, &f.ctx.config.clone());
        assert!(
            candidates[0]
                .label
                .ends_with(" — WARNING: limine-snapper-sync inactive, run it manually afterwards")
        );
    }

    #[test]
    fn test_cleanup_detector_limine_absent_no_suffix() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&["root"]))]),
            HashMap::from([(list_snapshots_argv("root"), cmd_output(&snapshot_json(&[])))]),
            limine_absent(),
        ]));
        let (candidates, _skips) = cleanup_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(
            candidates[0].label,
            "run snapper cleanup 'number' for config root (0 snapshots)"
        );
    }

    #[test]
    fn test_cleanup_detector_skips_config_with_invalid_name_not_a_candidate() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&["root", "-evil"]))]),
            HashMap::from([(list_snapshots_argv("root"), cmd_output(&snapshot_json(&[])))]),
            limine_absent(),
        ]));

        let (candidates, skips) = cleanup_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].label.contains("config root"));
        assert_eq!(skips.len(), 1);
        assert!(skips[0].0.contains("-evil"));
    }

    // --- cleanup builder ---

    #[test]
    fn test_cleanup_cmd_builds_one_spec_per_selected_config() {
        let candidates = [
            Candidate::new(
                None,
                "run snapper cleanup 'number' for config root (3 snapshots)".to_string(),
                0,
                Risk::Risky,
            ),
            Candidate::new(
                None,
                "run snapper cleanup 'number' for config home (1 snapshots)".to_string(),
                0,
                Risk::Risky,
            ),
        ];

        let root_only = &candidates[0..1];
        let specs = cleanup_cmd(&fixture().ctx, &Config::default(), root_only);
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec![
                    "snapper".to_string(),
                    "-c".to_string(),
                    "root".to_string(),
                    "cleanup".to_string(),
                    "number".to_string(),
                ],
                sudo: true,
                label: "Run snapper cleanup 'number' for root".to_string(),
            }]
        );

        let both = &candidates[..];
        let specs = cleanup_cmd(&fixture().ctx, &Config::default(), both);
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn test_cleanup_cmd_unparseable_label_yields_no_spec_and_does_not_panic() {
        let candidates = vec![Candidate::new(
            None,
            "garbage label".to_string(),
            0,
            Risk::Risky,
        )];
        let specs = cleanup_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert!(specs.is_empty());
    }

    // --- manual detector: core safety test ---

    #[test]
    fn test_manual_detector_excludes_booted_default_and_zero() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/5/snapshot\n");
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(btrfs_argv(), cmd_output("path @snapshots/7/snapshot\n"))]),
            HashMap::from([(list_configs_argv(), list_configs_output(&["root"]))]),
            HashMap::from([(
                list_snapshots_argv("root"),
                cmd_output(
                    r#"{"root": [
                        {"number":0},
                        {"number":4},
                        {"number":5},
                        {"number":6},
                        {"number":7}
                    ]}"#,
                ),
            )]),
            limine_absent(),
        ]));

        let (candidates, skips) = manual_detector(&f.ctx, &f.ctx.config.clone());
        assert!(skips.is_empty());
        let labels: Vec<&str> = candidates.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, vec!["root: #4", "root: #6"]);
    }

    #[test]
    fn test_manual_detector_no_booted_knowledge_yields_zero_candidates_and_one_skip() {
        let mut f = fixture();
        f.ctx.fake_command_output = Some(HashMap::new());

        let (candidates, skips) = manual_detector(&f.ctx, &f.ctx.config.clone());
        assert!(candidates.is_empty());
        assert_eq!(
            skips,
            vec![(
                "manual snapshot deletion".to_string(),
                "cannot identify the booted snapshot — not offering per-snapshot deletion (the \
                 cleanup rule above still works)"
                    .to_string()
            )]
        );
    }

    #[test]
    fn test_manual_detector_no_booted_knowledge_skip_surfaces_via_full_scan() {
        let mut f = fixture();
        f.ctx.available_commands = Some(vec!["snapper".to_string()]);
        f.ctx.fake_command_output = Some(HashMap::new());

        let groups = scan(&rules(), &f.ctx, &f.ctx.config.clone(), &empty_whitelist()).unwrap();
        let manual = groups
            .iter()
            .find(|g| g.rule_id == "snapshots.snapper_manual")
            .unwrap();
        assert!(manual.candidates.is_empty());
        assert_eq!(manual.skipped.len(), 1);
        assert_eq!(manual.skipped[0].0, "manual snapshot deletion");
    }

    #[test]
    fn test_manual_detector_limine_inactive_adds_skip() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/5/snapshot\n");
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&[]))]),
            limine_inactive(),
        ]));

        let (_, skips) = manual_detector(&f.ctx, &f.ctx.config.clone());
        assert_eq!(
            skips,
            vec![(
                "limine-snapper-sync".to_string(),
                "installed but inactive — run it manually after deleting snapshots so boot \
                 entries stay in sync"
                    .to_string()
            )]
        );
    }

    #[test]
    fn test_manual_detector_limine_active_no_skip() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/5/snapshot\n");
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&[]))]),
            limine_active(),
        ]));

        let (_, skips) = manual_detector(&f.ctx, &f.ctx.config.clone());
        assert!(skips.is_empty());
    }

    #[test]
    fn test_manual_detector_labels_pre_and_post_of() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/999/snapshot\n");
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&["root"]))]),
            HashMap::from([(
                list_snapshots_argv("root"),
                cmd_output(
                    r#"{"root": [
                        {"number":10, "type":"pre"},
                        {"number":11, "type":"post", "pre-number":10}
                    ]}"#,
                ),
            )]),
            limine_absent(),
        ]));

        let (candidates, _) = manual_detector(&f.ctx, &f.ctx.config.clone());
        let labels: Vec<&str> = candidates.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, vec!["root: #10 [pre]", "root: #11 [post of #10]"]);
    }

    #[test]
    fn test_manual_detector_skips_config_with_invalid_name_not_a_candidate() {
        let mut f = fixture();
        write_cmdline(&f, "subvol=@snapshots/999/snapshot\n");
        f.ctx.fake_command_output = Some(merge(vec![
            HashMap::from([(list_configs_argv(), list_configs_output(&["-evil", "root"]))]),
            HashMap::from([(
                list_snapshots_argv("root"),
                cmd_output(r#"{"root": [{"number":4}]}"#),
            )]),
            limine_absent(),
        ]));

        let (candidates, skips) = manual_detector(&f.ctx, &f.ctx.config.clone());
        let labels: Vec<&str> = candidates.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, vec!["root: #4"]);
        assert!(skips.iter().any(|s| s.0.contains("-evil")));
    }

    // --- parse_manual_label ---

    // Regression: a config name containing ": #" (e.g. a config literally
    // named "root: #999") must not redirect parsing to that earlier, hostile
    // occurrence. Splitting on the FIRST ": #" would read this label as
    // config "root", number 999, kind Single — an entirely different
    // snapshot than the real one (#4, [pre]) that follows the config name.
    #[test]
    fn test_parse_manual_label_hostile_config_name_does_not_redirect_number() {
        let parsed = parse_manual_label("root: #999: #4 [pre]").unwrap();
        assert_eq!(
            parsed,
            ParsedLabel {
                config: "root: #999".to_string(),
                number: 4,
                kind: ParsedKind::Pre,
            }
        );
    }

    // --- manual builder ---

    fn journal_and_ctx() -> (Fixture, Journal) {
        let f = fixture();
        let journal = Journal::new(&f.ctx.state_dir);
        (f, journal)
    }

    #[test]
    fn test_manual_cmd_complete_pair_and_single_build_one_spec_no_skips() {
        let candidates = vec![
            Candidate::new(None, "root: #10 [pre]".to_string(), 0, Risk::Risky),
            Candidate::new(None, "root: #11 [post of #10]".to_string(), 0, Risk::Risky),
            Candidate::new(None, "root: #4".to_string(), 0, Risk::Risky),
        ];
        let (specs, skips) = manual_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert!(skips.is_empty());
        assert_eq!(
            specs,
            vec![CmdSpec {
                argv: vec![
                    "snapper".to_string(),
                    "-c".to_string(),
                    "root".to_string(),
                    "delete".to_string(),
                    "4".to_string(),
                    "10".to_string(),
                    "11".to_string(),
                ],
                sudo: true,
                label: "Delete 3 snapshot(s) from config root".to_string(),
            }]
        );
    }

    #[test]
    fn test_manual_cmd_lone_pre_refused() {
        let candidates = vec![Candidate::new(
            None,
            "root: #10 [pre]".to_string(),
            0,
            Risk::Risky,
        )];
        let (specs, skips) = manual_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert!(specs.is_empty());
        assert_eq!(skips.len(), 1);
        assert!(skips[0].0.contains("#10"));
        assert!(skips[0].1.contains("nothing was deleted for config root"));
    }

    #[test]
    fn test_manual_cmd_lone_post_refused() {
        let candidates = vec![Candidate::new(
            None,
            "root: #11 [post of #10]".to_string(),
            0,
            Risk::Risky,
        )];
        let (specs, skips) = manual_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert!(specs.is_empty());
        assert_eq!(skips.len(), 1);
        assert!(skips[0].0.contains("#11"));
        assert!(skips[0].1.contains("nothing was deleted for config root"));
    }

    #[test]
    fn test_manual_cmd_violation_in_one_config_does_not_block_another() {
        let candidates = vec![
            Candidate::new(None, "root: #10 [pre]".to_string(), 0, Risk::Risky),
            Candidate::new(None, "home: #3".to_string(), 0, Risk::Risky),
        ];
        let (specs, skips) = manual_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].argv[2], "home");
        assert_eq!(skips.len(), 1);
        assert!(skips[0].0.contains("root"));
    }

    #[test]
    fn test_manual_cmd_unparseable_label_is_skipped_never_in_argv() {
        let candidates = vec![
            Candidate::new(None, "root: #0".to_string(), 0, Risk::Risky),
            Candidate::new(None, "garbage".to_string(), 0, Risk::Risky),
        ];
        let (specs, skips) = manual_cmd(&fixture().ctx, &Config::default(), &candidates);
        assert!(specs.is_empty());
        assert_eq!(skips.len(), 2);
        for spec in &specs {
            for arg in &spec.argv {
                assert_ne!(arg, "0");
            }
        }
    }

    // --- end-to-end seam ---

    #[test]
    fn test_execute_selected_manual_rule_refusal_journals_and_surfaces_as_note() {
        let (f, journal) = journal_and_ctx();
        let group = crate::core::item::Group {
            rule_id: "snapshots.snapper_manual".to_string(),
            title: "Snapper snapshots (manual delete)".to_string(),
            risk: Risk::Risky,
            requires_sudo: true,
            candidates: vec![Candidate::new(
                None,
                "root: #10 [pre]".to_string(),
                0,
                Risk::Risky,
            )],
            skipped: Vec::new(),
        };
        let mut effector = DryRunEffector;
        let selection: StdHashSet<(usize, usize)> = StdHashSet::from([(0usize, 0usize)]);

        let summary = execute_selected(
            &[group],
            &selection,
            &rules(),
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 1);
        let (_, _, notes) = crate::commands::shared::summarize_run(&journal, "run-1").unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("skipped:"));
    }

    // Regression seam: a builder-refused config (unpaired pre) sits alongside
    // a config whose selection *does* build a real (sudo) CmdSpec. In a
    // sandboxed ctx that spec must flow through `RealEffector`'s existing
    // "sudo is never run in a sandbox" behavior, exactly like every other
    // sudo `Cmd`/`CmdSelected` rule — this rule gets no special case.
    #[test]
    fn test_execute_selected_manual_rule_sudo_spec_is_skipped_in_sandbox_alongside_a_refusal() {
        let (f, journal) = journal_and_ctx();
        assert!(f.ctx.sandboxed);
        let group = crate::core::item::Group {
            rule_id: "snapshots.snapper_manual".to_string(),
            title: "Snapper snapshots (manual delete)".to_string(),
            risk: Risk::Risky,
            requires_sudo: true,
            candidates: vec![
                Candidate::new(None, "root: #10 [pre]".to_string(), 0, Risk::Risky),
                Candidate::new(None, "home: #3".to_string(), 0, Risk::Risky),
            ],
            skipped: Vec::new(),
        };
        let mut effector = crate::core::exec::RealEffector::new(
            &f.ctx,
            Box::new(crate::core::runner::FakeRunner::new()),
        );
        let selection: StdHashSet<(usize, usize)> =
            StdHashSet::from([(0usize, 0usize), (0usize, 1usize)]);

        let summary = execute_selected(
            &[group],
            &selection,
            &rules(),
            &f.ctx,
            &f.ctx.config.clone(),
            &mut effector,
            &journal,
            "run-1",
            false,
        )
        .unwrap();

        assert_eq!(summary.actions, 2);
        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.outcome.contains("#10")));
        assert!(
            records
                .iter()
                .any(|r| r.outcome == "skipped: sudo is never run in a sandbox")
        );
        let (_, _, notes) = crate::commands::shared::summarize_run(&journal, "run-1").unwrap();
        assert_eq!(notes.len(), 2);
    }
}
