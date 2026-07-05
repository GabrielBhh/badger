use std::path::Path;

use crate::output::{self, Mode};
use crate::safety::journal::{Journal, Record};

pub fn run(state_dir: &Path, run_filter: Option<&str>, mode: Mode) -> anyhow::Result<()> {
    let journal = Journal::new(state_dir);
    let (records, _skipped) = journal.read_all()?;

    match mode {
        Mode::Json => {
            for record in &records {
                if let Some(filter) = run_filter
                    && record.run_id != filter
                {
                    continue;
                }
                println!("{}", serde_json::to_string(record)?);
            }
        }
        Mode::Human => println!("{}", render(&records, run_filter)),
    }
    Ok(())
}

fn render(records: &[Record], run_filter: Option<&str>) -> String {
    if records.is_empty() {
        return "No operations recorded yet.".to_string();
    }

    let mut run_order: Vec<&str> = Vec::new();
    for record in records {
        if !run_order.contains(&record.run_id.as_str()) {
            run_order.push(&record.run_id);
        }
    }

    let mut out = String::new();
    for run_id in run_order {
        if let Some(filter) = run_filter
            && run_id != filter
        {
            continue;
        }
        let run_records: Vec<&Record> = records.iter().filter(|r| r.run_id == run_id).collect();
        let first = run_records[0];
        let date = first.ts.split('T').next().unwrap_or(&first.ts);
        let dry_run_marker = if first.dry_run { "  [dry-run]" } else { "" };
        out.push_str(&format!(
            "{date}  {}  run {run_id}{dry_run_marker}\n",
            first.cmd
        ));
        for record in &run_records {
            out.push_str(&format!(
                "  {}  {}  {}\n",
                record.rule,
                output::humanize_bytes(record.bytes_freed),
                record.outcome
            ));
            if run_filter.is_some() {
                if let Some(argv) = &record.argv {
                    out.push_str(&format!("    argv: {}\n", argv.join(" ")));
                }
                if let Some(paths) = &record.paths {
                    out.push_str(&format!("    paths: {}\n", paths.join(", ")));
                }
            }
        }
    }
    out.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(run_id: &str, cmd: &str, rule: &str, bytes: u64, dry_run: bool) -> Record {
        Record {
            ts: "2026-01-02T03:04:05Z".to_string(),
            run_id: run_id.to_string(),
            cmd: cmd.to_string(),
            rule: rule.to_string(),
            action: "delete".to_string(),
            argv: Some(vec!["badger".to_string(), "clean".to_string()]),
            paths: Some(vec!["/home/user/.cache/foo".to_string()]),
            sudo: false,
            dry_run,
            bytes_freed: bytes,
            outcome: "ok".to_string(),
        }
    }

    #[test]
    fn test_render_empty_shows_no_operations() {
        assert_eq!(render(&[], None), "No operations recorded yet.");
    }

    #[test]
    fn test_render_groups_two_runs_in_first_seen_order() {
        let records = vec![
            record("run-1", "clean", "paccache", 1024, false),
            record("run-2", "purge", "trash", 2048, false),
        ];
        let out = render(&records, None);
        let run1_pos = out.find("run-1").unwrap();
        let run2_pos = out.find("run-2").unwrap();
        assert!(run1_pos < run2_pos);
        assert!(out.contains("clean"));
        assert!(out.contains("purge"));
        assert!(out.contains("paccache"));
        assert!(out.contains("trash"));
    }

    #[test]
    fn test_render_shows_dry_run_marker() {
        let records = vec![record("run-1", "clean", "paccache", 1024, true)];
        let out = render(&records, None);
        assert!(out.contains("dry-run"));
    }

    #[test]
    fn test_render_run_filter_shows_full_detail() {
        let records = vec![
            record("run-1", "clean", "paccache", 1024, false),
            record("run-2", "purge", "trash", 2048, false),
        ];
        let out = render(&records, Some("run-1"));
        assert!(!out.contains("run-2"));
        assert!(out.contains("run-1"));
        assert!(out.contains("badger clean"));
        assert!(out.contains("/home/user/.cache/foo"));
    }
}
