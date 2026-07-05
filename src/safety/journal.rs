use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Record {
    pub ts: String,
    pub run_id: String,
    pub cmd: String,
    pub rule: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    pub sudo: bool,
    pub dry_run: bool,
    pub bytes_freed: u64,
    pub outcome: String,
}

impl Record {
    #[allow(clippy::too_many_arguments)]
    pub fn now(
        run_id: String,
        cmd: String,
        rule: String,
        action: String,
        argv: Option<Vec<String>>,
        paths: Option<Vec<String>>,
        sudo: bool,
        dry_run: bool,
        bytes_freed: u64,
        outcome: String,
    ) -> Record {
        Record {
            ts: jiff::Timestamp::now().to_string(),
            run_id,
            cmd,
            rule,
            action,
            argv,
            paths,
            sudo,
            dry_run,
            bytes_freed,
            outcome,
        }
    }
}

pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn new(state_dir: &Path) -> Journal {
        Journal {
            path: state_dir.join("history.jsonl"),
        }
    }

    /// Appends `record`; a failed audit-trail write must not fail the
    /// caller's action, so it's reported to stderr instead of propagated.
    pub fn append_or_warn(&self, record: &Record) {
        if let Err(e) = self.append(record) {
            eprintln!("warning: failed to record audit trail: {e:#}");
        }
    }

    pub fn append(&self, r: &Record) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open {}", self.path.display()))?;
        let line = serde_json::to_string(r).context("failed to serialize history record")?;
        writeln!(file, "{line}").with_context(|| format!("failed to write {}", self.path.display()))
    }

    pub fn read_all(&self) -> anyhow::Result<(Vec<Record>, usize)> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => {
                return Err(e).with_context(|| format!("failed to read {}", self.path.display()));
            }
        };

        let mut records = Vec::new();
        let mut skipped = 0;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(line) {
                Ok(record) => records.push(record),
                Err(_) => skipped += 1,
            }
        }
        Ok((records, skipped))
    }

    pub fn rotate_if_needed(&self, max_bytes: u64) -> anyhow::Result<()> {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(e).with_context(|| format!("failed to stat {}", self.path.display()));
            }
        };
        if metadata.len() <= max_bytes {
            return Ok(());
        }
        let rotated = self.path.with_file_name("history.1.jsonl");
        std::fs::rename(&self.path, &rotated).with_context(|| {
            format!(
                "failed to rotate {} to {}",
                self.path.display(),
                rotated.display()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(run_id: &str) -> Record {
        Record {
            ts: "2026-01-02T03:04:05Z".to_string(),
            run_id: run_id.to_string(),
            cmd: "clean".to_string(),
            rule: "paccache".to_string(),
            action: "delete".to_string(),
            argv: None,
            paths: None,
            sudo: false,
            dry_run: false,
            bytes_freed: 1024,
            outcome: "ok".to_string(),
        }
    }

    #[test]
    fn test_record_now_stamps_a_parseable_timestamp() {
        let record = Record::now(
            "run-1".to_string(),
            "clean".to_string(),
            "paccache".to_string(),
            "delete".to_string(),
            None,
            None,
            false,
            false,
            0,
            "ok".to_string(),
        );
        record.ts.parse::<jiff::Timestamp>().unwrap();
    }

    #[test]
    fn test_append_then_read_all_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        let record = sample("run-1");
        journal.append(&record).unwrap();

        let (records, skipped) = journal.read_all().unwrap();
        assert_eq!(records, vec![record]);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn test_append_twice_preserves_order() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        journal.append(&sample("run-1")).unwrap();
        journal.append(&sample("run-2")).unwrap();

        let (records, _) = journal.read_all().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].run_id, "run-1");
        assert_eq!(records[1].run_id, "run-2");
    }

    #[test]
    fn test_read_all_on_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        let (records, skipped) = journal.read_all().unwrap();
        assert!(records.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn test_read_all_skips_corrupt_lines_but_counts_them() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        journal.append(&sample("run-1")).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("history.jsonl"))
            .unwrap()
            .write_all(b"not json\n")
            .unwrap();
        journal.append(&sample("run-2")).unwrap();

        let (records, skipped) = journal.read_all().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn test_rotate_if_needed_leaves_small_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        journal.append(&sample("run-1")).unwrap();

        journal.rotate_if_needed(1024 * 1024).unwrap();

        assert!(dir.path().join("history.jsonl").exists());
        assert!(!dir.path().join("history.1.jsonl").exists());
    }

    #[test]
    fn test_rotate_if_needed_renames_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        journal.append(&sample("run-1")).unwrap();

        journal.rotate_if_needed(1).unwrap();

        assert!(!dir.path().join("history.jsonl").exists());
        assert!(dir.path().join("history.1.jsonl").exists());
    }
}
