//! Per-process CPU tracking: point-in-time samples of `/proc/<pid>/stat`
//! CPU ticks plus a rolling tracker that flags processes staying above a
//! CPU threshold for an entire sampling window ("sustained hogs").

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use crate::ctx::Ctx;

/// Linux's `sysconf(_SC_CLK_TCK)` is 100 on every architecture glibc/musl
/// support (it hasn't varied in practice for decades), so it's hardcoded
/// rather than pulling in a syscall for one constant.
const CLK_TCK: f64 = 100.0;

/// One process's CPU-tick counters and display name at a point in time.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcSample {
    pub pid: u32,
    pub name: String,
    pub utime: u64,
    pub stime: u64,
}

/// Parses `/proc/<pid>/stat`'s `comm`, `utime` (field 14), and `stime`
/// (field 15). `comm` is found between the first `(` and the *last* `)`
/// since process names can themselves contain parentheses. `None` on any
/// unexpected shape (short line, non-numeric tick fields).
fn parse_stat_ticks(text: &str) -> Option<(String, u64, u64)> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = text[open + 1..close].to_string();
    // Fields after the comm start at field 3 (state); field 14 (utime) is
    // therefore index 14-3=11, field 15 (stime) index 12.
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();
    let utime = rest.get(11)?.parse::<u64>().ok()?;
    let stime = rest.get(12)?.parse::<u64>().ok()?;
    Some((comm, utime, stime))
}

/// The process's display name: the basename of the first `cmdline`
/// argument, falling back to `/proc/<pid>/stat`'s `comm` for processes
/// with no cmdline (kernel threads).
fn process_name(dir: &Path, comm: &str) -> String {
    std::fs::read_to_string(dir.join("cmdline"))
        .ok()
        .and_then(|raw| {
            let first = raw.split('\0').find(|p| !p.is_empty())?;
            Path::new(first)
                .file_name()
                .and_then(|f| f.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| comm.to_string())
}

fn read_proc(dir: &Path, pid: u32) -> Option<ProcSample> {
    let stat_text = std::fs::read_to_string(dir.join("stat")).ok()?;
    let (comm, utime, stime) = parse_stat_ticks(&stat_text)?;
    let name = process_name(dir, &comm);
    Some(ProcSample {
        pid,
        name,
        utime,
        stime,
    })
}

/// Samples every numeric entry under `<root>/proc`, sorted by pid. A
/// process that exits mid-scan (its directory vanishes) is silently
/// skipped rather than erroring the whole sample.
pub fn sample_all(ctx: &Ctx) -> Vec<ProcSample> {
    let Ok(entries) = std::fs::read_dir(ctx.root.join("proc")) else {
        return Vec::new();
    };
    let mut out: Vec<ProcSample> = entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            read_proc(&entry.path(), pid)
        })
        .collect();
    out.sort_by_key(|s| s.pid);
    out
}

/// Accumulates successive `ProcSample` snapshots into a per-pid rolling
/// window of CPU percentages, so `sustained_hogs` can tell "briefly spiked"
/// apart from "pegged the whole window".
#[derive(Debug, Default)]
pub struct ProcCpuTracker {
    window: usize,
    last: Option<Vec<ProcSample>>,
    history: HashMap<u32, VecDeque<f64>>,
    names: HashMap<u32, String>,
}

impl ProcCpuTracker {
    /// `window` caps how many samples of history are kept per process;
    /// `sustained_hogs`'s `window_samples` must be `<= window` to ever see
    /// a full window.
    pub fn new(window: usize) -> ProcCpuTracker {
        ProcCpuTracker {
            window,
            last: None,
            history: HashMap::new(),
            names: HashMap::new(),
        }
    }

    /// Folds in a new sample. The first call only establishes the tick
    /// baseline (there's no prior sample to delta against); from the
    /// second call on, each process's CPU% for the interval is computed
    /// from its utime+stime delta and pushed onto its history, trimming to
    /// `window`. Processes absent from `sample` (exited) have their
    /// history dropped so they can never show up as a hog again.
    pub fn add_sample(&mut self, sample: Vec<ProcSample>, interval_secs: f64) {
        if let Some(prev) = &self.last {
            let prev_by_pid: HashMap<u32, &ProcSample> = prev.iter().map(|s| (s.pid, s)).collect();
            for curr in &sample {
                self.names.insert(curr.pid, curr.name.clone());
                let pct = match prev_by_pid.get(&curr.pid) {
                    Some(p) if interval_secs > 0.0 => {
                        let delta_ticks =
                            (curr.utime + curr.stime).saturating_sub(p.utime + p.stime);
                        (delta_ticks as f64 / CLK_TCK) / interval_secs * 100.0
                    }
                    _ => 0.0,
                };
                let hist = self.history.entry(curr.pid).or_default();
                hist.push_back(pct);
                while hist.len() > self.window {
                    hist.pop_front();
                }
            }
        } else {
            for curr in &sample {
                self.names.insert(curr.pid, curr.name.clone());
                self.history.entry(curr.pid).or_default();
            }
        }

        let alive: HashSet<u32> = sample.iter().map(|s| s.pid).collect();
        self.history.retain(|pid, _| alive.contains(pid));
        self.names.retain(|pid, _| alive.contains(pid));
        self.last = Some(sample);
    }

    /// Processes whose *entire* last `window_samples` of history are above
    /// `threshold_pct`, as `(pid, name, average_pct_over_the_window)`.
    /// Fewer than `window_samples` of history yet (just started tracking,
    /// or the process is new) excludes a pid rather than judging it early.
    pub fn sustained_hogs(
        &self,
        threshold_pct: f64,
        window_samples: usize,
    ) -> Vec<(u32, String, f64)> {
        let mut hogs: Vec<(u32, String, f64)> = self
            .history
            .iter()
            .filter(|(_, hist)| hist.len() >= window_samples)
            .filter_map(|(&pid, hist)| {
                let recent: Vec<f64> = hist.iter().rev().take(window_samples).copied().collect();
                if !recent.iter().all(|&p| p > threshold_pct) {
                    return None;
                }
                let avg = recent.iter().sum::<f64>() / recent.len() as f64;
                let name = self.names.get(&pid).cloned().unwrap_or_default();
                Some((pid, name, avg))
            })
            .collect();
        hogs.sort_by_key(|(pid, _, _)| *pid);
        hogs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn fixture_ctx(root: &Path) -> Ctx {
        Ctx {
            root: root.to_path_buf(),
            home: root.join("home/user"),
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            dry_run: false,
            debug: false,
            config: Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output: None,
        }
    }

    fn stat_line(pid: u32, comm: &str, utime: u64, stime: u64) -> String {
        // Real fields: pid (comm) state ppid pgrp session tty tpgid flags
        // minflt cminflt majflt cmajflt utime stime ...
        format!("{pid} ({comm}) S 1 1 1 0 -1 0 0 0 0 0 {utime} {stime} 0 0 20 0 1 0 0 0")
    }

    fn write_proc(
        root: &Path,
        pid: u32,
        comm: &str,
        utime: u64,
        stime: u64,
        cmdline: Option<&str>,
    ) {
        let dir = root.join("proc").join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stat"), stat_line(pid, comm, utime, stime)).unwrap();
        if let Some(cmdline) = cmdline {
            std::fs::write(dir.join("cmdline"), cmdline.replace(' ', "\0") + "\0").unwrap();
        }
    }

    // --- parse_stat_ticks ---

    #[test]
    fn test_parse_stat_ticks_reads_comm_utime_stime() {
        let text = stat_line(123, "bash", 500, 200);
        let (comm, utime, stime) = parse_stat_ticks(&text).unwrap();
        assert_eq!(comm, "bash");
        assert_eq!(utime, 500);
        assert_eq!(stime, 200);
    }

    #[test]
    fn test_parse_stat_ticks_handles_parens_in_comm() {
        let text = stat_line(1, "some (weird) name", 1, 2);
        let (comm, _, _) = parse_stat_ticks(&text).unwrap();
        assert_eq!(comm, "some (weird) name");
    }

    #[test]
    fn test_parse_stat_ticks_short_line_is_none() {
        assert_eq!(parse_stat_ticks("123 (bash) S 1 1"), None);
    }

    // --- sample_all ---

    #[test]
    fn test_sample_all_uses_cmdline_basename_when_present() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_proc(
            &ctx.root,
            42,
            "python3",
            10,
            5,
            Some("/usr/bin/python3 script.py"),
        );

        let samples = sample_all(&ctx);
        assert_eq!(
            samples,
            vec![ProcSample {
                pid: 42,
                name: "python3".to_string(),
                utime: 10,
                stime: 5,
            }]
        );
    }

    #[test]
    fn test_sample_all_falls_back_to_comm_without_cmdline() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_proc(&ctx.root, 2, "kthreadd", 0, 0, None);

        let samples = sample_all(&ctx);
        assert_eq!(samples[0].name, "kthreadd");
    }

    #[test]
    fn test_sample_all_ignores_non_pid_entries() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc/self")).unwrap();
        write_proc(&ctx.root, 1, "init", 0, 0, None);

        let samples = sample_all(&ctx);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].pid, 1);
    }

    #[test]
    fn test_sample_all_missing_proc_dir_is_empty() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert_eq!(sample_all(&ctx), Vec::new());
    }

    // --- ProcCpuTracker ---

    fn sample(pid: u32, name: &str, utime: u64, stime: u64) -> ProcSample {
        ProcSample {
            pid,
            name: name.to_string(),
            utime,
            stime,
        }
    }

    #[test]
    fn test_first_sample_establishes_baseline_with_no_history_yet() {
        let mut tracker = ProcCpuTracker::new(5);
        tracker.add_sample(vec![sample(1, "hog", 0, 0)], 1.0);
        assert_eq!(tracker.sustained_hogs(0.0, 1), Vec::new());
    }

    #[test]
    fn test_add_sample_computes_exact_cpu_percent_from_tick_delta() {
        // 100 ticks/sec CLK_TCK: 50 ticks delta over 1s interval = 50%.
        let mut tracker = ProcCpuTracker::new(5);
        tracker.add_sample(vec![sample(1, "hog", 0, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 30, 20)], 1.0);

        let hogs = tracker.sustained_hogs(0.0, 1);
        assert_eq!(hogs, vec![(1, "hog".to_string(), 50.0)]);
    }

    #[test]
    fn test_sustained_hogs_requires_the_whole_window_above_threshold() {
        let mut tracker = ProcCpuTracker::new(5);
        tracker.add_sample(vec![sample(1, "hog", 0, 0)], 1.0);
        // 90% for two samples, then drops to 10%: not sustained over a
        // 3-sample window.
        tracker.add_sample(vec![sample(1, "hog", 90, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 180, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 190, 0)], 1.0);

        assert_eq!(tracker.sustained_hogs(50.0, 3), Vec::new());
    }

    #[test]
    fn test_sustained_hogs_reports_process_above_threshold_for_whole_window() {
        let mut tracker = ProcCpuTracker::new(5);
        tracker.add_sample(vec![sample(1, "hog", 0, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 90, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 180, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 270, 0)], 1.0);

        let hogs = tracker.sustained_hogs(50.0, 3);
        assert_eq!(hogs, vec![(1, "hog".to_string(), 90.0)]);
    }

    #[test]
    fn test_sustained_hogs_excludes_process_with_too_little_history() {
        let mut tracker = ProcCpuTracker::new(5);
        tracker.add_sample(vec![sample(1, "hog", 0, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 90, 0)], 1.0);

        assert_eq!(tracker.sustained_hogs(50.0, 3), Vec::new());
    }

    #[test]
    fn test_history_trims_to_window_size() {
        let mut tracker = ProcCpuTracker::new(2);
        tracker.add_sample(vec![sample(1, "hog", 0, 0)], 1.0);
        for i in 1..=5u64 {
            tracker.add_sample(vec![sample(1, "hog", i * 90, 0)], 1.0);
        }
        // Only the last 2 samples survive; both are 90% -> still a hog
        // over a 2-sample window.
        assert_eq!(tracker.sustained_hogs(50.0, 2).len(), 1);
        assert_eq!(tracker.sustained_hogs(50.0, 3), Vec::new());
    }

    #[test]
    fn test_exited_process_disappears_from_history() {
        let mut tracker = ProcCpuTracker::new(5);
        tracker.add_sample(vec![sample(1, "hog", 0, 0)], 1.0);
        tracker.add_sample(vec![sample(1, "hog", 90, 0)], 1.0);
        // pid 1 is gone from this sample.
        tracker.add_sample(vec![sample(2, "other", 0, 0)], 1.0);

        assert_eq!(tracker.sustained_hogs(0.0, 1), Vec::new());
    }
}
