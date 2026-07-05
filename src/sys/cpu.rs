//! CPU time accounting (`/proc/stat`) and load average (`/proc/loadavg`).
//!
//! CPU usage is not a point-in-time value: it's derived from the delta of
//! two counter samples, so this module hands back raw counters
//! (`CpuSample`) and a pure `cpu_percent` function that turns a pair of
//! samples into percentages.

use crate::ctx::Ctx;

/// Raw jiffie counters for one CPU line of `/proc/stat` (the aggregate
/// `cpu` line or one `cpuN` line). `guest`/`guest_nice` are deliberately not
/// stored: the kernel already folds them into `user`/`nice`, so counting
/// them again would double-count.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CoreTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CoreTimes {
    fn idle_all(&self) -> u64 {
        self.idle + self.iowait
    }

    fn non_idle(&self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq + self.steal
    }

    fn total(&self) -> u64 {
        self.idle_all() + self.non_idle()
    }
}

/// One sample of `/proc/stat`'s CPU lines: the aggregate `cpu` line plus
/// each individual `cpuN` line, in the order they appeared.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CpuSample {
    pub total: CoreTimes,
    pub cores: Vec<CoreTimes>,
}

/// Parses one `cpu`/`cpuN` line's fields (after the label) into
/// `CoreTimes`. Tolerates missing trailing fields (treated as 0) and
/// ignores extra ones (`guest`, `guest_nice`, or future additions).
fn parse_core_times(fields: &[&str]) -> CoreTimes {
    let field = |i: usize| fields.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
    CoreTimes {
        user: field(0),
        nice: field(1),
        system: field(2),
        idle: field(3),
        iowait: field(4),
        irq: field(5),
        softirq: field(6),
        steal: field(7),
    }
}

/// Parses the CPU lines of a `/proc/stat`-style text into a `CpuSample`.
/// Stops at the first line that isn't `cpu`/`cpuN` (`intr`, `ctxt`, ...).
/// A missing or malformed `cpu` line yields a zeroed sample rather than an
/// error — callers just see 0% until a real sample lands.
pub fn parse_stat(text: &str) -> CpuSample {
    let mut sample = CpuSample::default();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(label) = fields.next() else {
            continue;
        };
        if label == "cpu" {
            sample.total = parse_core_times(&fields.collect::<Vec<_>>());
        } else if let Some(rest) = label.strip_prefix("cpu")
            && !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_digit())
        {
            sample
                .cores
                .push(parse_core_times(&fields.collect::<Vec<_>>()));
        } else {
            break;
        }
    }
    sample
}

/// Reads and parses `<root>/proc/stat`.
pub fn read_cpu_sample(ctx: &Ctx) -> anyhow::Result<CpuSample> {
    let text = std::fs::read_to_string(ctx.root.join("proc/stat"))?;
    Ok(parse_stat(&text))
}

/// Percent busy over the interval between `prev` and `curr`, aggregate
/// first followed by one entry per core (paired by position — hot-plugged
/// cores between samples aren't handled). Each value is clamped to
/// `0.0..=100.0`; a zero-length delta (identical samples, or a clock that
/// didn't advance) reports 0.0 rather than dividing by zero.
pub fn cpu_percent(prev: &CpuSample, curr: &CpuSample) -> Vec<f64> {
    let percent_of = |prev: &CoreTimes, curr: &CoreTimes| -> f64 {
        let total_delta = curr.total().saturating_sub(prev.total());
        if total_delta == 0 {
            return 0.0;
        }
        let busy_delta = curr.non_idle().saturating_sub(prev.non_idle());
        (busy_delta as f64 * 100.0 / total_delta as f64).clamp(0.0, 100.0)
    };

    let mut out = vec![percent_of(&prev.total, &curr.total)];
    out.extend(
        prev.cores
            .iter()
            .zip(curr.cores.iter())
            .map(|(p, c)| percent_of(p, c)),
    );
    out
}

/// One-minute/five-minute/fifteen-minute load averages from `/proc/loadavg`.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

/// Parses `/proc/loadavg`'s first three whitespace-separated fields.
/// Missing or unparseable fields default to `0.0`.
pub fn parse_loadavg(text: &str) -> LoadAvg {
    let mut fields = text.split_whitespace();
    let mut next = || fields.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    LoadAvg {
        one: next(),
        five: next(),
        fifteen: next(),
    }
}

/// Reads and parses `<root>/proc/loadavg`.
pub fn read_loadavg(ctx: &Ctx) -> anyhow::Result<LoadAvg> {
    let text = std::fs::read_to_string(ctx.root.join("proc/loadavg"))?;
    Ok(parse_loadavg(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;

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

    // --- parse_stat ---

    #[test]
    fn test_parse_stat_reads_aggregate_and_per_core_lines() {
        let text = "\
cpu  100 10 20 800 5 1 2 0 0 0
cpu0 50 5 10 400 2 1 1 0 0 0
cpu1 50 5 10 400 3 0 1 0 0 0
intr 12345 0 0
ctxt 6789
";
        let sample = parse_stat(text);
        assert_eq!(
            sample.total,
            CoreTimes {
                user: 100,
                nice: 10,
                system: 20,
                idle: 800,
                iowait: 5,
                irq: 1,
                softirq: 2,
                steal: 0,
            }
        );
        assert_eq!(sample.cores.len(), 2);
        assert_eq!(sample.cores[0].user, 50);
        assert_eq!(sample.cores[1].iowait, 3);
    }

    #[test]
    fn test_parse_stat_tolerates_missing_trailing_fields() {
        let text = "cpu  100 10 20 800\ncpu0 50 5 10 400\n";
        let sample = parse_stat(text);
        assert_eq!(sample.total.idle, 800);
        assert_eq!(sample.total.irq, 0);
        assert_eq!(sample.total.steal, 0);
    }

    #[test]
    fn test_parse_stat_ignores_extra_guest_fields() {
        let text = "cpu  100 10 20 800 5 1 2 0 999 999\n";
        let sample = parse_stat(text);
        assert_eq!(sample.total.steal, 0);
        // guest/guest_nice (999, 999) must not leak into any tracked field.
        assert_eq!(sample.total.user, 100);
    }

    #[test]
    fn test_parse_stat_empty_text_yields_zeroed_sample() {
        let sample = parse_stat("");
        assert_eq!(sample, CpuSample::default());
    }

    #[test]
    fn test_parse_stat_stops_at_first_non_cpu_line() {
        let text = "cpu 1 1 1 1\nintr 1 2 3\ncpu9999 1 1 1 1\n";
        let sample = parse_stat(text);
        assert_eq!(sample.cores.len(), 0);
    }

    // --- cpu_percent ---

    #[test]
    fn test_cpu_percent_computes_exact_busy_fraction() {
        // total delta = 1000, busy delta (user+nice+system+irq+softirq+steal)
        // = 250 -> 25%.
        let prev = CpuSample {
            total: CoreTimes {
                user: 100,
                nice: 0,
                system: 0,
                idle: 900,
                iowait: 0,
                irq: 0,
                softirq: 0,
                steal: 0,
            },
            cores: vec![],
        };
        let curr = CpuSample {
            total: CoreTimes {
                user: 300,
                nice: 0,
                system: 50,
                idle: 1650,
                iowait: 0,
                irq: 0,
                softirq: 0,
                steal: 0,
            },
            cores: vec![],
        };
        let got = cpu_percent(&prev, &curr);
        assert_eq!(got, vec![25.0]);
    }

    #[test]
    fn test_cpu_percent_per_core_paired_by_position() {
        let core = |user: u64, idle: u64| CoreTimes {
            user,
            idle,
            ..Default::default()
        };
        let prev = CpuSample {
            total: CoreTimes::default(),
            cores: vec![core(0, 100), core(0, 100)],
        };
        let curr = CpuSample {
            total: CoreTimes::default(),
            cores: vec![core(50, 150), core(0, 200)],
        };
        let got = cpu_percent(&prev, &curr);
        // core0: busy delta 50, total delta 100 -> 50%; core1: 0%.
        assert_eq!(got, vec![0.0, 50.0, 0.0]);
    }

    #[test]
    fn test_cpu_percent_zero_delta_is_zero_not_a_panic() {
        let sample = CpuSample {
            total: CoreTimes {
                user: 100,
                idle: 200,
                ..Default::default()
            },
            cores: vec![],
        };
        let got = cpu_percent(&sample, &sample);
        assert_eq!(got, vec![0.0]);
    }

    #[test]
    fn test_cpu_percent_clamps_to_100_on_a_counter_rollback() {
        // curr has less idle than prev but the same busy time: a corrupt or
        // rolled-back counter must not produce a value above 100 or panic.
        let prev = CoreTimes {
            user: 100,
            idle: 900,
            ..Default::default()
        };
        let curr = CoreTimes {
            user: 100,
            idle: 100,
            ..Default::default()
        };
        let prev_sample = CpuSample {
            total: prev,
            cores: vec![],
        };
        let curr_sample = CpuSample {
            total: curr,
            cores: vec![],
        };
        let got = cpu_percent(&prev_sample, &curr_sample);
        assert_eq!(got, vec![0.0]);
    }

    // --- read_cpu_sample ---

    #[test]
    fn test_read_cpu_sample_reads_through_ctx_root() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc")).unwrap();
        std::fs::write(
            ctx.root.join("proc/stat"),
            "cpu  1 2 3 4 5 6 7 8\ncpu0 1 2 3 4 5 6 7 8\n",
        )
        .unwrap();

        let sample = read_cpu_sample(&ctx).unwrap();
        assert_eq!(sample.total.user, 1);
        assert_eq!(sample.cores.len(), 1);
    }

    #[test]
    fn test_read_cpu_sample_missing_file_is_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert!(read_cpu_sample(&ctx).is_err());
    }

    // --- parse_loadavg / read_loadavg ---

    #[test]
    fn test_parse_loadavg_reads_first_three_fields() {
        let got = parse_loadavg("0.52 0.58 0.59 1/523 12345\n");
        assert_eq!(
            got,
            LoadAvg {
                one: 0.52,
                five: 0.58,
                fifteen: 0.59,
            }
        );
    }

    #[test]
    fn test_parse_loadavg_missing_fields_default_to_zero() {
        let got = parse_loadavg("1.0\n");
        assert_eq!(
            got,
            LoadAvg {
                one: 1.0,
                five: 0.0,
                fifteen: 0.0,
            }
        );
    }

    #[test]
    fn test_read_loadavg_reads_through_ctx_root() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc")).unwrap();
        std::fs::write(ctx.root.join("proc/loadavg"), "1.5 2.5 3.5 1/2 99\n").unwrap();

        let got = read_loadavg(&ctx).unwrap();
        assert_eq!(got.one, 1.5);
        assert_eq!(got.fifteen, 3.5);
    }
}
