//! Disk IO rates (`/proc/diskstats`) and root-filesystem fill level (via
//! `analyze::disk`, reused rather than re-implemented).
//!
//! Like CPU, IO throughput is a delta of two counter samples: this module
//! hands back raw per-device sector counts (`DiskSample`) and a pure
//! `disk_rates` function over a pair of samples plus the elapsed interval.

use crate::analyze::disk::{self, DiskTotals};
use crate::ctx::Ctx;

const SECTOR_BYTES: u64 = 512;

/// Raw sector counters for one block device.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceStat {
    pub name: String,
    pub sectors_read: u64,
    pub sectors_written: u64,
}

/// A full `/proc/diskstats` sample: one `DeviceStat` per physical device,
/// in file order.
pub type DiskSample = Vec<DeviceStat>;

/// True when `name` is a partition of some other device already present in
/// `names` (e.g. `sda1` is a partition of `sda`, `nvme0n1p1` of `nvme0n1`).
/// This is deliberately a string check rather than a sysfs lookup: it's
/// "simple and documented", not exhaustive — an unusual naming scheme could
/// slip through as its own device.
fn is_partition_of_counted(name: &str, names: &[String]) -> bool {
    names.iter().any(|other| {
        other != name && name.starts_with(other.as_str()) && {
            let suffix = &name[other.len()..];
            let digits = suffix.strip_prefix('p').unwrap_or(suffix);
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
    })
}

/// Parses `/proc/diskstats`, keeping physical devices: `loop*` is always
/// skipped, and a device is skipped when it's a partition of another device
/// also present in the file. `zram*` devices are kept — they're not
/// partitions of anything.
pub fn parse_diskstats(text: &str) -> DiskSample {
    // Field layout (0-indexed after splitting on whitespace): 0 major,
    // 1 minor, 2 name, 3 rd_ios, 4 rd_merges, 5 rd_sectors, 6 rd_ticks,
    // 7 wr_ios, 8 wr_merges, 9 wr_sectors, 10 wr_ticks, ... (discard/flush
    // fields on newer kernels, ignored here).
    let mut rows: Vec<(String, u64, u64)> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let name = fields[2].to_string();
        let Ok(rd_sectors) = fields[5].parse::<u64>() else {
            continue;
        };
        let Ok(wr_sectors) = fields[9].parse::<u64>() else {
            continue;
        };
        rows.push((name, rd_sectors, wr_sectors));
    }

    let names: Vec<String> = rows.iter().map(|(n, _, _)| n.clone()).collect();
    rows.into_iter()
        .filter(|(name, _, _)| !name.starts_with("loop"))
        .filter(|(name, _, _)| !is_partition_of_counted(name, &names))
        .map(|(name, sectors_read, sectors_written)| DeviceStat {
            name,
            sectors_read,
            sectors_written,
        })
        .collect()
}

/// Reads and parses `<root>/proc/diskstats`.
pub fn read_diskstats(ctx: &Ctx) -> anyhow::Result<DiskSample> {
    let text = std::fs::read_to_string(ctx.root.join("proc/diskstats"))?;
    Ok(parse_diskstats(&text))
}

/// Bytes/sec read and written for one device over the sampled interval.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRate {
    pub name: String,
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
}

/// Byte-per-second read/write rates for every device present in both
/// `prev` and `curr` (a device that appeared or disappeared between
/// samples — e.g. a plugged-in USB drive — is skipped rather than
/// guessed at). `interval_secs <= 0.0` reports 0.0 for every device rather
/// than dividing by zero.
pub fn disk_rates(prev: &DiskSample, curr: &DiskSample, interval_secs: f64) -> Vec<DeviceRate> {
    curr.iter()
        .filter_map(|c| {
            let p = prev.iter().find(|p| p.name == c.name)?;
            let rate = |prev_sectors: u64, curr_sectors: u64| -> f64 {
                if interval_secs <= 0.0 {
                    return 0.0;
                }
                let delta = curr_sectors.saturating_sub(prev_sectors);
                (delta * SECTOR_BYTES) as f64 / interval_secs
            };
            Some(DeviceRate {
                name: c.name.clone(),
                read_bytes_per_sec: rate(p.sectors_read, c.sectors_read),
                write_bytes_per_sec: rate(p.sectors_written, c.sectors_written),
            })
        })
        .collect()
}

/// Disk-space totals for the root filesystem, reusing
/// `analyze::disk::disk_totals` (which already handles the btrfs-aware
/// unallocated-space case).
pub fn root_fill(ctx: &Ctx) -> anyhow::Result<DiskTotals> {
    disk::disk_totals(ctx, &ctx.root)
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

    const FIXTURE: &str = "\
   8       0 sda 1470 11721 138716 32265 6 3 18 77 0 6823 32419 0 0 0 0 4 76
   8       1 sda1 1405 11721 127764 31872 6 3 18 77 0 6495 31949 0 0 0 0 0 0
 259       0 nvme0n1 49385 11936 5868807 11813 323461 10808 16818447 14969421 0 19463 15705929 11975 0 12400984 721434 4161 3260
 259       1 nvme0n1p1 100 0 200 0 5 0 300 0 0 0 0 0 0 0 0 0 0
   7       0 loop0 10 0 200 0 0 0 0 0 0 0 0
 253       0 zram0 500 0 4000 0 200 0 8000 0 0 0 0
";

    // --- parse_diskstats ---

    #[test]
    fn test_parse_diskstats_keeps_whole_disks_and_zram_skips_partitions_and_loop() {
        let got = parse_diskstats(FIXTURE);
        let names: Vec<&str> = got.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["sda", "nvme0n1", "zram0"]);
    }

    #[test]
    fn test_parse_diskstats_reads_sector_counts() {
        let got = parse_diskstats(FIXTURE);
        let sda = got.iter().find(|d| d.name == "sda").unwrap();
        assert_eq!(sda.sectors_read, 138716);
        assert_eq!(sda.sectors_written, 18);
    }

    #[test]
    fn test_parse_diskstats_ignores_short_or_malformed_lines() {
        let text = "not a diskstats line\n   8 0 sda 1 2\n";
        assert_eq!(parse_diskstats(text), vec![]);
    }

    #[test]
    fn test_parse_diskstats_empty_text_is_empty() {
        assert_eq!(parse_diskstats(""), vec![]);
    }

    // --- disk_rates ---

    #[test]
    fn test_disk_rates_computes_exact_bytes_per_sec() {
        let prev = vec![DeviceStat {
            name: "sda".to_string(),
            sectors_read: 1000,
            sectors_written: 2000,
        }];
        let curr = vec![DeviceStat {
            name: "sda".to_string(),
            sectors_read: 1100,
            sectors_written: 2500,
        }];
        // read delta 100 sectors * 512 = 51200 bytes / 2s = 25600 B/s
        // write delta 500 sectors * 512 = 256000 bytes / 2s = 128000 B/s
        let got = disk_rates(&prev, &curr, 2.0);
        assert_eq!(
            got,
            vec![DeviceRate {
                name: "sda".to_string(),
                read_bytes_per_sec: 25600.0,
                write_bytes_per_sec: 128000.0,
            }]
        );
    }

    #[test]
    fn test_disk_rates_skips_devices_not_in_both_samples() {
        let prev = vec![DeviceStat {
            name: "sda".to_string(),
            sectors_read: 0,
            sectors_written: 0,
        }];
        let curr = vec![
            DeviceStat {
                name: "sda".to_string(),
                sectors_read: 10,
                sectors_written: 0,
            },
            DeviceStat {
                name: "sdb".to_string(),
                sectors_read: 10,
                sectors_written: 0,
            },
        ];
        let got = disk_rates(&prev, &curr, 1.0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "sda");
    }

    #[test]
    fn test_disk_rates_zero_interval_is_zero_not_a_panic() {
        let prev = vec![DeviceStat {
            name: "sda".to_string(),
            sectors_read: 0,
            sectors_written: 0,
        }];
        let curr = vec![DeviceStat {
            name: "sda".to_string(),
            sectors_read: 100,
            sectors_written: 100,
        }];
        let got = disk_rates(&prev, &curr, 0.0);
        assert_eq!(got[0].read_bytes_per_sec, 0.0);
        assert_eq!(got[0].write_bytes_per_sec, 0.0);
    }

    // --- read_diskstats / root_fill ---

    #[test]
    fn test_read_diskstats_reads_through_ctx_root() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc")).unwrap();
        std::fs::write(ctx.root.join("proc/diskstats"), FIXTURE).unwrap();

        let got = read_diskstats(&ctx).unwrap();
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn test_read_diskstats_missing_file_is_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert!(read_diskstats(&ctx).is_err());
    }

    #[test]
    fn test_root_fill_reads_ctx_root_filesystem() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(&ctx.root).unwrap();
        std::fs::create_dir_all(ctx.root.join("proc/self")).unwrap();
        std::fs::write(
            ctx.root.join("proc/self/mounts"),
            format!("/dev/fake0 {} ext4 rw 0 0\n", ctx.root.display()),
        )
        .unwrap();

        let got = root_fill(&ctx).unwrap();
        assert_eq!(got.fs_kind, "ext4");
        assert!(got.total > 0);
    }
}
