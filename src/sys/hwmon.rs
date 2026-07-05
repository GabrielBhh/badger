//! Hardware temperature sensors (`/sys/class/hwmon/hwmon*/`).

use std::path::Path;

use crate::ctx::Ctx;

/// One `tempN_input` reading: its label (from `tempN_label` when present,
/// else a synthetic `tempN`) and value in Celsius.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TempReading {
    pub label: String,
    pub celsius: f64,
}

/// One hwmon chip: its name (from the `name` file) and every `tempN_input`
/// reading it exposes, ordered by `N`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HwmonChip {
    pub name: String,
    pub readings: Vec<TempReading>,
}

/// Reads one `hwmonN` directory. `None` when it has no `name` file (not a
/// real hwmon chip directory).
fn read_chip(dir: &Path) -> Option<HwmonChip> {
    let name = std::fs::read_to_string(dir.join("name"))
        .ok()?
        .trim()
        .to_string();

    let mut indices: Vec<u32> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_prefix("temp")?
                .strip_suffix("_input")?
                .parse::<u32>()
                .ok()
        })
        .collect();
    indices.sort_unstable();

    let readings = indices
        .into_iter()
        .filter_map(|n| {
            let millidegrees: i64 = std::fs::read_to_string(dir.join(format!("temp{n}_input")))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            let label = std::fs::read_to_string(dir.join(format!("temp{n}_label")))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("temp{n}"));
            Some(TempReading {
                label,
                celsius: millidegrees as f64 / 1000.0,
            })
        })
        .collect();

    Some(HwmonChip { name, readings })
}

/// Reads every chip under `<root>/sys/class/hwmon`. An absent directory (no
/// hwmon support at all) yields an empty list rather than an error.
pub fn read_hwmon(ctx: &Ctx) -> Vec<HwmonChip> {
    let Ok(entries) = std::fs::read_dir(ctx.root.join("sys/class/hwmon")) else {
        return Vec::new();
    };
    let mut dirs: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    dirs.sort();
    dirs.iter().filter_map(|d| read_chip(d)).collect()
}

/// The single hottest labeled reading across every chip, or `None` when
/// there are no readings at all.
pub fn hottest(chips: &[HwmonChip]) -> Option<(String, f64)> {
    chips
        .iter()
        .flat_map(|c| c.readings.iter().map(|r| (r.label.clone(), r.celsius)))
        .max_by(|a, b| a.1.total_cmp(&b.1))
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

    fn write_chip(base: &Path, hwmon_dir: &str, name: &str, temps: &[(u32, i64, Option<&str>)]) {
        let dir = base.join("sys/class/hwmon").join(hwmon_dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("name"), name).unwrap();
        for (n, millidegrees, label) in temps {
            std::fs::write(dir.join(format!("temp{n}_input")), millidegrees.to_string()).unwrap();
            if let Some(label) = label {
                std::fs::write(dir.join(format!("temp{n}_label")), label).unwrap();
            }
        }
    }

    #[test]
    fn test_read_hwmon_reads_name_and_labeled_temps() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_chip(
            &ctx.root,
            "hwmon0",
            "coretemp",
            &[(1, 45000, Some("Package id 0")), (2, 42000, Some("Core 0"))],
        );

        let chips = read_hwmon(&ctx);
        assert_eq!(chips.len(), 1);
        assert_eq!(chips[0].name, "coretemp");
        assert_eq!(
            chips[0].readings,
            vec![
                TempReading {
                    label: "Package id 0".to_string(),
                    celsius: 45.0,
                },
                TempReading {
                    label: "Core 0".to_string(),
                    celsius: 42.0,
                },
            ]
        );
    }

    #[test]
    fn test_read_hwmon_missing_label_falls_back_to_tempn() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_chip(&ctx.root, "hwmon0", "acpitz", &[(1, 27800, None)]);

        let chips = read_hwmon(&ctx);
        assert_eq!(chips[0].readings[0].label, "temp1");
        assert_eq!(chips[0].readings[0].celsius, 27.8);
    }

    #[test]
    fn test_read_hwmon_missing_directory_is_empty_not_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert_eq!(read_hwmon(&ctx), Vec::new());
    }

    #[test]
    fn test_hottest_picks_max_across_chips() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_chip(&ctx.root, "hwmon0", "coretemp", &[(1, 45000, Some("cpu"))]);
        write_chip(&ctx.root, "hwmon1", "nvme", &[(1, 62000, Some("nvme"))]);

        let chips = read_hwmon(&ctx);
        assert_eq!(hottest(&chips), Some(("nvme".to_string(), 62.0)));
    }

    #[test]
    fn test_hottest_none_when_no_readings() {
        assert_eq!(hottest(&[]), None);
    }
}
