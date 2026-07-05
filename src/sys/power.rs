//! Battery status (`/sys/class/power_supply/*`). A desktop with no battery
//! (or only peripheral batteries reporting a non-`Battery` type) is the
//! expected common case, not an error.

use crate::ctx::Ctx;

/// Charge percentage and charging state for the first `type == Battery`
/// power supply found.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Battery {
    pub capacity: u8,
    pub status: String,
}

/// Reads `<root>/sys/class/power_supply/*`, returning the first entry whose
/// `type` file says `Battery` and which has readable `capacity`/`status`
/// files. `None` when the directory is absent, empty, or has no battery
/// entry — a desktop machine, most commonly.
pub fn read_battery(ctx: &Ctx) -> Option<Battery> {
    let Ok(entries) = std::fs::read_dir(ctx.root.join("sys/class/power_supply")) else {
        return None;
    };
    let mut dirs: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    dirs.sort();

    for dir in dirs {
        let Ok(kind) = std::fs::read_to_string(dir.join("type")) else {
            continue;
        };
        if kind.trim() != "Battery" {
            continue;
        }
        let capacity = std::fs::read_to_string(dir.join("capacity"))
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok());
        let status = std::fs::read_to_string(dir.join("status"))
            .ok()
            .map(|s| s.trim().to_string());
        if let (Some(capacity), Some(status)) = (capacity, status) {
            return Some(Battery { capacity, status });
        }
    }
    None
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

    fn write_supply(
        base: &Path,
        dir_name: &str,
        kind: &str,
        capacity: Option<&str>,
        status: Option<&str>,
    ) {
        let dir = base.join("sys/class/power_supply").join(dir_name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("type"), kind).unwrap();
        if let Some(capacity) = capacity {
            std::fs::write(dir.join("capacity"), capacity).unwrap();
        }
        if let Some(status) = status {
            std::fs::write(dir.join("status"), status).unwrap();
        }
    }

    #[test]
    fn test_read_battery_finds_battery_type_entry() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_supply(
            &ctx.root,
            "BAT0",
            "Battery",
            Some("87"),
            Some("Discharging"),
        );

        let got = read_battery(&ctx).unwrap();
        assert_eq!(
            got,
            Battery {
                capacity: 87,
                status: "Discharging".to_string(),
            }
        );
    }

    #[test]
    fn test_read_battery_skips_non_battery_type_entries() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_supply(&ctx.root, "AC", "Mains", None, None);

        assert_eq!(read_battery(&ctx), None);
    }

    #[test]
    fn test_read_battery_absent_directory_is_none_not_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert_eq!(read_battery(&ctx), None);
    }
}
