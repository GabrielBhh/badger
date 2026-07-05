//! Memory and swap totals from `/proc/meminfo`.

use crate::ctx::Ctx;

/// Memory/swap sizes in bytes, taken from `/proc/meminfo`'s kB fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct MemInfo {
    pub total: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

/// Parses the `MemTotal`/`MemAvailable`/`SwapTotal`/`SwapFree` lines out of
/// a `/proc/meminfo`-style text. Every `/proc/meminfo` field is reported in
/// kB regardless of unit suffix, so values are multiplied by 1024. A
/// missing field defaults to 0 rather than erroring — callers just see a
/// zeroed-out value instead of losing the whole sample.
pub fn parse_meminfo(text: &str) -> MemInfo {
    let field = |name: &str| -> u64 {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().strip_suffix("kB"))
            .and_then(|n| n.trim().parse::<u64>().ok())
            .map(|kb| kb * 1024)
            .unwrap_or(0)
    };
    MemInfo {
        total: field("MemTotal:"),
        available: field("MemAvailable:"),
        swap_total: field("SwapTotal:"),
        swap_free: field("SwapFree:"),
    }
}

/// Reads and parses `<root>/proc/meminfo`.
pub fn read_meminfo(ctx: &Ctx) -> anyhow::Result<MemInfo> {
    let text = std::fs::read_to_string(ctx.root.join("proc/meminfo"))?;
    Ok(parse_meminfo(&text))
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
MemTotal:       16384000 kB
MemFree:         8000000 kB
MemAvailable:   12000000 kB
Buffers:          100000 kB
Cached:          3000000 kB
SwapTotal:       2048000 kB
SwapFree:        1500000 kB
";

    #[test]
    fn test_parse_meminfo_reads_the_four_tracked_fields() {
        let got = parse_meminfo(FIXTURE);
        assert_eq!(
            got,
            MemInfo {
                total: 16_384_000 * 1024,
                available: 12_000_000 * 1024,
                swap_total: 2_048_000 * 1024,
                swap_free: 1_500_000 * 1024,
            }
        );
    }

    #[test]
    fn test_parse_meminfo_missing_swap_defaults_to_zero() {
        let text = "MemTotal:       16384000 kB\nMemAvailable:   12000000 kB\n";
        let got = parse_meminfo(text);
        assert_eq!(got.swap_total, 0);
        assert_eq!(got.swap_free, 0);
    }

    #[test]
    fn test_parse_meminfo_empty_text_is_all_zero() {
        assert_eq!(parse_meminfo(""), MemInfo::default());
    }

    #[test]
    fn test_read_meminfo_reads_through_ctx_root() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc")).unwrap();
        std::fs::write(ctx.root.join("proc/meminfo"), FIXTURE).unwrap();

        let got = read_meminfo(&ctx).unwrap();
        assert_eq!(got.total, 16_384_000 * 1024);
    }

    #[test]
    fn test_read_meminfo_missing_file_is_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert!(read_meminfo(&ctx).is_err());
    }
}
