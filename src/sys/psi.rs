//! Pressure Stall Information (`/proc/pressure/{cpu,memory,io}`). Kernels
//! built without `CONFIG_PSI` don't have this directory at all, and `cpu`
//! pressure only gained a `full` line in Linux 5.13 — both are absence, not
//! error, conditions here.

use crate::ctx::Ctx;

/// One `some`/`full` line: percentage of time some/all tasks were stalled,
/// averaged over the last 10/60/300 seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
}

/// A parsed pressure file: `some` is always present when the file parses at
/// all; `full` is only present for `memory`/`io` on all kernels and for
/// `cpu` on 5.13+.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct PsiMetric {
    pub some: PsiLine,
    pub full: Option<PsiLine>,
}

/// Parses one `some`/`full` line's `avgN=value` fields (ignores `total=`).
fn parse_line(rest: &str) -> PsiLine {
    let field = |name: &str| -> f64 {
        rest.split_whitespace()
            .find_map(|tok| tok.strip_prefix(name))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0)
    };
    PsiLine {
        avg10: field("avg10="),
        avg60: field("avg60="),
        avg300: field("avg300="),
    }
}

/// Parses a `/proc/pressure/*`-style text. Returns `None` when there is no
/// `some` line to parse (empty or unrecognized content) — the file existing
/// but being unreadable as PSI is treated the same as it being absent.
pub fn parse_psi(text: &str) -> Option<PsiMetric> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("some ") {
            some = Some(parse_line(rest));
        } else if let Some(rest) = line.strip_prefix("full ") {
            full = Some(parse_line(rest));
        }
    }
    some.map(|some| PsiMetric { some, full })
}

/// Reads and parses `<root>/proc/pressure/<name>` (`name` is `cpu`,
/// `memory`, or `io`). `None` when the file is missing (no PSI support) or
/// unparseable.
pub fn read_psi(ctx: &Ctx, name: &str) -> Option<PsiMetric> {
    let text = std::fs::read_to_string(ctx.root.join("proc/pressure").join(name)).ok()?;
    parse_psi(&text)
}

/// All three pressure files in one read, for convenience at the call site.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct SystemPsi {
    pub cpu: Option<PsiMetric>,
    pub memory: Option<PsiMetric>,
    pub io: Option<PsiMetric>,
}

pub fn read_all(ctx: &Ctx) -> SystemPsi {
    SystemPsi {
        cpu: read_psi(ctx, "cpu"),
        memory: read_psi(ctx, "memory"),
        io: read_psi(ctx, "io"),
    }
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

    const CPU_FIXTURE: &str = "\
some avg10=0.06 avg60=0.25 avg300=0.53 total=14117689
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
";

    #[test]
    fn test_parse_psi_reads_some_and_full() {
        let got = parse_psi(CPU_FIXTURE).unwrap();
        assert_eq!(
            got.some,
            PsiLine {
                avg10: 0.06,
                avg60: 0.25,
                avg300: 0.53,
            }
        );
        assert_eq!(got.full, Some(PsiLine::default()));
    }

    #[test]
    fn test_parse_psi_some_only_is_full_none() {
        let text = "some avg10=1.00 avg60=2.00 avg300=3.00 total=1\n";
        let got = parse_psi(text).unwrap();
        assert_eq!(got.some.avg10, 1.0);
        assert_eq!(got.full, None);
    }

    #[test]
    fn test_parse_psi_empty_text_is_none() {
        assert_eq!(parse_psi(""), None);
    }

    #[test]
    fn test_read_psi_missing_file_is_none_not_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert_eq!(read_psi(&ctx, "cpu"), None);
    }

    #[test]
    fn test_read_psi_reads_through_ctx_root() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc/pressure")).unwrap();
        std::fs::write(ctx.root.join("proc/pressure/cpu"), CPU_FIXTURE).unwrap();

        let got = read_psi(&ctx, "cpu").unwrap();
        assert_eq!(got.some.avg60, 0.25);
    }

    #[test]
    fn test_read_all_mixes_present_and_absent_files() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc/pressure")).unwrap();
        std::fs::write(ctx.root.join("proc/pressure/cpu"), CPU_FIXTURE).unwrap();
        // memory and io files are absent (kernel without CONFIG_PSI, or a
        // partially-populated sandbox).

        let got = read_all(&ctx);
        assert!(got.cpu.is_some());
        assert_eq!(got.memory, None);
        assert_eq!(got.io, None);
    }
}
