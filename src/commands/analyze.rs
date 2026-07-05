//! `badger analyze`: non-interactive disk-usage report (plain table or
//! `--json`) for a directory. Reuses `analyze::sizer::scan` and
//! `analyze::disk::disk_totals`; a later slice adds an interactive
//! tree-explorer TUI on top of this same data.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use crossterm::event::{Event, KeyEventKind};
use serde::Serialize;

use crate::analyze::disk::{self, DiskTotals};
use crate::analyze::sizer::{self, DirNode, LargeFile, ScanOptions, ScanResult};
use crate::ctx::Ctx;
use crate::output::{self, Mode};
use crate::tui::{self, explorer};

pub struct AnalyzeOutput {
    pub rendered: String,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    path: String,
    totals: &'a DiskTotals,
    tree: &'a DirNode,
    large_files: &'a [LargeFile],
    warnings: &'a [String],
    skipped_mounts: &'a [PathBuf],
    complete: bool,
}

/// Validates the analyze target: it must exist and canonicalize to
/// somewhere inside the analyzable area (under the root or home).
fn validated_target(ctx: &Ctx, path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let requested = path.unwrap_or_else(|| ctx.home.clone());
    if !requested.exists() {
        anyhow::bail!("{}: no such file or directory", requested.display());
    }
    let target = requested.canonicalize()?;
    if !target.starts_with(&ctx.root) && !target.starts_with(&ctx.home) {
        anyhow::bail!(
            "path is outside the analyzable area (root: {}, home: {})",
            ctx.root.display(),
            ctx.home.display()
        );
    }
    Ok(target)
}

pub fn run(ctx: &Ctx, path: Option<PathBuf>, mode: Mode) -> anyhow::Result<AnalyzeOutput> {
    let target = validated_target(ctx, path)?;

    let (tx, rx) = mpsc::channel::<(u64, u64)>();
    let show_progress = std::io::stderr().is_terminal();
    let progress_thread = std::thread::spawn(move || {
        let mut printed = false;
        for (dirs, bytes) in rx {
            if show_progress {
                eprint!(
                    "\rscanned {dirs} dirs, {} so far…",
                    output::humanize_bytes(bytes)
                );
                printed = true;
            }
        }
        if printed {
            eprintln!();
        }
    });

    let cancel = Arc::new(AtomicBool::new(false));
    let result = sizer::scan(&target, &ScanOptions::default(), Some(tx), &cancel);
    let _ = progress_thread.join();

    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    for p in &result.skipped_mounts {
        eprintln!("warning: skipped mount: {}", p.display());
    }

    let totals = disk::disk_totals(ctx, &target)?;

    let rendered = match mode {
        Mode::Json => serde_json::to_string(&JsonOutput {
            path: target.display().to_string(),
            totals: &totals,
            tree: &result.root,
            large_files: &result.top_files,
            warnings: &result.warnings,
            skipped_mounts: &result.skipped_mounts,
            complete: result.complete,
        })?,
        Mode::Human => render_human(&target, &result, &totals),
    };

    Ok(AnalyzeOutput { rendered })
}

/// Interactive `badger analyze`: the scan runs on a background thread while
/// the TUI shows live progress counters, then the explorer opens over the
/// finished (or cancelled-partial) tree.
pub fn run_interactive(ctx: &Ctx, path: Option<PathBuf>) -> anyhow::Result<AnalyzeOutput> {
    let target = validated_target(ctx, path)?;
    let totals = disk::disk_totals(ctx, &target)?;

    let (tx, rx) = mpsc::channel::<(u64, u64)>();
    let cancel = Arc::new(AtomicBool::new(false));
    let scan_cancel = Arc::clone(&cancel);
    let scan_target = target.clone();
    let scan_thread = std::thread::spawn(move || {
        sizer::scan(
            &scan_target,
            &ScanOptions::default(),
            Some(tx),
            &scan_cancel,
        )
    });

    let now = jiff::Timestamp::now().as_second();
    let mut session = explorer::ExplorerSession::new(totals, now);

    let mut terminal = tui::init_terminal()?;
    let loop_result = drive_explorer(&mut terminal, &mut session, &rx, scan_thread, &cancel);
    // Leave the alternate screen before printing anything: warnings and the
    // final summary both need a normal, scrollable terminal.
    tui::restore_terminal(&mut terminal)?;
    let (warnings, skipped_mounts) = loop_result?;

    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    for p in &skipped_mounts {
        eprintln!("warning: skipped mount: {}", p.display());
    }

    Ok(AnalyzeOutput {
        rendered: String::new(),
    })
}

/// Drives the scanning-then-browsing event loop against a real terminal:
/// alternates between draining the scan's progress channel and polling for
/// key events, swapping the explorer in when the scan thread finishes. All
/// state transitions live on `ExplorerSession`/`ExplorerState` (unit-tested
/// separately); this loop is only the thread/terminal glue.
fn drive_explorer(
    terminal: &mut tui::Term,
    session: &mut explorer::ExplorerSession,
    rx: &mpsc::Receiver<(u64, u64)>,
    scan_thread: std::thread::JoinHandle<ScanResult>,
    cancel: &Arc<AtomicBool>,
) -> anyhow::Result<(Vec<String>, Vec<PathBuf>)> {
    let colors = tui::colors_enabled_now();
    let mut scan_thread = Some(scan_thread);
    let mut warnings = Vec::new();
    let mut skipped_mounts = Vec::new();

    loop {
        while let Ok((dirs, bytes)) = rx.try_recv() {
            session.on_progress(dirs, bytes);
        }

        if session.is_scanning()
            && scan_thread.as_ref().is_some_and(|h| h.is_finished())
            && let Some(handle) = scan_thread.take()
        {
            let scan = handle
                .join()
                .map_err(|_| anyhow::anyhow!("scan thread panicked"))?;
            warnings = scan.warnings;
            skipped_mounts = scan.skipped_mounts;
            session.on_finished(scan.root, scan.top_files, scan.complete);
        }

        let height = terminal.size()?.height;
        if let Some(state) = session.explorer_mut() {
            state.scroll_into_view(explorer::body_height(height));
        }
        terminal.draw(|f| explorer::render_session(f, session, colors))?;

        // Poll rather than block: progress ticks and scan completion have to
        // keep landing even while no key is pressed.
        if !crossterm::event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }

        let action = explorer::map_key(key);

        if session.is_scanning() {
            if action == Some(explorer::Action::Quit) {
                cancel.store(true, Ordering::Relaxed);
                session.request_cancel();
            }
            continue;
        }

        let Some(state) = session.explorer_mut() else {
            continue;
        };
        match action {
            Some(explorer::Action::Down) => state.move_down(),
            Some(explorer::Action::Up) => state.move_up(),
            Some(explorer::Action::Descend) => state.descend(),
            Some(explorer::Action::Ascend) => state.ascend(),
            Some(explorer::Action::CycleSort) => state.cycle_sort(),
            Some(explorer::Action::ToggleLargeFiles) => state.toggle_large_files(),
            Some(explorer::Action::Top) => state.top(),
            Some(explorer::Action::Bottom) => state.bottom(),
            Some(explorer::Action::Quit) => return Ok((warnings, skipped_mounts)),
            // Delete lands in the next slice.
            Some(explorer::Action::Delete) | None => {}
        }
    }
}

/// Renders the plain-text report: totals line, disk line, a table of the
/// scan root's direct children sorted by size, and the largest files found
/// anywhere in the tree.
fn render_human(target: &Path, result: &ScanResult, totals: &DiskTotals) -> String {
    let mut out = format!(
        "{} — {} in {} files\n",
        target.display(),
        output::humanize_bytes(result.root.bytes),
        result.root.files
    );

    out.push_str(&format!(
        "Disk ({}): {} used of {}, {} available",
        totals.fs_kind,
        output::humanize_bytes(totals.used),
        output::humanize_bytes(totals.total),
        output::humanize_bytes(totals.available)
    ));
    if let Some(unallocated) = totals.btrfs_unallocated {
        out.push_str(&format!(
            ", {} unallocated",
            output::humanize_bytes(unallocated)
        ));
    }

    out.push_str("\n\nDirectories:");
    if result.root.children.is_empty() {
        out.push_str(" (none)");
    } else {
        let mut children: Vec<&DirNode> = result.root.children.iter().collect();
        children.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
        children.truncate(15);
        let name_width = children.iter().map(|c| c.name.len()).max().unwrap_or(0);
        for child in &children {
            let pct = if result.root.bytes == 0 {
                0.0
            } else {
                child.bytes as f64 * 100.0 / result.root.bytes as f64
            };
            let min_bar = if child.bytes > 0 { 1 } else { 0 };
            let bar_len = ((pct / 5.0).round() as usize).max(min_bar);
            let bar = "#".repeat(bar_len);
            out.push_str(&format!(
                "\n  {:name_width$}  {:<9}  {:<6}  {bar}",
                child.name,
                output::humanize_bytes(child.bytes),
                format!("{pct:.1}%")
            ));
        }
    }

    out.push_str("\n\nLargest files:");
    if result.top_files.is_empty() {
        out.push_str(" (none)");
    } else {
        for file in result.top_files.iter().take(10) {
            let rel = file.path.strip_prefix(target).unwrap_or(&file.path);
            out.push_str(&format!(
                "\n  {:<9}  {}",
                output::humanize_bytes(file.bytes),
                rel.display()
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str, bytes: u64, files: u64) -> DirNode {
        DirNode {
            path: PathBuf::from(name),
            name: name.to_string(),
            bytes,
            files,
            mtime: 0,
            children: Vec::new(),
            truncated_depth: false,
        }
    }

    fn large_file(path: &str, bytes: u64) -> LargeFile {
        LargeFile {
            path: PathBuf::from(path),
            bytes,
            mtime: 0,
        }
    }

    fn scan_result(root: DirNode, top_files: Vec<LargeFile>) -> ScanResult {
        ScanResult {
            root,
            dirs_visited: 0,
            complete: true,
            skipped_mounts: Vec::new(),
            warnings: Vec::new(),
            top_files,
        }
    }

    #[test]
    fn test_render_human_typical_tree_with_btrfs_unallocated() {
        let target = Path::new("/home/user/data");
        let root = DirNode {
            path: target.to_path_buf(),
            name: "data".to_string(),
            bytes: 32768,
            files: 3,
            mtime: 0,
            children: vec![dir("big", 24576, 2), dir("small", 8192, 1)],
            truncated_depth: false,
        };
        let result = scan_result(
            root,
            vec![
                large_file("/home/user/data/big/file1.bin", 16384),
                large_file("/home/user/data/small/file2.bin", 8192),
            ],
        );
        let totals = DiskTotals {
            total: 50 * 1024 * 1024 * 1024,
            used: 10 * 1024 * 1024 * 1024,
            available: 40 * 1024 * 1024 * 1024,
            fs_kind: "btrfs".to_string(),
            btrfs_unallocated: Some(5 * 1024 * 1024 * 1024),
        };

        let rendered = render_human(target, &result, &totals);

        let expected = "\
/home/user/data — 32.0 KiB in 3 files
Disk (btrfs): 10.0 GiB used of 50.0 GiB, 40.0 GiB available, 5.0 GiB unallocated

Directories:
  big    24.0 KiB   75.0%   ###############
  small  8.0 KiB    25.0%   #####

Largest files:
  16.0 KiB   big/file1.bin
  8.0 KiB    small/file2.bin";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn test_render_human_empty_dir_shows_none_for_both_sections() {
        let target = Path::new("/home/user/empty");
        let root = dir("empty", 0, 0);
        let result = scan_result(root, Vec::new());
        let totals = DiskTotals {
            total: 1024,
            used: 512,
            available: 512,
            fs_kind: "ext4".to_string(),
            btrfs_unallocated: None,
        };

        let rendered = render_human(target, &result, &totals);

        let expected = "\
/home/user/empty — 0 B in 0 files
Disk (ext4): 512 B used of 1.0 KiB, 512 B available

Directories: (none)

Largest files: (none)";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn test_render_human_zero_byte_root_does_not_panic_on_division() {
        // root.bytes == 0 while a child still has bytes is not something a
        // real scan produces (children sum to the root), but it is exactly
        // the shape that would divide-by-zero computing that child's
        // percentage — this fabricated tree pins the 0.0% guard.
        let target = Path::new("/home/user/zeros");
        let root = DirNode {
            path: target.to_path_buf(),
            name: "zeros".to_string(),
            bytes: 0,
            files: 0,
            mtime: 0,
            children: vec![dir("child", 4096, 1)],
            truncated_depth: false,
        };
        let result = scan_result(root, Vec::new());
        let totals = DiskTotals {
            total: 1024,
            used: 0,
            available: 1024,
            fs_kind: "ext4".to_string(),
            btrfs_unallocated: None,
        };

        let rendered = render_human(target, &result, &totals);

        let expected = "\
/home/user/zeros — 0 B in 0 files
Disk (ext4): 0 B used of 1.0 KiB, 1.0 KiB available

Directories:
  child  4.0 KiB    0.0%    #

Largest files: (none)";
        assert_eq!(rendered, expected);
    }
}
