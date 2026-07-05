use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::analyze::disk::DiskTotals;
use crate::analyze::sizer::{DirNode, LargeFile};
use crate::output::humanize_bytes;

const BAR_WIDTH: usize = 20;

/// Pure state for the pre-browsing "scanning" screen: the progress counters
/// the engine's scan reports over its channel, and whether the person has
/// asked to cancel. No threads or terminal I/O here — the thread spawn/join
/// and crossterm event loop that feed these messages in live in
/// `commands::analyze`, which is why this only needs plain method calls to
/// be fully unit-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanProgress {
    dirs: u64,
    bytes: u64,
    cancel_requested: bool,
}

impl ScanProgress {
    pub fn new() -> ScanProgress {
        ScanProgress::default()
    }

    pub fn on_progress(&mut self, dirs: u64, bytes: u64) {
        self.dirs = dirs;
        self.bytes = bytes;
    }

    pub fn request_cancel(&mut self) {
        self.cancel_requested = true;
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    pub fn dirs(&self) -> u64 {
        self.dirs
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// The full lifecycle of one interactive analyze session as a message-driven
/// state machine: starts scanning, absorbs `(dirs, bytes)` progress ticks,
/// and swaps to a browsable `ExplorerState` when the scan's final tree
/// lands. The threading (scan worker, progress channel, crossterm polling)
/// lives in `commands::analyze`; everything here is plain method calls, so
/// the whole scanning-to-browsing transition is unit-testable without
/// threads.
pub struct ExplorerSession {
    progress: ScanProgress,
    explorer: Option<ExplorerState>,
    totals: DiskTotals,
    now: i64,
}

impl ExplorerSession {
    pub fn new(totals: DiskTotals, now: i64) -> ExplorerSession {
        ExplorerSession {
            progress: ScanProgress::new(),
            explorer: None,
            totals,
            now,
        }
    }

    pub fn is_scanning(&self) -> bool {
        self.explorer.is_none()
    }

    /// A `(dirs, bytes)` tick from the scan's progress channel. Ignored once
    /// the final tree has landed (a straggling tick can arrive after the
    /// scan thread finishes).
    pub fn on_progress(&mut self, dirs: u64, bytes: u64) {
        if self.is_scanning() {
            self.progress.on_progress(dirs, bytes);
        }
    }

    /// The scan finished (or was cancelled): swap in its tree — possibly
    /// partial — and start browsing.
    pub fn on_finished(&mut self, root: DirNode, top_files: Vec<LargeFile>, complete: bool) {
        self.explorer = Some(ExplorerState::new(
            root,
            self.totals.clone(),
            top_files,
            complete,
            self.now,
        ));
    }

    pub fn request_cancel(&mut self) {
        self.progress.request_cancel();
    }

    pub fn cancel_requested(&self) -> bool {
        self.progress.cancel_requested()
    }

    pub fn progress(&self) -> &ScanProgress {
        &self.progress
    }

    pub fn explorer_mut(&mut self) -> Option<&mut ExplorerState> {
        self.explorer.as_mut()
    }

    pub fn explorer(&self) -> Option<&ExplorerState> {
        self.explorer.as_ref()
    }
}

/// Renders whichever screen the session is on: the scanning counters, or
/// the explorer once the tree has landed.
pub fn render_session(frame: &mut Frame, session: &ExplorerSession, colors: bool) {
    match session.explorer() {
        Some(state) => render(frame, state, colors),
        None => render_scanning(frame, session.progress()),
    }
}

pub fn render_scanning(frame: &mut Frame, progress: &ScanProgress) {
    let lines = vec![
        Line::from("badger analyze — scanning\u{2026}"),
        Line::from(format!(
            "{} dirs, {} so far",
            progress.dirs(),
            humanize_bytes(progress.bytes())
        )),
        Line::from(""),
        if progress.cancel_requested() {
            Line::from("cancelling\u{2026} waiting for the scan to stop")
        } else {
            Line::from("q/esc cancel")
        },
    ];
    frame.render_widget(Paragraph::new(lines), frame.area());
}

/// How the current directory's rows are ordered. Cycled with `s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    SizeDesc,
    Name,
    Age,
}

impl SortMode {
    fn next(self) -> SortMode {
        match self {
            SortMode::SizeDesc => SortMode::Name,
            SortMode::Name => SortMode::Age,
            SortMode::Age => SortMode::SizeDesc,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortMode::SizeDesc => "size",
            SortMode::Name => "name",
            SortMode::Age => "age",
        }
    }
}

/// What one row in the main (directory-browsing) view represents. `Dir`
/// carries the index of the child within the current directory's
/// `children` — stable across re-sorts since sorting only reorders the
/// display-facing `rows` vector, never `DirNode::children` itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Dir(usize),
    LooseFiles,
}

#[derive(Debug, Clone)]
struct Row {
    kind: RowKind,
    name: String,
    bytes: u64,
    mtime: i64,
}

/// What's under the cursor, resolved to something a caller (e.g. a delete
/// action in a later slice) can act on without knowing about `Row`/`RowKind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Dir { path: PathBuf, bytes: u64 },
    LooseFiles,
    LargeFile { path: PathBuf, bytes: u64 },
    None,
}

/// Pure state for the `badger analyze` interactive tree explorer: browses a
/// scanned `DirNode` tree rooted at `root`, plus a flat top-N large-files
/// view. No terminal I/O lives here, so every transition is unit-testable
/// directly (mirrors `checklist::ChecklistState`).
pub struct ExplorerState {
    root: DirNode,
    totals: DiskTotals,
    top_files: Vec<LargeFile>,
    /// Whether the tree currently held is the result of a fully-completed
    /// scan. `false` means it's a partial tree (the scan was cancelled).
    complete: bool,
    /// Directory names from `root` down to the directory currently being
    /// browsed. Empty means "at the scan root".
    cursor_path: Vec<String>,
    rows: Vec<Row>,
    cursor: usize,
    scroll: usize,
    sort_mode: SortMode,
    large_files: bool,
    /// Reference time (unix seconds) ages are computed against. Passed in
    /// rather than read live so rendering/age math stays pure and testable.
    now: i64,
}

fn build_rows(node: &DirNode, sort_mode: SortMode) -> Vec<Row> {
    let mut rows: Vec<Row> = node
        .children
        .iter()
        .enumerate()
        .map(|(i, child)| Row {
            kind: RowKind::Dir(i),
            name: child.name.clone(),
            bytes: child.bytes,
            mtime: child.mtime,
        })
        .collect();

    let children_bytes: u64 = node.children.iter().map(|c| c.bytes).sum();
    let loose_bytes = node.bytes.saturating_sub(children_bytes);
    if loose_bytes > 0 {
        rows.push(Row {
            kind: RowKind::LooseFiles,
            name: "(loose files)".to_string(),
            bytes: loose_bytes,
            mtime: node.mtime,
        });
    }

    sort_rows(&mut rows, sort_mode);
    rows
}

fn sort_rows(rows: &mut [Row], mode: SortMode) {
    match mode {
        SortMode::SizeDesc => {
            rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)))
        }
        SortMode::Name => rows.sort_by(|a, b| a.name.cmp(&b.name)),
        // Oldest first: the point of sorting by age in a disk-cleanup tool
        // is finding the stalest data to reclaim, not the freshest.
        SortMode::Age => {
            rows.sort_by(|a, b| a.mtime.cmp(&b.mtime).then_with(|| a.name.cmp(&b.name)))
        }
    }
}

/// Formats how long ago `mtime` (unix seconds) was, relative to `now`:
/// under a day is "today", under a month is "`<n>`d", under two years is
/// "`<n>`mo", otherwise "`<n>`y".
fn format_age(mtime: i64, now: i64) -> String {
    let secs = now.saturating_sub(mtime).max(0);
    let days = secs / 86_400;
    if days < 1 {
        "today".to_string()
    } else if days < 30 {
        format!("{days}d")
    } else if days < 730 {
        format!("{}mo", days / 30)
    } else {
        format!("{}y", days / 365)
    }
}

impl ExplorerState {
    pub fn new(
        root: DirNode,
        totals: DiskTotals,
        top_files: Vec<LargeFile>,
        complete: bool,
        now: i64,
    ) -> ExplorerState {
        let sort_mode = SortMode::SizeDesc;
        let rows = build_rows(&root, sort_mode);
        ExplorerState {
            root,
            totals,
            top_files,
            complete,
            cursor_path: Vec::new(),
            rows,
            cursor: 0,
            scroll: 0,
            sort_mode,
            large_files: false,
            now,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn is_large_files_view(&self) -> bool {
        self.large_files
    }

    /// The directory currently being browsed (root if `cursor_path` is
    /// empty).
    fn current_node(&self) -> &DirNode {
        let mut node = &self.root;
        for name in &self.cursor_path {
            if let Some(child) = node.children.iter().find(|c| &c.name == name) {
                node = child;
            }
        }
        node
    }

    /// Absolute path of the directory currently being browsed.
    pub fn current_path(&self) -> PathBuf {
        let mut path = self.root.path.clone();
        for name in &self.cursor_path {
            path.push(name);
        }
        path
    }

    fn rebuild_rows(&mut self) {
        self.rows = build_rows(self.current_node(), self.sort_mode);
    }

    fn row_count(&self) -> usize {
        if self.large_files {
            self.top_files.len()
        } else {
            self.rows.len()
        }
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// What's under the cursor right now, in whichever view is active.
    pub fn selection(&self) -> Selection {
        if self.large_files {
            return match self.top_files.get(self.cursor) {
                Some(f) => Selection::LargeFile {
                    path: f.path.clone(),
                    bytes: f.bytes,
                },
                None => Selection::None,
            };
        }
        match self.rows.get(self.cursor) {
            Some(row) => match row.kind {
                RowKind::Dir(_) => Selection::Dir {
                    path: self.current_path().join(&row.name),
                    bytes: row.bytes,
                },
                RowKind::LooseFiles => Selection::LooseFiles,
            },
            None => Selection::None,
        }
    }

    pub fn move_down(&mut self) {
        let len = self.row_count();
        if self.cursor + 1 < len {
            self.cursor += 1;
        }
    }

    pub fn move_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn top(&mut self) {
        self.cursor = 0;
    }

    pub fn bottom(&mut self) {
        self.cursor = self.row_count().saturating_sub(1);
    }

    /// Enters the directory under the cursor. A no-op in the large-files
    /// view, on the "(loose files)" row, or when there's no selection.
    pub fn descend(&mut self) {
        if self.large_files {
            return;
        }
        let Some(row) = self.rows.get(self.cursor) else {
            return;
        };
        if let RowKind::Dir(_) = row.kind {
            self.cursor_path.push(row.name.clone());
            self.cursor = 0;
            self.scroll = 0;
            self.rebuild_rows();
        }
    }

    /// Leaves the current directory for its parent. A no-op at the scan
    /// root — browsing never goes above where the scan started.
    pub fn ascend(&mut self) {
        if self.cursor_path.is_empty() {
            return;
        }
        self.cursor_path.pop();
        self.cursor = 0;
        self.scroll = 0;
        self.rebuild_rows();
    }

    pub fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.cursor = 0;
        self.scroll = 0;
        self.rebuild_rows();
    }

    /// Toggles the flat top-50 large-files view. Resets the cursor since
    /// it's a different list with its own ordering.
    pub fn toggle_large_files(&mut self) {
        self.large_files = !self.large_files;
        self.cursor = 0;
        self.scroll = 0;
    }

    fn scroll_offset(&self) -> usize {
        self.scroll
    }

    /// Adjusts the scroll offset (if needed) so the cursor stays inside a
    /// `viewport_height`-row window. Callers must invoke this with the
    /// body area's height before rendering.
    pub fn scroll_into_view(&mut self, viewport_height: usize) {
        if viewport_height == 0 {
            return;
        }
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + viewport_height {
            self.scroll = self.cursor + 1 - viewport_height;
        }
        let max_scroll = self.row_count().saturating_sub(viewport_height);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }
}

/// Abstract keys the explorer screen reacts to, decoupled from crossterm's
/// event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Down,
    Up,
    Descend,
    Ascend,
    CycleSort,
    ToggleLargeFiles,
    Top,
    Bottom,
    Delete,
    Quit,
}

pub fn map_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => Some(Action::Down),
        KeyCode::Char('k') | KeyCode::Up => Some(Action::Up),
        KeyCode::Enter | KeyCode::Char('l') => Some(Action::Descend),
        KeyCode::Char('h') | KeyCode::Backspace => Some(Action::Ascend),
        KeyCode::Char('s') => Some(Action::CycleSort),
        KeyCode::Char('L') => Some(Action::ToggleLargeFiles),
        KeyCode::Char('g') => Some(Action::Top),
        KeyCode::Char('G') => Some(Action::Bottom),
        KeyCode::Char('d') | KeyCode::Delete => Some(Action::Delete),
        KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
        _ => None,
    }
}

fn disk_line(totals: &DiskTotals) -> String {
    let mut line = format!(
        "Disk ({}): {} used of {}, {} available",
        totals.fs_kind,
        humanize_bytes(totals.used),
        humanize_bytes(totals.total),
        humanize_bytes(totals.available)
    );
    if let Some(unallocated) = totals.btrfs_unallocated {
        line.push_str(&format!(", {} unallocated", humanize_bytes(unallocated)));
    }
    line
}

fn bar(pct: f64, bytes: u64) -> String {
    let min_len = if bytes > 0 { 1 } else { 0 };
    let len = (((pct / 100.0) * BAR_WIDTH as f64).round() as usize).clamp(min_len, BAR_WIDTH);
    "\u{2588}".repeat(len)
}

/// Body area height a caller should pass to `scroll_into_view` for a frame
/// of total height `frame_height` (accounting for the fixed header/footer).
pub fn body_height(frame_height: u16) -> usize {
    frame_height.saturating_sub(6) as usize
}

pub fn render(frame: &mut Frame, state: &ExplorerState, colors: bool) {
    let _ = colors; // reserved for parity with checklist/picker's signature; no color use yet
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(4),
        ])
        .split(frame.area());

    render_header(frame, chunks[0], state);
    if state.large_files {
        render_large_files_body(frame, chunks[1], state);
    } else {
        render_body(frame, chunks[1], state);
    }
    render_footer(frame, chunks[2], state);
}

fn render_header(frame: &mut Frame, area: Rect, state: &ExplorerState) {
    let title = if state.large_files {
        format!(
            "badger analyze — {} — largest files",
            state.current_path().display()
        )
    } else {
        format!("badger analyze — {}", state.current_path().display())
    };
    let lines = vec![Line::from(title), Line::from(disk_line(&state.totals))];
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_body(frame: &mut Frame, area: Rect, state: &ExplorerState) {
    let node = state.current_node();
    let name_width = state.rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    let lines: Vec<Line> = state
        .rows
        .iter()
        .enumerate()
        .skip(state.scroll_offset())
        .take(area.height as usize)
        .map(|(i, row)| {
            let pct = if node.bytes == 0 {
                0.0
            } else {
                row.bytes as f64 * 100.0 / node.bytes as f64
            };
            let marker = if i == state.cursor { ">" } else { " " };
            let age = format_age(row.mtime, state.now);
            Line::from(format!(
                "{marker} {:name_width$}  {:<9}  {:>6}  {}  {age}",
                row.name,
                humanize_bytes(row.bytes),
                format!("{pct:.1}%"),
                bar(pct, row.bytes)
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_large_files_body(frame: &mut Frame, area: Rect, state: &ExplorerState) {
    let lines: Vec<Line> = state
        .top_files
        .iter()
        .enumerate()
        .skip(state.scroll_offset())
        .take(area.height as usize)
        .map(|(i, file)| {
            let marker = if i == state.cursor { ">" } else { " " };
            let age = format_age(file.mtime, state.now);
            Line::from(format!(
                "{marker} {:<9}  {age:<6}  {}",
                humanize_bytes(file.bytes),
                file.path.display()
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_footer(frame: &mut Frame, area: Rect, state: &ExplorerState) {
    let mut lines = vec![
        Line::from(format!("sort: {}  {}", state.sort_mode.label(), {
            if !state.complete { "(partial)" } else { "" }
        })),
        Line::from("j/k move  enter/l open  h/backspace up  s sort  L large files"),
        Line::from("g/G top/bottom  q/esc quit"),
    ];
    lines.retain(|l| !l.spans.is_empty());
    frame.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    fn node(name: &str, bytes: u64, mtime: i64, children: Vec<DirNode>) -> DirNode {
        DirNode {
            path: PathBuf::from(name),
            name: name.to_string(),
            bytes,
            files: 0,
            mtime,
            children,
            truncated_depth: false,
        }
    }

    fn totals() -> DiskTotals {
        DiskTotals {
            total: 100 * 1024 * 1024 * 1024,
            used: 40 * 1024 * 1024 * 1024,
            available: 60 * 1024 * 1024 * 1024,
            fs_kind: "ext4".to_string(),
            btrfs_unallocated: None,
        }
    }

    /// root (12000 bytes total)
    ///   big  (8000 bytes, mtime 1000)
    ///   small (2000 bytes, mtime 5000)
    ///     nested (2000 bytes, mtime 5000)
    /// plus 2000 bytes of loose files directly in root (mtime = root's own).
    fn sample_root() -> DirNode {
        let mut root = node(
            "/scan/root",
            12000,
            9000,
            vec![
                node("big", 8000, 1000, Vec::new()),
                node(
                    "small",
                    2000,
                    5000,
                    vec![node("nested", 2000, 5000, Vec::new())],
                ),
            ],
        );
        root.path = PathBuf::from("/scan/root");
        root.name = "root".to_string();
        root
    }

    fn state() -> ExplorerState {
        ExplorerState::new(sample_root(), totals(), Vec::new(), true, 10_000)
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    // --- construction ---

    #[test]
    fn test_new_state_starts_at_scan_root_with_size_sort() {
        let s = state();
        assert_eq!(s.current_path(), PathBuf::from("/scan/root"));
        assert_eq!(s.cursor(), 0);
        assert!(s.is_complete());
        assert!(!s.is_large_files_view());
    }

    #[test]
    fn test_default_sort_is_size_descending_with_loose_files_included() {
        let s = state();
        // big=8000, loose=2000 (12000 - 8000 - 2000), small=2000; ties
        // broken by name, so "loose files" (2000) sorts after "small"
        // (2000) alphabetically... "(loose files)" < "small" lexically.
        assert_eq!(s.rows.len(), 3);
        assert_eq!(s.rows[0].name, "big");
        assert_eq!(s.rows[0].bytes, 8000);
    }

    #[test]
    fn test_loose_files_row_aggregates_bytes_not_covered_by_children() {
        let s = state();
        let loose = s.rows.iter().find(|r| r.name == "(loose files)").unwrap();
        assert_eq!(loose.bytes, 2000);
    }

    #[test]
    fn test_no_loose_files_row_when_children_cover_all_bytes() {
        let root = node(
            "root",
            8000,
            1000,
            vec![node("big", 8000, 1000, Vec::new())],
        );
        let s = ExplorerState::new(root, totals(), Vec::new(), true, 10_000);
        assert!(!s.rows.iter().any(|r| r.name == "(loose files)"));
    }

    // --- movement ---

    #[test]
    fn test_move_down_and_up_within_bounds() {
        let mut s = state();
        s.move_down();
        assert_eq!(s.cursor(), 1);
        s.move_down();
        assert_eq!(s.cursor(), 2);
        s.move_down(); // stops at last row
        assert_eq!(s.cursor(), 2);
        s.move_up();
        assert_eq!(s.cursor(), 1);
    }

    #[test]
    fn test_top_and_bottom_jump_to_ends() {
        let mut s = state();
        s.bottom();
        assert_eq!(s.cursor(), 2);
        s.top();
        assert_eq!(s.cursor(), 0);
    }

    // --- descend / ascend ---

    #[test]
    fn test_descend_into_dir_enters_and_resets_cursor() {
        let mut s = state();
        s.move_down(); // "loose files" or "small" depending on sort tie-break
        // Move cursor onto "small" explicitly via bottom/top navigation is
        // fragile with sort ties; find it directly instead.
        while s.selection()
            != (Selection::Dir {
                path: PathBuf::from("/scan/root/small"),
                bytes: 2000,
            })
        {
            s.move_down();
        }
        s.descend();
        assert_eq!(s.current_path(), PathBuf::from("/scan/root/small"));
        assert_eq!(s.cursor(), 0);
        assert_eq!(s.rows.len(), 1);
        assert_eq!(s.rows[0].name, "nested");
    }

    #[test]
    fn test_descend_on_loose_files_row_is_a_noop() {
        let mut s = state();
        while s.selection() != Selection::LooseFiles {
            s.move_down();
        }
        s.descend();
        assert_eq!(s.current_path(), PathBuf::from("/scan/root"));
    }

    #[test]
    fn test_ascend_from_child_returns_to_parent() {
        let mut s = state();
        while !matches!(s.selection(), Selection::Dir { ref path, .. } if path == &PathBuf::from("/scan/root/small"))
        {
            s.move_down();
        }
        s.descend();
        s.ascend();
        assert_eq!(s.current_path(), PathBuf::from("/scan/root"));
    }

    #[test]
    fn test_ascend_at_scan_root_is_a_noop() {
        let mut s = state();
        s.ascend();
        assert_eq!(s.current_path(), PathBuf::from("/scan/root"));
        assert_eq!(s.cursor(), 0);
    }

    // --- sort cycling ---

    #[test]
    fn test_cycle_sort_goes_size_name_age_then_back_to_size() {
        let mut s = state();
        assert_eq!(s.sort_mode, SortMode::SizeDesc);
        s.cycle_sort();
        assert_eq!(s.sort_mode, SortMode::Name);
        s.cycle_sort();
        assert_eq!(s.sort_mode, SortMode::Age);
        s.cycle_sort();
        assert_eq!(s.sort_mode, SortMode::SizeDesc);
    }

    #[test]
    fn test_name_sort_orders_alphabetically() {
        let mut s = state();
        s.cycle_sort(); // -> Name
        let names: Vec<&str> = s.rows.iter().map(|r| r.name.as_str()).collect();
        let mut expected = names.clone();
        expected.sort();
        assert_eq!(names, expected);
    }

    #[test]
    fn test_age_sort_orders_oldest_first() {
        let mut s = state();
        s.cycle_sort();
        s.cycle_sort(); // -> Age
        // "big" has mtime 1000 (oldest), so it must sort first.
        assert_eq!(s.rows[0].name, "big");
    }

    // --- large files view ---

    #[test]
    fn test_toggle_large_files_switches_view_and_resets_cursor() {
        let mut root = sample_root();
        root.path = PathBuf::from("/scan/root");
        let top_files = vec![
            LargeFile {
                path: PathBuf::from("/scan/root/big/f1"),
                bytes: 5000,
                mtime: 1000,
            },
            LargeFile {
                path: PathBuf::from("/scan/root/small/f2"),
                bytes: 3000,
                mtime: 2000,
            },
        ];
        let mut s = ExplorerState::new(root, totals(), top_files, true, 10_000);
        s.move_down();
        s.toggle_large_files();
        assert!(s.is_large_files_view());
        assert_eq!(s.cursor(), 0);
        assert_eq!(
            s.selection(),
            Selection::LargeFile {
                path: PathBuf::from("/scan/root/big/f1"),
                bytes: 5000
            }
        );
        s.toggle_large_files();
        assert!(!s.is_large_files_view());
    }

    #[test]
    fn test_descend_is_a_noop_in_large_files_view() {
        let top_files = vec![LargeFile {
            path: PathBuf::from("/scan/root/big/f1"),
            bytes: 5000,
            mtime: 1000,
        }];
        let mut s = ExplorerState::new(sample_root(), totals(), top_files, true, 10_000);
        s.toggle_large_files();
        s.descend();
        assert!(s.is_large_files_view());
        assert_eq!(s.current_path(), PathBuf::from("/scan/root"));
    }

    // --- scroll_into_view ---

    #[test]
    fn test_scroll_into_view_advances_when_cursor_moves_past_viewport() {
        let mut s = state();
        s.bottom();
        s.scroll_into_view(2);
        assert!(s.scroll_offset() > 0);
    }

    #[test]
    fn test_scroll_into_view_retreats_when_cursor_moves_back_above_viewport() {
        let mut s = state();
        s.bottom();
        s.scroll_into_view(2);
        s.top();
        s.scroll_into_view(2);
        assert_eq!(s.scroll_offset(), 0);
    }

    // --- format_age ---

    #[test]
    fn test_format_age_buckets() {
        let now = 10_000_000i64;
        assert_eq!(format_age(now, now), "today");
        assert_eq!(format_age(now - 3 * 86_400, now), "3d");
        assert_eq!(format_age(now - 90 * 86_400, now), "3mo");
        assert_eq!(format_age(now - 800 * 86_400, now), "2y");
    }

    // --- key mapping ---

    #[test]
    fn test_map_key_movement_and_control_keys() {
        assert_eq!(map_key(key(KeyCode::Char('j'))), Some(Action::Down));
        assert_eq!(map_key(key(KeyCode::Down)), Some(Action::Down));
        assert_eq!(map_key(key(KeyCode::Char('k'))), Some(Action::Up));
        assert_eq!(map_key(key(KeyCode::Up)), Some(Action::Up));
        assert_eq!(map_key(key(KeyCode::Enter)), Some(Action::Descend));
        assert_eq!(map_key(key(KeyCode::Char('l'))), Some(Action::Descend));
        assert_eq!(map_key(key(KeyCode::Char('h'))), Some(Action::Ascend));
        assert_eq!(map_key(key(KeyCode::Backspace)), Some(Action::Ascend));
        assert_eq!(map_key(key(KeyCode::Char('s'))), Some(Action::CycleSort));
        assert_eq!(
            map_key(key(KeyCode::Char('L'))),
            Some(Action::ToggleLargeFiles)
        );
        assert_eq!(map_key(key(KeyCode::Char('g'))), Some(Action::Top));
        assert_eq!(map_key(key(KeyCode::Char('G'))), Some(Action::Bottom));
        assert_eq!(map_key(key(KeyCode::Char('q'))), Some(Action::Quit));
        assert_eq!(map_key(key(KeyCode::Esc)), Some(Action::Quit));
        assert_eq!(map_key(key(KeyCode::Char('z'))), None);
    }

    // --- rendering ---

    fn row_text(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
            .collect::<String>()
    }

    fn full_text(buffer: &Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| row_text(buffer, y))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn draw(state: &ExplorerState) -> Buffer {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state, true)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_render_header_shows_breadcrumb_and_disk_line() {
        let s = state();
        let text = full_text(&draw(&s));
        assert!(text.contains("/scan/root"));
        assert!(text.contains("Disk (ext4): 40.0 GiB used of 100.0 GiB, 60.0 GiB available"));
    }

    #[test]
    fn test_render_body_shows_name_size_percent_and_bar() {
        let s = state();
        let text = full_text(&draw(&s));
        assert!(text.contains("big"));
        assert!(text.contains("7.8 KiB")); // 8000 bytes
        assert!(text.contains("66.7%"));
    }

    #[test]
    fn test_render_body_shows_cursor_marker_on_first_row() {
        let s = state();
        let text = full_text(&draw(&s));
        assert!(text.contains("> big"));
    }

    #[test]
    fn test_render_footer_shows_sort_mode_and_key_hints() {
        let s = state();
        let text = full_text(&draw(&s));
        assert!(text.contains("sort: size"));
        assert!(text.contains("enter/l open"));
        assert!(text.contains("q/esc quit"));
    }

    #[test]
    fn test_render_footer_marks_partial_when_scan_incomplete() {
        let s = ExplorerState::new(sample_root(), totals(), Vec::new(), false, 10_000);
        let text = full_text(&draw(&s));
        assert!(text.contains("(partial)"));
    }

    #[test]
    fn test_render_footer_omits_partial_marker_when_complete() {
        let s = state();
        let text = full_text(&draw(&s));
        assert!(!text.contains("(partial)"));
    }

    #[test]
    fn test_render_large_files_view_shows_flat_list() {
        let top_files = vec![LargeFile {
            path: PathBuf::from("/scan/root/big/f1.bin"),
            bytes: 5000,
            mtime: 1000,
        }];
        let mut s = ExplorerState::new(sample_root(), totals(), top_files, true, 10_000);
        s.toggle_large_files();
        let text = full_text(&draw(&s));
        assert!(text.contains("largest files"));
        assert!(text.contains("/scan/root/big/f1.bin"));
    }

    // --- ScanProgress ---

    #[test]
    fn test_scan_progress_starts_at_zero_and_not_cancelled() {
        let p = ScanProgress::new();
        assert_eq!(p.dirs(), 0);
        assert_eq!(p.bytes(), 0);
        assert!(!p.cancel_requested());
    }

    #[test]
    fn test_scan_progress_on_progress_updates_counters() {
        let mut p = ScanProgress::new();
        p.on_progress(100, 4096);
        assert_eq!(p.dirs(), 100);
        assert_eq!(p.bytes(), 4096);
    }

    #[test]
    fn test_scan_progress_request_cancel_is_sticky() {
        let mut p = ScanProgress::new();
        p.request_cancel();
        assert!(p.cancel_requested());
        p.on_progress(1, 1);
        assert!(p.cancel_requested());
    }

    #[test]
    fn test_render_scanning_shows_counters_and_cancel_hint() {
        let mut p = ScanProgress::new();
        p.on_progress(42, 8192);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_scanning(f, &p)).unwrap();
        let text = full_text(&terminal.backend().buffer().clone());
        assert!(text.contains("scanning"));
        assert!(text.contains("42 dirs, 8.0 KiB so far"));
        assert!(text.contains("q/esc cancel"));
    }

    #[test]
    fn test_render_scanning_shows_cancelling_hint_once_requested() {
        let mut p = ScanProgress::new();
        p.request_cancel();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_scanning(f, &p)).unwrap();
        let text = full_text(&terminal.backend().buffer().clone());
        assert!(text.contains("cancelling"));
        assert!(!text.contains("q/esc cancel"));
    }

    // --- ExplorerSession ---

    #[test]
    fn test_session_starts_scanning_with_no_explorer() {
        let session = ExplorerSession::new(totals(), 10_000);
        assert!(session.is_scanning());
        assert!(session.explorer().is_none());
        assert!(!session.cancel_requested());
    }

    #[test]
    fn test_session_progress_ticks_update_counters_while_scanning() {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.on_progress(200, 65536);
        assert_eq!(session.progress().dirs(), 200);
        assert_eq!(session.progress().bytes(), 65536);
    }

    #[test]
    fn test_session_finished_swaps_in_a_browsable_explorer() {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.on_finished(sample_root(), Vec::new(), true);
        assert!(!session.is_scanning());
        let explorer = session.explorer().unwrap();
        assert!(explorer.is_complete());
        assert_eq!(explorer.current_path(), PathBuf::from("/scan/root"));
    }

    #[test]
    fn test_session_cancelled_scan_lands_as_partial_tree() {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.request_cancel();
        assert!(session.cancel_requested());
        session.on_finished(sample_root(), Vec::new(), false);
        assert!(!session.explorer().unwrap().is_complete());
    }

    #[test]
    fn test_session_ignores_straggler_progress_after_finish() {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.on_progress(100, 1000);
        session.on_finished(sample_root(), Vec::new(), true);
        session.on_progress(999, 999_999);
        assert_eq!(session.progress().dirs(), 100);
        assert_eq!(session.progress().bytes(), 1000);
    }

    fn draw_session(session: &ExplorerSession) -> Buffer {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_session(f, session, true)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_render_session_shows_scanning_screen_before_tree_lands() {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.on_progress(42, 8192);
        let text = full_text(&draw_session(&session));
        assert!(text.contains("scanning"));
        assert!(text.contains("42 dirs"));
    }

    #[test]
    fn test_render_session_shows_explorer_after_tree_lands() {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.on_finished(sample_root(), Vec::new(), true);
        let text = full_text(&draw_session(&session));
        assert!(!text.contains("scanning"));
        assert!(text.contains("> big"));
    }
}
