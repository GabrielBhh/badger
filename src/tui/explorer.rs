use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::analyze::disk::DiskTotals;
use crate::analyze::sizer::{DirNode, LargeFile};
use crate::output::humanize_bytes;
use crate::tui::confirm;

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

/// Why a trash attempt didn't move anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrashError {
    /// Source sits on a different filesystem from the trash directory; the
    /// only way to delete it from the explorer is permanently.
    CrossFilesystem,
    Failed(String),
}

/// Carries out the explorer's delete actions. The real implementation
/// (in `commands::analyze`) wraps the engine's `trash_path` and the safety
/// deleter; tests inject a scripted fake — the same seam split as
/// `core::exec::Effector`.
pub trait AnalyzeEffector {
    /// Moves `path` to the freedesktop trash, returning the bytes freed.
    fn trash(&mut self, path: &Path) -> Result<u64, TrashError>;
    /// Permanently deletes `path` (no trash), returning the bytes freed.
    fn delete_permanent(&mut self, path: &Path) -> Result<u64, String>;
}

/// A delete confirmation in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompt {
    /// Plain yes/no before moving to trash.
    Trash { path: PathBuf, bytes: u64 },
    /// Typed-word ("delete") confirmation before a permanent delete —
    /// offered only after trash refused with `CrossFilesystem`.
    Permanent {
        path: PathBuf,
        bytes: u64,
        input: String,
    },
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
    prompt: Option<Prompt>,
    /// In a dry run, confirmed deletes only mark rows "(would trash)" —
    /// the injected effector journals but nothing moves, so the tree's
    /// numbers must not change either.
    dry_run: bool,
}

impl ExplorerSession {
    pub fn new(totals: DiskTotals, now: i64) -> ExplorerSession {
        ExplorerSession {
            progress: ScanProgress::new(),
            explorer: None,
            totals,
            now,
            prompt: None,
            dry_run: false,
        }
    }

    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
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

    pub fn prompt(&self) -> Option<&Prompt> {
        self.prompt.as_ref()
    }

    /// The delete key: opens the trash confirmation for the row under the
    /// cursor. The "(loose files)" aggregate isn't a real filesystem entry,
    /// so it only gets a status hint; the scan root never appears as a row.
    pub fn request_delete(&mut self) {
        if self.prompt.is_some() {
            return;
        }
        let Some(state) = self.explorer.as_mut() else {
            return;
        };
        match state.selection() {
            Selection::Dir { path, bytes } | Selection::LargeFile { path, bytes } => {
                self.prompt = Some(Prompt::Trash { path, bytes });
            }
            Selection::LooseFiles => {
                state.set_status(
                    "(loose files) is an aggregate — it can't be deleted as a unit".to_string(),
                );
            }
            Selection::None => {}
        }
    }

    pub fn cancel_prompt(&mut self) {
        self.prompt = None;
    }

    /// "Yes" on the trash prompt: attempts the move. Success removes the
    /// row and shrinks every ancestor's total; a cross-filesystem refusal
    /// escalates to the typed permanent-delete prompt; any other failure
    /// lands in the status line.
    pub fn confirm_trash(&mut self, effector: &mut dyn AnalyzeEffector) {
        let Some(Prompt::Trash { path, bytes }) = self.prompt.clone() else {
            return;
        };
        match effector.trash(&path) {
            Ok(freed) => {
                self.prompt = None;
                let dry_run = self.dry_run;
                if let Some(state) = self.explorer.as_mut() {
                    if dry_run {
                        state.mark_would_trash(path.clone());
                        state.set_status(format!(
                            "would trash {} ({}) — dry run, nothing moved",
                            path.display(),
                            humanize_bytes(freed)
                        ));
                    } else {
                        state.remove_path(&path, freed);
                        state.set_status(format!(
                            "trashed {} ({}) — recoverable from the trash",
                            path.display(),
                            humanize_bytes(freed)
                        ));
                    }
                }
            }
            Err(TrashError::CrossFilesystem) => {
                self.prompt = Some(Prompt::Permanent {
                    path,
                    bytes,
                    input: String::new(),
                });
            }
            Err(TrashError::Failed(msg)) => {
                self.prompt = None;
                if let Some(state) = self.explorer.as_mut() {
                    state.set_status(format!("error: {msg}"));
                }
            }
        }
    }

    pub fn prompt_input_push(&mut self, c: char) {
        if let Some(Prompt::Permanent { input, .. }) = self.prompt.as_mut() {
            input.push(c);
        }
    }

    pub fn prompt_input_backspace(&mut self) {
        if let Some(Prompt::Permanent { input, .. }) = self.prompt.as_mut() {
            input.pop();
        }
    }

    /// Enter on the permanent-delete prompt: only acts once the exact word
    /// "delete" has been typed.
    pub fn confirm_permanent(&mut self, effector: &mut dyn AnalyzeEffector) {
        let Some(Prompt::Permanent { path, input, .. }) = self.prompt.clone() else {
            return;
        };
        if input != "delete" {
            return;
        }
        self.prompt = None;
        let dry_run = self.dry_run;
        match effector.delete_permanent(&path) {
            Ok(freed) => {
                if let Some(state) = self.explorer.as_mut() {
                    if dry_run {
                        state.mark_would_trash(path.clone());
                        state.set_status(format!(
                            "would permanently delete {} ({}) — dry run, nothing moved",
                            path.display(),
                            humanize_bytes(freed)
                        ));
                    } else {
                        state.remove_path(&path, freed);
                        state.set_status(format!(
                            "permanently deleted {} ({})",
                            path.display(),
                            humanize_bytes(freed)
                        ));
                    }
                }
            }
            Err(msg) => {
                if let Some(state) = self.explorer.as_mut() {
                    state.set_status(format!("error: {msg}"));
                }
            }
        }
    }
}

/// Routes one key while a delete prompt is on screen. Returns `false` when
/// no prompt is active (the caller should handle the key normally).
pub fn handle_prompt_key(
    session: &mut ExplorerSession,
    key: KeyEvent,
    effector: &mut dyn AnalyzeEffector,
) -> bool {
    match session.prompt() {
        None => false,
        Some(Prompt::Trash { .. }) => {
            match confirm::handle_plain_key(key) {
                confirm::Outcome::Proceed => session.confirm_trash(effector),
                confirm::Outcome::Back => session.cancel_prompt(),
                confirm::Outcome::None => {}
            }
            true
        }
        Some(Prompt::Permanent { .. }) => {
            match key.code {
                KeyCode::Esc => session.cancel_prompt(),
                KeyCode::Enter => session.confirm_permanent(effector),
                KeyCode::Backspace => session.prompt_input_backspace(),
                KeyCode::Char(c) => session.prompt_input_push(c),
                _ => {}
            }
            true
        }
    }
}

/// Renders whichever screen the session is on: an active delete prompt,
/// the scanning counters, or the explorer once the tree has landed.
pub fn render_session(frame: &mut Frame, session: &ExplorerSession, colors: bool) {
    if let Some(prompt) = session.prompt() {
        render_prompt(frame, prompt, colors);
        return;
    }
    match session.explorer() {
        Some(state) => render(frame, state, colors),
        None => render_scanning(frame, session.progress()),
    }
}

fn render_prompt(frame: &mut Frame, prompt: &Prompt, colors: bool) {
    match prompt {
        Prompt::Trash { path, bytes } => {
            let state = confirm::PlainConfirmState::new(vec![
                "badger analyze — confirm trash".to_string(),
                String::new(),
                path.display().to_string(),
                format!("size: {}", humanize_bytes(*bytes)),
                "moves to trash — recoverable".to_string(),
            ]);
            confirm::render_plain(frame, &state);
        }
        Prompt::Permanent { path, bytes, input } => {
            let title_style = if colors {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let lines = vec![
                Line::styled("badger analyze — PERMANENT DELETE", title_style),
                Line::from(""),
                Line::from(path.display().to_string()),
                Line::from(format!("size: {}", humanize_bytes(*bytes))),
                Line::from(
                    "can't trash across filesystems — this delete is permanent, NOT recoverable",
                ),
                Line::from(""),
                Line::from("Type \"delete\" to confirm:"),
                Line::from(format!("> {input}")),
                Line::from(""),
                Line::from("enter confirm  esc back"),
            ];
            frame.render_widget(Paragraph::new(lines), frame.area());
        }
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

/// What one row in the main (directory-browsing) view represents. Dir rows
/// are matched back to their `DirNode` by name (unique within a directory),
/// so re-sorting only reorders the display-facing `rows` vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Dir,
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
    /// Latest action outcome ("trashed X", "error: ..."), shown in the
    /// footer until the next one replaces it.
    status: Option<String>,
    /// Paths a dry run "deleted": rows stay (numbers unchanged) but render
    /// with a "(would trash)" mark.
    would_trash: std::collections::HashSet<PathBuf>,
}

fn build_rows(node: &DirNode, sort_mode: SortMode) -> Vec<Row> {
    let mut rows: Vec<Row> = node
        .children
        .iter()
        .map(|child| Row {
            kind: RowKind::Dir,
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
            status: None,
            would_trash: std::collections::HashSet::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn set_status(&mut self, status: String) {
        self.status = Some(status);
    }

    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    pub fn mark_would_trash(&mut self, path: PathBuf) {
        self.would_trash.insert(path);
    }

    pub fn is_marked_would_trash(&self, path: &Path) -> bool {
        self.would_trash.contains(path)
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
                RowKind::Dir => Selection::Dir {
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
        if row.kind == RowKind::Dir {
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

    /// Removes a just-deleted `path` (a directory row or a large file) from
    /// the tree's accounting: every ancestor's recursive total shrinks by
    /// `bytes`, the directory's own node (if it was one) disappears, and
    /// any large-files entries at or under `path` are dropped. The scan
    /// root itself is never removed. Deletes only ever target rows of the
    /// directory being browsed (or large-file entries), so the browsing
    /// position itself can't dangle.
    /// `bytes` should be the effector's actual freed amount, not a
    /// scan-time size — those can diverge (the tree changed underneath, or
    /// only part of a delete succeeded). Note ancestor `files` counts are
    /// not adjusted here (the effector doesn't report a file count), so
    /// they go stale after a delete.
    pub fn remove_path(&mut self, path: &Path, bytes: u64) {
        fn walk(node: &mut DirNode, path: &Path, bytes: u64) {
            node.bytes = node.bytes.saturating_sub(bytes);
            if let Some(i) = node.children.iter().position(|c| c.path.as_path() == path) {
                node.children.remove(i);
                return;
            }
            if let Some(child) = node.children.iter_mut().find(|c| path.starts_with(&c.path)) {
                walk(child, path, bytes);
            }
        }

        if self.root.path.as_path() == path || !path.starts_with(&self.root.path) {
            return;
        }
        walk(&mut self.root, path, bytes);
        self.top_files.retain(|f| !f.path.starts_with(path));
        self.rebuild_rows();
        let count = self.row_count();
        if self.cursor >= count {
            self.cursor = count.saturating_sub(1);
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
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Some(Action::Quit);
    }
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
    let current = state.current_path();
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
            let would_trash = if row.kind == RowKind::Dir
                && state.is_marked_would_trash(&current.join(&row.name))
            {
                "  (would trash)"
            } else {
                ""
            };
            Line::from(format!(
                "{marker} {:name_width$}  {:<9}  {:>6}  {}  {age}{would_trash}",
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
            let would_trash = if state.is_marked_would_trash(&file.path) {
                "  (would trash)"
            } else {
                ""
            };
            Line::from(format!(
                "{marker} {:<9}  {age:<6}  {}{would_trash}",
                humanize_bytes(file.bytes),
                file.path.display()
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_footer(frame: &mut Frame, area: Rect, state: &ExplorerState) {
    let mut lines = Vec::with_capacity(4);
    if let Some(status) = state.status() {
        lines.push(Line::from(status.to_string()));
    }
    lines.push(Line::from(format!(
        "sort: {}{}",
        state.sort_mode.label(),
        if !state.complete { "  (partial)" } else { "" }
    )));
    lines.push(Line::from(
        "j/k move  enter/l open  h/backspace up  s sort  L large files",
    ));
    lines.push(Line::from("g/G top/bottom  d delete  q/esc quit"));
    frame.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    fn node(path: &str, bytes: u64, mtime: i64, children: Vec<DirNode>) -> DirNode {
        let path = PathBuf::from(path);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        DirNode {
            path,
            name,
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
        node(
            "/scan/root",
            12000,
            9000,
            vec![
                node("/scan/root/big", 8000, 1000, Vec::new()),
                node(
                    "/scan/root/small",
                    2000,
                    5000,
                    vec![node("/scan/root/small/nested", 2000, 5000, Vec::new())],
                ),
            ],
        )
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
        let root = sample_root();
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

    #[test]
    fn test_map_key_ctrl_c_quits() {
        // Raw mode swallows SIGINT, so Ctrl-C must map to the same quit
        // action as q/esc.
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(map_key(ctrl_c), Some(Action::Quit));
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

    // --- remove_path ---

    #[test]
    fn test_remove_path_removes_dir_and_decrements_every_ancestor() {
        let mut s = state();
        s.remove_path(Path::new("/scan/root/small/nested"), 2000);
        assert_eq!(s.root.bytes, 10000);
        let small = s.root.children.iter().find(|c| c.name == "small").unwrap();
        assert_eq!(small.bytes, 0);
        assert!(small.children.is_empty());
    }

    #[test]
    fn test_remove_path_of_a_file_decrements_ancestors_without_removing_dirs() {
        let mut s = state();
        // A large file inside big: dirs stay, sizes shrink.
        s.remove_path(Path::new("/scan/root/big/blob.bin"), 3000);
        assert_eq!(s.root.bytes, 9000);
        let big = s.root.children.iter().find(|c| c.name == "big").unwrap();
        assert_eq!(big.bytes, 5000);
        assert_eq!(s.root.children.len(), 2);
    }

    #[test]
    fn test_remove_path_drops_top_files_under_the_deleted_dir() {
        let top_files = vec![
            LargeFile {
                path: PathBuf::from("/scan/root/big/f1"),
                bytes: 5000,
                mtime: 1000,
            },
            LargeFile {
                path: PathBuf::from("/scan/root/small/f2"),
                bytes: 1000,
                mtime: 2000,
            },
        ];
        let mut s = ExplorerState::new(sample_root(), totals(), top_files, true, 10_000);
        s.remove_path(Path::new("/scan/root/big"), 8000);
        assert_eq!(s.top_files.len(), 1);
        assert_eq!(s.top_files[0].path, PathBuf::from("/scan/root/small/f2"));
    }

    #[test]
    fn test_remove_path_never_removes_the_scan_root() {
        let mut s = state();
        s.remove_path(Path::new("/scan/root"), 12000);
        assert_eq!(s.root.bytes, 12000);
        assert_eq!(s.root.children.len(), 2);
    }

    #[test]
    fn test_remove_path_clamps_cursor_when_last_row_disappears() {
        let mut s = state();
        s.bottom();
        assert_eq!(s.cursor(), 2);
        s.remove_path(Path::new("/scan/root/big"), 8000);
        assert!(s.cursor() < s.row_count());
    }

    // --- delete state machine ---

    struct FakeEffector {
        trash_result: Result<u64, TrashError>,
        delete_result: Result<u64, String>,
        trash_calls: Vec<PathBuf>,
        delete_calls: Vec<PathBuf>,
    }

    impl FakeEffector {
        fn new() -> FakeEffector {
            FakeEffector {
                trash_result: Ok(0),
                delete_result: Ok(0),
                trash_calls: Vec::new(),
                delete_calls: Vec::new(),
            }
        }

        fn trash_ok(bytes: u64) -> FakeEffector {
            FakeEffector {
                trash_result: Ok(bytes),
                ..FakeEffector::new()
            }
        }

        fn cross_filesystem() -> FakeEffector {
            FakeEffector {
                trash_result: Err(TrashError::CrossFilesystem),
                ..FakeEffector::new()
            }
        }

        fn trash_fails(msg: &str) -> FakeEffector {
            FakeEffector {
                trash_result: Err(TrashError::Failed(msg.to_string())),
                ..FakeEffector::new()
            }
        }

        fn permanent(delete_result: Result<u64, String>) -> FakeEffector {
            FakeEffector {
                trash_result: Err(TrashError::CrossFilesystem),
                delete_result,
                ..FakeEffector::new()
            }
        }
    }

    impl AnalyzeEffector for FakeEffector {
        fn trash(&mut self, path: &Path) -> Result<u64, TrashError> {
            self.trash_calls.push(path.to_path_buf());
            self.trash_result.clone()
        }

        fn delete_permanent(&mut self, path: &Path) -> Result<u64, String> {
            self.delete_calls.push(path.to_path_buf());
            self.delete_result.clone()
        }
    }

    /// A session already browsing `sample_root` with the cursor on "big".
    fn browsing_session() -> ExplorerSession {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.on_finished(sample_root(), Vec::new(), true);
        session
    }

    #[test]
    fn test_request_delete_on_dir_opens_trash_prompt() {
        let mut session = browsing_session();
        session.request_delete();
        assert_eq!(
            session.prompt(),
            Some(&Prompt::Trash {
                path: PathBuf::from("/scan/root/big"),
                bytes: 8000
            })
        );
    }

    #[test]
    fn test_request_delete_on_loose_files_sets_status_instead_of_prompt() {
        let mut session = browsing_session();
        while session.explorer().unwrap().selection() != Selection::LooseFiles {
            session.explorer_mut().unwrap().move_down();
        }
        session.request_delete();
        assert!(session.prompt().is_none());
        assert!(
            session
                .explorer()
                .unwrap()
                .status()
                .unwrap()
                .contains("aggregate")
        );
    }

    #[test]
    fn test_request_delete_while_scanning_is_a_noop() {
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.request_delete();
        assert!(session.prompt().is_none());
    }

    #[test]
    fn test_confirm_trash_success_removes_row_and_reports_status() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::trash_ok(7900);
        session.request_delete();
        session.confirm_trash(&mut effector);

        assert!(session.prompt().is_none());
        assert_eq!(effector.trash_calls, vec![PathBuf::from("/scan/root/big")]);
        let explorer = session.explorer().unwrap();
        assert!(!explorer.rows.iter().any(|r| r.name == "big"));
        // "big" was 8000 bytes when the prompt opened, but the effector
        // reports 7900 actually freed — ancestors must shrink by the
        // freed amount, not the stale scan-time size.
        assert_eq!(explorer.root.bytes, 4100);
        assert!(explorer.status().unwrap().contains("trashed"));
        assert!(explorer.status().unwrap().contains("recoverable"));
    }

    #[test]
    fn test_confirm_permanent_decrements_ancestors_by_freed_not_prompt_bytes() {
        let mut session = browsing_session();
        // Prompt bytes was 8000 (the scan-time size of "big"); the effector
        // reports a different actual freed amount.
        let mut effector = FakeEffector::permanent(Ok(7900));
        session.request_delete();
        session.confirm_trash(&mut effector); // cross-fs -> permanent prompt
        for c in "delete".chars() {
            session.prompt_input_push(c);
        }
        session.confirm_permanent(&mut effector);

        let explorer = session.explorer().unwrap();
        assert_eq!(explorer.root.bytes, 4100);
    }

    #[test]
    fn test_confirm_trash_cross_filesystem_escalates_to_permanent_prompt() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::cross_filesystem();
        session.request_delete();
        session.confirm_trash(&mut effector);

        assert_eq!(
            session.prompt(),
            Some(&Prompt::Permanent {
                path: PathBuf::from("/scan/root/big"),
                bytes: 8000,
                input: String::new()
            })
        );
        // Row must survive: nothing was deleted yet.
        assert!(
            session
                .explorer()
                .unwrap()
                .rows
                .iter()
                .any(|r| r.name == "big")
        );
    }

    #[test]
    fn test_confirm_trash_failure_sets_status_and_keeps_row() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::trash_fails("refused: protected path");
        session.request_delete();
        session.confirm_trash(&mut effector);

        assert!(session.prompt().is_none());
        let explorer = session.explorer().unwrap();
        assert!(explorer.rows.iter().any(|r| r.name == "big"));
        assert_eq!(explorer.root.bytes, 12000);
        assert_eq!(explorer.status(), Some("error: refused: protected path"));
    }

    #[test]
    fn test_permanent_delete_requires_the_exact_typed_word() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::permanent(Ok(8000));
        session.request_delete();
        session.confirm_trash(&mut effector); // -> permanent prompt

        for c in "del".chars() {
            session.prompt_input_push(c);
        }
        session.confirm_permanent(&mut effector);
        assert!(effector.delete_calls.is_empty(), "wrong word must not act");
        assert!(matches!(session.prompt(), Some(Prompt::Permanent { .. })));

        for c in "ete".chars() {
            session.prompt_input_push(c);
        }
        session.confirm_permanent(&mut effector);
        assert_eq!(effector.delete_calls, vec![PathBuf::from("/scan/root/big")]);
        assert!(session.prompt().is_none());
        let explorer = session.explorer().unwrap();
        assert!(!explorer.rows.iter().any(|r| r.name == "big"));
        assert!(explorer.status().unwrap().contains("permanently deleted"));
    }

    #[test]
    fn test_permanent_delete_failure_sets_status_and_keeps_row() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::permanent(Err("refused: not owned".to_string()));
        session.request_delete();
        session.confirm_trash(&mut effector);
        for c in "delete".chars() {
            session.prompt_input_push(c);
        }
        session.confirm_permanent(&mut effector);

        assert!(session.prompt().is_none());
        let explorer = session.explorer().unwrap();
        assert!(explorer.rows.iter().any(|r| r.name == "big"));
        assert_eq!(explorer.status(), Some("error: refused: not owned"));
    }

    #[test]
    fn test_cancel_prompt_returns_to_browsing_untouched() {
        let mut session = browsing_session();
        session.request_delete();
        session.cancel_prompt();
        assert!(session.prompt().is_none());
        assert_eq!(session.explorer().unwrap().root.bytes, 12000);
    }

    #[test]
    fn test_trash_from_large_files_view_removes_file_and_shrinks_dirs() {
        let top_files = vec![LargeFile {
            path: PathBuf::from("/scan/root/big/f1.bin"),
            bytes: 5000,
            mtime: 1000,
        }];
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.on_finished(sample_root(), top_files, true);
        session.explorer_mut().unwrap().toggle_large_files();

        let mut effector = FakeEffector::trash_ok(5000);
        session.request_delete();
        session.confirm_trash(&mut effector);

        assert_eq!(
            effector.trash_calls,
            vec![PathBuf::from("/scan/root/big/f1.bin")]
        );
        let explorer = session.explorer().unwrap();
        assert!(explorer.top_files.is_empty());
        assert_eq!(explorer.root.bytes, 7000);
        let big = explorer
            .root
            .children
            .iter()
            .find(|c| c.name == "big")
            .unwrap();
        assert_eq!(big.bytes, 3000);
    }

    // --- handle_prompt_key routing ---

    #[test]
    fn test_handle_prompt_key_is_inactive_without_a_prompt() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::new();
        assert!(!handle_prompt_key(
            &mut session,
            key(KeyCode::Char('y')),
            &mut effector
        ));
    }

    #[test]
    fn test_handle_prompt_key_y_confirms_trash() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::trash_ok(8000);
        session.request_delete();
        assert!(handle_prompt_key(
            &mut session,
            key(KeyCode::Char('y')),
            &mut effector
        ));
        assert_eq!(effector.trash_calls.len(), 1);
        assert!(session.prompt().is_none());
    }

    #[test]
    fn test_handle_prompt_key_esc_cancels_trash_prompt() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::new();
        session.request_delete();
        handle_prompt_key(&mut session, key(KeyCode::Esc), &mut effector);
        assert!(session.prompt().is_none());
        assert!(effector.trash_calls.is_empty());
    }

    #[test]
    fn test_handle_prompt_key_types_word_and_submits_permanent() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::permanent(Ok(8000));
        session.request_delete();
        handle_prompt_key(&mut session, key(KeyCode::Char('y')), &mut effector);
        assert!(matches!(session.prompt(), Some(Prompt::Permanent { .. })));

        for c in "deletex".chars() {
            handle_prompt_key(&mut session, key(KeyCode::Char(c)), &mut effector);
        }
        handle_prompt_key(&mut session, key(KeyCode::Backspace), &mut effector);
        handle_prompt_key(&mut session, key(KeyCode::Enter), &mut effector);
        assert_eq!(effector.delete_calls.len(), 1);
    }

    // --- prompt rendering ---

    #[test]
    fn test_render_trash_prompt_shows_path_size_and_recoverable_note() {
        let mut session = browsing_session();
        session.request_delete();
        let text = full_text(&draw_session(&session));
        assert!(text.contains("confirm trash"));
        assert!(text.contains("/scan/root/big"));
        assert!(text.contains("size: 7.8 KiB"));
        assert!(text.contains("moves to trash — recoverable"));
        assert!(text.contains("y confirm · n back"));
    }

    #[test]
    fn test_render_permanent_prompt_shows_typed_input_and_red_title() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::cross_filesystem();
        session.request_delete();
        session.confirm_trash(&mut effector);
        session.prompt_input_push('d');
        session.prompt_input_push('e');

        let buffer = draw_session(&session);
        let text = full_text(&buffer);
        assert!(text.contains("PERMANENT DELETE"));
        assert!(text.contains("NOT recoverable"));
        assert!(text.contains("Type \"delete\" to confirm:"));
        assert!(text.contains("> de"));
        assert!(text.contains("enter confirm  esc back"));

        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("PERMANENT DELETE"))
            .unwrap();
        let x = row_text(&buffer, y).find("PERMANENT DELETE").unwrap() as u16;
        assert_eq!(buffer.cell((x, y)).unwrap().fg, Color::Red);
    }

    #[test]
    fn test_render_footer_shows_status_line_after_an_action() {
        let mut session = browsing_session();
        let mut effector = FakeEffector::trash_ok(8000);
        session.request_delete();
        session.confirm_trash(&mut effector);
        let text = full_text(&draw_session(&session));
        assert!(text.contains("trashed /scan/root/big"));
    }

    #[test]
    fn test_render_footer_shows_delete_key_hint() {
        let s = state();
        let text = full_text(&draw(&s));
        assert!(text.contains("d delete"));
    }

    // --- dry run ---

    #[test]
    fn test_dry_run_trash_marks_row_instead_of_removing_it() {
        let mut session = browsing_session();
        session.set_dry_run(true);
        let mut effector = FakeEffector::trash_ok(8000);
        session.request_delete();
        session.confirm_trash(&mut effector);

        // The effector was still driven (it journals dry_run=true)...
        assert_eq!(effector.trash_calls, vec![PathBuf::from("/scan/root/big")]);
        // ...but nothing about the tree changed except the mark.
        let explorer = session.explorer().unwrap();
        assert!(explorer.rows.iter().any(|r| r.name == "big"));
        assert_eq!(explorer.root.bytes, 12000);
        assert!(explorer.is_marked_would_trash(Path::new("/scan/root/big")));
        assert!(explorer.status().unwrap().contains("would trash"));
        assert!(explorer.status().unwrap().contains("dry run"));
    }

    #[test]
    fn test_dry_run_permanent_delete_marks_row_instead_of_removing_it() {
        let mut session = browsing_session();
        session.set_dry_run(true);
        let mut effector = FakeEffector::permanent(Ok(8000));
        session.request_delete();
        session.confirm_trash(&mut effector); // cross-fs -> permanent prompt
        for c in "delete".chars() {
            session.prompt_input_push(c);
        }
        session.confirm_permanent(&mut effector);

        let explorer = session.explorer().unwrap();
        assert!(explorer.rows.iter().any(|r| r.name == "big"));
        assert_eq!(explorer.root.bytes, 12000);
        assert!(explorer.is_marked_would_trash(Path::new("/scan/root/big")));
        assert!(explorer.status().unwrap().contains("dry run"));
    }

    #[test]
    fn test_render_marks_would_trash_dir_row() {
        let mut session = browsing_session();
        session.set_dry_run(true);
        let mut effector = FakeEffector::trash_ok(8000);
        session.request_delete();
        session.confirm_trash(&mut effector);
        let text = full_text(&draw_session(&session));
        let big_row = text.lines().find(|l| l.contains("> big")).unwrap();
        assert!(big_row.contains("(would trash)"));
    }

    #[test]
    fn test_render_marks_would_trash_large_file_row() {
        let top_files = vec![LargeFile {
            path: PathBuf::from("/scan/root/big/f1.bin"),
            bytes: 5000,
            mtime: 1000,
        }];
        let mut session = ExplorerSession::new(totals(), 10_000);
        session.set_dry_run(true);
        session.on_finished(sample_root(), top_files, true);
        session.explorer_mut().unwrap().toggle_large_files();
        let mut effector = FakeEffector::trash_ok(5000);
        session.request_delete();
        session.confirm_trash(&mut effector);

        let explorer = session.explorer().unwrap();
        assert_eq!(explorer.top_files.len(), 1, "dry run must not remove it");
        let text = full_text(&draw_session(&session));
        let row = text.lines().find(|l| l.contains("f1.bin")).unwrap();
        assert!(row.contains("(would trash)"));
    }
}
