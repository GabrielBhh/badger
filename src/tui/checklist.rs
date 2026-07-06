use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::core::item::{Group, Risk};
use crate::output::humanize_bytes;

/// One line of the rendered checklist body, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Row {
    GroupHeader(usize),
    Candidate(usize, usize),
    Skipped(usize, usize),
}

/// Pure state for the checklist screen: which candidate the cursor is on,
/// which candidates are selected, and how far the body is scrolled. No
/// terminal I/O lives here, so every transition is unit-testable directly.
pub struct ChecklistState {
    groups: Vec<Group>,
    rows: Vec<Row>,
    /// `(group_idx, candidate_idx)` pairs the cursor can land on, in display
    /// order. Whitelisted candidates are included (visible, but toggling
    /// them is a no-op); skipped entries and group headers are not
    /// cursor stops.
    nav: Vec<(usize, usize)>,
    cursor: usize,
    selected: HashSet<(usize, usize)>,
    scroll: usize,
}

fn build_rows(groups: &[Group]) -> Vec<Row> {
    let mut rows = Vec::new();
    for (gi, group) in groups.iter().enumerate() {
        if group.candidates.is_empty() && group.skipped.is_empty() {
            continue;
        }
        rows.push(Row::GroupHeader(gi));
        for ci in 0..group.candidates.len() {
            rows.push(Row::Candidate(gi, ci));
        }
        for si in 0..group.skipped.len() {
            rows.push(Row::Skipped(gi, si));
        }
    }
    rows
}

fn build_nav(rows: &[Row]) -> Vec<(usize, usize)> {
    rows.iter()
        .filter_map(|row| match row {
            Row::Candidate(gi, ci) => Some((*gi, *ci)),
            _ => None,
        })
        .collect()
}

impl ChecklistState {
    /// Builds checklist state from a scan's groups. Initial selection
    /// matches each candidate's engine-assigned default (`selectable`):
    /// Safe, non-whitelisted candidates start checked; Moderate/Risky/
    /// whitelisted candidates start unchecked.
    pub fn new(groups: Vec<Group>) -> ChecklistState {
        let rows = build_rows(&groups);
        let nav = build_nav(&rows);
        let selected = groups
            .iter()
            .enumerate()
            .flat_map(|(gi, group)| {
                group
                    .candidates
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.selectable)
                    .map(move |(ci, _)| (gi, ci))
            })
            .collect();
        ChecklistState {
            groups,
            rows,
            nav,
            cursor: 0,
            selected,
            scroll: 0,
        }
    }

    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// `(group_idx, candidate_idx)` under the cursor, or `None` if there are
    /// no selectable candidates at all.
    pub fn cursor(&self) -> Option<(usize, usize)> {
        self.nav.get(self.cursor).copied()
    }

    pub fn is_selected(&self, group_idx: usize, candidate_idx: usize) -> bool {
        self.selected.contains(&(group_idx, candidate_idx))
    }

    pub fn total_selected_bytes(&self) -> u64 {
        self.selected
            .iter()
            .map(|&(gi, ci)| self.groups[gi].candidates[ci].bytes)
            .sum()
    }

    pub fn total_selected_count(&self) -> usize {
        self.selected.len()
    }

    /// The full selection as `(group_idx, candidate_idx)` pairs, for the
    /// confirmation screen and execution wiring to consume.
    pub fn selection(&self) -> &HashSet<(usize, usize)> {
        &self.selected
    }

    pub fn move_down(&mut self) {
        if self.cursor + 1 < self.nav.len() {
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
        self.cursor = self.nav.len().saturating_sub(1);
    }

    fn is_togglable(&self, group_idx: usize, candidate_idx: usize) -> bool {
        !self.groups[group_idx].candidates[candidate_idx].whitelisted
    }

    /// Flips the cursor's candidate, unless it's whitelisted (permanently
    /// unselectable).
    pub fn toggle(&mut self) {
        let Some((gi, ci)) = self.cursor() else {
            return;
        };
        if !self.is_togglable(gi, ci) {
            return;
        }
        if !self.selected.insert((gi, ci)) {
            self.selected.remove(&(gi, ci));
        }
    }

    /// Toggles every non-whitelisted candidate in the cursor's group: if all
    /// of them are currently selected, deselects them all; otherwise selects
    /// them all.
    pub fn toggle_group(&mut self) {
        let Some((gi, _)) = self.cursor() else {
            return;
        };
        let togglable: Vec<usize> = self.groups[gi]
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.whitelisted)
            .map(|(ci, _)| ci)
            .collect();
        if togglable.is_empty() {
            return;
        }
        let all_selected = togglable
            .iter()
            .all(|&ci| self.selected.contains(&(gi, ci)));
        for ci in togglable {
            if all_selected {
                self.selected.remove(&(gi, ci));
            } else {
                self.selected.insert((gi, ci));
            }
        }
    }

    /// Toggles every non-whitelisted candidate in a non-Risky group, across
    /// all groups: if all of them are currently selected, deselects them
    /// all; otherwise selects them all. Risky-tier candidates are never
    /// touched — they require the separate typed-confirm opt-in.
    pub fn toggle_all(&mut self) {
        let target: Vec<(usize, usize)> = self
            .groups
            .iter()
            .enumerate()
            .filter(|(_, g)| g.risk != Risk::Risky)
            .flat_map(|(gi, g)| {
                g.candidates
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| !c.whitelisted)
                    .map(move |(ci, _)| (gi, ci))
            })
            .collect();
        if target.is_empty() {
            return;
        }
        let all_selected = target.iter().all(|pos| self.selected.contains(pos));
        for pos in target {
            if all_selected {
                self.selected.remove(&pos);
            } else {
                self.selected.insert(pos);
            }
        }
    }

    fn cursor_row_index(&self) -> Option<usize> {
        let (gi, ci) = self.cursor()?;
        self.rows.iter().position(|r| *r == Row::Candidate(gi, ci))
    }

    /// Adjusts the scroll offset (if needed) so the cursor's row is inside a
    /// `viewport_height`-row window. Callers must invoke this with the
    /// body area's height before rendering — `render` itself never mutates
    /// state.
    pub fn scroll_into_view(&mut self, viewport_height: usize) {
        if viewport_height == 0 {
            return;
        }
        let Some(cursor_row) = self.cursor_row_index() else {
            return;
        };
        if self.cursor == 0 {
            // The very first candidate: always show from the top so its
            // group header stays visible too.
            self.scroll = 0;
            return;
        }
        if cursor_row < self.scroll {
            self.scroll = cursor_row;
        } else if cursor_row >= self.scroll + viewport_height {
            self.scroll = cursor_row + 1 - viewport_height;
        }
        let max_scroll = self.rows.len().saturating_sub(viewport_height);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }

    pub fn scroll_offset(&self) -> usize {
        self.scroll
    }
}

/// Abstract keys the checklist screen reacts to, decoupled from crossterm's
/// event type so the mapping is a plain, testable function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Down,
    Up,
    Toggle,
    ToggleGroup,
    ToggleAll,
    Top,
    Bottom,
    Confirm,
    Cancel,
}

pub fn map_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => Some(Action::Down),
        KeyCode::Char('k') | KeyCode::Up => Some(Action::Up),
        KeyCode::Char(' ') => Some(Action::Toggle),
        KeyCode::Char('a') => Some(Action::ToggleAll),
        KeyCode::Char('g') => Some(Action::ToggleGroup),
        KeyCode::Home => Some(Action::Top),
        KeyCode::End => Some(Action::Bottom),
        KeyCode::Enter => Some(Action::Confirm),
        KeyCode::Char('q') | KeyCode::Esc => Some(Action::Cancel),
        _ => None,
    }
}

/// Renders the checklist screen. Read-only over `state`: call
/// `state.scroll_into_view(body_height)` beforehand to keep the cursor on
/// screen (the body is the frame's height minus the header and footer, 2
/// rows each).
pub fn render(frame: &mut Frame, state: &ChecklistState, colors: bool) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame.area());

    render_header(frame, chunks[0], state);
    render_body(frame, chunks[1], state, colors);
    render_footer(frame, chunks[2], state, colors);
}

/// Body area height a caller should pass to `scroll_into_view` for a frame
/// of total height `frame_height` (accounting for the fixed header/footer).
pub fn body_height(frame_height: u16) -> usize {
    frame_height.saturating_sub(4) as usize
}

fn render_header(frame: &mut Frame, area: Rect, state: &ChecklistState) {
    let group_count = state
        .groups
        .iter()
        .filter(|g| !g.candidates.is_empty() || !g.skipped.is_empty())
        .count();
    let candidate_count: usize = state.groups.iter().map(|g| g.candidates.len()).sum();
    let text = format!("badger clean — {group_count} groups, {candidate_count} candidates");
    frame.render_widget(Paragraph::new(text), area);
}

fn render_body(frame: &mut Frame, area: Rect, state: &ChecklistState, colors: bool) {
    let lines: Vec<Line> = state
        .rows
        .iter()
        .skip(state.scroll)
        .take(area.height as usize)
        .map(|row| render_row(state, *row, colors))
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_row(state: &ChecklistState, row: Row, colors: bool) -> Line<'static> {
    match row {
        Row::GroupHeader(gi) => {
            let group = &state.groups[gi];
            let (tag, color) = match group.risk {
                Risk::Safe => ("safe", Color::Green),
                Risk::Moderate => ("moderate", Color::Yellow),
                Risk::Risky => ("risky", Color::Red),
            };
            let tag_style = if colors {
                Style::default().fg(color)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::raw(format!("{} ", group.title)),
                Span::styled(format!("[{tag}]"), tag_style),
            ])
        }
        Row::Candidate(gi, ci) => {
            let candidate = &state.groups[gi].candidates[ci];
            let checked = state.is_selected(gi, ci);
            let is_cursor = state.cursor() == Some((gi, ci));
            let marker = if is_cursor { ">" } else { " " };
            let checkbox = if checked { "☑" } else { "☐" };
            let mut text = format!(
                "{marker} {checkbox} {}  {}",
                candidate.label,
                humanize_bytes(candidate.bytes)
            );
            if candidate.whitelisted {
                text.push_str(" (whitelisted)");
            }
            let style = if candidate.whitelisted {
                Style::default().add_modifier(Modifier::DIM)
            } else {
                Style::default()
            };
            Line::styled(text, style)
        }
        Row::Skipped(gi, si) => {
            let (label, reason) = &state.groups[gi].skipped[si];
            Line::styled(
                format!("    {label}  skipped: {reason}"),
                Style::default().add_modifier(Modifier::DIM),
            )
        }
    }
}

fn render_footer(frame: &mut Frame, area: Rect, state: &ChecklistState, colors: bool) {
    let total = humanize_bytes(state.total_selected_bytes());
    let count = state.total_selected_count();
    let recent = state
        .groups
        .iter()
        .flat_map(|g| g.candidates.iter())
        .filter(|c| c.label.contains(" (recent)"))
        .count();
    let whitelisted = state
        .groups
        .iter()
        .flat_map(|g| g.candidates.iter())
        .filter(|c| c.whitelisted)
        .count();
    let risky = state
        .groups
        .iter()
        .filter(|g| g.risk == Risk::Risky)
        .map(|g| g.candidates.len())
        .sum::<usize>();

    let mut status = format!("{count} selected · {total}");
    // Risky note first: the footer line clips (no wrap) on narrow terminals,
    // and the safety-relevant note must survive truncation.
    if risky > 0 {
        status.push_str(&format!(" · {risky} risky need typed confirm"));
    }
    if recent > 0 {
        status.push_str(&format!(" · {recent} recent excluded — space includes"));
    }
    if whitelisted > 0 {
        status.push_str(&format!(" · {whitelisted} whitelisted (locked)"));
    }

    let key_style = if colors {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let sep = Span::raw(" · ");
    let hints = Line::from(vec![
        Span::styled("space", key_style),
        Span::raw(" toggle"),
        sep.clone(),
        Span::styled("a", key_style),
        Span::raw(" all"),
        sep.clone(),
        Span::styled("g", key_style),
        Span::raw(" group"),
        sep.clone(),
        Span::styled("enter", key_style),
        Span::raw(" continue"),
        sep,
        Span::styled("q", key_style),
        Span::raw(" quit"),
    ]);

    let lines = vec![Line::from(status), hints];
    frame.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use std::path::PathBuf;

    use crate::core::item::Candidate;

    fn candidate(label: &str, bytes: u64, risk: Risk) -> Candidate {
        Candidate::new(Some(PathBuf::from("/x")), label.to_string(), bytes, risk)
    }

    fn whitelisted(mut c: Candidate) -> Candidate {
        c.whitelisted = true;
        c.selectable = false;
        c
    }

    fn group(
        title: &str,
        risk: Risk,
        candidates: Vec<Candidate>,
        skipped: Vec<(&str, &str)>,
    ) -> Group {
        Group {
            rule_id: title.to_lowercase(),
            title: title.to_string(),
            risk,
            requires_sudo: false,
            candidates,
            skipped: skipped
                .into_iter()
                .map(|(l, r)| (l.to_string(), r.to_string()))
                .collect(),
        }
    }

    /// group 0: Safe, 2 candidates (one whitelisted).
    /// group 1: Moderate, 1 candidate (opted-in allowed, starts unchecked).
    /// group 2: Risky, 1 candidate.
    /// group 3: only skipped entries, no candidates (not a cursor stop).
    fn sample_groups() -> Vec<Group> {
        vec![
            group(
                "User caches",
                Risk::Safe,
                vec![
                    candidate("~/.cache/a", 1024, Risk::Safe),
                    whitelisted(candidate("~/.cache/b", 2048, Risk::Safe)),
                ],
                vec![],
            ),
            group(
                "Journal",
                Risk::Moderate,
                vec![candidate("/var/log/journal", 4096, Risk::Moderate)],
                vec![],
            ),
            group(
                "Risky thing",
                Risk::Risky,
                vec![candidate("/risky/path", 8192, Risk::Risky)],
                vec![],
            ),
            group(
                "SSH",
                Risk::Safe,
                vec![],
                vec![("~/.ssh", "protected path")],
            ),
        ]
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    // --- construction / defaults ---

    #[test]
    fn test_new_state_preselects_only_safe_non_whitelisted_candidates() {
        let state = ChecklistState::new(sample_groups());
        assert!(state.is_selected(0, 0));
        assert!(!state.is_selected(0, 1), "whitelisted must start unchecked");
        assert!(!state.is_selected(1, 0), "moderate must start unchecked");
        assert!(!state.is_selected(2, 0), "risky must start unchecked");
    }

    #[test]
    fn test_new_state_cursor_starts_on_first_candidate() {
        let state = ChecklistState::new(sample_groups());
        assert_eq!(state.cursor(), Some((0, 0)));
    }

    #[test]
    fn test_group_with_only_skipped_entries_has_no_candidates_to_navigate() {
        let state = ChecklistState::new(sample_groups());
        // 4 candidates total across groups 0-2; none from group 3.
        assert_eq!(state.nav.len(), 4);
    }

    // --- movement ---

    #[test]
    fn test_move_down_advances_across_groups() {
        let mut state = ChecklistState::new(sample_groups());
        state.move_down();
        assert_eq!(state.cursor(), Some((0, 1)));
        state.move_down();
        assert_eq!(state.cursor(), Some((1, 0)));
    }

    #[test]
    fn test_move_down_stops_at_last_candidate() {
        let mut state = ChecklistState::new(sample_groups());
        for _ in 0..10 {
            state.move_down();
        }
        assert_eq!(state.cursor(), Some((2, 0)));
    }

    #[test]
    fn test_move_up_stops_at_first_candidate() {
        let mut state = ChecklistState::new(sample_groups());
        state.move_up();
        state.move_up();
        assert_eq!(state.cursor(), Some((0, 0)));
    }

    #[test]
    fn test_top_and_bottom_jump_to_ends() {
        let mut state = ChecklistState::new(sample_groups());
        state.bottom();
        assert_eq!(state.cursor(), Some((2, 0)));
        state.top();
        assert_eq!(state.cursor(), Some((0, 0)));
    }

    #[test]
    fn test_movement_on_empty_candidate_list_is_a_noop() {
        let mut state = ChecklistState::new(vec![group(
            "Only skipped",
            Risk::Safe,
            vec![],
            vec![("~/.ssh", "protected path")],
        )]);
        assert_eq!(state.cursor(), None);
        state.move_down();
        state.move_up();
        state.top();
        state.bottom();
        assert_eq!(state.cursor(), None);
    }

    // --- toggling ---

    #[test]
    fn test_toggle_flips_a_safe_candidate_off_then_on() {
        let mut state = ChecklistState::new(sample_groups());
        assert!(state.is_selected(0, 0));
        state.toggle();
        assert!(!state.is_selected(0, 0));
        state.toggle();
        assert!(state.is_selected(0, 0));
    }

    #[test]
    fn test_toggle_allows_opting_into_a_moderate_candidate() {
        let mut state = ChecklistState::new(sample_groups());
        state.move_down();
        state.move_down();
        assert_eq!(state.cursor(), Some((1, 0)));
        assert!(!state.is_selected(1, 0));
        state.toggle();
        assert!(state.is_selected(1, 0), "toggling Moderate must be allowed");
    }

    #[test]
    fn test_toggle_is_a_noop_on_whitelisted_candidate() {
        let mut state = ChecklistState::new(sample_groups());
        state.move_down();
        assert_eq!(state.cursor(), Some((0, 1)));
        state.toggle();
        assert!(!state.is_selected(0, 1));
    }

    #[test]
    fn test_toggle_group_selects_all_togglable_members_when_not_all_selected() {
        let mut state = ChecklistState::new(sample_groups());
        // group 0 has candidate 0 selected, candidate 1 whitelisted (never
        // selectable) — so "not all [togglable] selected" is vacuously true
        // only if candidate 0 were unselected. Start from a clean slate.
        state.toggle(); // deselect (0,0)
        assert!(!state.is_selected(0, 0));
        state.toggle_group();
        assert!(state.is_selected(0, 0));
        assert!(!state.is_selected(0, 1), "whitelisted stays excluded");
    }

    #[test]
    fn test_toggle_group_deselects_all_when_all_togglable_members_selected() {
        let mut state = ChecklistState::new(sample_groups());
        assert!(state.is_selected(0, 0));
        state.toggle_group();
        assert!(!state.is_selected(0, 0));
    }

    #[test]
    fn test_toggle_group_on_moderate_group_opts_in_all_candidates() {
        let mut state = ChecklistState::new(sample_groups());
        state.move_down();
        state.move_down();
        assert_eq!(state.cursor(), Some((1, 0)));
        state.toggle_group();
        assert!(state.is_selected(1, 0));
    }

    #[test]
    fn test_toggle_all_selects_every_safe_and_moderate_non_whitelisted_candidate() {
        let mut state = ChecklistState::new(sample_groups());
        state.toggle_all();
        assert!(state.is_selected(0, 0));
        assert!(state.is_selected(1, 0), "moderate must be included");
    }

    #[test]
    fn test_toggle_all_never_touches_risky_candidates() {
        let mut state = ChecklistState::new(sample_groups());
        assert!(!state.is_selected(2, 0));
        state.toggle_all();
        assert!(
            !state.is_selected(2, 0),
            "risky must never be auto-selected"
        );
    }

    #[test]
    fn test_toggle_all_excludes_whitelisted_candidates() {
        let mut state = ChecklistState::new(sample_groups());
        state.toggle_all();
        assert!(!state.is_selected(0, 1), "whitelisted stays excluded");
    }

    #[test]
    fn test_toggle_all_deselects_when_target_set_is_fully_selected() {
        let mut state = ChecklistState::new(sample_groups());
        state.toggle_all(); // select every safe/moderate candidate
        assert!(state.is_selected(0, 0));
        assert!(state.is_selected(1, 0));
        state.toggle_all(); // fully selected -> deselect
        assert!(!state.is_selected(0, 0));
        assert!(!state.is_selected(1, 0));
    }

    #[test]
    fn test_toggle_all_is_noop_when_target_set_is_empty() {
        let mut state = ChecklistState::new(vec![
            group(
                "Risky thing",
                Risk::Risky,
                vec![candidate("/risky/path", 8192, Risk::Risky)],
                vec![],
            ),
            group(
                "Whitelisted only",
                Risk::Safe,
                vec![whitelisted(candidate("~/.cache/c", 512, Risk::Safe))],
                vec![],
            ),
        ]);
        assert_eq!(state.total_selected_count(), 0);
        state.toggle_all();
        assert_eq!(state.total_selected_count(), 0);
    }

    // --- totals ---

    #[test]
    fn test_total_selected_bytes_and_count_reflect_selection() {
        let mut state = ChecklistState::new(sample_groups());
        assert_eq!(state.total_selected_count(), 1);
        assert_eq!(state.total_selected_bytes(), 1024);
        state.move_down();
        state.move_down();
        state.toggle(); // opt into the Moderate candidate (4096 bytes)
        assert_eq!(state.total_selected_count(), 2);
        assert_eq!(state.total_selected_bytes(), 1024 + 4096);
    }

    // --- scrolling ---

    #[test]
    fn test_scroll_into_view_advances_when_cursor_moves_past_viewport() {
        let mut state = ChecklistState::new(sample_groups());
        state.bottom(); // cursor on (2, 0), row index near the end
        state.scroll_into_view(2);
        assert!(state.scroll_offset() > 0);
    }

    #[test]
    fn test_scroll_into_view_retreats_when_cursor_moves_back_above_viewport() {
        let mut state = ChecklistState::new(sample_groups());
        state.bottom();
        state.scroll_into_view(2);
        assert!(state.scroll_offset() > 0);
        state.top();
        state.scroll_into_view(2);
        assert_eq!(state.scroll_offset(), 0);
    }

    #[test]
    fn test_scroll_into_view_is_noop_when_cursor_already_visible() {
        let mut state = ChecklistState::new(sample_groups());
        state.scroll_into_view(100);
        assert_eq!(state.scroll_offset(), 0);
    }

    // --- key mapping ---

    #[test]
    fn test_map_key_movement_and_control_keys() {
        assert_eq!(map_key(key(KeyCode::Char('j'))), Some(Action::Down));
        assert_eq!(map_key(key(KeyCode::Down)), Some(Action::Down));
        assert_eq!(map_key(key(KeyCode::Char('k'))), Some(Action::Up));
        assert_eq!(map_key(key(KeyCode::Up)), Some(Action::Up));
        assert_eq!(map_key(key(KeyCode::Char(' '))), Some(Action::Toggle));
        assert_eq!(map_key(key(KeyCode::Char('a'))), Some(Action::ToggleAll));
        assert_eq!(map_key(key(KeyCode::Char('g'))), Some(Action::ToggleGroup));
        assert_eq!(map_key(key(KeyCode::Home)), Some(Action::Top));
        assert_eq!(map_key(key(KeyCode::End)), Some(Action::Bottom));
        assert_eq!(map_key(key(KeyCode::Enter)), Some(Action::Confirm));
        assert_eq!(map_key(key(KeyCode::Char('q'))), Some(Action::Cancel));
        assert_eq!(map_key(key(KeyCode::Esc)), Some(Action::Cancel));
        assert_eq!(map_key(key(KeyCode::Char('z'))), None);
    }

    // --- rendering ---

    fn row_text(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
            .collect::<String>()
    }

    fn draw(state: &ChecklistState, colors: bool) -> Buffer {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state, colors)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn full_text(buffer: &Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| row_text(buffer, y))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn test_render_header_shows_group_and_candidate_counts() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        assert!(full_text(&buffer).contains("4 groups, 4 candidates"));
    }

    #[test]
    fn test_render_safe_candidate_shows_checked_box() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        let text = full_text(&buffer);
        assert!(text.contains("☑ ~/.cache/a"));
        assert!(text.contains("1.0 KiB"));
    }

    #[test]
    fn test_render_moderate_candidate_shows_unchecked_box() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        assert!(full_text(&buffer).contains("☐ /var/log/journal"));
    }

    #[test]
    fn test_render_whitelisted_candidate_is_marked_and_greyed() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        let text = full_text(&buffer);
        assert!(text.contains("☐ ~/.cache/b"));
        assert!(text.contains("(whitelisted)"));
        // find the whitelisted row and confirm it carries the DIM modifier.
        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("(whitelisted)"))
            .expect("whitelisted row must be rendered");
        let x = row_text(&buffer, y).find("(whitelisted)").unwrap() as u16;
        let cell = buffer.cell((x, y)).unwrap();
        assert!(cell.modifier.contains(Modifier::DIM));
    }

    #[test]
    fn test_render_skipped_entry_shows_reason_dimmed() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        let text = full_text(&buffer);
        assert!(text.contains("~/.ssh"));
        assert!(text.contains("skipped: protected path"));
    }

    #[test]
    fn test_render_footer_shows_total_selected_size() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        assert!(full_text(&buffer).contains("1 selected · 1.0 KiB"));
    }

    #[test]
    fn test_render_footer_selected_size_updates_live_after_toggle() {
        let mut state = ChecklistState::new(sample_groups());
        state.toggle(); // deselect the only default-selected candidate
        let buffer = draw(&state, true);
        assert!(full_text(&buffer).contains("0 selected · 0 B"));
    }

    #[test]
    fn test_render_footer_shows_key_hints() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        let text = full_text(&buffer);
        assert!(text.contains("space toggle · a all · g group · enter continue · q quit"));
    }

    #[test]
    fn test_render_footer_key_hint_is_colored_when_colors_enabled() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("space toggle"))
            .unwrap();
        let x = row_text(&buffer, y).find("space").unwrap() as u16;
        assert_eq!(buffer.cell((x, y)).unwrap().fg, Color::Cyan);
    }

    #[test]
    fn test_render_footer_key_hint_is_plain_without_colors() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, false);
        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("space toggle"))
            .unwrap();
        let x = row_text(&buffer, y).find("space").unwrap() as u16;
        assert_eq!(buffer.cell((x, y)).unwrap().fg, Color::Reset);
    }

    #[test]
    fn test_render_footer_notes_absent_when_no_recent_whitelisted_or_risky() {
        let state = ChecklistState::new(vec![group(
            "User caches",
            Risk::Safe,
            vec![candidate("~/.cache/a", 1024, Risk::Safe)],
            vec![],
        )]);
        let buffer = draw(&state, true);
        let text = full_text(&buffer);
        assert!(!text.contains("recent excluded"));
        assert!(!text.contains("whitelisted (locked)"));
        assert!(!text.contains("risky need typed confirm"));
    }

    #[test]
    fn test_render_footer_shows_recent_excluded_note() {
        let state = ChecklistState::new(vec![group(
            "User caches",
            Risk::Safe,
            vec![candidate("~/.cache/a (recent)", 1024, Risk::Safe)],
            vec![],
        )]);
        let buffer = draw(&state, true);
        assert!(
            full_text(&buffer).contains("1 recent excluded — space includes"),
            "{}",
            full_text(&buffer)
        );
    }

    #[test]
    fn test_render_footer_shows_whitelisted_note() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        assert!(full_text(&buffer).contains("1 whitelisted (locked)"));
    }

    #[test]
    fn test_render_footer_shows_risky_note() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        assert!(full_text(&buffer).contains("1 risky need typed confirm"));
    }

    #[test]
    fn test_render_risk_tag_color_reflects_group_risk() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("[safe]"))
            .unwrap();
        let x = row_text(&buffer, y).find("[safe]").unwrap() as u16;
        assert_eq!(buffer.cell((x, y)).unwrap().fg, Color::Green);
    }

    #[test]
    fn test_render_without_colors_uses_default_fg_for_risk_tag() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, false);
        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("[safe]"))
            .unwrap();
        let x = row_text(&buffer, y).find("[safe]").unwrap() as u16;
        assert_eq!(buffer.cell((x, y)).unwrap().fg, Color::Reset);
    }

    #[test]
    fn test_render_cursor_row_is_marked() {
        let state = ChecklistState::new(sample_groups());
        let buffer = draw(&state, true);
        let text = full_text(&buffer);
        assert!(text.contains("> ☑ ~/.cache/a"));
    }
}
