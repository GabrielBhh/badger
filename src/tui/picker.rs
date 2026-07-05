use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::output::humanize_bytes;
use crate::pkg::{Backend, InstalledPackage};

/// Pure state for `badger uninstall`'s package picker: a single-select list
/// over every installed package, narrowed by an incremental text filter
/// (matched case-insensitively against name or id). No terminal I/O lives
/// here, so every transition is unit-testable directly — mirrors
/// `checklist::ChecklistState`'s split between state and rendering.
pub struct PickerState {
    items: Vec<InstalledPackage>,
    filter: String,
    /// Indices into `items` that match the current filter, in display order.
    filtered: Vec<usize>,
    /// Index into `filtered`, not into `items`.
    cursor: usize,
}

impl PickerState {
    pub fn new(items: Vec<InstalledPackage>) -> PickerState {
        let filtered = (0..items.len()).collect();
        PickerState {
            items,
            filter: String::new(),
            filtered,
            cursor: 0,
        }
    }

    pub fn filter_text(&self) -> &str {
        &self.filter
    }

    pub fn visible(&self) -> Vec<&InstalledPackage> {
        self.filtered.iter().map(|&i| &self.items[i]).collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The package currently under the cursor, or `None` if the filter
    /// matches nothing.
    pub fn selected(&self) -> Option<&InstalledPackage> {
        self.filtered.get(self.cursor).map(|&i| &self.items[i])
    }

    pub fn push_char(&mut self, c: char) {
        self.filter.push(c);
        self.recompute_filter();
    }

    pub fn backspace(&mut self) {
        self.filter.pop();
        self.recompute_filter();
    }

    /// Re-derives `filtered` from the current filter text and resets the
    /// cursor to the top — the previous cursor position has no fixed
    /// relationship to whatever the narrowed list looks like now.
    fn recompute_filter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.filtered = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                needle.is_empty()
                    || p.name.to_lowercase().contains(&needle)
                    || p.id.to_lowercase().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect();
        self.cursor = 0;
    }

    pub fn move_down(&mut self) {
        if self.cursor + 1 < self.filtered.len() {
            self.cursor += 1;
        }
    }

    pub fn move_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }
}

/// Abstract keys the picker screen reacts to. `j`/`k` are ordinary filter
/// text here (unlike the checklist), so navigation is arrow keys or
/// ctrl-j/ctrl-k rather than bare `j`/`k`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Down,
    Up,
    Type(char),
    Backspace,
    Select,
    Cancel,
}

pub fn map_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Down => Some(Action::Down),
        KeyCode::Up => Some(Action::Up),
        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => Some(Action::Down),
        KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => Some(Action::Up),
        KeyCode::Enter => Some(Action::Select),
        KeyCode::Esc => Some(Action::Cancel),
        KeyCode::Backspace => Some(Action::Backspace),
        KeyCode::Char(c) => Some(Action::Type(c)),
        _ => None,
    }
}

/// The `[pacman|aur|flatpak|snap]` badge for one package: a pacman package
/// installed from the AUR shows `aur` instead of its backend's own label.
fn badge(package: &InstalledPackage) -> &'static str {
    if package.backend == Backend::Pacman && package.aur {
        "aur"
    } else {
        package.backend.label()
    }
}

pub fn render(frame: &mut Frame, state: &PickerState, colors: bool) {
    let _ = colors; // reserved for parity with checklist::render's signature; no color use yet
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let header = vec![
        Line::from(format!(
            "badger uninstall — {} package(s)",
            state.visible().len()
        )),
        Line::from(format!("> {}", state.filter_text())),
    ];
    frame.render_widget(Paragraph::new(header), chunks[0]);

    let body: Vec<Line> = state
        .visible()
        .iter()
        .enumerate()
        .map(|(i, package)| render_row(package, i == state.cursor()))
        .collect();
    frame.render_widget(Paragraph::new(body), chunks[1]);

    let footer = vec![Line::from(
        "type to filter  ctrl-j/k or up/down move  enter select  esc cancel",
    )];
    frame.render_widget(Paragraph::new(footer), chunks[2]);
}

fn render_row(package: &InstalledPackage, is_cursor: bool) -> Line<'static> {
    let marker = if is_cursor { ">" } else { " " };
    let size = match package.size_bytes {
        Some(bytes) => format!("  {}", humanize_bytes(bytes)),
        None => String::new(),
    };
    Line::from(format!(
        "{marker} {} {} [{}]{size}",
        package.name,
        package.version,
        badge(package)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    fn package(name: &str, version: &str, backend: Backend, aur: bool) -> InstalledPackage {
        InstalledPackage {
            backend,
            id: name.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            size_bytes: None,
            aur,
        }
    }

    fn sample_items() -> Vec<InstalledPackage> {
        vec![
            package("firefox", "121.0-1", Backend::Pacman, false),
            package("yay-bin", "12.3.5-1", Backend::Pacman, true),
            InstalledPackage {
                size_bytes: Some(245 * 1024 * 1024),
                ..package("org.gimp.GIMP", "2.10.36", Backend::Flatpak, false)
            },
            package("hello", "2.10", Backend::Snap, false),
        ]
    }

    // --- construction / defaults ---

    #[test]
    fn test_new_state_shows_every_item_unfiltered() {
        let state = PickerState::new(sample_items());
        assert_eq!(state.visible().len(), 4);
        assert_eq!(state.cursor(), 0);
    }

    #[test]
    fn test_selected_is_none_on_empty_item_list() {
        let state = PickerState::new(Vec::new());
        assert!(state.selected().is_none());
    }

    // --- filtering ---

    #[test]
    fn test_typing_narrows_by_case_insensitive_name_substring() {
        let mut state = PickerState::new(sample_items());
        for c in "FIRE".chars() {
            state.push_char(c);
        }
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.visible()[0].name, "firefox");
    }

    #[test]
    fn test_filter_also_matches_on_id() {
        let mut state = PickerState::new(sample_items());
        for c in "org.gimp".chars() {
            state.push_char(c);
        }
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.visible()[0].id, "org.gimp.GIMP");
    }

    #[test]
    fn test_backspace_widens_the_filter_back_out() {
        let mut state = PickerState::new(sample_items());
        state.push_char('y');
        state.push_char('a');
        state.push_char('y');
        assert_eq!(state.visible().len(), 1);
        state.backspace();
        state.backspace();
        state.backspace();
        assert_eq!(state.filter_text(), "");
        assert_eq!(state.visible().len(), 4);
    }

    #[test]
    fn test_filter_change_resets_cursor_to_top() {
        let mut state = PickerState::new(sample_items());
        state.move_down();
        state.move_down();
        assert_eq!(state.cursor(), 2);
        state.push_char('h');
        assert_eq!(state.cursor(), 0);
    }

    #[test]
    fn test_filter_matching_nothing_yields_no_selection() {
        let mut state = PickerState::new(sample_items());
        for c in "zzz-nope".chars() {
            state.push_char(c);
        }
        assert!(state.visible().is_empty());
        assert!(state.selected().is_none());
    }

    // --- movement ---

    #[test]
    fn test_move_down_and_up_within_bounds() {
        let mut state = PickerState::new(sample_items());
        state.move_down();
        assert_eq!(state.cursor(), 1);
        state.move_up();
        assert_eq!(state.cursor(), 0);
    }

    #[test]
    fn test_move_up_stops_at_top_and_down_stops_at_bottom() {
        let mut state = PickerState::new(sample_items());
        state.move_up();
        assert_eq!(state.cursor(), 0);
        for _ in 0..10 {
            state.move_down();
        }
        assert_eq!(state.cursor(), 3);
    }

    #[test]
    fn test_selected_reflects_cursor_within_filtered_list() {
        let mut state = PickerState::new(sample_items());
        state.move_down();
        assert_eq!(state.selected().unwrap().name, "yay-bin");
    }

    // --- key mapping ---

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn test_map_key_arrows_and_control_keys() {
        assert_eq!(map_key(key(KeyCode::Down)), Some(Action::Down));
        assert_eq!(map_key(key(KeyCode::Up)), Some(Action::Up));
        assert_eq!(map_key(key(KeyCode::Enter)), Some(Action::Select));
        assert_eq!(map_key(key(KeyCode::Esc)), Some(Action::Cancel));
        assert_eq!(map_key(key(KeyCode::Backspace)), Some(Action::Backspace));
    }

    #[test]
    fn test_map_key_plain_j_and_k_are_typed_not_navigation() {
        assert_eq!(map_key(key(KeyCode::Char('j'))), Some(Action::Type('j')));
        assert_eq!(map_key(key(KeyCode::Char('k'))), Some(Action::Type('k')));
    }

    #[test]
    fn test_map_key_ctrl_j_and_ctrl_k_navigate() {
        assert_eq!(map_key(ctrl_key(KeyCode::Char('j'))), Some(Action::Down));
        assert_eq!(map_key(ctrl_key(KeyCode::Char('k'))), Some(Action::Up));
    }

    #[test]
    fn test_map_key_ordinary_char_is_type() {
        assert_eq!(map_key(key(KeyCode::Char('x'))), Some(Action::Type('x')));
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

    fn draw(state: &PickerState) -> Buffer {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state, true)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_render_shows_name_version_and_backend_badge() {
        let state = PickerState::new(sample_items());
        let text = full_text(&draw(&state));
        assert!(text.contains("firefox 121.0-1 [pacman]"));
    }

    #[test]
    fn test_render_shows_aur_badge_instead_of_pacman_for_aur_package() {
        let state = PickerState::new(sample_items());
        let text = full_text(&draw(&state));
        assert!(text.contains("yay-bin 12.3.5-1 [aur]"));
    }

    #[test]
    fn test_render_shows_flatpak_and_snap_badges() {
        let state = PickerState::new(sample_items());
        let text = full_text(&draw(&state));
        assert!(text.contains("[flatpak]"));
        assert!(text.contains("[snap]"));
    }

    #[test]
    fn test_render_shows_size_when_known_and_omits_it_when_not() {
        let state = PickerState::new(sample_items());
        let text = full_text(&draw(&state));
        assert!(text.contains("org.gimp.GIMP 2.10.36 [flatpak]  245.0 MiB"));
        // firefox has no known size: its row must not carry a trailing size.
        let firefox_row = text.lines().find(|l| l.contains("firefox")).unwrap();
        assert!(firefox_row.trim_end().ends_with("[pacman]"));
    }

    #[test]
    fn test_render_narrows_visible_rows_when_filtered() {
        let mut state = PickerState::new(sample_items());
        for c in "hello".chars() {
            state.push_char(c);
        }
        let text = full_text(&draw(&state));
        assert!(text.contains("hello"));
        assert!(!text.contains("firefox"));
        assert!(text.contains("1 package(s)"));
    }

    #[test]
    fn test_render_shows_cursor_marker_on_first_row() {
        let state = PickerState::new(sample_items());
        let text = full_text(&draw(&state));
        assert!(text.contains("> firefox"));
    }

    #[test]
    fn test_render_shows_filter_text_and_key_hints() {
        let mut state = PickerState::new(sample_items());
        state.push_char('a');
        let text = full_text(&draw(&state));
        assert!(text.contains("> a"));
        assert!(text.contains("enter select"));
        assert!(text.contains("esc cancel"));
    }
}
