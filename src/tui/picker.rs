use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::output::humanize_bytes;
use crate::pkg::desktop::Category;
use crate::pkg::recommend::{self, Kind};
use crate::pkg::{AppEntry, Backend, InstalledPackage};

/// Which row source the picker is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// Friendly application names (`AppEntry`s), the default when any exist.
    Apps,
    /// Every installed package by its raw package name.
    Packages,
}

/// One displayable row: a name (an app's display name, or a package's own
/// name) paired with the underlying package it would remove.
pub struct PickerRow<'a> {
    pub display_name: &'a str,
    pub package: &'a InstalledPackage,
    /// Index into the picker's own `items`/packages — the key
    /// `PickerState::recommendations_for` looks badges up by.
    pub package_index: usize,
}

/// Pure state for `badger uninstall`'s package picker: a single-select list
/// over either friendly applications or every installed package, narrowed by
/// an incremental text filter (matched case-insensitively against name, or
/// also id in the Packages view). No terminal I/O lives here, so every
/// transition is unit-testable directly — mirrors `checklist::ChecklistState`'s
/// split between state and rendering.
pub struct PickerState {
    items: Vec<InstalledPackage>,
    apps: Vec<AppEntry>,
    view: View,
    filter: String,
    /// Indices into whichever of `apps`/`items` the current `view` reads
    /// from, matching the current filter, in display order.
    filtered: Vec<usize>,
    /// Index into `filtered`, not into `apps`/`items`.
    cursor: usize,
    /// First row index of `filtered` currently drawn at the body's top.
    scroll: usize,
    /// Advisory hints keyed by package index (see `pkg::recommend`) — empty
    /// until `set_recommendations` is called. Display-only: never affects
    /// `selected()`.
    recommendations: HashMap<usize, Vec<Kind>>,
    /// Ctrl-R-toggled "recommended only" filter, narrowing and re-sorting the
    /// Apps view on top of the text filter.
    recommended_only: bool,
}

impl PickerState {
    /// Starts in the Apps view when `apps` is non-empty, else falls back to
    /// the Packages view (headless system, scan failure) — an empty Apps
    /// view is never shown or advertised.
    pub fn new(items: Vec<InstalledPackage>, apps: Vec<AppEntry>) -> PickerState {
        let view = if apps.is_empty() {
            View::Packages
        } else {
            View::Apps
        };
        let mut state = PickerState {
            items,
            apps,
            view,
            filter: String::new(),
            filtered: Vec::new(),
            cursor: 0,
            scroll: 0,
            recommendations: HashMap::new(),
            recommended_only: false,
        };
        state.recompute_filter();
        state
    }

    /// Installs the advisory recommendations for the Applications view,
    /// keyed by package index — called once after a scan, before the picker
    /// is first drawn. Re-derives the filter since `recommended_only` may
    /// already be (harmlessly) set with nothing yet to narrow to.
    pub fn set_recommendations(&mut self, recommendations: Vec<recommend::Recommendation>) {
        self.recommendations = HashMap::new();
        for r in recommendations {
            self.recommendations
                .entry(r.package_index)
                .or_default()
                .push(r.kind);
        }
        self.recompute_filter();
    }

    /// Like `new`, but starts in the Packages view even when apps exist
    /// (`badger uninstall --packages`). Tab still toggles both ways at
    /// runtime; with an empty apps list this is identical to `new`'s own
    /// fallback (Packages view, no toggle advertised).
    pub fn new_starting_with_packages(
        items: Vec<InstalledPackage>,
        apps: Vec<AppEntry>,
    ) -> PickerState {
        let mut state = PickerState::new(items, apps);
        if state.view == View::Apps {
            state.view = View::Packages;
            state.recompute_filter();
        }
        state
    }

    pub fn view(&self) -> View {
        self.view
    }

    /// Whether there's an Apps view to toggle to at all — the footer hint
    /// and `Tab` both no-op when this is `false`.
    pub fn has_apps_view(&self) -> bool {
        !self.apps.is_empty()
    }

    /// Swaps between the Apps and Packages views (a no-op if there's no Apps
    /// view to swap to) and resets the filter — the simplest honest behavior,
    /// since a filter match in one view has no fixed meaning in the other.
    pub fn toggle_view(&mut self) {
        if !self.has_apps_view() {
            return;
        }
        self.view = match self.view {
            View::Apps => View::Packages,
            View::Packages => View::Apps,
        };
        self.filter.clear();
        self.recompute_filter();
    }

    pub fn filter_text(&self) -> &str {
        &self.filter
    }

    pub fn visible(&self) -> Vec<PickerRow<'_>> {
        match self.view {
            View::Apps => self
                .filtered
                .iter()
                .map(|&i| PickerRow {
                    display_name: self.apps[i].display_name.as_str(),
                    package: &self.items[self.apps[i].package_index],
                    package_index: self.apps[i].package_index,
                })
                .collect(),
            View::Packages => self
                .filtered
                .iter()
                .map(|&i| PickerRow {
                    display_name: self.items[i].name.as_str(),
                    package: &self.items[i],
                    package_index: i,
                })
                .collect(),
        }
    }

    /// Every recommendation for `package_index`, or an empty slice if it has
    /// none — display-only, consulted by `render` for the Apps view's badge
    /// suffixes.
    pub fn recommendations_for(&self, package_index: usize) -> &[Kind] {
        self.recommendations
            .get(&package_index)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Whether at least one app carries a recommendation at all — the
    /// footer's `ctrl-r recommended` hint (Apps view only) is conditional on
    /// this.
    pub fn has_any_recommendation(&self) -> bool {
        !self.recommendations.is_empty()
    }

    pub fn recommended_only(&self) -> bool {
        self.recommended_only
    }

    /// Toggles the "recommended only" filter and re-derives `filtered`. A
    /// no-op outside the Apps view (Packages rows never carry badges, so
    /// there is nothing meaningful to narrow to there).
    pub fn toggle_recommended_only(&mut self) {
        if self.view != View::Apps {
            return;
        }
        self.recommended_only = !self.recommended_only;
        self.recompute_filter();
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The package currently under the cursor, or `None` if the filter
    /// matches nothing. The same `InstalledPackage` either view would have
    /// selected, so the removal/leftover flow downstream never needs to
    /// care which view picked it.
    pub fn selected(&self) -> Option<&InstalledPackage> {
        match self.view {
            View::Apps => self
                .filtered
                .get(self.cursor)
                .map(|&i| &self.items[self.apps[i].package_index]),
            View::Packages => self.filtered.get(self.cursor).map(|&i| &self.items[i]),
        }
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
        self.filtered = match self.view {
            View::Apps => {
                let mut idxs: Vec<usize> = self
                    .apps
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| {
                        needle.is_empty() || a.display_name.to_lowercase().contains(&needle)
                    })
                    .map(|(i, _)| i)
                    .collect();
                if self.recommended_only {
                    idxs.retain(|&i| {
                        self.recommendations
                            .contains_key(&self.apps[i].package_index)
                    });
                    idxs.sort_by_key(|&i| self.recommendation_sort_key(self.apps[i].package_index));
                }
                idxs
            }
            View::Packages => self
                .items
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    needle.is_empty()
                        || p.name.to_lowercase().contains(&needle)
                        || p.id.to_lowercase().contains(&needle)
                })
                .map(|(i, _)| i)
                .collect(),
        };
        self.cursor = 0;
        self.scroll = 0;
    }

    /// Sort key for the recommended-only Apps view: duplicates first, then
    /// unused (oldest — largest `months` — first), then overlaps. A stable
    /// sort keeps ties in their prior (alphabetical) order. Normal-view
    /// alphabetical order is untouched — this is only ever consulted when
    /// `recommended_only` is set.
    fn recommendation_sort_key(&self, package_index: usize) -> (u8, i64) {
        let kinds = self.recommendations_for(package_index);
        if kinds.iter().any(|k| matches!(k, Kind::Duplicate { .. })) {
            return (0, 0);
        }
        if let Some(months) = kinds.iter().find_map(|k| match k {
            Kind::Unused { months } => Some(*months),
            _ => None,
        }) {
            return (1, -i64::from(months));
        }
        (2, 0)
    }

    pub fn move_down(&mut self) {
        if self.cursor + 1 < self.filtered.len() {
            self.cursor += 1;
        }
    }

    pub fn move_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn scroll_offset(&self) -> usize {
        self.scroll
    }

    /// Adjusts the scroll offset (if needed) so the cursor stays inside a
    /// `viewport_height`-row window. Callers must invoke this with the body
    /// area's height before rendering — mirrors `ExplorerState::scroll_into_view`.
    pub fn scroll_into_view(&mut self, viewport_height: usize) {
        if viewport_height == 0 {
            return;
        }
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + viewport_height {
            self.scroll = self.cursor + 1 - viewport_height;
        }
        let max_scroll = self.filtered.len().saturating_sub(viewport_height);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
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
    ToggleView,
    ToggleRecommended,
}

/// `ToggleRecommended` lives on Ctrl-R, not plain `r`: the picker's filter
/// box is a free-text box, and plain `r` must be typeable (e.g. "firefox")
/// without triggering the toggle.
pub fn map_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Down => Some(Action::Down),
        KeyCode::Up => Some(Action::Up),
        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => Some(Action::Down),
        KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => Some(Action::Up),
        KeyCode::Enter => Some(Action::Select),
        KeyCode::Esc => Some(Action::Cancel),
        KeyCode::Backspace => Some(Action::Backspace),
        KeyCode::Tab => Some(Action::ToggleView),
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(Action::ToggleRecommended)
        }
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

/// Body area height a caller should pass to `scroll_into_view` for a frame
/// of total height `frame_height` (accounting for the fixed header/footer).
pub fn body_height(frame_height: u16) -> usize {
    frame_height.saturating_sub(4) as usize
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

    let view_label = match state.view() {
        View::Apps => "applications",
        View::Packages => "all packages",
    };
    let header = vec![
        Line::from(format!(
            "badger uninstall — {view_label} — {} package(s)",
            state.visible().len()
        )),
        Line::from(format!("> {}", state.filter_text())),
    ];
    frame.render_widget(Paragraph::new(header), chunks[0]);

    let show_badges = state.view() == View::Apps;
    let body: Vec<Line> = state
        .visible()
        .iter()
        .enumerate()
        .skip(state.scroll_offset())
        .take(chunks[1].height as usize)
        .map(|(i, row)| {
            let recommendations = if show_badges {
                state.recommendations_for(row.package_index)
            } else {
                &[]
            };
            render_row(row, i == state.cursor(), recommendations)
        })
        .collect();
    frame.render_widget(Paragraph::new(body), chunks[1]);

    let mut footer_text =
        "type to filter  ctrl-j/k or up/down move  enter select  esc cancel".to_string();
    if state.has_apps_view() {
        footer_text.push_str(match state.view() {
            View::Apps => "  tab: all packages",
            View::Packages => "  tab: applications",
        });
    }
    if state.view() == View::Apps && state.has_any_recommendation() {
        footer_text.push_str("  ctrl-r recommended");
    }
    frame.render_widget(Paragraph::new(vec![Line::from(footer_text)]), chunks[2]);
}

fn render_row(row: &PickerRow, is_cursor: bool, recommendations: &[Kind]) -> Line<'static> {
    let marker = if is_cursor { ">" } else { " " };
    let size = match row.package.size_bytes {
        Some(bytes) => format!("  {}", humanize_bytes(bytes)),
        None => String::new(),
    };
    let hints: String = recommendations
        .iter()
        .map(|k| format!("  {}", recommendation_text(k)))
        .collect();
    Line::from(format!(
        "{marker} {} {} [{}]{size}{hints}",
        row.display_name,
        row.package.version,
        badge(row.package)
    ))
}

/// The advisory suffix text for one recommendation kind, e.g. `dup w/
/// flatpak`, `unused ~6mo`, `1 of 4 browsers` — always a plain-language
/// guess, never phrased as a directive.
fn recommendation_text(kind: &Kind) -> String {
    match kind {
        Kind::Duplicate { other_backend } => format!("dup w/ {}", other_backend.label()),
        Kind::Unused { months } => format!("unused ~{months}mo"),
        Kind::Overlap { category, count } => format!("1 of {count} {}", category_word(*category)),
    }
}

/// Plain-language word for a `.desktop` main category, used in the `1 of N
/// <word>` overlap badge.
fn category_word(category: Category) -> &'static str {
    match category {
        Category::WebBrowser => "browsers",
        Category::Email => "email clients",
        Category::AudioVideo | Category::Video => "video players",
        Category::Audio => "audio players",
        Category::TextEditor => "text editors",
        Category::IDE => "IDEs",
        Category::FileManager => "file managers",
        Category::TerminalEmulator => "terminals",
        Category::Graphics => "graphics apps",
        Category::Game => "games",
    }
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
        let state = PickerState::new(sample_items(), Vec::new());
        assert_eq!(state.visible().len(), 4);
        assert_eq!(state.cursor(), 0);
    }

    #[test]
    fn test_selected_is_none_on_empty_item_list() {
        let state = PickerState::new(Vec::new(), Vec::new());
        assert!(state.selected().is_none());
    }

    // --- filtering ---

    #[test]
    fn test_typing_narrows_by_case_insensitive_name_substring() {
        let mut state = PickerState::new(sample_items(), Vec::new());
        for c in "FIRE".chars() {
            state.push_char(c);
        }
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.visible()[0].display_name, "firefox");
    }

    #[test]
    fn test_filter_also_matches_on_id() {
        let mut state = PickerState::new(sample_items(), Vec::new());
        for c in "org.gimp".chars() {
            state.push_char(c);
        }
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.visible()[0].package.id, "org.gimp.GIMP");
    }

    #[test]
    fn test_backspace_widens_the_filter_back_out() {
        let mut state = PickerState::new(sample_items(), Vec::new());
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
        let mut state = PickerState::new(sample_items(), Vec::new());
        state.move_down();
        state.move_down();
        assert_eq!(state.cursor(), 2);
        state.push_char('h');
        assert_eq!(state.cursor(), 0);
    }

    #[test]
    fn test_filter_matching_nothing_yields_no_selection() {
        let mut state = PickerState::new(sample_items(), Vec::new());
        for c in "zzz-nope".chars() {
            state.push_char(c);
        }
        assert!(state.visible().is_empty());
        assert!(state.selected().is_none());
    }

    // --- movement ---

    #[test]
    fn test_move_down_and_up_within_bounds() {
        let mut state = PickerState::new(sample_items(), Vec::new());
        state.move_down();
        assert_eq!(state.cursor(), 1);
        state.move_up();
        assert_eq!(state.cursor(), 0);
    }

    #[test]
    fn test_move_up_stops_at_top_and_down_stops_at_bottom() {
        let mut state = PickerState::new(sample_items(), Vec::new());
        state.move_up();
        assert_eq!(state.cursor(), 0);
        for _ in 0..10 {
            state.move_down();
        }
        assert_eq!(state.cursor(), 3);
    }

    #[test]
    fn test_selected_reflects_cursor_within_filtered_list() {
        let mut state = PickerState::new(sample_items(), Vec::new());
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

    #[test]
    fn test_map_key_tab_is_toggle_view() {
        assert_eq!(map_key(key(KeyCode::Tab)), Some(Action::ToggleView));
    }

    #[test]
    fn test_map_key_ctrl_r_is_toggle_recommended() {
        assert_eq!(
            map_key(ctrl_key(KeyCode::Char('r'))),
            Some(Action::ToggleRecommended)
        );
    }

    // Regression: plain `r` used to toggle the recommended-only filter,
    // which made it impossible to type "r" into the text filter (e.g. to
    // search for "firefox"). Plain `r` must be ordinary filter text now;
    // only Ctrl-R toggles the filter.
    #[test]
    fn test_map_key_plain_r_is_typed_not_toggle_recommended() {
        assert_eq!(map_key(key(KeyCode::Char('r'))), Some(Action::Type('r')));
    }

    // --- apps view / toggle ---

    fn sample_apps() -> Vec<AppEntry> {
        vec![
            AppEntry {
                display_name: "Firefox".to_string(),
                package_index: 0,
            },
            AppEntry {
                display_name: "GIMP".to_string(),
                package_index: 2,
            },
        ]
    }

    #[test]
    fn test_new_state_defaults_to_apps_view_when_apps_exist() {
        let state = PickerState::new(sample_items(), sample_apps());
        assert_eq!(state.view(), View::Apps);
        assert_eq!(state.visible().len(), 2);
        assert_eq!(state.visible()[0].display_name, "Firefox");
    }

    #[test]
    fn test_new_state_falls_back_to_packages_view_when_apps_is_empty() {
        let state = PickerState::new(sample_items(), Vec::new());
        assert_eq!(state.view(), View::Packages);
        assert!(!state.has_apps_view());
    }

    #[test]
    fn test_selected_from_apps_view_maps_to_the_right_underlying_package() {
        let mut state = PickerState::new(sample_items(), sample_apps());
        state.move_down();
        // sample_apps()[1] is GIMP, mapped to package_index 2 (org.gimp.GIMP).
        assert_eq!(state.selected().unwrap().id, "org.gimp.GIMP");
    }

    #[test]
    fn test_toggle_view_switches_from_apps_to_packages_and_back() {
        let mut state = PickerState::new(sample_items(), sample_apps());
        assert_eq!(state.view(), View::Apps);
        state.toggle_view();
        assert_eq!(state.view(), View::Packages);
        assert_eq!(state.visible().len(), 4);
        state.toggle_view();
        assert_eq!(state.view(), View::Apps);
        assert_eq!(state.visible().len(), 2);
    }

    #[test]
    fn test_toggle_view_resets_the_filter_and_cursor() {
        let mut state = PickerState::new(sample_items(), sample_apps());
        state.push_char('F');
        assert_eq!(state.visible().len(), 1);
        state.move_down(); // no-op: only one match, but exercises the cursor
        state.toggle_view();
        assert_eq!(state.filter_text(), "");
        assert_eq!(state.cursor(), 0);
        assert_eq!(state.visible().len(), 4, "unfiltered Packages view");
    }

    #[test]
    fn test_toggle_view_is_a_no_op_when_there_is_no_apps_view() {
        let mut state = PickerState::new(sample_items(), Vec::new());
        state.toggle_view();
        assert_eq!(state.view(), View::Packages);
        assert!(!state.has_apps_view());
    }

    #[test]
    fn test_new_starting_with_packages_overrides_the_apps_default() {
        let mut state = PickerState::new_starting_with_packages(sample_items(), sample_apps());
        assert_eq!(state.view(), View::Packages);
        assert_eq!(state.visible().len(), 4);
        // Tab must still toggle both ways at runtime.
        assert!(state.has_apps_view());
        state.toggle_view();
        assert_eq!(state.view(), View::Apps);
        state.toggle_view();
        assert_eq!(state.view(), View::Packages);
    }

    #[test]
    fn test_new_starting_with_packages_with_empty_apps_matches_the_plain_fallback() {
        let mut state = PickerState::new_starting_with_packages(sample_items(), Vec::new());
        assert_eq!(state.view(), View::Packages);
        assert!(!state.has_apps_view());
        state.toggle_view();
        assert_eq!(state.view(), View::Packages, "toggle stays a no-op");
    }

    #[test]
    fn test_apps_view_filter_matches_on_display_name() {
        let mut state = PickerState::new(sample_items(), sample_apps());
        for c in "gimp".chars() {
            state.push_char(c);
        }
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.visible()[0].display_name, "GIMP");
    }

    // Regression: plain `r` used to toggle the recommended-only filter, so
    // typing a filter containing "r" (e.g. "firefox") could never reach the
    // text box. Dispatches through `map_key` exactly as the real key-handling
    // loop does, to pin the whole path, not just the mapping.
    #[test]
    fn test_typing_r_narrows_text_filter_and_does_not_toggle_recommended_only() {
        let mut state = PickerState::new(sample_items(), sample_apps());
        match map_key(key(KeyCode::Char('r'))).unwrap() {
            Action::Type(c) => state.push_char(c),
            Action::ToggleRecommended => state.toggle_recommended_only(),
            other => panic!("unexpected action for plain 'r': {other:?}"),
        }
        assert!(!state.recommended_only());
        assert_eq!(state.visible().len(), 1);
        assert_eq!(
            state.visible()[0].display_name,
            "Firefox",
            "GIMP has no 'r' in its name, Firefox does"
        );
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
        // Wide enough that the footer's "tab: ..." hint isn't clipped —
        // ratatui's Paragraph doesn't wrap by default.
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state, true)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_render_shows_name_version_and_backend_badge() {
        let state = PickerState::new(sample_items(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("firefox 121.0-1 [pacman]"));
    }

    #[test]
    fn test_render_shows_aur_badge_instead_of_pacman_for_aur_package() {
        let state = PickerState::new(sample_items(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("yay-bin 12.3.5-1 [aur]"));
    }

    #[test]
    fn test_render_shows_flatpak_and_snap_badges() {
        let state = PickerState::new(sample_items(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("[flatpak]"));
        assert!(text.contains("[snap]"));
    }

    #[test]
    fn test_render_shows_size_when_known_and_omits_it_when_not() {
        let state = PickerState::new(sample_items(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("org.gimp.GIMP 2.10.36 [flatpak]  245.0 MiB"));
        // firefox has no known size: its row must not carry a trailing size.
        let firefox_row = text.lines().find(|l| l.contains("firefox")).unwrap();
        assert!(firefox_row.trim_end().ends_with("[pacman]"));
    }

    #[test]
    fn test_render_narrows_visible_rows_when_filtered() {
        let mut state = PickerState::new(sample_items(), Vec::new());
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
        let state = PickerState::new(sample_items(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("> firefox"));
    }

    #[test]
    fn test_render_shows_filter_text_and_key_hints() {
        let mut state = PickerState::new(sample_items(), Vec::new());
        state.push_char('a');
        let text = full_text(&draw(&state));
        assert!(text.contains("> a"));
        assert!(text.contains("enter select"));
        assert!(text.contains("esc cancel"));
    }

    #[test]
    fn test_render_packages_view_with_no_apps_omits_the_toggle_hint() {
        let state = PickerState::new(sample_items(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(!text.contains("tab:"), "no apps view to toggle to");
    }

    #[test]
    fn test_render_apps_view_shows_display_names_not_package_names_and_still_shows_badge() {
        let state = PickerState::new(sample_items(), sample_apps());
        let text = full_text(&draw(&state));
        assert!(text.contains("Firefox 121.0-1 [pacman]"));
        assert!(text.contains("GIMP 2.10.36 [flatpak]  245.0 MiB"));
        assert!(
            !text.contains("firefox 121.0-1"),
            "raw package name must not show in apps view"
        );
        assert!(text.contains("applications"));
        assert!(text.contains("tab: all packages"));
    }

    #[test]
    fn test_render_packages_view_footer_hints_at_toggling_to_apps() {
        let mut state = PickerState::new(sample_items(), sample_apps());
        state.toggle_view();
        let text = full_text(&draw(&state));
        assert!(text.contains("all packages"));
        assert!(text.contains("tab: applications"));
    }

    // Threat: a hostile `.desktop` file's `Name=` is attacker-controlled and
    // ends up directly in a picker row (terminal-injection / spoofing via raw
    // ESC bytes, ANSI color sequences, or bidi override characters). Nothing
    // in badger sanitizes it before rendering — the protection comes entirely
    // from ratatui's `Buffer::set_stringn`, which strips control and
    // zero-width graphemes when writing cells. This test pins that upstream
    // behavior: if a future hand-rolled truncation/rendering path replaced
    // `set_stringn`'s use and dropped the filtering, this would catch it.
    // --- scrolling ---

    fn many_packages(n: usize) -> Vec<InstalledPackage> {
        (0..n)
            .map(|i| package(&format!("pkg-{i:02}"), "1.0", Backend::Pacman, false))
            .collect()
    }

    fn draw_sized(state: &PickerState, width: u16, height: u16) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state, true)).unwrap();
        terminal.backend().buffer().clone()
    }

    // Regression for the reported bug: moving the cursor down past the
    // bottom of the terminal didn't scroll the list — render always drew
    // from row 0 (no scroll offset existed), so the highlighted row walked
    // off the visible window instead of the window following it down.
    #[test]
    fn test_scrolling_down_past_viewport_brings_cursor_row_into_view() {
        let mut state = PickerState::new(many_packages(30), Vec::new());
        for _ in 0..20 {
            state.move_down();
        }
        assert_eq!(state.cursor(), 20);
        state.scroll_into_view(8); // 80x12 terminal: 12 - 4 fixed rows = 8
        let text = full_text(&draw_sized(&state, 80, 12));
        assert!(text.contains("pkg-20"), "cursor row must be visible");
        assert!(!text.contains("pkg-00"), "window must have scrolled down");
    }

    #[test]
    fn test_scrolling_back_up_above_viewport_brings_cursor_row_into_view() {
        let mut state = PickerState::new(many_packages(30), Vec::new());
        for _ in 0..25 {
            state.move_down();
        }
        state.scroll_into_view(8);
        assert!(state.scroll_offset() > 0);
        for _ in 0..20 {
            state.move_up();
        }
        assert_eq!(state.cursor(), 5);
        state.scroll_into_view(8);
        let text = full_text(&draw_sized(&state, 80, 12));
        assert!(
            text.contains("pkg-05"),
            "window must have followed cursor up"
        );
    }

    #[test]
    fn test_filter_narrowing_after_scroll_clamps_cursor_and_offset() {
        let mut state = PickerState::new(many_packages(30), Vec::new());
        for _ in 0..20 {
            state.move_down();
        }
        state.scroll_into_view(8);
        assert!(state.scroll_offset() > 0);
        // Narrow to a single match: recompute_filter resets the cursor to
        // 0, and the offset must be re-clamped against the now-tiny list
        // rather than pointing past its end (no panic either).
        for c in "pkg-05".chars() {
            state.push_char(c);
        }
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.cursor(), 0);
        state.scroll_into_view(8);
        assert_eq!(state.scroll_offset(), 0);
        let text = full_text(&draw_sized(&state, 80, 12));
        assert!(text.contains("> pkg-05"), "selected row must be visible");
    }

    #[test]
    fn test_toggle_view_from_scrolled_position_keeps_cursor_visible() {
        let apps: Vec<AppEntry> = (0..30)
            .map(|i| AppEntry {
                display_name: format!("App-{i:02}"),
                package_index: 0,
            })
            .collect();
        let mut state = PickerState::new(many_packages(30), apps);
        assert_eq!(state.view(), View::Apps);
        for _ in 0..20 {
            state.move_down();
        }
        state.scroll_into_view(8);
        assert!(state.scroll_offset() > 0);
        state.toggle_view();
        assert_eq!(state.view(), View::Packages);
        assert_eq!(state.cursor(), 0);
        state.scroll_into_view(8);
        assert_eq!(state.scroll_offset(), 0, "offset must reset with the view");
        let text = full_text(&draw_sized(&state, 80, 12));
        assert!(text.contains("> pkg-00"), "cursor row must be visible");
    }

    #[test]
    fn test_render_filters_hostile_desktop_name_control_and_bidi_chars() {
        let hostile_prefix = "PWNED\x1b[31m\x1b\u{202E}";
        let mut hostile_name = hostile_prefix.to_string();
        while hostile_name.chars().count() < 500 {
            hostile_name.push('A');
        }
        let items = vec![package("evil-pkg", "1.0-1", Backend::Pacman, false)];
        let apps = vec![AppEntry {
            display_name: hostile_name,
            package_index: 0,
        }];
        let state = PickerState::new(items, apps);

        let buffer = draw(&state);
        let text = full_text(&buffer);

        assert!(!text.contains('\x1b'), "raw ESC byte must not render");
        assert!(!text.contains('\u{202E}'), "bidi override must not render");
        assert!(
            text.contains("PWNED"),
            "leading printable prefix must still show"
        );
    }

    // --- recommendations / `r` toggle ---

    fn recommendation_fixture() -> (Vec<InstalledPackage>, Vec<AppEntry>) {
        // package_index: 0 firefox(pacman) 1 firefox(flatpak, dup of 0)
        // 2 oldapp(unused) 3 chromium(overlap) 4 brave(overlap) 5 plainapp(none)
        let items = vec![
            package("firefox", "121.0", Backend::Pacman, false),
            InstalledPackage {
                id: "org.mozilla.firefox".to_string(),
                ..package("Firefox", "121.0", Backend::Flatpak, false)
            },
            package("oldapp", "1.0", Backend::Pacman, false),
            package("chromium", "1.0", Backend::Pacman, false),
            package("brave", "1.0", Backend::Pacman, false),
            package("plainapp", "1.0", Backend::Pacman, false),
        ];
        // Alphabetical by display name, as pkg::applications produces.
        let apps = vec![
            app_entry("Brave", 4),
            app_entry("Chromium", 3),
            app_entry("Firefox", 0),
            app_entry("Firefox", 1),
            app_entry("OldApp", 2),
            app_entry("PlainApp", 5),
        ];
        (items, apps)
    }

    fn app_entry(display_name: &str, package_index: usize) -> AppEntry {
        AppEntry {
            display_name: display_name.to_string(),
            package_index,
        }
    }

    fn recommendation_fixture_recs() -> Vec<recommend::Recommendation> {
        vec![
            recommend::Recommendation {
                package_index: 0,
                kind: Kind::Duplicate {
                    other_backend: Backend::Flatpak,
                },
            },
            recommend::Recommendation {
                package_index: 1,
                kind: Kind::Duplicate {
                    other_backend: Backend::Pacman,
                },
            },
            recommend::Recommendation {
                package_index: 2,
                kind: Kind::Unused { months: 6 },
            },
            recommend::Recommendation {
                package_index: 3,
                kind: Kind::Overlap {
                    category: Category::WebBrowser,
                    count: 3,
                },
            },
            recommend::Recommendation {
                package_index: 4,
                kind: Kind::Overlap {
                    category: Category::WebBrowser,
                    count: 3,
                },
            },
        ]
    }

    fn visible_ids(state: &PickerState) -> Vec<String> {
        state
            .visible()
            .iter()
            .map(|r| r.package.id.clone())
            .collect()
    }

    #[test]
    fn test_has_any_recommendation_is_false_until_set() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        assert!(!state.has_any_recommendation());
        state.set_recommendations(recommendation_fixture_recs());
        assert!(state.has_any_recommendation());
    }

    #[test]
    fn test_toggle_recommended_only_narrows_to_only_flagged_apps() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());

        assert!(!state.recommended_only());
        state.toggle_recommended_only();
        assert!(state.recommended_only());
        assert_eq!(
            visible_ids(&state),
            vec![
                "firefox",
                "org.mozilla.firefox",
                "oldapp",
                "brave",
                "chromium"
            ],
            "duplicates first, then unused (oldest first), then overlaps"
        );
        state.toggle_recommended_only();
        assert!(!state.recommended_only());
    }

    #[test]
    fn test_normal_view_alphabetical_order_is_unaffected_by_recommendations() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());

        assert_eq!(
            state
                .visible()
                .iter()
                .map(|r| r.display_name.to_string())
                .collect::<Vec<_>>(),
            vec![
                "Brave", "Chromium", "Firefox", "Firefox", "OldApp", "PlainApp"
            ]
        );
    }

    #[test]
    fn test_recommended_only_combines_with_the_text_filter() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());
        state.toggle_recommended_only();

        for c in "old".chars() {
            state.push_char(c);
        }
        assert_eq!(visible_ids(&state), vec!["oldapp"]);

        state.backspace();
        state.backspace();
        state.backspace();
        for c in "plain".chars() {
            state.push_char(c);
        }
        assert!(
            visible_ids(&state).is_empty(),
            "plainapp matches the text filter but carries no recommendation"
        );
    }

    #[test]
    fn test_toggle_recommended_only_resets_cursor_and_scroll() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());
        state.move_down();
        state.move_down();
        assert_eq!(state.cursor(), 2);

        state.toggle_recommended_only();
        assert_eq!(state.cursor(), 0);
        assert_eq!(state.scroll_offset(), 0);
    }

    #[test]
    fn test_toggle_recommended_only_is_a_no_op_in_packages_view() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());
        state.toggle_view();
        assert_eq!(state.view(), View::Packages);

        state.toggle_recommended_only();
        assert!(!state.recommended_only());
        assert_eq!(state.visible().len(), 6, "all packages still shown");
    }

    // Deliberate UX: `toggle_view` (Tab) resets the text filter but leaves
    // `recommended_only` untouched, so switching to Packages and back to Apps
    // doesn't silently drop the recommended-only narrowing.
    #[test]
    fn test_recommended_only_survives_a_tab_round_trip() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());
        state.toggle_recommended_only();
        assert!(state.recommended_only());

        state.toggle_view();
        assert_eq!(state.view(), View::Packages);
        state.toggle_view();
        assert_eq!(state.view(), View::Apps);

        assert!(state.recommended_only(), "recommended_only survives Tab");
    }

    #[test]
    fn test_render_shows_recommendation_badges_in_apps_view() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());

        let text = full_text(&draw(&state));
        assert!(text.contains("Firefox 121.0 [pacman]  dup w/ flatpak"));
        assert!(text.contains("OldApp 1.0 [pacman]  unused ~6mo"));
        assert!(text.contains("Chromium 1.0 [pacman]  1 of 3 browsers"));
        let plain_row = text.lines().find(|l| l.contains("PlainApp")).unwrap();
        assert!(
            plain_row.trim_end().ends_with("[pacman]"),
            "an app with no recommendation gets no badge suffix"
        );
    }

    #[test]
    fn test_render_hint_shown_only_in_apps_view_and_only_when_a_recommendation_exists() {
        // Wide enough that the footer's combined "tab: ..." + "ctrl-r ..."
        // hints aren't clipped (unlike most tests here, `draw`'s default 100
        // cols isn't quite enough once both hints are present).
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items.clone(), apps.clone());
        assert!(
            !full_text(&draw_sized(&state, 140, 24)).contains("ctrl-r recommended"),
            "no recommendations set yet"
        );

        state.set_recommendations(recommendation_fixture_recs());
        assert!(full_text(&draw_sized(&state, 140, 24)).contains("ctrl-r recommended"));

        state.toggle_view();
        assert!(
            !full_text(&draw_sized(&state, 140, 24)).contains("ctrl-r recommended"),
            "hint is Apps-view only"
        );
    }

    #[test]
    fn test_render_packages_view_never_shows_badges() {
        let (items, apps) = recommendation_fixture();
        let mut state = PickerState::new(items, apps);
        state.set_recommendations(recommendation_fixture_recs());
        state.toggle_view();
        assert_eq!(state.view(), View::Packages);

        let text = full_text(&draw(&state));
        assert!(!text.contains("dup w/"));
        assert!(!text.contains("unused ~"));
        assert!(!text.contains(" browsers"));
    }
}
