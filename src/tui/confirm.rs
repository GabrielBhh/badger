use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::core::item::Risk;
use crate::output::humanize_bytes;
use crate::tui::checklist::ChecklistState;

/// One Moderate-risk group that has at least one selected candidate, named
/// explicitly so the confirmation screen can call it out.
#[derive(Debug, Clone, PartialEq)]
pub struct ModerateGroupSummary {
    pub title: String,
    pub bytes: u64,
    pub count: usize,
}

/// What happens when a key is handled: whether to leave the confirmation
/// screen, and in which direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Proceed,
    Back,
    None,
}

/// Pure state for the risk-scaled confirmation screen. Built once from a
/// `ChecklistState`'s current selection; typed digits (for the Risky
/// item-count check) live here so the state stays terminal-free and
/// testable without a `Term`.
pub struct ConfirmState {
    total_count: usize,
    total_bytes: u64,
    moderate_groups: Vec<ModerateGroupSummary>,
    /// Number of selected Risky candidates. `0` means no Risky items are
    /// selected, so no typed confirmation is required. No current rule is
    /// Risky-tier, but the checklist lets a later rule opt in, so this path
    /// is built (and tested) now.
    risky_required_count: usize,
    input: String,
}

impl ConfirmState {
    pub fn from_checklist(checklist: &ChecklistState) -> ConfirmState {
        let groups = checklist.groups();
        let mut moderate_groups = Vec::new();
        let mut risky_required_count = 0;

        for (gi, group) in groups.iter().enumerate() {
            let selected_in_group: Vec<usize> = group
                .candidates
                .iter()
                .enumerate()
                .filter(|(ci, _)| checklist.is_selected(gi, *ci))
                .map(|(ci, _)| ci)
                .collect();
            if selected_in_group.is_empty() {
                continue;
            }
            match group.risk {
                Risk::Moderate => {
                    let bytes = selected_in_group
                        .iter()
                        .map(|&ci| group.candidates[ci].bytes)
                        .sum();
                    moderate_groups.push(ModerateGroupSummary {
                        title: group.title.clone(),
                        bytes,
                        count: selected_in_group.len(),
                    });
                }
                Risk::Risky => risky_required_count += selected_in_group.len(),
                Risk::Safe => {}
            }
        }

        ConfirmState {
            total_count: checklist.total_selected_count(),
            total_bytes: checklist.total_selected_bytes(),
            moderate_groups,
            risky_required_count,
            input: String::new(),
        }
    }

    pub fn total_count(&self) -> usize {
        self.total_count
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn moderate_groups(&self) -> &[ModerateGroupSummary] {
        &self.moderate_groups
    }

    pub fn requires_typed_confirmation(&self) -> bool {
        self.risky_required_count > 0
    }

    pub fn risky_required_count(&self) -> usize {
        self.risky_required_count
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    fn input_matches(&self) -> bool {
        self.input.parse::<usize>() == Ok(self.risky_required_count)
    }

    fn push_digit(&mut self, c: char) {
        self.input.push(c);
    }

    fn backspace(&mut self) {
        self.input.pop();
    }
}

/// Applies one key to the confirmation screen, mutating typed-input state
/// and returning what the caller should do next.
pub fn handle_key(state: &mut ConfirmState, key: KeyEvent) -> Outcome {
    match key.code {
        KeyCode::Char('n') | KeyCode::Esc => Outcome::Back,
        KeyCode::Char('y') if !state.requires_typed_confirmation() => Outcome::Proceed,
        KeyCode::Enter if state.requires_typed_confirmation() => {
            if state.input_matches() {
                Outcome::Proceed
            } else {
                Outcome::None
            }
        }
        KeyCode::Char(c) if state.requires_typed_confirmation() && c.is_ascii_digit() => {
            state.push_digit(c);
            Outcome::None
        }
        KeyCode::Backspace if state.requires_typed_confirmation() => {
            state.backspace();
            Outcome::None
        }
        _ => Outcome::None,
    }
}

/// Plain yes/no confirmation with no typed-count requirement — used by
/// screens (like `badger uninstall`'s removal confirm) that have nothing
/// like the checklist's Moderate/Risky selection to summarize, just a fixed
/// set of informational lines shown verbatim.
pub struct PlainConfirmState {
    lines: Vec<String>,
}

impl PlainConfirmState {
    pub fn new(lines: Vec<String>) -> PlainConfirmState {
        PlainConfirmState { lines }
    }
}

/// Applies one key to a plain confirmation screen. Reuses `Outcome` from the
/// checklist-driven confirm above; there's no typed-input state to mutate.
pub fn handle_plain_key(key: KeyEvent) -> Outcome {
    match key.code {
        KeyCode::Char('y') => Outcome::Proceed,
        KeyCode::Char('n') | KeyCode::Esc => Outcome::Back,
        _ => Outcome::None,
    }
}

pub fn render_plain(frame: &mut Frame, state: &PlainConfirmState) {
    let mut lines: Vec<Line> = state.lines.iter().map(|l| Line::from(l.clone())).collect();
    lines.push(Line::from(""));
    lines.push(Line::from("y proceed  n/esc back"));
    frame.render_widget(Paragraph::new(lines), frame.area());
}

pub fn render(frame: &mut Frame, state: &ConfirmState) {
    let mut lines = vec![
        Line::from("badger clean — confirm"),
        Line::from(""),
        Line::from(format!(
            "About to clean {} item(s), freeing {}.",
            state.total_count(),
            humanize_bytes(state.total_bytes())
        )),
    ];

    if !state.moderate_groups().is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Moderate-risk groups included:"));
        for group in state.moderate_groups() {
            lines.push(Line::from(format!(
                "  - {} ({} item(s), {})",
                group.title,
                group.count,
                humanize_bytes(group.bytes)
            )));
        }
        lines.push(Line::styled(
            "Warning: Moderate-risk items can affect running services or recent state.",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }

    if state.requires_typed_confirmation() {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "This selection includes {} Risky item(s). Type that number to confirm:",
            state.risky_required_count()
        )));
        lines.push(Line::from(format!("> {}", state.input())));
        lines.push(Line::from(""));
        lines.push(Line::from("enter confirm  n/esc back"));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("y proceed  n/esc back"));
    }

    frame.render_widget(Paragraph::new(lines), frame.area());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::item::{Candidate, Group};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use std::path::PathBuf;

    fn candidate(label: &str, bytes: u64, risk: Risk) -> Candidate {
        Candidate::new(Some(PathBuf::from("/x")), label.to_string(), bytes, risk)
    }

    fn group(title: &str, risk: Risk, candidates: Vec<Candidate>) -> Group {
        Group {
            rule_id: title.to_lowercase(),
            title: title.to_string(),
            risk,
            requires_sudo: false,
            candidates,
            skipped: Vec::new(),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    fn safe_only_checklist() -> ChecklistState {
        ChecklistState::new(vec![group(
            "User caches",
            Risk::Safe,
            vec![candidate("~/.cache/a", 1024, Risk::Safe)],
        )])
    }

    fn checklist_with_moderate_selected() -> ChecklistState {
        let mut state = ChecklistState::new(vec![
            group(
                "User caches",
                Risk::Safe,
                vec![candidate("~/.cache/a", 1024, Risk::Safe)],
            ),
            group(
                "Journal",
                Risk::Moderate,
                vec![candidate("/var/log/journal", 4096, Risk::Moderate)],
            ),
        ]);
        state.move_down(); // land on the Moderate candidate
        state.toggle(); // opt in
        state
    }

    fn checklist_with_risky_selected() -> ChecklistState {
        let mut state = ChecklistState::new(vec![group(
            "Risky thing",
            Risk::Risky,
            vec![candidate("/risky/path", 512, Risk::Risky)],
        )]);
        state.toggle();
        state
    }

    // --- from_checklist ---

    #[test]
    fn test_from_checklist_computes_totals_from_current_selection() {
        let confirm = ConfirmState::from_checklist(&safe_only_checklist());
        assert_eq!(confirm.total_count(), 1);
        assert_eq!(confirm.total_bytes(), 1024);
        assert!(confirm.moderate_groups().is_empty());
        assert!(!confirm.requires_typed_confirmation());
    }

    #[test]
    fn test_from_checklist_lists_selected_moderate_group_by_name() {
        let confirm = ConfirmState::from_checklist(&checklist_with_moderate_selected());
        assert_eq!(confirm.moderate_groups().len(), 1);
        assert_eq!(confirm.moderate_groups()[0].title, "Journal");
        assert_eq!(confirm.moderate_groups()[0].bytes, 4096);
        assert_eq!(confirm.total_count(), 2);
    }

    #[test]
    fn test_from_checklist_requires_typed_confirmation_when_risky_selected() {
        let confirm = ConfirmState::from_checklist(&checklist_with_risky_selected());
        assert!(confirm.requires_typed_confirmation());
        assert_eq!(confirm.risky_required_count(), 1);
    }

    // --- handle_key ---

    #[test]
    fn test_y_proceeds_when_no_typed_confirmation_required() {
        let mut confirm = ConfirmState::from_checklist(&safe_only_checklist());
        assert_eq!(
            handle_key(&mut confirm, key(KeyCode::Char('y'))),
            Outcome::Proceed
        );
    }

    #[test]
    fn test_n_and_esc_go_back() {
        let mut confirm = ConfirmState::from_checklist(&safe_only_checklist());
        assert_eq!(
            handle_key(&mut confirm, key(KeyCode::Char('n'))),
            Outcome::Back
        );
        assert_eq!(handle_key(&mut confirm, key(KeyCode::Esc)), Outcome::Back);
    }

    #[test]
    fn test_y_is_ignored_when_typed_confirmation_is_required() {
        let mut confirm = ConfirmState::from_checklist(&checklist_with_risky_selected());
        assert_eq!(
            handle_key(&mut confirm, key(KeyCode::Char('y'))),
            Outcome::None
        );
    }

    #[test]
    fn test_typing_digits_builds_the_input_string() {
        let mut confirm = ConfirmState::from_checklist(&checklist_with_risky_selected());
        handle_key(&mut confirm, key(KeyCode::Char('1')));
        assert_eq!(confirm.input(), "1");
    }

    #[test]
    fn test_backspace_removes_last_typed_digit() {
        let mut confirm = ConfirmState::from_checklist(&checklist_with_risky_selected());
        handle_key(&mut confirm, key(KeyCode::Char('1')));
        handle_key(&mut confirm, key(KeyCode::Char('2')));
        handle_key(&mut confirm, key(KeyCode::Backspace));
        assert_eq!(confirm.input(), "1");
    }

    #[test]
    fn test_enter_proceeds_only_when_typed_count_matches() {
        let mut confirm = ConfirmState::from_checklist(&checklist_with_risky_selected());
        handle_key(&mut confirm, key(KeyCode::Char('9')));
        assert_eq!(handle_key(&mut confirm, key(KeyCode::Enter)), Outcome::None);
        handle_key(&mut confirm, key(KeyCode::Backspace));
        handle_key(&mut confirm, key(KeyCode::Char('1')));
        assert_eq!(
            handle_key(&mut confirm, key(KeyCode::Enter)),
            Outcome::Proceed
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

    fn draw(state: &ConfirmState) -> Buffer {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_render_shows_item_count_and_total_size() {
        let confirm = ConfirmState::from_checklist(&safe_only_checklist());
        let text = full_text(&draw(&confirm));
        assert!(text.contains("About to clean 1 item(s), freeing 1.0 KiB."));
        assert!(text.contains("y proceed  n/esc back"));
    }

    #[test]
    fn test_render_omits_moderate_section_when_none_selected() {
        let confirm = ConfirmState::from_checklist(&safe_only_checklist());
        let text = full_text(&draw(&confirm));
        assert!(!text.contains("Moderate-risk"));
    }

    #[test]
    fn test_render_names_moderate_group_and_warns() {
        let confirm = ConfirmState::from_checklist(&checklist_with_moderate_selected());
        let text = full_text(&draw(&confirm));
        assert!(text.contains("Moderate-risk groups included:"));
        assert!(text.contains("Journal"));
        assert!(text.contains("4.0 KiB"));
        assert!(text.contains("Warning: Moderate-risk items"));
    }

    #[test]
    fn test_render_shows_input_box_when_risky_confirmation_required() {
        let confirm = ConfirmState::from_checklist(&checklist_with_risky_selected());
        let text = full_text(&draw(&confirm));
        assert!(text.contains("includes 1 Risky item(s)"));
        assert!(text.contains("enter confirm  n/esc back"));
        assert!(!text.contains("y proceed"));
    }

    // --- PlainConfirmState / handle_plain_key / render_plain ---

    #[test]
    fn test_handle_plain_key_y_proceeds() {
        assert_eq!(handle_plain_key(key(KeyCode::Char('y'))), Outcome::Proceed);
    }

    #[test]
    fn test_handle_plain_key_n_and_esc_go_back() {
        assert_eq!(handle_plain_key(key(KeyCode::Char('n'))), Outcome::Back);
        assert_eq!(handle_plain_key(key(KeyCode::Esc)), Outcome::Back);
    }

    #[test]
    fn test_handle_plain_key_ignores_other_keys() {
        assert_eq!(handle_plain_key(key(KeyCode::Char('x'))), Outcome::None);
    }

    fn draw_plain(state: &PlainConfirmState) -> Buffer {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_plain(f, state)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_render_plain_shows_every_line_and_the_prompt() {
        let state = PlainConfirmState::new(vec![
            "About to remove firefox (121.0-1) via pacman.".to_string(),
            "Command: sudo pacman -Rns --noconfirm firefox".to_string(),
        ]);
        let text = full_text(&draw_plain(&state));
        assert!(text.contains("About to remove firefox (121.0-1) via pacman."));
        assert!(text.contains("Command: sudo pacman -Rns --noconfirm firefox"));
        assert!(text.contains("y proceed  n/esc back"));
    }
}
