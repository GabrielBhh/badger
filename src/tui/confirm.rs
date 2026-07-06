use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::core::item::Risk;
use crate::output::{count_label, humanize_bytes};
use crate::tui::checklist::ChecklistState;

/// What the confirmation is about to do, for plain-language wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Deletes files permanently (clean, purge).
    Delete,
    /// Runs maintenance tasks (optimize).
    Run,
}

/// One Moderate-risk group that has at least one selected candidate, named
/// explicitly so the confirmation screen can call it out.
#[derive(Debug, Clone, PartialEq)]
pub struct ModerateGroupSummary {
    pub title: String,
    pub bytes: u64,
    pub count: usize,
}

/// One Risky-tier group that has at least one selected candidate, named
/// explicitly so the confirmation screen can call it out alongside the
/// typed-count phrase.
#[derive(Debug, Clone, PartialEq)]
pub struct RiskyGroupSummary {
    pub title: String,
    pub count: usize,
    pub bytes: u64,
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
    risky_groups: Vec<RiskyGroupSummary>,
    /// Labels of every selected candidate in a `requires_sudo` group, in
    /// group order, so the confirmation screen can call out exactly what
    /// will run with elevated privileges.
    sudo_labels: Vec<String>,
    verb: Verb,
    dry_run: bool,
    input: String,
}

impl ConfirmState {
    pub fn from_checklist(checklist: &ChecklistState, verb: Verb, dry_run: bool) -> ConfirmState {
        let groups = checklist.groups();
        let mut moderate_groups = Vec::new();
        let mut risky_groups = Vec::new();
        let mut risky_required_count = 0;
        let mut sudo_labels = Vec::new();

        for (gi, group) in groups.iter().enumerate() {
            let selected_in_group: Vec<usize> = group
                .candidates
                .iter()
                .enumerate()
                .filter(|(ci, _)| checklist.is_selected(gi, *ci))
                .map(|(ci, _)| ci)
                .collect();

            if group.requires_sudo {
                sudo_labels.extend(
                    selected_in_group
                        .iter()
                        .map(|&ci| group.candidates[ci].label.clone()),
                );
            }

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
                Risk::Risky => {
                    let bytes = selected_in_group
                        .iter()
                        .map(|&ci| group.candidates[ci].bytes)
                        .sum();
                    let count = selected_in_group.len();
                    risky_required_count += count;
                    risky_groups.push(RiskyGroupSummary {
                        title: group.title.clone(),
                        count,
                        bytes,
                    });
                }
                Risk::Safe => {}
            }
        }

        ConfirmState {
            total_count: checklist.total_selected_count(),
            total_bytes: checklist.total_selected_bytes(),
            moderate_groups,
            risky_required_count,
            risky_groups,
            sudo_labels,
            verb,
            dry_run,
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
    lines.push(Line::from("y confirm · n back"));
    frame.render_widget(Paragraph::new(lines), frame.area());
}

/// Builds a key-hint line matching the checklist footer's style: each
/// `(key, label)` pair renders as a colored key followed by its plain-text
/// label, separated by " · ".
fn hints_line(colors: bool, pairs: &[(&str, &str)]) -> Line<'static> {
    let key_style = if colors {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let mut spans = Vec::new();
    for (i, (key, label)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" · "));
        }
        spans.push(Span::styled((*key).to_string(), key_style));
        spans.push(Span::raw(format!(" {label}")));
    }
    Line::from(spans)
}

pub fn render(frame: &mut Frame, state: &ConfirmState, colors: bool) {
    let mut lines = Vec::new();

    let title = match state.verb {
        Verb::Delete => "Confirm cleanup",
        Verb::Run => "Confirm tasks",
    };
    lines.push(Line::from(title));

    if state.dry_run {
        let banner = match state.verb {
            Verb::Delete => "DRY RUN — nothing will be deleted",
            Verb::Run => "DRY RUN — nothing will be executed",
        };
        let banner_style = if colors {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::styled(banner, banner_style));
    }

    lines.push(Line::from(""));

    let headline = match state.verb {
        Verb::Delete => format!(
            "Deletes {} ({})",
            count_label(state.total_count(), "item"),
            humanize_bytes(state.total_bytes())
        ),
        Verb::Run => format!("Runs {}", count_label(state.total_count(), "task")),
    };
    lines.push(Line::from(headline));

    if state.verb == Verb::Delete {
        lines.push(Line::from("Permanent — cannot be undone."));
    }

    if !state.moderate_groups.is_empty() {
        lines.push(Line::from(""));
        for group in &state.moderate_groups {
            lines.push(Line::from(format!(
                "  • {} — {}, {}",
                group.title,
                count_label(group.count, "item"),
                humanize_bytes(group.bytes)
            )));
        }
        let caution_style = if colors {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::styled(
            "  These can affect running services or recent state.",
            caution_style,
        ));
    }

    if !state.sudo_labels.is_empty() {
        lines.push(Line::from(""));
        for label in &state.sudo_labels {
            lines.push(Line::from(format!("  [sudo] {label}")));
        }
    }

    if !state.risky_groups.is_empty() {
        lines.push(Line::from(""));
        let risky_style = if colors {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        for group in &state.risky_groups {
            lines.push(Line::styled(
                format!(
                    "  ! {} — {}, {} — type {} to confirm",
                    group.title,
                    count_label(group.count, "item"),
                    humanize_bytes(group.bytes),
                    state.risky_required_count
                ),
                risky_style,
            ));
        }
    }

    lines.push(Line::from(""));
    if state.requires_typed_confirmation() {
        lines.push(Line::from(format!(
            "type the item count to proceed: {}_",
            state.input()
        )));
        lines.push(hints_line(colors, &[("enter", "confirm"), ("n", "back")]));
    } else {
        lines.push(hints_line(colors, &[("y", "confirm"), ("n", "back")]));
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

    fn sudo_group(title: &str, risk: Risk, candidates: Vec<Candidate>) -> Group {
        let mut g = group(title, risk, candidates);
        g.requires_sudo = true;
        g
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

    fn two_safe_checklist() -> ChecklistState {
        ChecklistState::new(vec![group(
            "User caches",
            Risk::Safe,
            vec![
                candidate("~/.cache/a", 512, Risk::Safe),
                candidate("~/.cache/b", 512, Risk::Safe),
            ],
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

    fn checklist_with_two_risky_selected() -> ChecklistState {
        let mut state = ChecklistState::new(vec![group(
            "Risky thing",
            Risk::Risky,
            vec![
                candidate("/risky/path/1", 512, Risk::Risky),
                candidate("/risky/path/2", 512, Risk::Risky),
            ],
        )]);
        state.toggle();
        state.move_down();
        state.toggle();
        state
    }

    fn checklist_with_sudo_selected() -> ChecklistState {
        ChecklistState::new(vec![sudo_group(
            "Trim SSD free space",
            Risk::Safe,
            vec![candidate(
                "Trim free space on all mounted filesystems (fstrim -av)",
                0,
                Risk::Safe,
            )],
        )])
    }

    fn run_checklist() -> ChecklistState {
        ChecklistState::new(vec![group(
            "Refresh font cache",
            Risk::Safe,
            vec![candidate("fc-cache -f", 0, Risk::Safe)],
        )])
    }

    // --- from_checklist ---

    #[test]
    fn test_from_checklist_computes_totals_from_current_selection() {
        let confirm = ConfirmState::from_checklist(&safe_only_checklist(), Verb::Delete, false);
        assert_eq!(confirm.total_count(), 1);
        assert_eq!(confirm.total_bytes(), 1024);
        assert!(confirm.moderate_groups().is_empty());
        assert!(!confirm.requires_typed_confirmation());
    }

    #[test]
    fn test_from_checklist_lists_selected_moderate_group_by_name() {
        let confirm =
            ConfirmState::from_checklist(&checklist_with_moderate_selected(), Verb::Delete, false);
        assert_eq!(confirm.moderate_groups().len(), 1);
        assert_eq!(confirm.moderate_groups()[0].title, "Journal");
        assert_eq!(confirm.moderate_groups()[0].bytes, 4096);
        assert_eq!(confirm.total_count(), 2);
    }

    #[test]
    fn test_from_checklist_requires_typed_confirmation_when_risky_selected() {
        let confirm =
            ConfirmState::from_checklist(&checklist_with_risky_selected(), Verb::Delete, false);
        assert!(confirm.requires_typed_confirmation());
        assert_eq!(confirm.risky_required_count(), 1);
    }

    #[test]
    fn test_from_checklist_collects_risky_group_summary_with_title_count_bytes() {
        let confirm =
            ConfirmState::from_checklist(&checklist_with_two_risky_selected(), Verb::Delete, false);
        assert_eq!(confirm.risky_groups.len(), 1);
        assert_eq!(confirm.risky_groups[0].title, "Risky thing");
        assert_eq!(confirm.risky_groups[0].count, 2);
        assert_eq!(confirm.risky_groups[0].bytes, 1024);
        assert_eq!(confirm.risky_required_count, 2);
    }

    #[test]
    fn test_from_checklist_collects_sudo_labels_from_selected_sudo_group_candidates() {
        let state = ChecklistState::new(vec![
            sudo_group(
                "Sudo task",
                Risk::Safe,
                vec![candidate("cmd one", 0, Risk::Safe)],
            ),
            group(
                "Non-sudo",
                Risk::Safe,
                vec![candidate("~/.cache/a", 1024, Risk::Safe)],
            ),
        ]);
        let confirm = ConfirmState::from_checklist(&state, Verb::Run, false);
        assert_eq!(confirm.sudo_labels, vec!["cmd one".to_string()]);
    }

    #[test]
    fn test_from_checklist_excludes_unselected_candidates_from_sudo_labels() {
        let mut state = ChecklistState::new(vec![sudo_group(
            "Sudo moderate",
            Risk::Moderate,
            vec![candidate("moderate task", 0, Risk::Moderate)],
        )]);
        let confirm = ConfirmState::from_checklist(&state, Verb::Run, false);
        assert!(confirm.sudo_labels.is_empty());

        state.toggle(); // opt the moderate candidate in
        let confirm = ConfirmState::from_checklist(&state, Verb::Run, false);
        assert_eq!(confirm.sudo_labels, vec!["moderate task".to_string()]);
    }

    // --- handle_key ---

    #[test]
    fn test_y_proceeds_when_no_typed_confirmation_required() {
        let mut confirm = ConfirmState::from_checklist(&safe_only_checklist(), Verb::Delete, false);
        assert_eq!(
            handle_key(&mut confirm, key(KeyCode::Char('y'))),
            Outcome::Proceed
        );
    }

    #[test]
    fn test_n_and_esc_go_back() {
        let mut confirm = ConfirmState::from_checklist(&safe_only_checklist(), Verb::Delete, false);
        assert_eq!(
            handle_key(&mut confirm, key(KeyCode::Char('n'))),
            Outcome::Back
        );
        assert_eq!(handle_key(&mut confirm, key(KeyCode::Esc)), Outcome::Back);
    }

    #[test]
    fn test_y_is_ignored_when_typed_confirmation_is_required() {
        let mut confirm =
            ConfirmState::from_checklist(&checklist_with_risky_selected(), Verb::Delete, false);
        assert_eq!(
            handle_key(&mut confirm, key(KeyCode::Char('y'))),
            Outcome::None
        );
    }

    #[test]
    fn test_typing_digits_builds_the_input_string() {
        let mut confirm =
            ConfirmState::from_checklist(&checklist_with_risky_selected(), Verb::Delete, false);
        handle_key(&mut confirm, key(KeyCode::Char('1')));
        assert_eq!(confirm.input(), "1");
    }

    #[test]
    fn test_backspace_removes_last_typed_digit() {
        let mut confirm =
            ConfirmState::from_checklist(&checklist_with_risky_selected(), Verb::Delete, false);
        handle_key(&mut confirm, key(KeyCode::Char('1')));
        handle_key(&mut confirm, key(KeyCode::Char('2')));
        handle_key(&mut confirm, key(KeyCode::Backspace));
        assert_eq!(confirm.input(), "1");
    }

    #[test]
    fn test_enter_proceeds_only_when_typed_count_matches() {
        let mut confirm =
            ConfirmState::from_checklist(&checklist_with_risky_selected(), Verb::Delete, false);
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

    fn draw(state: &ConfirmState, colors: bool) -> Buffer {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state, colors)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_render_safe_only_shows_headline_permanence_and_plain_hints() {
        let confirm = ConfirmState::from_checklist(&safe_only_checklist(), Verb::Delete, false);
        let text = full_text(&draw(&confirm, true));
        assert!(text.contains("Confirm cleanup"));
        assert!(text.contains("Deletes 1 item (1.0 KiB)"));
        assert!(text.contains("Permanent — cannot be undone."));
        assert!(text.contains("y confirm · n back"));
        assert!(!text.contains("DRY RUN"));
        assert!(!text.contains('•'));
        assert!(!text.contains("[sudo]"));
        assert!(!text.contains("type the item count"));
    }

    #[test]
    fn test_render_with_moderate_shows_bullet_and_caution_line() {
        let confirm =
            ConfirmState::from_checklist(&checklist_with_moderate_selected(), Verb::Delete, false);
        let buffer = draw(&confirm, true);
        let text = full_text(&buffer);
        assert!(text.contains("• Journal — 1 item, 4.0 KiB"));
        assert!(text.contains("These can affect running services or recent state."));

        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("These can affect"))
            .expect("caution line must be rendered");
        let x = row_text(&buffer, y).find("These").unwrap() as u16;
        assert!(
            buffer
                .cell((x, y))
                .unwrap()
                .modifier
                .contains(Modifier::BOLD)
        );
    }

    #[test]
    fn test_render_with_sudo_shows_verbatim_label_prefixed() {
        let confirm =
            ConfirmState::from_checklist(&checklist_with_sudo_selected(), Verb::Run, false);
        let text = full_text(&draw(&confirm, true));
        assert!(text.contains("[sudo] Trim free space on all mounted filesystems (fstrim -av)"));
    }

    #[test]
    fn test_render_with_risky_shows_red_line_input_label_and_no_y_confirm() {
        let confirm =
            ConfirmState::from_checklist(&checklist_with_risky_selected(), Verb::Delete, false);
        let buffer = draw(&confirm, true);
        let text = full_text(&buffer);
        assert!(text.contains("! Risky thing — 1 item, 512 B — type 1 to confirm"));
        assert!(text.contains("type the item count to proceed: _"));
        assert!(text.contains("enter confirm · n back"));
        assert!(!text.contains("y confirm"));

        let y = (0..buffer.area.height)
            .find(|&y| row_text(&buffer, y).contains("Risky thing"))
            .unwrap();
        let x = row_text(&buffer, y).find('!').unwrap() as u16;
        assert_eq!(buffer.cell((x, y)).unwrap().fg, Color::Red);

        let plain_buffer = draw(&confirm, false);
        let y = (0..plain_buffer.area.height)
            .find(|&y| row_text(&plain_buffer, y).contains("Risky thing"))
            .unwrap();
        let x = row_text(&plain_buffer, y).find('!').unwrap() as u16;
        assert_eq!(plain_buffer.cell((x, y)).unwrap().fg, Color::Reset);
    }

    #[test]
    fn test_render_dry_run_banner_present_when_true_absent_when_false() {
        let dry = ConfirmState::from_checklist(&safe_only_checklist(), Verb::Delete, true);
        assert!(full_text(&draw(&dry, true)).contains("DRY RUN — nothing will be deleted"));

        let not_dry = ConfirmState::from_checklist(&safe_only_checklist(), Verb::Delete, false);
        assert!(!full_text(&draw(&not_dry, true)).contains("DRY RUN"));
    }

    #[test]
    fn test_render_run_verb_shows_tasks_title_and_no_size_or_permanence() {
        let confirm = ConfirmState::from_checklist(&run_checklist(), Verb::Run, false);
        let text = full_text(&draw(&confirm, true));
        assert!(text.contains("Confirm tasks"));
        assert!(text.contains("Runs 1 task"));
        assert!(!text.contains("Permanent"));
        assert!(!text.contains("(0 B)"));
    }

    #[test]
    fn test_render_run_verb_dry_run_banner_says_executed() {
        let confirm = ConfirmState::from_checklist(&run_checklist(), Verb::Run, true);
        assert!(full_text(&draw(&confirm, true)).contains("DRY RUN — nothing will be executed"));
    }

    #[test]
    fn test_render_singular_vs_plural_wording() {
        let one = ConfirmState::from_checklist(&safe_only_checklist(), Verb::Delete, false);
        assert!(full_text(&draw(&one, true)).contains("Deletes 1 item (1.0 KiB)"));

        let two = ConfirmState::from_checklist(&two_safe_checklist(), Verb::Delete, false);
        assert!(full_text(&draw(&two, true)).contains("Deletes 2 items (1.0 KiB)"));

        let one_task = ConfirmState::from_checklist(&run_checklist(), Verb::Run, false);
        assert!(full_text(&draw(&one_task, true)).contains("Runs 1 task"));
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
        assert!(text.contains("y confirm · n back"));
    }
}
