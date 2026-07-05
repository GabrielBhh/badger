//! Helpers shared by every interactive top-level command (`clean`, `purge`,
//! ...): driving the checklist/confirm TUI loop against a scan's groups, and
//! reading back a run's journal for execution-time notes. Both are already
//! generic over `Group`/`Journal` with no `Rule`/`Action` awareness, so they
//! don't belong to any one command.

use std::collections::HashSet;

use crossterm::event::{Event, KeyEventKind};
use serde::Serialize;

use crate::core::exec::Summary;
use crate::core::item::Group;
use crate::safety::journal::Journal;
use crate::tui::{self, checklist, confirm};

/// The `--json` payload every scan-and-execute command (`clean`, `purge`,
/// `optimize`) emits: the scanned groups, the execution summary (absent for
/// a plain plan), and whether this was a dry run.
#[derive(Serialize)]
pub(crate) struct JsonOutput<'a> {
    pub(crate) groups: &'a [Group],
    pub(crate) summary: Option<&'a Summary>,
    pub(crate) dry_run: bool,
}

/// Drives the checklist -> confirm key-handling loop against a real
/// terminal. Returns the confirmed selection, or `None` if the person
/// cancelled from the checklist.
pub(crate) fn drive_selection(
    terminal: &mut tui::Term,
    groups: Vec<Group>,
) -> anyhow::Result<Option<HashSet<(usize, usize)>>> {
    let mut state = checklist::ChecklistState::new(groups);
    let mut confirming: Option<confirm::ConfirmState> = None;
    let colors = tui::colors_enabled_now();

    loop {
        let height = terminal.size()?.height;
        if let Some(confirm_state) = &confirming {
            terminal.draw(|f| confirm::render(f, confirm_state))?;
        } else {
            state.scroll_into_view(checklist::body_height(height));
            terminal.draw(|f| checklist::render(f, &state, colors))?;
        }

        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }

        if let Some(confirm_state) = &mut confirming {
            match confirm::handle_key(confirm_state, key) {
                confirm::Outcome::Proceed => return Ok(Some(state.selection().clone())),
                confirm::Outcome::Back => confirming = None,
                confirm::Outcome::None => {}
            }
            continue;
        }

        match checklist::map_key(key) {
            Some(checklist::Action::Down) => state.move_down(),
            Some(checklist::Action::Up) => state.move_up(),
            Some(checklist::Action::Toggle) => state.toggle(),
            Some(checklist::Action::ToggleGroup) => state.toggle_group(),
            Some(checklist::Action::Top) => state.top(),
            Some(checklist::Action::Bottom) => state.bottom(),
            Some(checklist::Action::Cancel) => return Ok(None),
            Some(checklist::Action::Confirm) => {
                confirming = Some(confirm::ConfirmState::from_checklist(&state));
            }
            None => {}
        }
    }
}

/// Reads back the journal for `run_id` and formats "note: <rule> —
/// <outcome>" lines for skipped/error/refused outcomes recorded during
/// execution — so a TOCTOU refusal or a privileged-helper error never
/// silently just shrinks the "Freed" total.
pub(crate) fn execution_notes(journal: &Journal, run_id: &str) -> anyhow::Result<Vec<String>> {
    let (records, _) = journal.read_all()?;
    Ok(records
        .iter()
        .filter(|r| r.run_id == run_id)
        .filter(|r| {
            r.outcome.starts_with("skipped")
                || r.outcome.starts_with("error")
                || r.outcome.starts_with("refused")
        })
        .map(|r| format!("note: {} — {}", r.rule, r.outcome))
        .collect())
}
