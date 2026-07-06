//! Helpers shared by every interactive top-level command (`clean`, `purge`,
//! ...): driving the checklist/confirm TUI loop against a scan's groups, and
//! reading back a run's journal for execution-time counts and notes. Both are
//! already generic over `Group`/`Journal` with no `Rule`/`Action` awareness,
//! so they don't belong to any one command.

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
    verb: confirm::Verb,
    dry_run: bool,
) -> anyhow::Result<Option<HashSet<(usize, usize)>>> {
    let mut state = checklist::ChecklistState::new(groups);
    let mut confirming: Option<confirm::ConfirmState> = None;
    let colors = tui::colors_enabled_now();

    loop {
        let height = terminal.size()?.height;
        if let Some(confirm_state) = &confirming {
            terminal.draw(|f| confirm::render(f, confirm_state, colors))?;
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
            Some(checklist::Action::ToggleAll) => state.toggle_all(),
            Some(checklist::Action::Top) => state.top(),
            Some(checklist::Action::Bottom) => state.bottom(),
            Some(checklist::Action::Cancel) => return Ok(None),
            Some(checklist::Action::Confirm) => {
                confirming = Some(confirm::ConfirmState::from_checklist(&state, verb, dry_run));
            }
            None => {}
        }
    }
}

/// Reads this run's journal records once and classifies all of them: how
/// many actually ran (or, in a dry run, would have), how many were skipped
/// (sudo in a sandbox), and "note: <rule> — <outcome>" lines for the
/// skipped/error/refused ones — so a TOCTOU refusal or a privileged-helper
/// error never silently just shrinks the "Freed"/"Ran" total.
pub(crate) fn summarize_run(
    journal: &Journal,
    run_id: &str,
) -> anyhow::Result<(usize, usize, Vec<String>)> {
    let (records, _) = journal.read_all()?;
    let mut ran = 0;
    let mut skipped = 0;
    let mut notes = Vec::new();
    for record in records.iter().filter(|r| r.run_id == run_id) {
        if record.outcome.starts_with("skipped") {
            skipped += 1;
            notes.push(format!("note: {} — {}", record.rule, record.outcome));
        } else if record.outcome.starts_with("error") || record.outcome.starts_with("refused") {
            notes.push(format!("note: {} — {}", record.rule, record.outcome));
        } else {
            ran += 1;
        }
    }
    Ok((ran, skipped, notes))
}

/// Pluralizes a count for the execution summaries below: `1 item` / `2
/// items`, `1 task` / `2 tasks`. Every unit used here pluralizes by simply
/// appending `s`.
pub(crate) fn count_label(n: usize, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}
