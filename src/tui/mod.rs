use std::io::Stdout;

use anyhow::Context;
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

pub mod checklist;
pub mod confirm;
pub mod explorer;
pub mod picker;

pub type Term = Terminal<CrosstermBackend<Stdout>>;

/// Whether `badger clean` should show the interactive checklist rather than
/// the plain plan-and-exit output: only when both stdout and stderr are
/// attached to a real terminal, and neither `--json` nor `--yes` was given
/// (both are explicit requests for non-interactive behavior).
pub fn is_interactive(json: bool, yes: bool, stdout_tty: bool, stderr_tty: bool) -> bool {
    stdout_tty && stderr_tty && !json && !yes
}

/// Live version of `is_interactive`, reading the real tty state.
pub fn is_interactive_now(json: bool, yes: bool) -> bool {
    use std::io::IsTerminal;
    is_interactive(
        json,
        yes,
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

/// Whether the TUI should draw with color. `NO_COLOR` (any value) disables
/// color but the TUI still runs — it just renders in the terminal's default
/// foreground.
pub fn colors_enabled(no_color_env_set: bool) -> bool {
    !no_color_env_set
}

/// Live version of `colors_enabled`, reading `NO_COLOR` from the process
/// environment.
pub fn colors_enabled_now() -> bool {
    colors_enabled(std::env::var_os("NO_COLOR").is_some())
}

/// Enables raw mode and switches to the alternate screen, returning a ready
/// ratatui terminal. Pair with `restore_terminal` (or the panic hook
/// installed by `install_panic_hook`) to leave the terminal how we found it.
pub fn init_terminal() -> anyhow::Result<Term> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let terminal =
        Terminal::new(CrosstermBackend::new(stdout)).context("failed to construct terminal")?;
    Ok(terminal)
}

/// Reverses `init_terminal`: leaves the alternate screen, disables raw mode,
/// and restores the cursor.
pub fn restore_terminal(terminal: &mut Term) -> anyhow::Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;
    Ok(())
}

/// Best-effort terminal restore for the panic hook: a panic can happen with
/// no `Term` handle in scope, so this talks to stdout directly and swallows
/// errors — the priority is not leaving the user's shell in raw/alternate
/// screen mode, not reporting a secondary failure.
fn restore_terminal_best_effort() {
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
}

/// Installs a panic hook that restores the terminal before running the
/// previous (default) hook, so a panic while the TUI is on screen prints its
/// message to a normal, scrollable terminal instead of getting lost in the
/// alternate screen. Call only when the TUI is actually about to run —
/// harmless otherwise, but pointless.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal_best_effort();
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_interactive_true_when_tty_and_no_flags() {
        assert!(is_interactive(false, false, true, true));
    }

    #[test]
    fn test_is_interactive_false_when_json_flag_set() {
        assert!(!is_interactive(true, false, true, true));
    }

    #[test]
    fn test_is_interactive_false_when_yes_flag_set() {
        assert!(!is_interactive(false, true, true, true));
    }

    #[test]
    fn test_is_interactive_false_when_stdout_not_a_tty() {
        assert!(!is_interactive(false, false, false, true));
    }

    #[test]
    fn test_is_interactive_false_when_stderr_not_a_tty() {
        assert!(!is_interactive(false, false, true, false));
    }

    #[test]
    fn test_colors_enabled_by_default() {
        assert!(colors_enabled(false));
    }

    #[test]
    fn test_colors_disabled_when_no_color_env_set() {
        assert!(!colors_enabled(true));
    }
}
