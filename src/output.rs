#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Human,
    Json,
}

pub fn decide(flag_json: bool, env_json: bool, stdout_is_tty: bool) -> Mode {
    if flag_json || env_json || !stdout_is_tty {
        Mode::Json
    } else {
        Mode::Human
    }
}

pub fn current(flag_json: bool) -> Mode {
    use std::io::IsTerminal;
    let env_json = std::env::var_os("BADGER_JSON").as_deref() == Some(std::ffi::OsStr::new("1"));
    decide(flag_json, env_json, std::io::stdout().is_terminal())
}

pub fn humanize_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Formats a count with its noun, singular or plural: `count_label(1,
/// "item")` -> `"1 item"`, `count_label(5, "item")` -> `"5 items"`. Every
/// noun used here pluralizes by simply appending `s`.
pub fn count_label(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_forces_json() {
        assert_eq!(decide(true, false, true), Mode::Json);
    }

    #[test]
    fn test_env_forces_json() {
        assert_eq!(decide(false, true, true), Mode::Json);
    }

    #[test]
    fn test_non_tty_forces_json() {
        assert_eq!(decide(false, false, false), Mode::Json);
    }

    #[test]
    fn test_tty_no_flags_is_human() {
        assert_eq!(decide(false, false, true), Mode::Human);
    }

    #[test]
    fn test_count_label_singular_and_plural() {
        assert_eq!(count_label(1, "item"), "1 item");
        assert_eq!(count_label(0, "item"), "0 items");
        assert_eq!(count_label(5, "task"), "5 tasks");
    }

    #[test]
    fn test_humanize_bytes_stays_in_b_below_1024() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(500), "500 B");
    }

    #[test]
    fn test_humanize_bytes_switches_to_kib() {
        assert_eq!(humanize_bytes(1024), "1.0 KiB");
        assert_eq!(humanize_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn test_humanize_bytes_switches_to_mib_and_gib() {
        assert_eq!(humanize_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(humanize_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
