pub mod dirsize;

/// Parses a human-readable size like `"1024.00 KiB"` or `"128MB"` into
/// bytes. Binary (`KiB`/`MiB`/`GiB`/`TiB`) and decimal-labeled
/// (`KB`/`MB`/`GB`/`TB`, and their bare `K`/`M`/`G`/`T` forms) units are both
/// treated as 1024-based — close enough for a display estimate, and it
/// keeps parsing pacman's and podman/docker's differing size formats to one
/// function. Returns `None` for anything it can't confidently parse.
pub fn parse_human_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let split_at = s.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (number, unit) = s.split_at(split_at);
    let value: f64 = number.trim().parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let multiplier: f64 = match unit.trim().to_ascii_uppercase().as_str() {
        "B" => 1.0,
        "K" | "KB" | "KIB" => 1024.0,
        "M" | "MB" | "MIB" => 1024.0f64.powi(2),
        "G" | "GB" | "GIB" => 1024.0f64.powi(3),
        "T" | "TB" | "TIB" => 1024.0f64.powi(4),
        _ => return None,
    };
    Some((value * multiplier).round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parses_binary_units_with_a_space() {
        assert_eq!(parse_human_size("1.00 KiB"), Some(1024));
        assert_eq!(parse_human_size("2.00 MiB"), Some(2 * 1024 * 1024));
    }

    #[test]
    fn test_parses_decimal_labeled_units_with_no_space() {
        assert_eq!(parse_human_size("128MB"), Some(128 * 1024 * 1024));
        assert_eq!(parse_human_size("1GB"), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn test_parses_plain_bytes() {
        assert_eq!(parse_human_size("512 B"), Some(512));
        assert_eq!(parse_human_size("0.00 B"), Some(0));
    }

    #[test]
    fn test_unparseable_input_is_none() {
        assert_eq!(parse_human_size("bogus"), None);
        assert_eq!(parse_human_size(""), None);
        assert_eq!(parse_human_size("-5 MB"), None);
    }
}
