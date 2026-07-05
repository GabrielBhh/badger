use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use globset::{Glob, GlobSet, GlobSetBuilder};

#[derive(Debug)]
pub struct Whitelist {
    globset: GlobSet,
    raw_lines: Vec<String>,
    disabled_rules: HashSet<String>,
}

impl Whitelist {
    pub fn matches(&self, path: &Path) -> bool {
        self.globset.is_match(path)
    }

    pub fn rule_disabled(&self, id: &str) -> bool {
        self.disabled_rules.contains(id)
    }

    pub fn raw_lines(&self) -> &[String] {
        &self.raw_lines
    }

    pub fn load(config_dir: &Path, home: &Path) -> anyhow::Result<Whitelist> {
        let path = config_dir.join("whitelist");
        match std::fs::read_to_string(&path) {
            Ok(text) => parse(&text, home),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => parse("", home),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }
}

pub fn parse(text: &str, home: &Path) -> anyhow::Result<Whitelist> {
    let mut builder = GlobSetBuilder::new();
    let mut raw_lines = Vec::new();
    let mut disabled_rules = HashSet::new();

    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(id) = trimmed.strip_prefix("rule:") {
            disabled_rules.insert(id.trim().to_string());
            continue;
        }
        let expanded = expand_tilde(trimmed, home);
        let glob = Glob::new(&expanded)
            .with_context(|| format!("invalid glob pattern on line {}: {trimmed}", i + 1))?;
        builder.add(glob);
        raw_lines.push(trimmed.to_string());
    }

    let globset = builder
        .build()
        .context("failed to build whitelist globset")?;
    Ok(Whitelist {
        globset,
        raw_lines,
        disabled_rules,
    })
}

fn expand_tilde(pattern: &str, home: &Path) -> String {
    if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{}/{rest}", home.display())
    } else if pattern == "~" {
        home.display().to_string()
    } else {
        pattern.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blank_lines_and_comments_are_skipped() {
        let wl = parse("\n# a comment\n   \n", Path::new("/home/user")).unwrap();
        assert!(wl.raw_lines().is_empty());
    }

    #[test]
    fn test_tilde_is_expanded_to_home() {
        let wl = parse("~/cache/*", Path::new("/home/user")).unwrap();
        assert!(wl.matches(Path::new("/home/user/cache/foo.tmp")));
        assert!(!wl.matches(Path::new("/home/other/cache/foo.tmp")));
    }

    #[test]
    fn test_glob_star_matches() {
        let wl = parse("/var/log/*.log", Path::new("/home/user")).unwrap();
        assert!(wl.matches(Path::new("/var/log/pacman.log")));
        assert!(!wl.matches(Path::new("/var/log/pacman.log.old")));
    }

    #[test]
    fn test_rule_entries_disable_by_id() {
        let wl = parse("rule:paccache\nrule: journal \n", Path::new("/home/user")).unwrap();
        assert!(wl.rule_disabled("paccache"));
        assert!(wl.rule_disabled("journal"));
        assert!(!wl.rule_disabled("other"));
    }

    #[test]
    fn test_invalid_glob_errors_with_line_number() {
        let err = parse("~/ok/*\n[unterminated", Path::new("/home/user")).unwrap_err();
        assert!(err.to_string().contains('2'), "error was: {err}");
    }

    #[test]
    fn test_missing_file_yields_empty_whitelist() {
        let dir = tempfile::tempdir().unwrap();
        let wl = Whitelist::load(dir.path(), Path::new("/home/user")).unwrap();
        assert!(wl.raw_lines().is_empty());
        assert!(!wl.matches(Path::new("/home/user/anything")));
    }

    #[test]
    fn test_present_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("whitelist"), "~/cache/*\n").unwrap();
        let wl = Whitelist::load(dir.path(), Path::new("/home/user")).unwrap();
        assert!(wl.matches(Path::new("/home/user/cache/foo")));
    }
}
