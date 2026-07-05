use std::path::{Path, PathBuf};

use anyhow::Context;

fn whitelist_path(config_dir: &Path) -> PathBuf {
    config_dir.join("whitelist")
}

fn read_lines(config_dir: &Path) -> anyhow::Result<Vec<String>> {
    let path = whitelist_path(config_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text.lines().map(str::to_string).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

pub fn list(config_dir: &Path) -> anyhow::Result<String> {
    let significant: Vec<String> = read_lines(config_dir)?
        .into_iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if significant.is_empty() {
        Ok("(whitelist is empty)".to_string())
    } else {
        Ok(significant.join("\n"))
    }
}

pub fn add(config_dir: &Path, pattern: &str) -> anyhow::Result<String> {
    let lines = read_lines(config_dir)?;
    if lines.iter().any(|line| line.trim() == pattern.trim()) {
        return Ok(format!("Already whitelisted: {pattern}"));
    }

    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;
    let path = whitelist_path(config_dir);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    use std::io::Write;
    writeln!(file, "{pattern}").with_context(|| format!("failed to write {}", path.display()))?;
    Ok(format!("Added to whitelist: {pattern}"))
}

pub fn remove(config_dir: &Path, pattern: &str) -> anyhow::Result<String> {
    let lines = read_lines(config_dir)?;
    if !lines.iter().any(|line| line.trim() == pattern.trim()) {
        return Ok(format!("Not in whitelist: {pattern}"));
    }

    let remaining: Vec<String> = lines
        .into_iter()
        .filter(|line| line.trim() != pattern.trim())
        .collect();
    let path = whitelist_path(config_dir);
    let mut text = remaining.join("\n");
    if !remaining.is_empty() {
        text.push('\n');
    }
    std::fs::write(&path, text).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(format!("Removed from whitelist: {pattern}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_on_missing_file_says_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(list(dir.path()).unwrap(), "(whitelist is empty)");
    }

    #[test]
    fn test_add_then_list_shows_the_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let msg = add(dir.path(), "~/cache/*").unwrap();
        assert!(msg.contains("~/cache/*"));
        assert_eq!(list(dir.path()).unwrap(), "~/cache/*");
    }

    #[test]
    fn test_add_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        add(dir.path(), "~/cache/*").unwrap();
        let msg = add(dir.path(), "~/cache/*").unwrap();
        assert!(msg.contains("Already"), "message was: {msg}");
        assert_eq!(list(dir.path()).unwrap(), "~/cache/*");
    }

    #[test]
    fn test_remove_deletes_a_present_pattern() {
        let dir = tempfile::tempdir().unwrap();
        add(dir.path(), "~/cache/*").unwrap();
        let msg = remove(dir.path(), "~/cache/*").unwrap();
        assert!(msg.contains("Removed"));
        assert_eq!(list(dir.path()).unwrap(), "(whitelist is empty)");
    }

    #[test]
    fn test_remove_missing_pattern_is_a_friendly_noop() {
        let dir = tempfile::tempdir().unwrap();
        let msg = remove(dir.path(), "~/nope/*").unwrap();
        assert!(msg.contains("Not in whitelist"), "message was: {msg}");
    }
}
