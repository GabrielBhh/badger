use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub clean: Clean,
    pub purge: Purge,
    pub snapshots: Snapshots,
    pub optimize: Optimize,
    pub ui: Ui,
    pub uninstall: Uninstall,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Clean {
    pub paccache_keep: u32,
    pub journal_max_size: String,
    pub trash_older_than_days: u32,
    /// How old (by mtime) an unmatched `~/.config`/`~/.local/share`/`~/.cache`
    /// directory must be before `leftovers.orphan_configs` (experimental)
    /// will consider it a candidate.
    pub orphan_min_age_days: u32,
}

impl Default for Clean {
    fn default() -> Self {
        Clean {
            paccache_keep: 2,
            journal_max_size: "300M".to_string(),
            trash_older_than_days: 30,
            orphan_min_age_days: 180,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Purge {
    pub roots: Vec<String>,
    pub recent_days: u32,
}

impl Default for Purge {
    fn default() -> Self {
        Purge {
            roots: vec![
                "~/dev".to_string(),
                "~/projects".to_string(),
                "~/claude_apps".to_string(),
            ],
            recent_days: 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Snapshots {
    pub manage: bool,
}

impl Default for Snapshots {
    fn default() -> Self {
        Snapshots { manage: true }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Optimize {
    pub mirror_tool: String,
}

impl Default for Optimize {
    fn default() -> Self {
        Optimize {
            mirror_tool: "auto".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ui {
    pub mascot: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Ui { mascot: true }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Uninstall {
    /// How old (by mtime) an app's `~/.cache/<name>` and `~/.config/<name>`
    /// must be — with none touched more recently — before the uninstall
    /// picker's Applications view hints it as possibly unused.
    pub unused_days: u32,
}

impl Default for Uninstall {
    fn default() -> Self {
        Uninstall { unused_days: 90 }
    }
}

pub fn load_from_str(s: &str) -> anyhow::Result<Config> {
    toml::from_str(s).context("failed to parse config")
}

pub fn load(config_dir: &Path) -> anyhow::Result<Config> {
    let path = config_dir.join("config.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    load_from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string_yields_defaults() {
        assert_eq!(load_from_str("").unwrap(), Config::default());
    }

    #[test]
    fn test_partial_file_overrides_only_named_keys() {
        let cfg = load_from_str("[clean]\npaccache_keep = 5\n").unwrap();
        assert_eq!(cfg.clean.paccache_keep, 5);
        assert_eq!(cfg.clean.journal_max_size, "300M");
        assert_eq!(cfg.clean.orphan_min_age_days, 180);
        assert_eq!(cfg.purge, Purge::default());
    }

    #[test]
    fn test_orphan_min_age_days_defaults_and_can_be_overridden() {
        assert_eq!(Clean::default().orphan_min_age_days, 180);
        let cfg = load_from_str("[clean]\norphan_min_age_days = 10\n").unwrap();
        assert_eq!(cfg.clean.orphan_min_age_days, 10);
    }

    #[test]
    fn test_unused_days_defaults_and_can_be_overridden() {
        assert_eq!(Uninstall::default().unused_days, 90);
        let cfg = load_from_str("[uninstall]\nunused_days = 30\n").unwrap();
        assert_eq!(cfg.uninstall.unused_days, 30);
    }

    #[test]
    fn test_unknown_key_errors() {
        assert!(load_from_str("bogus_key = 1\n").is_err());
    }

    #[test]
    fn test_unknown_nested_key_errors() {
        assert!(load_from_str("[clean]\nbogus = 1\n").is_err());
    }

    #[test]
    fn test_invalid_toml_errors() {
        assert!(load_from_str("not valid toml [[[").is_err());
    }

    #[test]
    fn test_missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn test_present_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), "[ui]\nmascot = false\n").unwrap();
        let cfg = load(dir.path()).unwrap();
        assert!(!cfg.ui.mascot);
    }

    #[test]
    fn test_invalid_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), "not valid toml [[[").unwrap();
        assert!(load(dir.path()).is_err());
    }
}
