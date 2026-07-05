use std::path::PathBuf;

use anyhow::Context;

use crate::config::{self, Config};

#[derive(Debug, Clone, Default)]
pub struct EnvOverrides {
    pub root: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_state_home: Option<PathBuf>,
}

impl EnvOverrides {
    pub fn from_process() -> EnvOverrides {
        EnvOverrides {
            root: std::env::var_os("BADGER_ROOT").map(PathBuf::from),
            home: std::env::var_os("BADGER_HOME").map(PathBuf::from),
            config_dir: std::env::var_os("BADGER_CONFIG_DIR").map(PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ctx {
    pub root: PathBuf,
    pub home: PathBuf,
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub dry_run: bool,
    pub debug: bool,
    pub config: Config,
    pub sandboxed: bool,
    /// Test-only override for which commands `Applicability::CommandExists`
    /// should treat as present. Only consulted while `sandboxed`; populated
    /// from the comma-separated `BADGER_COMMANDS` env var.
    pub available_commands: Option<Vec<String>>,
}

impl Ctx {
    pub fn resolve(dry_run: bool, debug: bool, env: EnvOverrides) -> anyhow::Result<Ctx> {
        let root = env.root.unwrap_or_else(|| PathBuf::from("/"));
        let sandboxed = root != std::path::Path::new("/");

        // A BADGER_HOME override means the sandbox must fully contain its own
        // state, so XDG_CONFIG_HOME/XDG_STATE_HOME are ignored in that case.
        let home_overridden = env.home.is_some();

        let home = match env.home {
            Some(home) => home,
            None => {
                let home = std::env::var_os("HOME")
                    .context("HOME is not set and no home override was given")?;
                PathBuf::from(home)
            }
        };

        let config_dir = match env.config_dir {
            Some(config_dir) => config_dir,
            None => {
                let base = if home_overridden {
                    home.join(".config")
                } else {
                    env.xdg_config_home.unwrap_or_else(|| home.join(".config"))
                };
                base.join("badger")
            }
        };

        let state_dir = {
            let base = if home_overridden {
                home.join(".local/state")
            } else {
                env.xdg_state_home
                    .unwrap_or_else(|| home.join(".local/state"))
            };
            base.join("badger")
        };

        let config = config::load(&config_dir)?;

        let available_commands = if sandboxed {
            std::env::var("BADGER_COMMANDS")
                .ok()
                .map(|v| v.split(',').map(str::to_string).collect())
        } else {
            None
        };

        Ok(Ctx {
            root,
            home,
            config_dir,
            state_dir,
            dry_run,
            debug,
            config,
            sandboxed,
            available_commands,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_resolution_with_fake_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let env = EnvOverrides {
            home: Some(home.clone()),
            ..Default::default()
        };
        let ctx = Ctx::resolve(false, false, env).unwrap();
        assert_eq!(ctx.root, PathBuf::from("/"));
        assert_eq!(ctx.home, home);
        assert_eq!(ctx.config_dir, home.join(".config").join("badger"));
        assert_eq!(ctx.state_dir, home.join(".local/state").join("badger"));
        assert!(!ctx.sandboxed);
        assert_eq!(ctx.config, Config::default());
    }

    #[test]
    fn test_badger_root_sets_sandboxed() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let env = EnvOverrides {
            root: Some(root.clone()),
            home: Some(home),
            ..Default::default()
        };
        let ctx = Ctx::resolve(false, false, env).unwrap();
        assert_eq!(ctx.root, root);
        assert!(ctx.sandboxed);
    }

    #[test]
    fn test_badger_home_ignores_xdg_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let xdg_config = dir.path().join("xdg-config");
        let xdg_state = dir.path().join("xdg-state");
        let env = EnvOverrides {
            home: Some(home.clone()),
            xdg_config_home: Some(xdg_config),
            xdg_state_home: Some(xdg_state),
            ..Default::default()
        };
        let ctx = Ctx::resolve(false, false, env).unwrap();
        assert_eq!(ctx.config_dir, home.join(".config").join("badger"));
        assert_eq!(ctx.state_dir, home.join(".local/state").join("badger"));
    }

    #[test]
    fn test_config_dir_override_wins() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config_dir = dir.path().join("custom-config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let env = EnvOverrides {
            home: Some(home),
            config_dir: Some(config_dir.clone()),
            ..Default::default()
        };
        let ctx = Ctx::resolve(false, false, env).unwrap();
        assert_eq!(ctx.config_dir, config_dir);
    }
}
