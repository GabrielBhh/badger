//! Installed-package backends for `badger uninstall`: enumerating what's
//! installed (pacman/AUR, flatpak, snap) and the argv each backend's removal
//! takes. Every backend goes through `core::runner`'s `CommandRunner` seam —
//! nothing here ever shells out directly — so tests never run real pacman/
//! flatpak/snap.

pub mod desktop;
pub mod flatpak;
pub mod pacman;
pub mod snap;

use crate::ctx::Ctx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Pacman,
    Flatpak,
    Snap,
}

impl Backend {
    /// Display label for the picker's `[pacman|aur|flatpak|snap]` badge.
    /// `aur` itself is not a `Backend` variant — it's `Pacman` with
    /// `InstalledPackage::aur` set, and callers that want the "aur" badge
    /// check that flag themselves before falling back to this label.
    pub fn label(self) -> &'static str {
        match self {
            Backend::Pacman => "pacman",
            Backend::Flatpak => "flatpak",
            Backend::Snap => "snap",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstalledPackage {
    pub backend: Backend,
    /// The identifier the backend's own remove command takes: a pacman
    /// package name, a flatpak application ID, or a snap name.
    pub id: String,
    pub name: String,
    pub version: String,
    pub size_bytes: Option<u64>,
    /// `true` for a pacman package installed from the AUR (foreign,
    /// `pacman -Qm`). Always `false` for flatpak/snap.
    pub aur: bool,
}

/// Every installed package across whichever backends are actually present on
/// this system (`CommandExists`-gated per backend) — an absent backend is
/// skipped silently rather than erroring.
pub fn list_installed(ctx: &Ctx) -> Vec<InstalledPackage> {
    let mut all = Vec::new();
    if pacman::is_available(ctx) {
        all.extend(pacman::list(ctx));
    }
    if flatpak::is_available(ctx) {
        all.extend(flatpak::list(ctx));
    }
    if snap::is_available(ctx) {
        all.extend(snap::list(ctx));
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    fn ctx() -> Ctx {
        Ctx {
            root: PathBuf::from("/root"),
            home: PathBuf::from("/root/home/user"),
            config_dir: PathBuf::new(),
            state_dir: PathBuf::new(),
            dry_run: false,
            debug: false,
            config: Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output: None,
        }
    }

    #[test]
    fn test_list_installed_is_empty_when_no_backend_is_available() {
        assert!(list_installed(&ctx()).is_empty());
    }
}
