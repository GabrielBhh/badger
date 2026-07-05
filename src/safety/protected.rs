use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    System,
    User,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Refusal {
    #[error("path does not exist or cannot be inspected: {0}")]
    Uninspectable(String),
    #[error("protected path")]
    DenyListed,
    #[error("escapes allowed prefix via symlink")]
    SymlinkEscape,
    #[error("outside this rule's allowed locations")]
    OutsidePrefix,
    #[error("path is too shallow to delete safely")]
    TooShallow,
    #[error("path is a mount point")]
    MountPoint,
    #[error("not owned by the current user")]
    NotOwned,
}

pub struct SafetyEnv {
    pub root: PathBuf,
    pub home: PathBuf,
    pub mount_points: HashSet<PathBuf>,
    pub euid: u32,
}

impl SafetyEnv {
    pub fn deny_list(&self) -> Vec<PathBuf> {
        const ROOT_RELATIVE: &[&str] = &[
            "boot",
            "efi",
            "etc",
            "usr",
            "bin",
            "sbin",
            "lib",
            "lib64",
            "lib32",
            "opt",
            "srv",
            "root",
            "home",
            "var/lib/pacman/local",
        ];
        const HOME_RELATIVE: &[&str] = &[
            ".ssh",
            ".gnupg",
            ".password-store",
            ".mozilla",
            ".config/badger",
        ];

        let mut list = vec![self.root.clone()];
        list.extend(ROOT_RELATIVE.iter().map(|rel| self.root.join(rel)));
        list.push(self.home.clone());
        list.extend(HOME_RELATIVE.iter().map(|rel| self.home.join(rel)));
        list
    }

    pub fn from_system(ctx: &crate::ctx::Ctx) -> SafetyEnv {
        let mount_points = std::fs::read_to_string("/proc/self/mountinfo")
            .map(|text| parse_mountinfo(&text))
            .unwrap_or_default();
        SafetyEnv {
            root: ctx.root.clone(),
            home: ctx.home.clone(),
            mount_points,
            euid: nix::unistd::geteuid().as_raw(),
        }
    }
}

pub fn validate_deletable(
    path: &Path,
    allowed_prefixes: &[PathBuf],
    tier: Tier,
    env: &SafetyEnv,
) -> Result<(), Refusal> {
    let uninspectable = || Refusal::Uninspectable(path.display().to_string());

    // 1. Leaf may itself be a symlink — inspect it, never follow it.
    let leaf_metadata = std::fs::symlink_metadata(path).map_err(|_| uninspectable())?;

    // 2. Resolve the parent through any symlinks so later checks operate on
    // where the path *really* points, not where it syntactically appears to.
    let syntactic_parent = path.parent().unwrap_or(path);
    let canonical_parent = syntactic_parent
        .canonicalize()
        .map_err(|_| uninspectable())?;
    let file_name = path.file_name();
    let effective = match file_name {
        Some(name) => canonical_parent.join(name),
        None => canonical_parent.clone(),
    };
    let parent_was_symlinked = canonical_parent != syntactic_parent;

    // 3. Absolute deny list, checked in both directions so an ancestor of a
    // protected path (and not just the path itself) is refused too.
    //
    // The root and home "container" entries (root itself, root/home, and home
    // itself) are boundaries, not protected subtrees: everything legitimate
    // that badger ever deletes lives *inside* home, so a plain starts_with
    // containment check against `home` would deny every single path in the
    // user's own home directory. Those three entries only refuse an exact
    // match or an attempt to delete one of their ancestors; every other deny
    // entry (system dirs, .ssh, .gnupg, etc.) protects its whole subtree.
    let boundaries = [env.root.clone(), env.root.join("home"), env.home.clone()];
    let deny_list = env.deny_list();
    let is_denied = deny_list.iter().any(|d| {
        if boundaries.contains(d) {
            effective == *d || d.starts_with(&effective)
        } else {
            effective == *d || effective.starts_with(d) || d.starts_with(&effective)
        }
    });
    if is_denied {
        return Err(Refusal::DenyListed);
    }

    // 4. Must land inside one of the rule's allowed prefixes.
    let canonical_prefixes: Vec<PathBuf> = allowed_prefixes
        .iter()
        .filter_map(|p| p.canonicalize().ok())
        .collect();
    let inside_prefix = canonical_prefixes.iter().any(|p| effective.starts_with(p));
    if !inside_prefix {
        return Err(if parent_was_symlinked {
            Refusal::SymlinkEscape
        } else {
            Refusal::OutsidePrefix
        });
    }

    // 5. Refuse to delete something too close to the top of its tree.
    let home_canonical = env.home.canonicalize().unwrap_or_else(|_| env.home.clone());
    let root_canonical = env.root.canonicalize().unwrap_or_else(|_| env.root.clone());
    let min_depth = if effective.starts_with(&home_canonical) {
        effective
            .strip_prefix(&home_canonical)
            .map(|rel| rel.components().count())
            .unwrap_or(0)
            < 2
    } else {
        effective
            .strip_prefix(&root_canonical)
            .map(|rel| rel.components().count())
            .unwrap_or(0)
            < 3
    };
    if min_depth {
        return Err(Refusal::TooShallow);
    }

    // 6. Never delete a mount point out from under the system.
    if env.mount_points.contains(&effective) {
        return Err(Refusal::MountPoint);
    }

    // 7. For user-tier rules, the leaf must actually belong to the caller.
    if tier == Tier::User && leaf_metadata.uid() != env.euid {
        return Err(Refusal::NotOwned);
    }

    Ok(())
}

pub fn parse_mountinfo(text: &str) -> HashSet<PathBuf> {
    text.lines()
        .filter_map(|line| {
            let mount_point = line.split_whitespace().nth(4)?;
            Some(PathBuf::from(unescape_octal(mount_point)))
        })
        .collect()
}

/// mountinfo escapes space, tab, newline, and backslash as \NNN octal.
fn unescape_octal(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && let Ok(value) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 4]).unwrap_or_default(),
                8,
            )
        {
            out.push(value);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mountinfo_extracts_mount_points() {
        let text = "\
36 35 98:0 / / rw,noatime master:1 - ext4 /dev/root rw,errors=remount-ro
25 30 0:24 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
30 25 0:5 / /home/user/My\\040Files rw,relatime shared:2 - ext4 /dev/sda1 rw
";
        let mounts = parse_mountinfo(text);
        assert!(mounts.contains(Path::new("/")));
        assert!(mounts.contains(Path::new("/proc")));
        assert!(mounts.contains(Path::new("/home/user/My Files")));
    }
}
