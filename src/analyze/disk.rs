use std::path::{Path, PathBuf};

use crate::ctx::Ctx;
use crate::safety::protected::unescape_octal;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DiskTotals {
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub fs_kind: String,
    pub btrfs_unallocated: Option<u64>,
}

/// Finds the mount entry in `mounts_text` (the contents of a `/proc/self/mounts`-
/// style file) whose mount point is the longest prefix of `path`, and returns
/// its `(device, fstype)`. Mount points are octal-escaped the same way as
/// `/proc/self/mountinfo`, so they're run through the shared decoder.
fn fs_for_path(mounts_text: &str, path: &Path) -> Option<(String, String)> {
    let mut best: Option<(PathBuf, String, String)> = None;
    for line in mounts_text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(device), Some(mount_point), Some(fstype)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let mount_point = PathBuf::from(unescape_octal(mount_point));
        if !path.starts_with(&mount_point) {
            continue;
        }
        let better = match &best {
            Some((best_mp, _, _)) => {
                mount_point.components().count() > best_mp.components().count()
            }
            None => true,
        };
        if better {
            best = Some((mount_point, device.to_string(), fstype.to_string()));
        }
    }
    best.map(|(_, device, fstype)| (device, fstype))
}

/// Sums the btrfs data/metadata/system chunk allocations for the device named
/// `device` (e.g. `/dev/nvme0n1p2`) under a `sys/fs/btrfs`-style sysfs tree.
/// Returns `None` on any failure: no matching uuid dir, missing or corrupt
/// allocation files.
fn btrfs_allocated(sysfs_btrfs: &Path, device: &str) -> Option<u64> {
    let device_name = Path::new(device).file_name()?.to_str()?;
    let entries = std::fs::read_dir(sysfs_btrfs).ok()?;
    for entry in entries.flatten() {
        let uuid_dir = entry.path();
        if !uuid_dir.join("devices").join(device_name).exists() {
            continue;
        }
        let mut total = 0u64;
        for kind in ["data", "metadata", "system"] {
            let file = uuid_dir.join("allocation").join(kind).join("disk_total");
            let contents = std::fs::read_to_string(&file).ok()?;
            total += contents.trim().parse::<u64>().ok()?;
        }
        return Some(total);
    }
    None
}

/// Disk-space totals for the filesystem containing `path`, plus btrfs-specific
/// unallocated space when that filesystem is btrfs.
pub fn disk_totals(ctx: &Ctx, path: &Path) -> anyhow::Result<DiskTotals> {
    let stat = nix::sys::statvfs::statvfs(path)?;
    let frsize: u64 = stat.fragment_size();
    let blocks: u64 = stat.blocks();
    let bfree: u64 = stat.blocks_free();
    let bavail: u64 = stat.blocks_available();

    let total = blocks * frsize;
    let used = (blocks - bfree) * frsize;
    let available = bavail * frsize;

    let mounts_path = ctx.root.join("proc/self/mounts");
    let mount_info = std::fs::read_to_string(&mounts_path)
        .ok()
        .and_then(|text| fs_for_path(&text, path));

    let (fs_kind, btrfs_unallocated) = match mount_info {
        Some((device, fstype)) if fstype == "btrfs" => {
            let sysfs_btrfs = ctx.root.join("sys/fs/btrfs");
            let unallocated = btrfs_allocated(&sysfs_btrfs, &device)
                .map(|allocated| total.saturating_sub(allocated));
            (fstype, unallocated)
        }
        Some((_, fstype)) => (fstype, None),
        None => ("unknown".to_string(), None),
    };

    Ok(DiskTotals {
        total,
        used,
        available,
        fs_kind,
        btrfs_unallocated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn fixture_ctx(sandbox: &Path) -> Ctx {
        let root = sandbox.join("root");
        let home = root.join("home/user");
        std::fs::create_dir_all(&home).unwrap();
        Ctx {
            root,
            home,
            config_dir: sandbox.join("config"),
            state_dir: sandbox.join("state"),
            dry_run: false,
            debug: false,
            config: Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output: None,
        }
    }

    fn write_allocation(uuid_dir: &Path, data: u64, metadata: u64, system: u64) {
        for (kind, value) in [("data", data), ("metadata", metadata), ("system", system)] {
            let dir = uuid_dir.join("allocation").join(kind);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("disk_total"), value.to_string()).unwrap();
        }
    }

    // --- fs_for_path ---

    #[test]
    fn test_fs_for_path_picks_longest_prefix_mount() {
        let mounts = "\
/dev/sda1 / ext4 rw 0 0
/dev/sda2 /home ext4 rw 0 0
";
        let got = fs_for_path(mounts, Path::new("/home/user/file")).unwrap();
        assert_eq!(got, ("/dev/sda2".to_string(), "ext4".to_string()));
    }

    #[test]
    fn test_fs_for_path_respects_component_boundaries() {
        let mounts = "\
/dev/root / ext4 rw 0 0
/dev/sda2 /home ext4 rw 0 0
";
        let got = fs_for_path(mounts, Path::new("/homework/x")).unwrap();
        assert_eq!(got, ("/dev/root".to_string(), "ext4".to_string()));
    }

    #[test]
    fn test_fs_for_path_decodes_octal_escaped_mount_point() {
        let mounts = "/dev/sda3 /mnt/My\\040Files ext4 rw 0 0\n";
        let got = fs_for_path(mounts, Path::new("/mnt/My Files/sub")).unwrap();
        assert_eq!(got, ("/dev/sda3".to_string(), "ext4".to_string()));
    }

    #[test]
    fn test_fs_for_path_empty_text_is_none() {
        assert_eq!(fs_for_path("", Path::new("/anything")), None);
    }

    // --- btrfs_allocated ---

    #[test]
    fn test_btrfs_allocated_sums_data_metadata_system() {
        let sandbox = tempfile::tempdir().unwrap();
        let sysfs_btrfs = sandbox.path().join("sys/fs/btrfs");
        let uuid_dir = sysfs_btrfs.join("fake-uuid");
        std::fs::create_dir_all(uuid_dir.join("devices/fake1")).unwrap();
        write_allocation(&uuid_dir, 1_000_000, 2_000_000, 500_000);

        let got = btrfs_allocated(&sysfs_btrfs, "/dev/fake1");
        assert_eq!(got, Some(3_500_000));
    }

    #[test]
    fn test_btrfs_allocated_wrong_device_is_none() {
        let sandbox = tempfile::tempdir().unwrap();
        let sysfs_btrfs = sandbox.path().join("sys/fs/btrfs");
        let uuid_dir = sysfs_btrfs.join("fake-uuid");
        std::fs::create_dir_all(uuid_dir.join("devices/fake1")).unwrap();
        write_allocation(&uuid_dir, 1_000_000, 2_000_000, 500_000);

        assert_eq!(btrfs_allocated(&sysfs_btrfs, "/dev/nope"), None);
    }

    #[test]
    fn test_btrfs_allocated_missing_allocation_file_is_none() {
        let sandbox = tempfile::tempdir().unwrap();
        let sysfs_btrfs = sandbox.path().join("sys/fs/btrfs");
        let uuid_dir = sysfs_btrfs.join("fake-uuid");
        std::fs::create_dir_all(uuid_dir.join("devices/fake1")).unwrap();
        // Only data and metadata; system is missing.
        for (kind, value) in [("data", 1_000_000u64), ("metadata", 2_000_000)] {
            let dir = uuid_dir.join("allocation").join(kind);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("disk_total"), value.to_string()).unwrap();
        }

        assert_eq!(btrfs_allocated(&sysfs_btrfs, "/dev/fake1"), None);
    }

    // --- disk_totals ---

    #[test]
    fn test_disk_totals_reports_btrfs_unallocated_space() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        let mount_dir = ctx.root.join("data");
        std::fs::create_dir_all(&mount_dir).unwrap();

        let proc_dir = ctx.root.join("proc/self");
        std::fs::create_dir_all(&proc_dir).unwrap();
        std::fs::write(
            proc_dir.join("mounts"),
            format!("/dev/fake1 {} btrfs rw 0 0\n", mount_dir.display()),
        )
        .unwrap();

        let sysfs_btrfs = ctx.root.join("sys/fs/btrfs");
        let uuid_dir = sysfs_btrfs.join("fake-uuid");
        std::fs::create_dir_all(uuid_dir.join("devices/fake1")).unwrap();
        write_allocation(&uuid_dir, 1_000_000, 2_000_000, 500_000);

        let expected_stat = nix::sys::statvfs::statvfs(&mount_dir).unwrap();
        let expected_total: u64 = expected_stat.blocks() * expected_stat.fragment_size();

        let got = disk_totals(&ctx, &mount_dir).unwrap();
        assert_eq!(got.fs_kind, "btrfs");
        assert_eq!(
            got.btrfs_unallocated,
            Some(expected_total.saturating_sub(3_500_000))
        );
    }

    #[test]
    fn test_disk_totals_smoke_for_ext4() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        let mount_dir = ctx.root.join("data");
        std::fs::create_dir_all(&mount_dir).unwrap();

        let proc_dir = ctx.root.join("proc/self");
        std::fs::create_dir_all(&proc_dir).unwrap();
        std::fs::write(
            proc_dir.join("mounts"),
            format!("/dev/fake0 {} ext4 rw 0 0\n", mount_dir.display()),
        )
        .unwrap();

        let got = disk_totals(&ctx, &mount_dir).unwrap();
        assert!(got.total > 0);
        assert!(got.used <= got.total);
        assert!(got.available <= got.total);
        assert_eq!(got.fs_kind, "ext4");
        assert_eq!(got.btrfs_unallocated, None);
    }

    #[test]
    fn test_disk_totals_missing_mounts_file_is_unknown_not_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        let mount_dir = ctx.root.join("data");
        std::fs::create_dir_all(&mount_dir).unwrap();

        let got = disk_totals(&ctx, &mount_dir).unwrap();
        assert_eq!(got.fs_kind, "unknown");
        assert_eq!(got.btrfs_unallocated, None);
    }
}
