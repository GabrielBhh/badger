use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Recursively sums the on-disk size (`st_blocks * 512`) of every file and
/// symlink under `path`, using the same accounting as
/// `safety::deleter::delete_tree` so a scan-time estimate matches what a real
/// delete would report freed. Never follows symlinks. Stops descending into
/// a child directory that crosses onto a different filesystem (`st_dev`),
/// matching the deleter's mount-boundary behavior.
pub fn dir_size(path: &Path) -> u64 {
    let Ok(top_metadata) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    size_entry(path, &top_metadata, top_metadata.dev())
}

fn size_entry(path: &Path, metadata: &std::fs::Metadata, top_dev: u64) -> u64 {
    if !metadata.is_dir() {
        return metadata.blocks() * 512;
    }

    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };

    let mut total = 0;
    for entry in entries.flatten() {
        let child_path = entry.path();
        let Ok(child_metadata) = std::fs::symlink_metadata(&child_path) else {
            continue;
        };
        if child_metadata.is_dir() && child_metadata.dev() != top_dev {
            continue;
        }
        total += size_entry(&child_path, &child_metadata, top_dev);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn blocks_of(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).unwrap().blocks() * 512
    }

    #[test]
    fn test_sums_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/one.txt"), b"hello world").unwrap();
        std::fs::write(root.join("a/two.txt"), b"more data here").unwrap();

        let expected = blocks_of(&root.join("a/b/one.txt")) + blocks_of(&root.join("a/two.txt"));
        assert_eq!(dir_size(&root), expected);
    }

    #[test]
    fn test_missing_path_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(dir_size(&dir.path().join("nope")), 0);
    }

    #[test]
    fn test_symlink_target_is_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let outside = dir.path().join("big.txt");
        std::fs::write(&outside, vec![b'x'; 8192]).unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();

        let expected = blocks_of(&root.join("link.txt"));
        assert_eq!(dir_size(&root), expected);
        assert!(expected < blocks_of(&outside));
    }

    #[test]
    fn test_single_file_path_sizes_just_that_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("solo.txt");
        std::fs::write(&file, b"content").unwrap();
        assert_eq!(dir_size(&file), blocks_of(&file));
    }
}
