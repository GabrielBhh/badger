use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct DeleteReport {
    pub bytes_freed: u64,
    pub files: u64,
    pub errors: Vec<(PathBuf, String)>,
}

pub fn delete_tree(path: &Path) -> DeleteReport {
    let mut report = DeleteReport::default();
    let top_metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            report.errors.push((path.to_path_buf(), e.to_string()));
            return report;
        }
    };
    delete_entry(path, &top_metadata, top_metadata.dev(), &mut report);
    report
}

/// Deletes one entry (file, symlink, or directory). Directories are only
/// descended into while they share `top_dev` with the tree's top-level path
/// — a child directory on a different filesystem is left alone. Symlinks are
/// always unlinked, never followed, whether they are the top-level path or
/// found while walking.
fn delete_entry(
    path: &Path,
    metadata: &std::fs::Metadata,
    top_dev: u64,
    report: &mut DeleteReport,
) {
    if !metadata.is_dir() {
        let bytes = metadata.blocks() * 512;
        match std::fs::remove_file(path) {
            Ok(()) => {
                report.bytes_freed += bytes;
                report.files += 1;
            }
            Err(e) => report.errors.push((path.to_path_buf(), e.to_string())),
        }
        return;
    }

    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            report.errors.push((path.to_path_buf(), e.to_string()));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                report.errors.push((path.to_path_buf(), e.to_string()));
                continue;
            }
        };
        let child_path = entry.path();
        let child_metadata = match std::fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(e) => {
                report.errors.push((child_path, e.to_string()));
                continue;
            }
        };
        if child_metadata.is_dir() && child_metadata.dev() != top_dev {
            report.errors.push((
                child_path,
                "skipped: crosses filesystem boundary".to_string(),
            ));
            continue;
        }
        delete_entry(&child_path, &child_metadata, top_dev, report);
    }

    if let Err(e) = std::fs::remove_dir(path) {
        report.errors.push((path.to_path_buf(), e.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn test_removes_nested_tree_with_correct_file_count_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/one.txt"), b"hello world").unwrap();
        std::fs::write(root.join("a/two.txt"), b"more data here").unwrap();

        let report = delete_tree(&root);

        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert_eq!(report.files, 2);
        assert!(report.bytes_freed > 0);
        assert!(!root.exists());
    }

    #[test]
    fn test_symlink_inside_tree_is_unlinked_but_target_survives() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let outside_target = dir.path().join("outside.txt");
        std::fs::write(&outside_target, b"keep me").unwrap();
        symlink(&outside_target, root.join("link.txt")).unwrap();

        let report = delete_tree(&root);

        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert!(!root.exists());
        assert!(outside_target.exists());
        assert_eq!(std::fs::read_to_string(&outside_target).unwrap(), "keep me");
    }

    #[test]
    fn test_top_level_symlink_to_dir_removes_only_the_link() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("real-dir");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::write(target_dir.join("keep.txt"), b"keep me").unwrap();
        let link = dir.path().join("link-to-dir");
        symlink(&target_dir, &link).unwrap();

        let report = delete_tree(&link);

        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert!(!link.exists());
        assert!(target_dir.exists());
        assert!(target_dir.join("keep.txt").exists());
    }

    #[test]
    fn test_nonexistent_path_yields_single_error_and_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");

        let report = delete_tree(&missing);

        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.files, 0);
    }
}
