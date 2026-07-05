use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// One directory in a recursive size scan. `bytes`/`files` are always full
/// recursive totals, even for a node whose `children` have been pruned by
/// `max_depth` — only the tree shape is truncated, never the numbers.
#[derive(Debug, serde::Serialize)]
pub struct DirNode {
    pub path: PathBuf,
    pub name: String,
    pub bytes: u64,
    pub files: u64,
    pub mtime: i64,
    pub children: Vec<DirNode>,
    pub truncated_depth: bool,
}

#[derive(Debug)]
pub struct ScanOptions {
    pub max_depth: usize,
    pub workers: usize,
    pub top_files_limit: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_depth: 2,
            workers: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            top_files_limit: 50,
        }
    }
}

/// One of the N largest files seen anywhere in a scanned tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LargeFile {
    pub path: PathBuf,
    pub bytes: u64,
    pub mtime: i64,
}

#[derive(Debug)]
pub struct ScanResult {
    pub root: DirNode,
    pub dirs_visited: u64,
    pub complete: bool,
    pub skipped_mounts: Vec<PathBuf>,
    pub warnings: Vec<String>,
    pub top_files: Vec<LargeFile>,
}

/// An entry in the bounded top-files heap. Orders by `bytes` ascending, then
/// by `path` *descending* as the tiebreak: this makes the "smallest" entry
/// (the one a min-heap surfaces at its root for eviction) the one with the
/// fewest bytes, and among equal bytes, the one with the lexicographically
/// greatest path — so ties are broken in favor of keeping the smallest paths.
#[derive(Debug, Clone)]
struct HeapEntry {
    bytes: u64,
    path: PathBuf,
    mtime: i64,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.path == other.path
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes
            .cmp(&other.bytes)
            .then_with(|| other.path.cmp(&self.path))
    }
}

/// Offers `entry` to a bounded min-heap of the largest files seen so far.
/// Pushes it if the heap has room; otherwise replaces the current worst entry
/// (smallest bytes, tie-broken toward the greatest path) if `entry` is
/// strictly better.
fn push_bounded(heap: &mut BinaryHeap<Reverse<HeapEntry>>, limit: usize, entry: HeapEntry) {
    if heap.len() < limit {
        heap.push(Reverse(entry));
        return;
    }
    if let Some(worst) = heap.peek()
        && entry > worst.0
    {
        heap.pop();
        heap.push(Reverse(entry));
    }
}

/// State shared across the main thread and every worker thread for one scan.
struct Shared {
    top_dev: u64,
    max_depth: usize,
    top_files_limit: usize,
    visited: AtomicU64,
    bytes_so_far: AtomicU64,
    warnings: Mutex<Vec<String>>,
    skipped_mounts: Mutex<Vec<PathBuf>>,
    top_files: Mutex<BinaryHeap<Reverse<HeapEntry>>>,
    cancel: Arc<AtomicBool>,
    progress: Mutex<Option<Sender<(u64, u64)>>>,
}

/// Locks a mutex, recovering the inner value rather than panicking if a
/// previous holder panicked while the lock was held.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether `n` (a visited-directory count, taken after incrementing) is a
/// progress-reporting checkpoint.
fn is_progress_checkpoint(n: u64) -> bool {
    n.is_multiple_of(100)
}

/// Whether a child directory's device id crosses the filesystem boundary of
/// the scan's top-level path.
fn crosses_device(child_dev: u64, top_dev: u64) -> bool {
    child_dev != top_dev
}

fn file_name_lossy(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn maybe_report(shared: &Shared, visited: u64) {
    if !is_progress_checkpoint(visited) {
        return;
    }
    let bytes = shared.bytes_so_far.load(Ordering::Relaxed);
    if let Some(sender) = lock(&shared.progress).as_ref() {
        let _ = sender.send((visited, bytes));
    }
}

/// Records `path` as a candidate for the scan's top-N-largest-files list.
/// No-op (and skips locking) when the scan's `top_files_limit` is 0.
fn offer_top_file(shared: &Shared, path: PathBuf, bytes: u64, mtime: i64) {
    if shared.top_files_limit == 0 {
        return;
    }
    let entry = HeapEntry { bytes, path, mtime };
    push_bounded(&mut lock(&shared.top_files), shared.top_files_limit, entry);
}

fn empty_node(path: &Path, name: String) -> DirNode {
    DirNode {
        path: path.to_path_buf(),
        name,
        bytes: 0,
        files: 0,
        mtime: 0,
        children: Vec::new(),
        truncated_depth: false,
    }
}

/// Recursively builds the `DirNode` for `path` (a directory), which is at
/// `depth` below the scan's start path. Always recurses fully; `max_depth`
/// only affects whether `children` is kept once the totals are computed.
fn build_node(
    path: PathBuf,
    name: String,
    metadata: std::fs::Metadata,
    depth: usize,
    shared: &Shared,
) -> DirNode {
    let mtime = metadata.mtime();

    let visited = shared.visited.fetch_add(1, Ordering::Relaxed) + 1;
    maybe_report(shared, visited);

    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(e) => {
            lock(&shared.warnings).push(format!("{}: {e}", path.display()));
            return DirNode {
                path,
                name,
                bytes: 0,
                files: 0,
                mtime,
                children: Vec::new(),
                truncated_depth: false,
            };
        }
    };

    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut children = Vec::new();

    for entry in entries.flatten() {
        if shared.cancel.load(Ordering::Relaxed) {
            break;
        }
        let child_path = entry.path();
        let Ok(child_metadata) = std::fs::symlink_metadata(&child_path) else {
            continue;
        };
        if child_metadata.is_dir() {
            let child_name = file_name_lossy(&child_path);
            if child_name == ".snapshots" {
                continue;
            }
            if crosses_device(child_metadata.dev(), shared.top_dev) {
                lock(&shared.skipped_mounts).push(child_path);
                continue;
            }
            let child_node = build_node(child_path, child_name, child_metadata, depth + 1, shared);
            bytes += child_node.bytes;
            files += child_node.files;
            children.push(child_node);
        } else {
            let size = child_metadata.blocks() * 512;
            bytes += size;
            files += 1;
            shared.bytes_so_far.fetch_add(size, Ordering::Relaxed);
            offer_top_file(shared, child_path, size, child_metadata.mtime());
        }
    }

    let truncated_depth = depth >= shared.max_depth && !children.is_empty();
    if truncated_depth {
        children.clear();
    }

    DirNode {
        path,
        name,
        bytes,
        files,
        mtime,
        children,
        truncated_depth,
    }
}

pub fn scan(
    start: &Path,
    options: &ScanOptions,
    progress: Option<Sender<(u64, u64)>>,
    cancel: &Arc<AtomicBool>,
) -> ScanResult {
    let name = file_name_lossy(start);

    if cancel.load(Ordering::Relaxed) {
        return ScanResult {
            root: empty_node(start, name),
            dirs_visited: 0,
            complete: false,
            skipped_mounts: Vec::new(),
            warnings: Vec::new(),
            top_files: Vec::new(),
        };
    }

    let top_metadata = match std::fs::symlink_metadata(start) {
        Ok(m) => m,
        Err(e) => {
            return ScanResult {
                root: empty_node(start, name),
                dirs_visited: 0,
                complete: true,
                skipped_mounts: Vec::new(),
                warnings: vec![format!("{}: {e}", start.display())],
                top_files: Vec::new(),
            };
        }
    };

    if !top_metadata.is_dir() {
        let bytes = top_metadata.blocks() * 512;
        let top_files = if options.top_files_limit == 0 {
            Vec::new()
        } else {
            vec![LargeFile {
                path: start.to_path_buf(),
                bytes,
                mtime: top_metadata.mtime(),
            }]
        };
        return ScanResult {
            root: DirNode {
                path: start.to_path_buf(),
                name,
                bytes,
                files: 1,
                mtime: top_metadata.mtime(),
                children: Vec::new(),
                truncated_depth: false,
            },
            dirs_visited: 0,
            complete: true,
            skipped_mounts: Vec::new(),
            warnings: Vec::new(),
            top_files,
        };
    }

    let shared = Arc::new(Shared {
        top_dev: top_metadata.dev(),
        max_depth: options.max_depth,
        top_files_limit: options.top_files_limit,
        visited: AtomicU64::new(0),
        bytes_so_far: AtomicU64::new(0),
        warnings: Mutex::new(Vec::new()),
        skipped_mounts: Mutex::new(Vec::new()),
        top_files: Mutex::new(BinaryHeap::new()),
        cancel: Arc::clone(cancel),
        progress: Mutex::new(progress),
    });

    let visited = shared.visited.fetch_add(1, Ordering::Relaxed) + 1;
    maybe_report(&shared, visited);

    let queue: Arc<Mutex<VecDeque<(PathBuf, String)>>> = Arc::new(Mutex::new(VecDeque::new()));
    let mut root_bytes = 0u64;
    let mut root_files = 0u64;

    match std::fs::read_dir(start) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if shared.cancel.load(Ordering::Relaxed) {
                    break;
                }
                let child_path = entry.path();
                let Ok(child_metadata) = std::fs::symlink_metadata(&child_path) else {
                    continue;
                };
                if child_metadata.is_dir() {
                    let child_name = file_name_lossy(&child_path);
                    if child_name == ".snapshots" {
                        continue;
                    }
                    if crosses_device(child_metadata.dev(), shared.top_dev) {
                        lock(&shared.skipped_mounts).push(child_path);
                        continue;
                    }
                    lock(&queue).push_back((child_path, child_name));
                } else {
                    let size = child_metadata.blocks() * 512;
                    root_bytes += size;
                    root_files += 1;
                    shared.bytes_so_far.fetch_add(size, Ordering::Relaxed);
                    offer_top_file(&shared, child_path, size, child_metadata.mtime());
                }
            }
        }
        Err(e) => {
            lock(&shared.warnings).push(format!("{}: {e}", start.display()));
        }
    }

    let worker_count = options.workers.max(1);
    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let shared = Arc::clone(&shared);
        handles.push(std::thread::spawn(move || -> Vec<DirNode> {
            let mut results = Vec::new();
            loop {
                let Some((path, name)) = lock(&queue).pop_front() else {
                    break;
                };
                let metadata = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) => {
                        lock(&shared.warnings).push(format!("{}: {e}", path.display()));
                        continue;
                    }
                };
                results.push(build_node(path, name, metadata, 1, &shared));
            }
            results
        }));
    }

    let mut children: Vec<DirNode> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap_or_default())
        .collect();
    children.sort_by(|a, b| a.name.cmp(&b.name));

    for child in &children {
        root_bytes += child.bytes;
        root_files += child.files;
    }

    let truncated_depth = options.max_depth == 0 && !children.is_empty();
    if truncated_depth {
        children.clear();
    }

    let dirs_visited = shared.visited.load(Ordering::Relaxed);
    let complete = !shared.cancel.load(Ordering::Relaxed);
    let warnings = std::mem::take(&mut *lock(&shared.warnings));
    let skipped_mounts = std::mem::take(&mut *lock(&shared.skipped_mounts));

    let mut top_files: Vec<LargeFile> = std::mem::take(&mut *lock(&shared.top_files))
        .into_iter()
        .map(|Reverse(entry)| LargeFile {
            path: entry.path,
            bytes: entry.bytes,
            mtime: entry.mtime,
        })
        .collect();
    top_files.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));

    ScanResult {
        root: DirNode {
            path: start.to_path_buf(),
            name,
            bytes: root_bytes,
            files: root_files,
            mtime: top_metadata.mtime(),
            children,
            truncated_depth,
        },
        dirs_visited,
        complete,
        skipped_mounts,
        warnings,
        top_files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn blocks_of(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).unwrap().blocks() * 512
    }

    #[test]
    fn test_computes_exact_bytes_and_file_counts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/one.txt"), b"hello world").unwrap();
        std::fs::write(root.join("a/two.txt"), b"more data here").unwrap();
        std::fs::write(root.join("top.txt"), b"top level file").unwrap();

        let expected = blocks_of(&root.join("a/b/one.txt"))
            + blocks_of(&root.join("a/two.txt"))
            + blocks_of(&root.join("top.txt"));

        let cancel = Arc::new(AtomicBool::new(false));
        let result = scan(&root, &ScanOptions::default(), None, &cancel);

        assert_eq!(result.root.bytes, expected);
        assert_eq!(result.root.files, 3);
        assert!(result.complete);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_prunes_children_past_max_depth_but_keeps_aggregated_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        let deep = root.join("l1/l2/l3/l4");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("deep.txt"), b"deep content here").unwrap();

        let expected_bytes = blocks_of(&deep.join("deep.txt"));

        let cancel = Arc::new(AtomicBool::new(false));
        let options = ScanOptions {
            max_depth: 2,
            ..Default::default()
        };
        let result = scan(&root, &options, None, &cancel);

        let l1 = result
            .root
            .children
            .iter()
            .find(|n| n.name == "l1")
            .unwrap();
        assert_eq!(l1.bytes, expected_bytes);
        assert_eq!(l1.files, 1);
        assert!(!l1.truncated_depth);
        assert_eq!(l1.children.len(), 1);

        let l2 = &l1.children[0];
        assert_eq!(l2.name, "l2");
        assert_eq!(l2.bytes, expected_bytes);
        assert_eq!(l2.files, 1);
        assert!(l2.truncated_depth);
        assert!(l2.children.is_empty());
    }

    #[test]
    fn test_symlink_inside_tree_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let outside = dir.path().join("big.txt");
        std::fs::write(&outside, vec![b'x'; 8192]).unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let result = scan(&root, &ScanOptions::default(), None, &cancel);

        let expected = blocks_of(&root.join("link.txt"));
        assert_eq!(result.root.bytes, expected);
        assert_eq!(result.root.files, 1);
        assert!(expected < blocks_of(&outside));
    }

    #[test]
    fn test_cancelled_before_start_returns_incomplete_empty_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"data").unwrap();

        let cancel = Arc::new(AtomicBool::new(true));
        let result = scan(&root, &ScanOptions::default(), None, &cancel);

        assert!(!result.complete);
        assert_eq!(result.dirs_visited, 0);
        assert!(result.root.children.is_empty());
        assert_eq!(result.root.bytes, 0);
        assert!(result.warnings.is_empty());
        assert!(result.skipped_mounts.is_empty());
    }

    #[test]
    fn test_snapshots_directory_is_invisible() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join(".snapshots")).unwrap();
        std::fs::write(root.join(".snapshots/big-file"), vec![b'x'; 4096]).unwrap();
        std::fs::write(root.join("keep.txt"), b"keep").unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let result = scan(&root, &ScanOptions::default(), None, &cancel);

        assert_eq!(result.root.files, 1);
        assert_eq!(result.root.bytes, blocks_of(&root.join("keep.txt")));
        assert!(result.root.children.iter().all(|c| c.name != ".snapshots"));
    }

    #[test]
    fn test_crosses_device_detects_different_dev_ids() {
        assert!(crosses_device(2, 1));
        assert!(!crosses_device(1, 1));
    }

    #[test]
    fn test_is_progress_checkpoint_multiples_of_100() {
        assert!(is_progress_checkpoint(100));
        assert!(is_progress_checkpoint(200));
        assert!(!is_progress_checkpoint(1));
        assert!(!is_progress_checkpoint(99));
        assert!(!is_progress_checkpoint(150));
    }

    #[test]
    fn test_top_files_orders_largest_first() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("a/b/c/d")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();

        std::fs::write(root.join("small.txt"), vec![0u8; 4096]).unwrap();
        std::fs::write(root.join("a/med.txt"), vec![0u8; 8192]).unwrap();
        std::fs::write(root.join("a/b/big1.txt"), vec![0u8; 12288]).unwrap();
        std::fs::write(root.join("a/b/c/deep_big.txt"), vec![0u8; 24576]).unwrap();
        std::fs::write(root.join("a/b/c/d/deep_small.txt"), vec![0u8; 8192]).unwrap();
        std::fs::write(root.join("other/big4.txt"), vec![0u8; 20480]).unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let options = ScanOptions {
            top_files_limit: 3,
            ..Default::default()
        };
        let result = scan(&root, &options, None, &cancel);

        let expected_paths = [
            root.join("a/b/c/deep_big.txt"),
            root.join("other/big4.txt"),
            root.join("a/b/big1.txt"),
        ];
        assert_eq!(result.top_files.len(), 3);
        for (got, expected_path) in result.top_files.iter().zip(expected_paths.iter()) {
            assert_eq!(&got.path, expected_path);
            assert_eq!(got.bytes, blocks_of(expected_path));
        }
    }

    #[test]
    fn test_top_files_ties_break_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();

        for name in ["z.txt", "a.txt", "m.txt", "b.txt"] {
            std::fs::write(root.join(name), vec![0u8; 4096]).unwrap();
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let options = ScanOptions {
            top_files_limit: 2,
            ..Default::default()
        };
        let result = scan(&root, &options, None, &cancel);

        let expected_paths = vec![root.join("a.txt"), root.join("b.txt")];
        assert_eq!(
            result
                .top_files
                .iter()
                .map(|f| f.path.clone())
                .collect::<Vec<_>>(),
            expected_paths
        );
    }

    #[test]
    fn test_top_files_limit_zero_collects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), vec![0u8; 4096]).unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let options = ScanOptions {
            top_files_limit: 0,
            ..Default::default()
        };
        let result = scan(&root, &options, None, &cancel);

        assert!(result.top_files.is_empty());
    }

    #[test]
    fn test_top_files_excludes_skipped_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join(".snapshots")).unwrap();
        std::fs::write(root.join(".snapshots/huge.txt"), vec![0u8; 24576]).unwrap();
        std::fs::write(root.join("keep.txt"), vec![0u8; 4096]).unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let options = ScanOptions {
            top_files_limit: 10,
            ..Default::default()
        };
        let result = scan(&root, &options, None, &cancel);

        assert!(
            result
                .top_files
                .iter()
                .all(|f| !f.path.to_string_lossy().contains(".snapshots"))
        );
        assert!(
            result
                .top_files
                .iter()
                .any(|f| f.path == root.join("keep.txt"))
        );
    }

    #[test]
    fn test_push_bounded_evicts_smallest_bytes_then_largest_path() {
        let mut heap: std::collections::BinaryHeap<std::cmp::Reverse<HeapEntry>> =
            std::collections::BinaryHeap::new();
        push_bounded(
            &mut heap,
            2,
            HeapEntry {
                bytes: 10,
                path: PathBuf::from("b"),
                mtime: 0,
            },
        );
        push_bounded(
            &mut heap,
            2,
            HeapEntry {
                bytes: 10,
                path: PathBuf::from("a"),
                mtime: 0,
            },
        );
        // Heap full at limit 2 with equal bytes; "b" is the worse (evict-first) entry.
        // A smaller-bytes candidate must not replace anything.
        push_bounded(
            &mut heap,
            2,
            HeapEntry {
                bytes: 5,
                path: PathBuf::from("z"),
                mtime: 0,
            },
        );
        // An equal-bytes candidate with a lexicographically smaller path than the
        // current worst ("b") must replace it.
        push_bounded(
            &mut heap,
            2,
            HeapEntry {
                bytes: 10,
                path: PathBuf::from("0"),
                mtime: 0,
            },
        );

        let mut result: Vec<HeapEntry> = heap.into_iter().map(|std::cmp::Reverse(e)| e).collect();
        result.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].path, PathBuf::from("0"));
        assert_eq!(result[1].path, PathBuf::from("a"));
    }

    #[test]
    fn test_unreadable_directory_produces_warning_and_scan_continues() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("locked")).unwrap();
        std::fs::create_dir_all(root.join("ok")).unwrap();
        std::fs::write(root.join("ok/file.txt"), b"hello").unwrap();

        let locked = root.join("locked");
        let original = std::fs::metadata(&locked).unwrap().permissions();
        let mut denied = original.clone();
        denied.set_mode(0o000);
        std::fs::set_permissions(&locked, denied).unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let result = scan(&root, &ScanOptions::default(), None, &cancel);

        std::fs::set_permissions(&locked, original).unwrap();

        assert!(result.warnings.iter().any(|w| w.contains("locked")));
        let ok_node = result
            .root
            .children
            .iter()
            .find(|n| n.name == "ok")
            .unwrap();
        assert_eq!(ok_node.files, 1);
    }
}
