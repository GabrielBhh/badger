use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};

use crate::ctx::Ctx;
use crate::safety::journal::{Journal, Record};
use crate::safety::protected::{SafetyEnv, Tier, validate_deletable};
use crate::util::dirsize::dir_size;

pub struct TrashOutcome {
    pub trashed_to: PathBuf,
    pub bytes: u64,
}

/// Whether two `st_dev` values refer to the same filesystem.
fn same_device(a: u64, b: u64) -> bool {
    a == b
}

/// Percent-encodes `path` byte-by-byte for a `.trashinfo` `Path=` line: ASCII
/// alphanumerics and `/ - _ . ~` pass through literally, everything else
/// (including each byte of a multi-byte UTF-8 character) becomes `%XX`
/// uppercase hex.
fn percent_encode(path: &Path) -> String {
    let mut out = String::new();
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Candidate trash names for `file_name`: itself, then `.2`, `.3`, ...
fn candidate_names(file_name: &str) -> impl Iterator<Item = String> {
    let file_name = file_name.to_string();
    std::iter::once(file_name.clone()).chain((2..).map(move |n| format!("{file_name}.{n}")))
}

/// Claims the first available `<info_dir>/<candidate>.trashinfo` name for
/// `file_name` (itself, then `.2`, `.3`, ...), creating the file exclusively.
/// `candidate_names` never terminates, so the loop below only ever exits via
/// `return` or `?` — using a bare `loop` (rather than `for`) means the loop
/// expression itself has type `!`, so there's no fallthrough to handle.
fn claim_info_file(
    info_dir: &Path,
    file_name: &str,
) -> anyhow::Result<(std::fs::File, PathBuf, String)> {
    let mut candidates = candidate_names(file_name);
    loop {
        let Some(candidate) = candidates.next() else {
            continue;
        };
        let info_path = info_dir.join(format!("{candidate}.trashinfo"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&info_path)
        {
            Ok(f) => return Ok((f, info_path, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("failed to create {}", info_path.display()));
            }
        }
    }
}

/// Writes a record to the journal; a failed audit-trail write must not fail
/// the caller's action, so it's reported to stderr instead (matches
/// `core::exec`'s "audit trail must not abort" convention).
fn journal_or_warn(ctx: &Ctx, record: &Record) {
    if let Err(e) = Journal::new(&ctx.state_dir).append(record) {
        eprintln!("warning: failed to record audit trail: {e:#}");
    }
}

/// Moves `path` into the freedesktop trash under `ctx.home`, after passing
/// the same safety validation the executor applies before a real delete.
/// `start` is the directory the current analyze session was started on — the
/// only prefix trashing is allowed inside. Journals the operation.
pub fn trash_path(
    ctx: &Ctx,
    start: &Path,
    path: &Path,
    run_id: &str,
) -> anyhow::Result<TrashOutcome> {
    let record = |bytes: u64, outcome: String| {
        Record::now(
            run_id.to_string(),
            "analyze".to_string(),
            "analyze.trash".to_string(),
            "trash".to_string(),
            None,
            Some(vec![path.display().to_string()]),
            false,
            false,
            bytes,
            outcome,
        )
    };

    let env = SafetyEnv::from_system(ctx)?;
    if let Err(refusal) = validate_deletable(path, &[start.to_path_buf()], Tier::User, &env) {
        journal_or_warn(ctx, &record(0, format!("refused: {refusal}")));
        bail!("refused: {refusal}");
    }

    // Deliberately ignores XDG_DATA_HOME: `Ctx` has no data-dir plumbing, and
    // badger's ctx already ignores XDG vars once home is overridden — trash
    // always lives under the resolved home.
    let trash_dir = ctx.home.join(".local/share/Trash");
    let files_dir = trash_dir.join("files");
    let info_dir = trash_dir.join("info");
    std::fs::create_dir_all(&files_dir)
        .with_context(|| format!("failed to create {}", files_dir.display()))?;
    std::fs::create_dir_all(&info_dir)
        .with_context(|| format!("failed to create {}", info_dir.display()))?;

    let source_dev = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .dev();
    let trash_dev = std::fs::metadata(&files_dir)
        .with_context(|| format!("failed to stat {}", files_dir.display()))?
        .dev();
    if !same_device(source_dev, trash_dev) {
        let msg = "can't trash across filesystems — delete permanently from the TUI instead";
        journal_or_warn(
            ctx,
            &record(0, "refused: can't trash across filesystems".to_string()),
        );
        bail!(msg);
    }

    let bytes = dir_size(path);

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("path has no file name: {}", path.display()))?
        .to_string_lossy()
        .into_owned();

    let deletion_date = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S").to_string();
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .with_context(|| "failed to get current directory")?
            .join(path)
    };
    let info_contents = format!(
        "[Trash Info]\nPath={}\nDeletionDate={deletion_date}\n",
        percent_encode(&absolute_path)
    );

    let (mut info_file, info_path, final_name) = claim_info_file(&info_dir, &file_name)?;

    if let Err(e) = info_file
        .write_all(info_contents.as_bytes())
        .with_context(|| format!("failed to write {}", info_path.display()))
    {
        let _ = std::fs::remove_file(&info_path);
        return Err(e);
    }

    let target = files_dir.join(&final_name);
    if let Err(e) = std::fs::rename(path, &target)
        .with_context(|| format!("failed to move {} to {}", path.display(), target.display()))
    {
        let _ = std::fs::remove_file(&info_path);
        return Err(e);
    }

    journal_or_warn(ctx, &record(bytes, "ok".to_string()));

    Ok(TrashOutcome {
        trashed_to: target,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    struct Fixture {
        _sandbox: tempfile::TempDir,
        ctx: Ctx,
    }

    fn fixture() -> Fixture {
        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let home = root.join("home/user");
        std::fs::create_dir_all(&home).unwrap();
        let ctx = Ctx {
            root,
            home,
            config_dir: sandbox.path().join("config"),
            state_dir: sandbox.path().join("state"),
            dry_run: false,
            debug: false,
            config: Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output: None,
        };
        Fixture {
            _sandbox: sandbox,
            ctx,
        }
    }

    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    fn parse_trashinfo(path: &Path) -> (String, String) {
        let text = std::fs::read_to_string(path).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next().unwrap(), "[Trash Info]");
        let path_line = lines.next().unwrap();
        let deletion_line = lines.next().unwrap();
        let encoded = path_line.strip_prefix("Path=").unwrap();
        let deletion = deletion_line.strip_prefix("DeletionDate=").unwrap();
        (percent_decode(encoded), deletion.to_string())
    }

    #[test]
    fn test_trashed_file_lands_in_trash_with_valid_trashinfo() {
        let f = fixture();
        let stuff = f.ctx.home.join("stuff");
        std::fs::create_dir_all(&stuff).unwrap();
        let target = stuff.join("junk.txt");
        std::fs::write(&target, b"hello").unwrap();

        let outcome = trash_path(&f.ctx, &f.ctx.home, &target, "run-1").unwrap();

        assert!(!target.exists());
        let trashed = f.ctx.home.join(".local/share/Trash/files/junk.txt");
        assert!(trashed.exists());
        assert_eq!(outcome.trashed_to, trashed);

        let info_path = f
            .ctx
            .home
            .join(".local/share/Trash/info/junk.txt.trashinfo");
        assert!(info_path.exists());
        let (decoded_path, deletion_date) = parse_trashinfo(&info_path);
        assert_eq!(decoded_path, target.display().to_string());
        deletion_date.parse::<jiff::civil::DateTime>().unwrap();
    }

    #[test]
    fn test_collision_appends_numeric_suffix() {
        let f = fixture();
        let dir_a = f.ctx.home.join("stuff_a");
        let dir_b = f.ctx.home.join("stuff_b");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        let target_a = dir_a.join("junk.txt");
        let target_b = dir_b.join("junk.txt");
        std::fs::write(&target_a, b"a").unwrap();
        std::fs::write(&target_b, b"b").unwrap();

        trash_path(&f.ctx, &f.ctx.home, &target_a, "run-1").unwrap();
        let outcome_b = trash_path(&f.ctx, &f.ctx.home, &target_b, "run-1").unwrap();

        let files = f.ctx.home.join(".local/share/Trash/files");
        let info = f.ctx.home.join(".local/share/Trash/info");
        assert_eq!(outcome_b.trashed_to, files.join("junk.txt.2"));
        assert!(info.join("junk.txt.2.trashinfo").exists());

        let (decoded_a, _) = parse_trashinfo(&info.join("junk.txt.trashinfo"));
        let (decoded_b, _) = parse_trashinfo(&info.join("junk.txt.2.trashinfo"));
        assert_eq!(decoded_a, target_a.display().to_string());
        assert_eq!(decoded_b, target_b.display().to_string());
    }

    #[test]
    fn test_deny_listed_path_is_refused() {
        let f = fixture();
        let ssh = f.ctx.home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let target = ssh.join("id_rsa");
        std::fs::write(&target, b"secret").unwrap();

        let result = trash_path(&f.ctx, &f.ctx.home, &target, "run-1");

        assert!(result.is_err());
        assert!(target.exists());
        let (records, _) = Journal::new(&f.ctx.state_dir).read_all().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].outcome.starts_with("refused:"));
    }

    #[test]
    fn test_path_outside_start_prefix_is_refused() {
        let f = fixture();
        let start = f.ctx.home.join("stuff");
        let other = f.ctx.home.join("other");
        std::fs::create_dir_all(&start).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let target = other.join("file.txt");
        std::fs::write(&target, b"data").unwrap();

        let result = trash_path(&f.ctx, &start, &target, "run-1");

        assert!(result.is_err());
        assert!(target.exists());
    }

    #[test]
    fn test_journal_records_successful_trash() {
        let f = fixture();
        let stuff = f.ctx.home.join("stuff");
        std::fs::create_dir_all(&stuff).unwrap();
        let target = stuff.join("junk.txt");
        std::fs::write(&target, b"hello").unwrap();

        trash_path(&f.ctx, &f.ctx.home, &target, "run-1").unwrap();

        let (records, _) = Journal::new(&f.ctx.state_dir).read_all().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].cmd, "analyze");
        assert_eq!(records[0].action, "trash");
        assert_eq!(records[0].outcome, "ok");
        assert!(records[0].bytes_freed > 0);
        assert_eq!(records[0].paths, Some(vec![target.display().to_string()]));
    }

    #[test]
    fn test_a_directory_can_be_trashed_wholly() {
        let f = fixture();
        let stuff = f.ctx.home.join("stuff");
        let olddir = stuff.join("olddir");
        std::fs::create_dir_all(&olddir).unwrap();
        std::fs::write(olddir.join("inside.txt"), b"content").unwrap();

        let outcome = trash_path(&f.ctx, &f.ctx.home, &olddir, "run-1").unwrap();

        assert!(!olddir.exists());
        let trashed = f.ctx.home.join(".local/share/Trash/files/olddir");
        assert!(trashed.is_dir());
        assert!(trashed.join("inside.txt").exists());
        assert_eq!(outcome.trashed_to, trashed);
        assert!(outcome.bytes > 0);
    }

    #[test]
    fn test_percent_encode_leaves_plain_path_unchanged() {
        assert_eq!(
            percent_encode(Path::new("/home/user/stuff/junk.txt")),
            "/home/user/stuff/junk.txt"
        );
    }

    #[test]
    fn test_percent_encode_escapes_space_percent_and_non_ascii() {
        assert_eq!(percent_encode(Path::new("/a b")), "/a%20b");
        assert_eq!(percent_encode(Path::new("/100%")), "/100%25");
        assert_eq!(percent_encode(Path::new("/café")), "/caf%C3%A9");
    }

    #[test]
    fn test_same_device_compares_dev_ids() {
        assert!(same_device(42, 42));
        assert!(!same_device(1, 2));
    }
}
