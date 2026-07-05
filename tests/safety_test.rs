use std::collections::HashSet;
use std::path::{Path, PathBuf};

use badger::safety::protected::{Refusal, SafetyEnv, Tier, validate_deletable};

fn make_env(root: &Path, home: &Path) -> SafetyEnv {
    SafetyEnv {
        root: root.to_path_buf(),
        home: home.to_path_buf(),
        mount_points: HashSet::new(),
        euid: nix::unistd::Uid::current().as_raw(),
    }
}

struct Fixture {
    _sandbox: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

fn fixture() -> Fixture {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home").join("testuser");
    std::fs::create_dir_all(&home).unwrap();
    Fixture {
        _sandbox: sandbox,
        root,
        home,
    }
}

#[test]
fn test_happy_path_file_in_allowed_prefix_validates() {
    let f = fixture();
    let allowed = f.home.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let file = allowed.join("data.txt");
    std::fs::write(&file, b"x").unwrap();

    let env = make_env(&f.root, &f.home);
    assert_eq!(
        validate_deletable(&file, &[allowed], Tier::User, &env),
        Ok(())
    );
}

#[test]
fn test_refuses_path_inside_dotssh() {
    let f = fixture();
    let ssh = f.home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let key = ssh.join("id_rsa");
    std::fs::write(&key, b"secret").unwrap();

    let env = make_env(&f.root, &f.home);
    assert_eq!(
        validate_deletable(&key, std::slice::from_ref(&f.home), Tier::User, &env),
        Err(Refusal::DenyListed)
    );
}

#[test]
fn test_refuses_home_itself() {
    let f = fixture();
    let env = make_env(&f.root, &f.home);
    let parent = f.home.parent().unwrap().to_path_buf();
    assert_eq!(
        validate_deletable(&f.home, &[parent], Tier::User, &env),
        Err(Refusal::DenyListed)
    );
}

#[test]
fn test_refuses_ancestor_of_deny_entry() {
    let f = fixture();
    let config_dir = f.home.join(".config");
    std::fs::create_dir_all(&config_dir).unwrap();
    // .config/badger is deny-listed; .config is its ancestor.
    let env = make_env(&f.root, &f.home);
    assert_eq!(
        validate_deletable(&config_dir, std::slice::from_ref(&f.home), Tier::User, &env),
        Err(Refusal::DenyListed)
    );
}

#[test]
fn test_symlink_escape_via_directory_component_is_refused() {
    let f = fixture();
    let allowed = f.home.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();

    let outside = f.home.parent().unwrap().join("outside-target");
    std::fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("file.txt");
    std::fs::write(&outside_file, b"x").unwrap();

    let cache_link = allowed.join("cache");
    std::os::unix::fs::symlink(&outside, &cache_link).unwrap();

    let candidate = cache_link.join("file.txt");
    let env = make_env(&f.root, &f.home);
    let result = validate_deletable(&candidate, &[allowed], Tier::User, &env);
    assert_ne!(result, Ok(()));
    assert_eq!(result, Err(Refusal::SymlinkEscape));
}

#[test]
fn test_symlink_leaf_itself_is_ok() {
    let f = fixture();
    let allowed = f.home.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let target = allowed.join("real.txt");
    std::fs::write(&target, b"x").unwrap();
    let link = allowed.join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let env = make_env(&f.root, &f.home);
    assert_eq!(
        validate_deletable(&link, &[allowed], Tier::User, &env),
        Ok(())
    );
}

#[test]
fn test_refuses_outside_prefix() {
    let f = fixture();
    let allowed = f.home.join("only-this");
    std::fs::create_dir_all(&allowed).unwrap();
    let other = f.home.join("other-dir");
    std::fs::create_dir_all(&other).unwrap();
    let file = other.join("file.txt");
    std::fs::write(&file, b"x").unwrap();

    let env = make_env(&f.root, &f.home);
    assert_eq!(
        validate_deletable(&file, &[allowed], Tier::User, &env),
        Err(Refusal::OutsidePrefix)
    );
}

#[test]
fn test_refuses_too_shallow_under_home() {
    let f = fixture();
    let cache = f.home.join(".cache");
    std::fs::create_dir_all(&cache).unwrap();

    let env = make_env(&f.root, &f.home);
    assert_eq!(
        validate_deletable(&cache, std::slice::from_ref(&f.home), Tier::User, &env),
        Err(Refusal::TooShallow)
    );
}

#[test]
fn test_refuses_too_shallow_under_root() {
    let f = fixture();
    let var = f.root.join("var");
    let log = var.join("log");
    std::fs::create_dir_all(&log).unwrap();

    let env = make_env(&f.root, &f.home);
    assert_eq!(
        validate_deletable(&log, &[var], Tier::System, &env),
        Err(Refusal::TooShallow)
    );
}

#[test]
fn test_refuses_mount_point() {
    let f = fixture();
    let allowed = f.home.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let target = allowed.join("deep").join("dir");
    std::fs::create_dir_all(&target).unwrap();

    let mut env = make_env(&f.root, &f.home);
    let canonical = target.canonicalize().unwrap();
    env.mount_points.insert(canonical);

    assert_eq!(
        validate_deletable(&target, &[allowed], Tier::User, &env),
        Err(Refusal::MountPoint)
    );
}

#[test]
fn test_refuses_not_owned_for_user_tier() {
    let f = fixture();
    let allowed = f.home.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let file = allowed.join("data.txt");
    std::fs::write(&file, b"x").unwrap();

    let mut env = make_env(&f.root, &f.home);
    env.euid += 1;

    assert_eq!(
        validate_deletable(&file, &[allowed], Tier::User, &env),
        Err(Refusal::NotOwned)
    );
}

#[test]
fn test_uninspectable_for_nonexistent_path() {
    let f = fixture();
    let allowed = f.home.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let missing = allowed.join("does-not-exist.txt");

    let env = make_env(&f.root, &f.home);
    let result = validate_deletable(&missing, &[allowed], Tier::User, &env);
    assert!(matches!(result, Err(Refusal::Uninspectable(_))));
}
