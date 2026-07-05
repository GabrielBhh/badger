use badger::commands::analyze;
use badger::config::Config;
use badger::ctx::Ctx;
use badger::output::Mode;

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

/// Builds `home/data/{big,small}` with exact 4096-multiple file sizes, plus
/// one file directly in `home/data`, and returns the `data` directory path.
fn fabricated_tree(ctx: &Ctx) -> std::path::PathBuf {
    let data = ctx.home.join("data");
    let big = data.join("big");
    let small = data.join("small");
    std::fs::create_dir_all(&big).unwrap();
    std::fs::create_dir_all(&small).unwrap();
    std::fs::write(big.join("a.bin"), vec![0u8; 4096 * 4]).unwrap();
    std::fs::write(small.join("b.bin"), vec![0u8; 4096]).unwrap();
    std::fs::write(data.join("top.bin"), vec![0u8; 4096 * 2]).unwrap();
    data
}

#[test]
fn test_human_report_for_fabricated_tree() {
    let f = fixture();
    let data = fabricated_tree(&f.ctx);

    let output = analyze::run(&f.ctx, Some(data), Mode::Human).unwrap();

    assert!(output.rendered.contains("big"));
    assert!(output.rendered.contains("16.0 KiB"));
    assert!(output.rendered.contains("small"));
    assert!(output.rendered.contains("4.0 KiB"));
    // "big" (16 KiB) must be listed before "small" (4 KiB): largest first.
    let big_pos = output.rendered.find("big").unwrap();
    let small_pos = output.rendered.find("small").unwrap();
    assert!(big_pos < small_pos);
    assert!(output.rendered.contains("Largest files:"));
    assert!(output.rendered.contains("top.bin"));
}

#[test]
fn test_json_output_shape() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    let data = home.join("data");
    std::fs::create_dir_all(data.join("big")).unwrap();
    std::fs::create_dir_all(data.join("small")).unwrap();
    std::fs::write(data.join("big/a.bin"), vec![0u8; 4096 * 4]).unwrap();
    std::fs::write(data.join("small/b.bin"), vec![0u8; 4096]).unwrap();
    std::fs::write(data.join("top.bin"), vec![0u8; 4096 * 2]).unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let output = std::process::Command::new(bin)
        .arg("analyze")
        .arg(&data)
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!value["tree"]["children"].as_array().unwrap().is_empty());
    assert!(!value["large_files"].as_array().unwrap().is_empty());
    assert!(value["totals"]["total"].as_u64().unwrap() > 0);
    assert_eq!(value["complete"], true);
    assert_eq!(
        value["tree"]["bytes"].as_u64().unwrap(),
        4096 * 4 + 4096 + 4096 * 2
    );
}

#[test]
fn test_nonexistent_path_fails_with_clear_error() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    std::fs::create_dir_all(&home).unwrap();
    let missing = home.join("nope-does-not-exist");

    let bin = env!("CARGO_BIN_EXE_badger");
    let output = std::process::Command::new(bin)
        .arg("analyze")
        .arg(&missing)
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&missing.display().to_string()));
}

#[test]
fn test_path_outside_root_and_home_is_rejected() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    std::fs::create_dir_all(&home).unwrap();
    let outside = tempfile::tempdir().unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let output = std::process::Command::new(bin)
        .arg("analyze")
        .arg(outside.path())
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_default_path_is_home() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = sandbox.path().join("root");
    let home = root.join("home/user");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("file.bin"), vec![0u8; 4096]).unwrap();

    let bin = env!("CARGO_BIN_EXE_badger");
    let output = std::process::Command::new(bin)
        .arg("analyze")
        .env("BADGER_ROOT", &root)
        .env("BADGER_HOME", &home)
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let home_canonical = home.canonicalize().unwrap();
    assert_eq!(value["path"], home_canonical.display().to_string());
}
