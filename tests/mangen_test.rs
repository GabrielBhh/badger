#[test]
fn test_run_writes_top_level_man_page_with_about_text() {
    let dir = tempfile::tempdir().unwrap();

    let result = badger::commands::mangen::run(dir.path());
    assert!(result.is_ok());

    let man_path = dir.path().join("badger.1");
    assert!(man_path.exists());

    let contents = std::fs::read_to_string(&man_path).unwrap();
    assert!(contents.contains("Clean, uninstall, analyze, optimize"));
}
