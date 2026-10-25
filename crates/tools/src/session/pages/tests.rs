use std::path::PathBuf;

use ghidorah_analysis::pages::{PageError, PageStore};
use ghidorah_db::RealFs;

use super::ProjectPages;

/// Gives a new empty directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("ghidorah-pages-{}", std::process::id()))
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn pages_go_to_files_and_back() {
    let dir = scratch("round_trip");
    let mut store = ProjectPages::new(Box::new(RealFs), dir.clone());
    assert_eq!(store.clear(), Ok(()), "no directory yet");
    assert_eq!(store.read(5), Ok(None));
    store.write(5, b"first").unwrap();
    store.write(5, b"second").unwrap();
    store.write(6, b"other").unwrap();
    assert_eq!(store.read(5), Ok(Some(b"second".to_vec())));
    assert!(dir.join("0000000000000005.page").is_file());
    std::fs::write(dir.join("keep.txt"), b"x").unwrap();
    store.clear().unwrap();
    assert_eq!(store.read(6), Ok(None));
    assert!(
        dir.join("keep.txt").is_file(),
        "a clear removes page files only"
    );
    store.write(6, b"again").unwrap();
    assert_eq!(store.read(6), Ok(Some(b"again".to_vec())));
    assert!(format!("{store:?}").contains("round_trip"));
}

#[test]
fn a_page_file_of_an_earlier_store_takes_the_new_bytes() {
    let dir = scratch("earlier");
    ProjectPages::new(Box::new(RealFs), dir.clone())
        .write(1, b"old bytes")
        .unwrap();
    let mut store = ProjectPages::new(Box::new(RealFs), dir);
    store.write(1, b"new").unwrap();
    assert_eq!(store.read(1), Ok(Some(b"new".to_vec())));
}

#[test]
fn file_system_errors_are_page_errors() {
    let dir = scratch("errors");
    std::fs::create_dir_all(dir.join("0000000000000002.page")).unwrap();
    let mut store = ProjectPages::new(Box::new(RealFs), dir.clone());
    assert!(matches!(store.read(2), Err(PageError::Io(_))));
    assert!(matches!(store.clear(), Err(PageError::Io(_))));
    let file = dir.join("plain");
    std::fs::write(&file, b"x").unwrap();
    let mut blocked = ProjectPages::new(Box::new(RealFs), file);
    assert!(matches!(blocked.write(0, b"x"), Err(PageError::Io(_))));
    assert!(matches!(blocked.clear(), Err(PageError::Io(_))));
}
