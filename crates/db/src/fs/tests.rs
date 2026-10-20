//! Tests of the real file system and the file replace.

use std::path::Path;

use super::{Fs, FsError, RealFs, replace_file};
use crate::project::tests::fs_sim::SimFs;

#[test]
fn regress_replace_file_keeps_other_tmp() {
    let fs = SimFs::new();
    let dir = Path::new("/p/0011223344556677");
    let path = dir.join("a.json");
    let tmp = dir.join("a.json.tmp");
    // The temporary files of two other processes. One is in flight at this time.
    let other = dir.join("a.json.tmp.4194305.0");
    fs.seed(&tmp, b"in flight");
    fs.seed(&other, b"other");
    let mut handle = fs.boxed();
    replace_file(handle.as_mut(), &path, &tmp, b"new").unwrap();
    replace_file(handle.as_mut(), &path, &tmp, b"newer").unwrap();
    assert_eq!(fs.get(&path), Some(b"newer".to_vec()));
    assert_eq!(fs.get(&tmp), Some(b"in flight".to_vec()), "the file stays");
    assert_eq!(fs.get(&other), Some(b"other".to_vec()), "the file stays");
    assert_eq!(
        handle.list(dir).unwrap(),
        vec!["a.json", "a.json.tmp", "a.json.tmp.4194305.0"],
        "the temporary file of this process goes"
    );
}

#[test]
fn real_fs_operations() {
    let dir = std::env::temp_dir().join(format!("ghidorah-fs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut fs = RealFs;
    fs.create_dir_all(&dir.join("sub")).unwrap();
    let file = dir.join("a.txt");
    fs.create_new(&file).unwrap();
    assert_eq!(fs.create_new(&file), Err(FsError::Exists(file.clone())));
    fs.append(&file, b"one\n").unwrap();
    fs.append(&file, b"two\n").unwrap();
    fs.sync_file(&file).unwrap();
    assert_eq!(fs.read(&file).unwrap(), b"one\ntwo\n");
    fs.write_all(&file, b"three").unwrap();
    assert_eq!(fs.read(&file).unwrap(), b"three");
    let moved = dir.join("b.txt");
    fs.rename(&file, &moved).unwrap();
    fs.sync_dir(&dir).unwrap();
    assert!(!fs.exists(&file));
    assert!(fs.exists(&moved));
    assert_eq!(fs.list(&dir).unwrap(), vec!["b.txt", "sub"]);
    fs.set_read_only(&moved).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&moved).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o444);
    }
    fs.remove(&moved).unwrap();
    assert!(fs.read(&moved).unwrap_err().is_not_found());
    assert!(fs.append(&moved, b"x").unwrap_err().is_not_found());
    let mut other = fs.boxed();
    assert!(other.exists(&dir));
    let _ = std::fs::remove_dir_all(&dir);
}
