//! Tests of the real file system.

use super::{Fs, FsError, RealFs};

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
