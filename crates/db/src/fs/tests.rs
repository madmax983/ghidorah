//! Tests of the real file system and the file replace.

use std::path::Path;

use super::{EntryKind, Fs, FsError, RealFs, SWEEP_MAX, remove_dead_temps, replace_file, temp_pid};
use crate::project::tests::fs_sim::SimFs;

#[cfg(unix)]
#[test]
fn regress_project_dir_mode_0700() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("ghidorah-fs-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let before = std::fs::metadata(&base).unwrap().permissions().mode() & 0o777;
    let mut fs = RealFs;
    let project = base.join("projects").join("0011223344556677");
    fs.create_dir_all(&project.join("bin")).unwrap();
    for dir in [base.join("projects"), project.clone(), project.join("bin")] {
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", dir.display());
    }
    let after = std::fs::metadata(&base).unwrap().permissions().mode() & 0o777;
    assert_eq!(after, before, "a directory that exists keeps its mode");
    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn real_fs_refuses_symbolic_links() {
    let dir = std::env::temp_dir().join(format!("ghidorah-fs-links-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut fs = RealFs;
    fs.create_dir_all(&dir).unwrap();
    let victim = dir.join("victim.txt");
    std::fs::write(&victim, b"victim").unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let dangling = dir.join("dangling");
    std::os::unix::fs::symlink(dir.join("none"), &dangling).unwrap();
    let refused = FsError::WrongKind(link.clone());
    assert_eq!(fs.append(&link, b"x"), Err(refused.clone()));
    assert_eq!(fs.write_all(&link, b"x"), Err(refused.clone()));
    assert_eq!(fs.truncate(&link, 0), Err(refused.clone()));
    assert_eq!(fs.create_new(&link), Err(refused));
    assert_eq!(
        fs.create_new(&dangling),
        Err(FsError::WrongKind(dangling.clone()))
    );
    assert_eq!(fs.append(&dir, b"x"), Err(FsError::WrongKind(dir.clone())));
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    assert_eq!(fs.kind(&victim), Some(EntryKind::File));
    assert_eq!(fs.kind(&dir), Some(EntryKind::Dir));
    assert_eq!(fs.kind(&link), Some(EntryKind::Other));
    assert_eq!(fs.kind(&dir.join("none")), None);
    let text = FsError::WrongKind(link).to_string();
    assert!(text.contains("symbolic link"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

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
    fs.truncate(&file, 2).unwrap();
    assert_eq!(fs.read(&file).unwrap(), b"th");
    assert!(
        fs.truncate(&dir.join("none"), 0)
            .unwrap_err()
            .is_not_found()
    );
    fs.write_all(&file, b"three").unwrap();
    let linked = dir.join("c.txt");
    fs.link_new(&file, &linked).unwrap();
    assert_eq!(fs.read(&linked).unwrap(), b"three");
    assert_eq!(
        fs.link_new(&file, &linked),
        Err(FsError::Exists(linked.clone()))
    );
    assert!(
        fs.link_new(&dir.join("none"), &dir.join("d.txt"))
            .unwrap_err()
            .is_not_found()
    );
    fs.remove(&linked).unwrap();
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

#[test]
fn temp_pid_reads_only_the_temp_shape() {
    let base = "snapshot.json.tmp";
    assert_eq!(temp_pid("snapshot.json.tmp.42.0", base), Some(42));
    assert_eq!(
        temp_pid("snapshot.json.tmp.4294967295.18446744073709551615", base),
        Some(u32::MAX)
    );
    for name in [
        "snapshot.json.tmp",
        "snapshot.json.tmp.",
        "snapshot.json.tmp.42",
        "snapshot.json.tmp.42.",
        "snapshot.json.tmp..0",
        "snapshot.json.tmp.4294967296.0",
        "snapshot.json.tmp.42.18446744073709551616",
        "snapshot.json.tmp.42.99999999999999999999999",
        "snapshot.json.tmp.042.0",
        "snapshot.json.tmp.42.00",
        "snapshot.json.tmp.+42.0",
        "snapshot.json.tmp.-1.0",
        "snapshot.json.tmp.42.0.1",
        "snapshot.json.tmp.4 2.0",
        "snapshot.json.tmpx42.0",
        "snapshot.json.tmp.\u{664}\u{662}.0",
        "journal.jsonl.tmp.42.0",
    ] {
        assert_eq!(temp_pid(name, base), None, "{name}");
    }
}

#[test]
fn dead_temps_sweep_is_bounded_and_keeps_live_files() {
    let fs = SimFs::new();
    let dir = Path::new("/p/0011223344556677");
    let mut handle = fs.boxed();
    // No process has an ID above 4194304 (PID_MAX_LIMIT), so the test process has none of these.
    let dead = |_: &mut dyn Fs, pid: u32| pid == 4_194_305;
    let count = SWEEP_MAX + 3;
    for n in 0..count {
        fs.seed(&dir.join(format!("a.json.tmp.4194305.{n}")), b"x");
    }
    let me = std::process::id();
    let keep = [
        format!("a.json.tmp.{me}.0"),
        "a.json.tmp.4194306.0".to_owned(),
        "b.json.tmp.4194305.0".to_owned(),
    ];
    for name in &keep {
        fs.seed(&dir.join(name), b"x");
    }
    handle
        .create_dir_all(&dir.join("a.json.tmp.4194305.x"))
        .unwrap();
    handle
        .create_dir_all(&dir.join("a.json.tmp.4194305.99999"))
        .unwrap();
    let first = remove_dead_temps(handle.as_mut(), dir, &["a.json.tmp"], dead);
    assert!(
        first <= SWEEP_MAX,
        "one sweep reads at most {SWEEP_MAX} entries"
    );
    assert!(first < count, "{first}");
    let second = remove_dead_temps(handle.as_mut(), dir, &["a.json.tmp"], dead);
    assert_eq!(first + second, count);
    let mut want: Vec<String> = keep.to_vec();
    want.extend([
        "a.json.tmp.4194305.99999".to_owned(),
        "a.json.tmp.4194305.x".to_owned(),
    ]);
    want.sort();
    assert_eq!(
        handle.list(dir).unwrap(),
        want,
        "a live file, a directory and another base stay"
    );
    assert_eq!(
        remove_dead_temps(handle.as_mut(), Path::new("/none"), &["a.json.tmp"], dead),
        0,
        "a directory that does not exist gives no remove"
    );
}
