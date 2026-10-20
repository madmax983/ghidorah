//! Tests of the project lock.

use std::path::Path;

use super::{
    LOCK_FILE, LockError, acquire, is_alive, pid_dead, process_info, release, stat_start_time,
};
use crate::fs::Fs;
use crate::project::tests::{ROOT, create, input, me, opts, sim, stat_line};
use crate::project::{Access, LoadSpec, PROJECT_FILE, Project, ProjectError, ProjectMeta};

#[test]
fn stat_start_time_reads_field_22() {
    assert_eq!(stat_start_time(&stat_line(42, 98765)), Some(98765));
    assert_eq!(stat_start_time("42 (a) S 1"), None);
    assert_eq!(stat_start_time("no parenthesis"), None);
    assert_eq!(stat_start_time(""), None);
}

#[test]
fn liveness_needs_the_same_start_and_boot() {
    let fs = sim(&[100]);
    let mut h = fs.boxed();
    assert_eq!(process_info(h.as_mut(), 100), Some(me(100)));
    assert!(is_alive(h.as_mut(), &me(100)));
    let mut other_boot = me(100);
    other_boot.boot_id = "another-boot".to_owned();
    assert!(!is_alive(h.as_mut(), &other_boot));
    let mut restarted = me(100);
    restarted.start_time += 1;
    assert!(!is_alive(h.as_mut(), &restarted));
    assert!(!is_alive(h.as_mut(), &me(300)));
    // Only a missing stat file makes a process ID dead. A failed read keeps it alive.
    assert!(!pid_dead(h.as_mut(), 100));
    assert!(pid_dead(h.as_mut(), 300));
    fs.stop_after(0);
    assert!(!pid_dead(h.as_mut(), 300));
    fs.resume();
}

#[test]
fn acquire_held_stale_and_break() {
    let fs = sim(&[100, 200]);
    let dir = Path::new("/data/projects/p");
    let mut h = fs.boxed();
    h.create_dir_all(dir).unwrap();
    acquire(h.as_mut(), dir, &me(100), false).unwrap();
    assert_eq!(
        acquire(h.as_mut(), dir, &me(200), false),
        Err(LockError::Held(me(100)))
    );
    assert_eq!(
        acquire(h.as_mut(), dir, &me(200), true),
        Err(LockError::Held(me(100))),
        "--break-lock never takes a live lock"
    );
    // Another owner keeps its lock.
    release(h.as_mut(), dir, &me(200)).unwrap();
    assert!(fs.get(&dir.join("project.lock")).is_some());
    h.remove(Path::new("/proc/100/stat")).unwrap();
    assert_eq!(
        acquire(h.as_mut(), dir, &me(200), false),
        Err(LockError::Stale(me(100)))
    );
    acquire(h.as_mut(), dir, &me(200), true).unwrap();
    release(h.as_mut(), dir, &me(200)).unwrap();
    assert!(fs.get(&dir.join("project.lock")).is_none());
    // An unknown process can hold a lock file that does not parse.
    h.create_new(&dir.join("project.lock")).unwrap();
    h.write_all(&dir.join("project.lock"), b"garbage").unwrap();
    assert_eq!(
        acquire(h.as_mut(), dir, &me(200), false),
        Err(LockError::Unknown)
    );
    acquire(h.as_mut(), dir, &me(200), true).unwrap();
    assert_eq!(
        h.list(dir).unwrap(),
        vec!["project.lock"],
        "no temporary lock file stays"
    );
}

#[test]
fn lock_publish_writes_the_owner_before_the_name() {
    let fs = sim(&[100]);
    let dir = Path::new("/data/projects/p");
    let mut h = fs.boxed();
    h.create_dir_all(dir).unwrap();
    let _ = fs.take_log();
    acquire(h.as_mut(), dir, &me(100), false).unwrap();
    let log = fs.take_log();
    let tmp = log[0].strip_prefix("create_new ").unwrap();
    assert!(tmp.starts_with("project.lock.tmp."), "{tmp}");
    assert_eq!(
        log,
        vec![
            format!("create_new {tmp}"),
            format!("write_all {tmp}"),
            format!("sync_file {tmp}"),
            format!("link_new {tmp} project.lock"),
            format!("remove {tmp}"),
        ]
    );
    // A crash before the link takes no lock.
    release(h.as_mut(), dir, &me(100)).unwrap();
    fs.stop_after(3);
    assert_eq!(
        acquire(h.as_mut(), dir, &me(100), false),
        Err(LockError::Fs(crate::fs::FsError::Stopped))
    );
    fs.resume();
    assert!(fs.get(&dir.join(LOCK_FILE)).is_none());
    let display = [
        LockError::Held(me(100)).to_string(),
        LockError::Unknown.to_string(),
        LockError::Stale(me(100)).to_string(),
    ];
    assert!(
        display.iter().all(|t| t.contains("project lock")),
        "{display:?}"
    );
}

#[test]
fn regress_empty_lock_is_held_not_stale() {
    let fs = sim(&[100, 200]);
    let (project, program, dir) = create(&fs, 100);
    drop(project);
    let lock = dir.join(LOCK_FILE);
    let write = opts(Access::Write { break_lock: false }, 200);
    let unknown = ProjectError::Locked {
        owner: None,
        stale: false,
    };
    for text in [&b""[..], b"garbage", b"{\"pid\":1}"] {
        let _ = fs.boxed().remove(&lock);
        fs.seed(&lock, text);
        let got = Project::open(fs.boxed(), &dir, &write).unwrap_err();
        assert_eq!(got, unknown, "open with the lock {text:?}");
        assert_eq!(
            fs.get(&lock),
            Some(text.to_vec()),
            "the lock {text:?} stays"
        );
    }
    // A directory with no project file and an empty lock: the create breaks no lock.
    fs.boxed().remove(&dir.join(PROJECT_FILE)).unwrap();
    let _ = fs.boxed().remove(&lock);
    fs.seed(&lock, b"");
    let (bytes, _) = input("hello.gcc-O2");
    let meta = ProjectMeta::new(&program, "hello.gcc-O2", LoadSpec::Auto);
    let got = Project::create(fs.boxed(), Path::new(ROOT), meta, &bytes, &program, &write);
    assert_eq!(got.unwrap_err(), unknown, "create with an empty lock");
    assert_eq!(fs.get(&lock), Some(Vec::new()), "the empty lock stays");
    assert!(
        fs.get(&dir.join(PROJECT_FILE)).is_none(),
        "the create writes no project file"
    );
}
