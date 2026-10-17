//! Tests of the project lock.

use std::path::Path;

use super::{LockError, acquire, is_alive, process_info, release, stat_start_time};
use crate::fs::Fs;
use crate::project::tests::{me, sim, stat_line};

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
        Err(LockError::Stale(Some(me(100))))
    );
    acquire(h.as_mut(), dir, &me(200), true).unwrap();
    release(h.as_mut(), dir, &me(200)).unwrap();
    assert!(fs.get(&dir.join("project.lock")).is_none());
    // A lock file that does not parse is stale.
    h.create_new(&dir.join("project.lock")).unwrap();
    h.write_all(&dir.join("project.lock"), b"garbage").unwrap();
    assert_eq!(
        acquire(h.as_mut(), dir, &me(200), false),
        Err(LockError::Stale(None))
    );
}
