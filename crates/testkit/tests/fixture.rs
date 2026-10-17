//! Tests of the fixture cache.

use std::sync::atomic::{AtomicUsize, Ordering};

use ghidorah_testkit::fixture;

static BUILDS: AtomicUsize = AtomicUsize::new(0);

fn build() -> Vec<u8> {
    BUILDS.fetch_add(1, Ordering::SeqCst);
    vec![1, 2, 3]
}

#[test]
fn cached_builds_once_per_key() {
    let threads: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(|| fixture::cached("shared_fixture", build) as *const Vec<u8> as usize))
        .collect();
    let mut addresses = Vec::new();
    for t in threads {
        addresses.push(t.join().unwrap_or(0));
    }
    let first = fixture::cached("shared_fixture", build);
    assert_eq!(first, &vec![1, 2, 3]);
    assert_eq!(BUILDS.load(Ordering::SeqCst), 1, "the build ran once");
    let want = std::ptr::from_ref(first) as usize;
    assert!(addresses.iter().all(|&a| a == want), "every caller gets the same value");
}

#[test]
fn cached_keys_on_type_too() {
    let a: &u32 = fixture::cached("typed_fixture", || 7u32);
    let b: &String = fixture::cached("typed_fixture", || "seven".to_string());
    assert_eq!(*a, 7);
    assert_eq!(b, "seven");
    let c: &u32 = fixture::cached("typed_fixture", || 8u32);
    assert_eq!(*c, 7, "the first value stays");
}
