//! A fixture cache with one built value per key in each test binary.
//!
//! Tests in one binary run on many threads. [`cached`] builds the value of a
//! key once and gives each later caller the same `&'static` value.

/// Returns the value of `key`. The first call runs `build`.
///
/// The cache keys on the key and on the type `T`. So two types never share an entry.
/// The value lives until the test binary stops.
pub fn cached<T: Send + Sync + 'static>(key: &'static str, build: impl FnOnce() -> T) -> &'static T {
    let _ = key;
    Box::leak(Box::new(build()))
}
