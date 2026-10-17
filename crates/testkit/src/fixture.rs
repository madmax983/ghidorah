//! A fixture cache with one built value per key in each test binary.
//!
//! Tests in one binary run on many threads. [`cached`] builds the value of a
//! key once and gives each later caller the same `&'static` value. Each key
//! has its own `OnceLock`, so a slow build blocks only the callers of its key.

use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

/// The registry key: the fixture key and the value type.
type Key = (&'static str, TypeId);

/// The registry of per-key cells. Each cell is a leaked `OnceLock<T>`.
type Registry = Mutex<BTreeMap<Key, &'static (dyn Any + Send + Sync)>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Returns the cell of `key` for the type `T`. The first call makes the cell.
fn cell<T: Send + Sync + 'static>(key: &'static str) -> &'static OnceLock<T> {
    let mut map = registry().lock().unwrap_or_else(PoisonError::into_inner);
    let entry = map.entry((key, TypeId::of::<T>())).or_insert_with(|| {
        let fresh: &'static OnceLock<T> = Box::leak(Box::new(OnceLock::new()));
        fresh
    });
    // The key holds the type ID, so the downcast always succeeds.
    // A failed downcast gives a fresh cell, which only loses the cache.
    entry
        .downcast_ref::<OnceLock<T>>()
        .unwrap_or_else(|| Box::leak(Box::new(OnceLock::new())))
}

/// Returns the value of `key`. The first call runs `build`.
///
/// The cache keys on the key and on the type `T`. So two types never share an entry.
/// The value lives until the test binary stops. Do not call `cached` with the same
/// key and type from inside `build`.
pub fn cached<T: Send + Sync + 'static>(
    key: &'static str,
    build: impl FnOnce() -> T,
) -> &'static T {
    cell::<T>(key).get_or_init(build)
}
