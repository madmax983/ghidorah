//! Vectors and the vector cache.

use std::sync::Arc;

use ghidorah_analysis::similar::{
    CacheKey, Context, Feature, Kind, MAX_COUNT, Vector, VectorCache, inputs_hash, key_of,
};
use ghidorah_base::{BinaryId, Fuel, Rev};

use crate::features::LOOP;
use crate::support::{BASE, blob, fid, fixture};

#[test]
fn vector_counts_merge_and_sort() {
    let features = vec![
        Feature::new(Kind::Opcode, "op1:Ret.0".to_owned()),
        Feature::new(Kind::Cfg, "cfg:blocks=1".to_owned()),
        Feature::new(Kind::Opcode, "op1:Ret.0".to_owned()),
        Feature::keyed(Kind::String, "str:0x30".to_owned(), "abc"),
        Feature::keyed(Kind::String, "str:0x20".to_owned(), "abc"),
    ];
    let v = Vector::new(features);
    assert_eq!(v.len(), 3);
    let keys: Vec<u64> = v.entries().iter().map(|e| e.key).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "the entries are in key order");
    let ret = v
        .entries()
        .iter()
        .find(|e| e.text == "op1:Ret.0")
        .expect("the ret entry");
    assert_eq!(ret.count, 2);
    let s = v
        .entries()
        .iter()
        .find(|e| e.kind == Kind::String)
        .expect("the string entry");
    assert_eq!(s.count, 2, "equal strings at two addresses share a key");
    assert_eq!(s.text, "str:0x20", "the entry keeps the lowest text");
    assert_eq!(v.get(ret.key), Some(ret));
}

#[test]
fn vector_count_saturates() {
    let features = (0..70_000)
        .map(|_| Feature::new(Kind::Opcode, "op1:Nop.0".to_owned()))
        .collect();
    let v = Vector::new(features);
    assert_eq!(v.entries().first().map(|e| e.count), Some(MAX_COUNT));
}

fn key(n: u64) -> CacheKey {
    CacheKey {
        binary: BinaryId([0; 8]),
        func: fid(n),
        epoch: Rev(1),
        inputs: n,
    }
}

#[test]
fn cache_hits_and_eviction() {
    let mut cache = VectorCache::new(2);
    let one = Vector::new(vec![Feature::new(Kind::Cfg, "cfg:blocks=1".to_owned())]);
    let _ = cache.put(key(1), one.clone());
    let _ = cache.put(key(2), Vector::default());
    assert_eq!(cache.get(&key(1)).as_deref(), Some(&one), "a hit");
    let _ = cache.put(key(3), Vector::default());
    assert_eq!(cache.len(), 2);
    assert!(cache.get(&key(2)).is_none(), "key 2 has the oldest use");
    assert!(cache.get(&key(1)).is_some());
    assert!(cache.get(&key(3)).is_some());
    let stats = cache.stats();
    assert_eq!((stats.hits, stats.misses), (3, 1));
    assert_eq!(VectorCache::default().capacity(), 65_536);
}

#[test]
fn cache_builds_once() {
    let p = blob(&LOOP, 0);
    let ctx = Context::new(&p);
    let mut cache = VectorCache::default();
    let mut fuel = Fuel::unlimited();
    let a = cache.vector(&ctx, fid(BASE), &mut fuel).expect("a vector");
    let used = fuel.used();
    assert!(used > 0, "a build takes fuel");
    let b = cache.vector(&ctx, fid(BASE), &mut fuel).expect("a vector");
    assert_eq!(fuel.used(), used, "a hit takes no fuel");
    assert!(Arc::ptr_eq(&a, &b));
    assert!(!a.is_empty());
    assert_eq!(
        *a,
        Vector::build(&ctx, fid(BASE), &mut Fuel::unlimited()).expect("a build")
    );
}

#[test]
fn cache_key_tells_programs_apart() {
    let gcc = fixture("fixtures/bin/loops.gcc-O2");
    let clang = fixture("fixtures/bin/loops.clang-O2");
    let a = gcc
        .funcs()
        .first()
        .map(ghidorah_db::FuncView::id)
        .expect("a function");
    let ka = key_of(&Context::new(gcc), a);
    assert_eq!(ka, key_of(&Context::new(gcc), a), "the key is stable");
    assert_eq!(ka.binary, gcc.meta().binary_id);
    assert_eq!(ka.epoch, gcc.func_epoch(a));
    let mut hashes: Vec<u64> = gcc
        .funcs()
        .iter()
        .map(|f| inputs_hash(&Context::new(gcc), f.id()))
        .collect();
    let n = hashes.len();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(hashes.len(), n, "each function has its own inputs hash");
    let b = clang
        .funcs()
        .first()
        .map(ghidorah_db::FuncView::id)
        .expect("a function");
    assert_ne!(ka, key_of(&Context::new(clang), b));
}
