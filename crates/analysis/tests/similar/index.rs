//! The Q16 arithmetic, the weights, the scores, the candidate order and the explained
//! matches.

use std::sync::Arc;
use std::time::Instant;

use ghidorah_analysis::similar::{
    self, Doc, Feature, Index, Kind, MAX_TOP, Scope, Vector, VectorCache, isqrt, l2,
};
use ghidorah_base::{Address, BinaryId, Fuel, Limits};
use ghidorah_db::{Edit, FuncRecord, Function, SessionLabel, Source, StartReason};

use crate::support::{BASE, blob, corpus, fid, fixture, json, root, t1};

#[test]
fn q16_log2_table() {
    let table: [(u64, u64); 18] = [
        (0, 0),
        (1, 0),
        (2, 65_536),
        (3, 103_872),
        (4, 131_072),
        (5, 152_169),
        (7, 183_982),
        (8, 196_608),
        (10, 217_705),
        (100, 435_411),
        (1_000, 653_117),
        (65_535, 1_048_574),
        (65_536, 1_048_576),
        (1 << 32, 2_097_152),
        ((1 << 32) + 1, 2_097_152),
        (1_000_000_000_000, 2_612_470),
        (1 << 63, 4_128_768),
        (u64::MAX, 4_194_303),
    ];
    for (x, want) in table {
        assert_eq!(l2(x), want, "l2({x})");
    }
}

#[test]
fn isqrt_values() {
    let cases: [(u128, u128); 7] = [
        (0, 0),
        (1, 1),
        (15, 3),
        (16, 4),
        (17_199_931_392, 131_148),
        (
            u128::from(u64::MAX) * u128::from(u64::MAX),
            u128::from(u64::MAX),
        ),
        (u128::MAX, u128::from(u64::MAX)),
    ];
    for (x, want) in cases {
        assert_eq!(isqrt(x), want, "isqrt({x})");
    }
}

/// Makes a document of `binary` at `addr` with one occurrence of each feature text.
fn doc(binary: u8, addr: u64, texts: &[&str]) -> Doc {
    let features = texts
        .iter()
        .map(|t| Feature::new(Kind::Opcode, (*t).to_owned()))
        .collect();
    Doc {
        binary: BinaryId([binary; 8]),
        func: fid(addr),
        vector: Arc::new(Vector::new(features)),
    }
}

#[test]
fn weights_and_scores_follow_the_formula() {
    let index = Index::build(vec![
        doc(1, 0x10, &["op1:a", "op1:b"]),
        doc(1, 0x20, &["op1:a", "op1:b"]),
        doc(1, 0x30, &["op1:c"]),
    ]);
    let ka = similar::feature_key(Kind::Opcode, "op1:a");
    let kc = similar::feature_key(Kind::Opcode, "op1:c");
    assert_eq!(index.df(ka), 2);
    // tf = 65,536 and idf = 65,536 + l2(4) - l2(3) = 92,736.
    assert_eq!(index.weight(0, ka), Some(92_736));
    // idf = 65,536 + l2(4) - l2(2) = 131,072.
    assert_eq!(index.weight(2, kc), Some(131_072));
    assert_eq!(index.norm(0), 131_148);
    assert_eq!(index.score(0, 1), Some(1_000), "equal vectors");
    assert_eq!(index.score(0, 2), Some(0), "no shared key");
    let m = index.explain(0, 1);
    assert_eq!((m.score, m.shared, m.total), (1_000, 2, 2));
    let weights: Vec<u32> = m.top.iter().map(|t| t.weight).collect();
    assert_eq!(weights, [500, 500]);
    assert_eq!(index.position(BinaryId([1; 8]), fid(0x30)), Some(2));
}

#[test]
fn candidates_follow_scope_and_order() {
    let index = Index::build(vec![
        doc(1, 0x10, &["op1:a", "op1:b", "op1:c"]),
        doc(1, 0x20, &["op1:a", "op1:x"]),
        doc(2, 0x08, &["op1:a", "op1:b", "op1:c"]),
        doc(2, 0x18, &["op1:a", "op1:b", "op1:c"]),
        doc(2, 0x28, &["op1:y"]),
    ]);
    let mut fuel = Fuel::unlimited();
    let binary = index.ranked(0, Scope::Binary, &mut fuel).expect("ranked");
    let docs: Vec<usize> = binary.iter().map(|s| s.doc).collect();
    assert_eq!(docs, [1], "scope binary keeps the binary of the query");
    let open = index.ranked(0, Scope::Open, &mut fuel).expect("ranked");
    let docs: Vec<usize> = open.iter().map(|s| s.doc).collect();
    assert_eq!(
        docs,
        [2, 3, 1],
        "score, then binary, then address; no shared key gives no candidate"
    );
    assert_eq!(open[0].score, 1_000);
    let capped = index
        .matches(0, Scope::Open, 0, 2, &mut fuel)
        .expect("matches");
    assert_eq!(capped.len(), 2);
    let strong = index
        .matches(0, Scope::Open, 1_000, 50, &mut fuel)
        .expect("matches");
    assert_eq!(strong.iter().map(|m| m.doc).collect::<Vec<_>>(), [2, 3]);
}

#[test]
fn similar_scores_symmetric() {
    let programs = t1();
    let index = corpus(&programs);
    let n = index.len();
    assert!(n >= 40, "{n} documents");
    let mut checked = 0;
    for a in (0..n).step_by(3) {
        for b in (0..n).step_by(5) {
            assert_eq!(index.score(a, b), index.score(b, a), "{a} {b}");
            if a != b && index.score(a, b).unwrap_or(0) > 0 {
                assert_eq!(index.explain(a, b).score, index.explain(b, a).score);
                checked += 1;
            }
        }
    }
    assert!(checked > 50, "{checked} pairs");
    let mut fuel = Fuel::unlimited();
    for q in (0..n).step_by(7) {
        for s in index.ranked(q, Scope::Open, &mut fuel).expect("ranked") {
            assert_eq!(index.score(q, s.doc), Some(s.score));
        }
    }
}

#[test]
fn ac_240_top_features_shared() {
    let programs = t1();
    let index = corpus(&programs);
    let mut fuel = Fuel::unlimited();
    let mut seen = 0;
    for q in 0..index.len() {
        let query = &index.docs()[q].vector;
        for m in index
            .matches(q, Scope::Open, 0, 50, &mut fuel)
            .expect("matches")
        {
            assert!(m.top.len() <= MAX_TOP);
            assert!(m.shared >= 1 && m.shared <= m.total);
            let sum: u32 = m.top.iter().map(|t| t.weight).sum();
            assert!(sum <= m.score, "{sum} > {}", m.score);
            let other = &index.docs()[m.doc].vector;
            for pair in m.top.windows(2) {
                assert!(pair[0].weight >= pair[1].weight, "weight order");
            }
            for t in &m.top {
                let entry = query
                    .entries()
                    .iter()
                    .find(|e| e.kind == t.kind && e.text == t.text)
                    .unwrap_or_else(|| panic!("{} is not in the query vector", t.text));
                assert!(
                    other.get(entry.key).is_some(),
                    "{} is not in the match vector",
                    t.text
                );
                seen += 1;
            }
        }
    }
    assert!(seen > 1_000, "{seen} top features");
}

#[test]
fn ac_242_empty_and_tiny_functions() {
    // A `ret` at the entry, int3 padding, and two bytes that do not decode at 0x10.
    let mut bytes = vec![0xc3];
    bytes.resize(0x10, 0xcc);
    bytes.extend_from_slice(&[0x06, 0x06, 0xc3]);
    let mut p = blob(&bytes, 0);
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("create", Source::Agent, label).expect("a tx");
    let func = Function::new(
        Address::ram(BASE + 0x10),
        StartReason::Agent,
        100,
        Source::Agent,
    );
    tx.apply(Edit::CreateFunction(Box::new(FuncRecord {
        func,
        vars: Vec::new(),
        plate: None,
    })))
    .expect("the create applies");
    tx.commit().expect("the commit");
    let index = corpus(&[&p]);
    assert_eq!(index.len(), 2);
    let mut fuel = Fuel::unlimited();
    let empty = index
        .position(p.meta().binary_id, fid(BASE + 0x10))
        .expect("the empty function is a document");
    assert!(index.docs()[empty].vector.is_empty(), "a zero vector");
    assert_eq!(index.norm(empty), 0);
    assert_eq!(index.score(empty, 0), None, "a zero norm gives no score");
    assert!(
        index
            .ranked(empty, Scope::Open, &mut fuel)
            .expect("ranked")
            .is_empty()
    );
    let tiny = index
        .position(p.meta().binary_id, fid(BASE))
        .expect("the one-block function");
    assert!(!index.docs()[tiny].vector.is_empty());
    assert!(
        index
            .matches(tiny, Scope::Binary, 0, 50, &mut fuel)
            .expect("matches")
            .is_empty()
    );

    let one = blob(&[0xc3], 0);
    let index = corpus(&[&one]);
    assert_eq!(index.len(), 1);
    assert!(
        index
            .matches(0, Scope::Binary, 0, 50, &mut fuel)
            .expect("matches")
            .is_empty()
    );
    assert!(
        index
            .matches(0, Scope::Open, 0, 50, &mut fuel)
            .expect("matches")
            .is_empty()
    );
}

#[test]
fn corpus_order_and_fuel_stop_keep_the_cache() {
    let programs = t1();
    let full = corpus(&programs);
    let mut keys: Vec<(BinaryId, u64)> = full
        .docs()
        .iter()
        .map(|d| (d.binary, d.func.0.off))
        .collect();
    let given = keys.clone();
    keys.sort_unstable();
    assert_eq!(given, keys, "binary ID order, then entry order");
    let mut cache = VectorCache::default();
    let mut stops = 0;
    let index = loop {
        match similar::corpus(&programs, &mut cache, &mut Fuel::new(2_000)) {
            Ok(index) => break index,
            Err(_) => stops += 1,
        }
        assert!(stops < 10_000, "the cache fills");
    };
    assert!(stops > 0, "a small fuel stops the first build");
    assert_eq!(index.docs(), full.docs());
}

/// The budget of AC-243 in milliseconds: `perf/budget.json` key `similar_2k_ms`.
fn budget_ms() -> u128 {
    let text = std::fs::read_to_string(root().join("perf/budget.json")).expect("the budget");
    let value = json(&text);
    u128::from(
        value
            .get("similar_2k_ms")
            .and_then(ghidorah_json::Value::as_u64)
            .expect("the key similar_2k_ms"),
    )
}

#[test]
#[ignore = "tier2"]
fn ac_243_similar_2k_budget() {
    let builds = [
        "fixtures/bin/large.gcc-O2",
        "fixtures/bin/large.gcc-O2.stripped",
        "fixtures/bin/large.clang-O2",
        "fixtures/bin/large.clang-O2.stripped",
    ];
    let programs: Vec<&ghidorah_db::Program> = builds.iter().map(|b| fixture(b)).collect();
    let mut times = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let mut cache = VectorCache::default();
        let mut fuel = Fuel::unlimited();
        let index = similar::corpus(&programs, &mut cache, &mut fuel).expect("the corpus");
        assert!(index.len() >= 2_000, "{} documents", index.len());
        let mut found = 0usize;
        for q in 0..2_000 {
            found += index
                .matches(q, Scope::Open, 500, 10, &mut fuel)
                .expect("matches")
                .len();
        }
        assert!(found > 0);
        times.push(start.elapsed().as_millis());
    }
    times.sort_unstable();
    let median = times[times.len() / 2];
    let budget = budget_ms();
    assert!(
        median <= budget,
        "median {median} ms > {budget} ms: {times:?}"
    );
    let _ = Limits::DEFAULT;
}
