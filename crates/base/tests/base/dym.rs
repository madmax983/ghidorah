//! Tests of `did_you_mean` (design Section 10.5, AC-047).

use ghidorah_base::dym::{MAX_QUERY_CHARS, MAX_SUGGESTIONS, distance, max_distance};
use ghidorah_base::{Fuel, Suggestion, did_you_mean};

fn names(found: &[Suggestion]) -> Vec<&str> {
    found.iter().map(|s| s.name.as_str()).collect()
}

#[test]
fn ac_047_did_you_mean() {
    let tools = [
        "func_get",
        "func_list",
        "func_edit",
        "func_similar",
        "xref_list",
        "search",
        "mem_read",
        "addr_info",
        "fact_check",
    ];
    let mut fuel = Fuel::unlimited();
    let found = did_you_mean("fnuc_get", tools.iter().copied(), &mut fuel);
    assert_eq!(found.first().map(|s| s.name.as_str()), Some("func_get"));
    assert_eq!(found[0].distance, 1, "an adjacent transposition costs 1");

    // Ties sort by name, whatever the input order.
    let ties = [
        "zbcdef", "abcxyz", "bacdef", "abcdxy", "abdcef", "abcdfe", "abcdeg", "abcdef",
    ];
    let mut fuel = Fuel::unlimited();
    let forward = did_you_mean("abcdef", ties.iter().copied(), &mut fuel);
    let mut fuel = Fuel::unlimited();
    let backward = did_you_mean("abcdef", ties.iter().rev().copied(), &mut fuel);
    assert_eq!(forward, backward);
    assert_eq!(names(&forward), ["abcdef", "abcdeg", "abcdfe", "abdcef", "bacdef"]);
    assert_eq!(forward.len(), MAX_SUGGESTIONS);
    let distances: Vec<usize> = forward.iter().map(|s| s.distance).collect();
    assert_eq!(distances, [0, 1, 1, 1, 1]);

    // Far names and duplicates do not count.
    let mut fuel = Fuel::unlimited();
    let found = did_you_mean("main", ["main", "main", "mian", "zzzzzzzz"], &mut fuel);
    assert_eq!(names(&found), ["main", "mian"]);
    let mut fuel = Fuel::unlimited();
    assert!(did_you_mean("", ["a"], &mut fuel).len() <= MAX_SUGGESTIONS);
    let long = "q".repeat(MAX_QUERY_CHARS + 1);
    let mut fuel = Fuel::unlimited();
    assert!(did_you_mean(&long, [long.as_str()], &mut fuel).is_empty());

    // Fuel bounds the work. An empty tank gives no candidate.
    let mut fuel = Fuel::new(0);
    assert!(did_you_mean("main", ["main"], &mut fuel).is_empty());
    let many: Vec<String> = (0..10_000).map(|i| format!("name_{i:05}")).collect();
    let mut fuel = Fuel::new(5_000);
    let _ = did_you_mean("name_00042", many.iter().map(String::as_str), &mut fuel);
    assert!(fuel.used() <= 5_000);
}

#[test]
fn dym_distance_table() {
    let cases = [
        ("", "", 0),
        ("a", "", 1),
        ("", "abc", 3),
        ("abc", "abc", 0),
        ("abc", "ABC", 0),
        ("ab", "ba", 1),
        ("abcd", "acbd", 1),
        ("ca", "abc", 3),
        ("kitten", "sitting", 3),
        ("caf\u{e9}", "cafe", 1),
    ];
    for (a, b, want) in cases {
        assert_eq!(distance(a, b), want, "{a:?} {b:?}");
        assert_eq!(distance(b, a), want, "{b:?} {a:?}");
    }
    let limits: Vec<usize> = [0, 1, 2, 3, 5, 6, 9, 12, 100].map(max_distance).to_vec();
    assert_eq!(limits, [1, 1, 1, 1, 1, 2, 3, 4, 4]);
}
