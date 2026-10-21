//! AC-238: on the stripped twin of each T2 fixture, the best match from the unstripped twin is
//! the same function for at least 90% of the functions with 8 or more instructions.

use ghidorah_json::Value;

use crate::support::{call_value, data, json, list_at, open, root, similar_args, text_at};

/// The T2 fixtures with their stripped twins.
const PAIRS: [(&str, &str); 2] = [
    ("large.gcc-O2", "large.gcc-O2.stripped"),
    ("large.clang-O2", "large.clang-O2.stripped"),
];

/// The number of targets of one call.
const CHUNK: usize = 10;

/// Gives the entries of the truth functions of `fixture` with 8 or more instructions.
fn truth_entries(fixture: &str) -> Vec<String> {
    let path = root().join(format!("fixtures/truth/{fixture}.json"));
    let text = std::fs::read_to_string(&path).expect("the truth file");
    let truth = json(&text);
    list_at(&truth, "/functions")
        .iter()
        .filter(|f| f.get("insns").and_then(Value::as_u64).unwrap_or(0) >= 8)
        .map(|f| text_at(f, "/addr"))
        .collect()
}

#[test]
fn ac_238_twin_top_match() {
    for (full, stripped) in PAIRS {
        let (mut session, ids) = open(&[stripped, full]);
        let (query_bin, twin_bin) = (ids[0], ids[1]);
        let twin = twin_bin.to_string();
        let entries = truth_entries(full);
        assert!(entries.len() > 400, "{full}: {} functions", entries.len());
        let (mut hits, mut misses) = (0usize, Vec::new());
        for chunk in entries.chunks(CHUNK) {
            let targets: Vec<Value> = chunk
                .iter()
                .map(|a| Value::from(format!("fn:{a}")))
                .collect();
            let mut args = similar_args(
                query_bin,
                r#"{"scope":"open","min_score":0,"limit":5,"max_chars":60000}"#,
            );
            if let Value::Object(object) = &mut args {
                object.push("targets", Value::Array(targets));
            }
            let envelope = call_value(&mut session, "func_similar", args);
            let items = list_at(data(&envelope), "/items");
            assert_eq!(items.len(), chunk.len(), "{envelope}");
            for (addr, item) in chunk.iter().zip(&items) {
                let best = list_at(item, "/matches")
                    .into_iter()
                    .find(|m| text_at(m, "/binary_id") == twin);
                let want = format!("fn:{addr}");
                if best.as_ref().map(|m| text_at(m, "/id")) == Some(want.clone()) {
                    hits += 1;
                } else {
                    misses.push(want);
                }
            }
        }
        let total = hits + misses.len();
        assert!(
            hits * 10 >= total * 9,
            "{stripped}: {hits} of {total} twins on top, misses {misses:?}"
        );
    }
}
