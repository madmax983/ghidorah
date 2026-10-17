//! AC-039: the vendored `JSONTestSuite` files (MIT, `tests/data/jsontestsuite/`).

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use std::collections::BTreeMap;

use ghidorah_json::{parse, parse_bytes, write};

/// The expected result of one `i_` file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pinned {
    Accept,
    Reject(String, usize),
}

fn pinned() -> BTreeMap<String, Pinned> {
    let text = include_str!("data/i_pinned.txt");
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let words: Vec<&str> = line.split_whitespace().collect();
        let entry = match words.as_slice() {
            [_, "accept"] => Pinned::Accept,
            [_, "reject", code, offset] => Pinned::Reject(
                (*code).to_owned(),
                offset
                    .parse()
                    .unwrap_or_else(|e| panic!("offset in {line:?}: {e}")),
            ),
            _ => panic!("bad pinned line {line:?}"),
        };
        out.insert(words[0].to_owned(), entry);
    }
    out
}

fn suite_files() -> Vec<(String, Vec<u8>)> {
    let dir = common::suite_dir();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.unwrap_or_else(|e| panic!("dir entry: {e}")).path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.extension().is_some_and(|x| x == "json") {
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
            files.push((name, bytes));
        }
    }
    files.sort();
    files
}

#[test]
fn ac_039_json_test_suite() {
    let limits = common::limits();
    let pins = pinned();
    let files = suite_files();
    let count = |p: &str| files.iter().filter(|(n, _)| n.starts_with(p)).count();
    assert_eq!(
        (count("y_"), count("n_"), count("i_")),
        (95, 188, 35),
        "the vendored suite is complete"
    );
    let mut failures = Vec::new();
    let mut seen_pins = 0;
    for (name, bytes) in &files {
        let result = parse_bytes(bytes, &limits);
        if name.starts_with("y_") {
            match &result {
                Ok(value) => {
                    // The writer output reads back as the same value.
                    let again = parse(&write(value), &limits);
                    if again.as_ref() != Ok(value) {
                        failures.push(format!("{name}: write gives {again:?}"));
                    }
                }
                Err(e) => failures.push(format!("{name}: must parse, got {e}")),
            }
        } else if name.starts_with("n_") {
            if let Ok(value) = &result {
                failures.push(format!("{name}: must fail, got {value:?}"));
            } else if let Err(e) = &result
                && e.offset > bytes.len()
            {
                failures.push(format!("{name}: offset {} after the end", e.offset));
            }
        } else if name.starts_with("i_") {
            let Some(pin) = pins.get(name) else {
                failures.push(format!("{name}: no pinned result"));
                continue;
            };
            seen_pins += 1;
            let got = match &result {
                Ok(_) => Pinned::Accept,
                Err(e) => Pinned::Reject(e.code.as_str().to_owned(), e.offset),
            };
            if &got != pin {
                failures.push(format!("{name}: pinned {pin:?}, got {got:?}"));
            }
        }
    }
    assert_eq!(seen_pins, pins.len(), "each pinned file exists");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
