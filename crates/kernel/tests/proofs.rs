//! AC-034 and AC-035: the proof record is fresh, and the kernel has no proof cheats.

mod support;

use support::json::Value;
use support::rustsrc::strip;
use support::{kernel_sources, proofs_required, results, root, tree};

/// Gives the text after the attribute that starts at byte `at`, or `None` without a closing `]`.
fn after_attribute(code: &str, at: usize) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in code.get(at..)?.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return code.get(at + i + 1..);
                }
            }
            _ => {}
        }
    }
    None
}

/// Gives the attributes directly before byte `at`, nearest first.
fn attributes_before(code: &str, at: usize) -> Vec<&str> {
    let mut found = Vec::new();
    let mut end = at;
    loop {
        let head = code.get(..end).unwrap_or_default().trim_end();
        if !head.ends_with(']') {
            return found;
        }
        let mut depth = 0usize;
        let mut open = None;
        for (i, c) in head.char_indices().rev() {
            match c {
                ']' => depth += 1,
                '[' => {
                    depth -= 1;
                    if depth == 0 {
                        open = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open.filter(|&i| i > 0 && head.get(i - 1..i) == Some("#")) else {
            return found;
        };
        found.push(head.get(open - 1..).unwrap_or_default());
        end = open - 1;
    }
}

/// Gives the record value at `pointer`, or fails the test.
fn record(pointer: &str) -> Value {
    let value = results().expect("verify/results.json exists and holds valid JSON");
    value
        .pointer(pointer)
        .cloned()
        .unwrap_or_else(|| panic!("verify/results.json has {pointer}"))
}

/// Tells if the record matches the current tree. A stale record fails under `GHIDORAH_REQUIRE_PROOFS=1`.
fn record_is_fresh() -> bool {
    let current = tree::tree_sha256(&root()).expect("the kernel and spec sources are readable");
    let recorded = record("/tree_sha256");
    if recorded.as_str() == Some(current.as_str()) {
        return true;
    }
    assert!(
        !proofs_required(),
        "verify/results.json is stale: run `cargo xtask verify` (record {recorded:?}, tree {current})"
    );
    eprintln!("warning: verify/results.json is stale; run `cargo xtask verify`");
    false
}

#[test]
fn ac_034_proof_freshness() {
    let argv: Vec<Value> = tree::ARGV.iter().map(|a| Value::from(*a)).collect();
    assert_eq!(
        record("/argv"),
        Value::Array(argv),
        "the record names the Verus argv"
    );
    for key in ["verus_commit", "toolchain", "z3"] {
        assert!(
            record(&format!("/{key}"))
                .as_str()
                .is_some_and(|v| !v.is_empty()),
            "the record names `{key}`"
        );
    }
    let hash = record("/tree_sha256");
    let hash = hash.as_str().unwrap_or_default();
    assert_eq!(hash.len(), 64, "the tree hash is 64 hex digits");
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    let _fresh = record_is_fresh();
}

#[test]
fn ac_035a_no_assume() {
    let sources = kernel_sources();
    assert!(!sources.is_empty(), "the kernel has source files");
    let cheats = [
        "assume(",
        "admit(",
        "external_body",
        "assume_specification",
        "external_fn",
    ];
    for (path, text) in &sources {
        let code = strip(text);
        for cheat in cheats {
            for (i, _) in code.match_indices(cheat) {
                let before = code.get(..i).and_then(|h| h.chars().next_back());
                let in_word = before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                assert!(in_word, "{path}: the kernel has `{cheat}` at byte {i}");
            }
        }
    }
}

#[test]
fn ac_035b_cfg_placement() {
    let sources = kernel_sources();
    assert!(!sources.is_empty(), "the kernel has source files");
    for (path, text) in &sources {
        let code = strip(text);
        for (i, _) in code.match_indices("verus_only") {
            let start = code.get(..i).and_then(|h| h.rfind("#")).unwrap_or(0);
            let attr = code.get(start..i).unwrap_or_default();
            let next = after_attribute(&code, start)
                .unwrap_or_default()
                .trim_start();
            let ok = match attr {
                "#[cfg(" => next.starts_with("use vstd::") || next.starts_with("verus! {"),
                "#[cfg(not(" => next.starts_with("use ghidorah_spec::"),
                "#[cfg_attr(" => {
                    code.get(i..)
                        .is_some_and(|t| t.starts_with("verus_only, verus_spec("))
                        && ["while ", "loop ", "for "]
                            .iter()
                            .any(|k| next.starts_with(k))
                }
                "#![cfg_attr(" => {
                    path.ends_with("/lib.rs")
                        && code.get(i..).is_some_and(|t| {
                            t.starts_with("verus_only, feature(proc_macro_hygiene))]")
                        })
                }
                _ => false,
            };
            assert!(
                ok,
                "{path}: `verus_only` in `{attr}` before `{}`",
                next.lines().next().unwrap_or("")
            );
        }
    }
    let lib = sources
        .iter()
        .find(|(p, _)| p.ends_with("/lib.rs"))
        .expect("the kernel has lib.rs");
    assert!(
        lib.1
            .starts_with("#![cfg_attr(verus_only, feature(proc_macro_hygiene))]"),
        "lib.rs starts with the proc_macro_hygiene line"
    );
}

#[test]
fn ac_035c_specs_present() {
    let sources = kernel_sources();
    assert!(!sources.is_empty(), "the kernel has source files");
    let mut total = 0u64;
    for (path, text) in &sources {
        let code = strip(text);
        for (i, _) in code.match_indices("pub fn ") {
            let attrs = attributes_before(&code, i);
            let spec = attrs.iter().find(|a| a.starts_with("#[verus_spec("));
            let line = code.get(..i).unwrap_or_default().lines().count();
            let spec =
                spec.unwrap_or_else(|| panic!("{path}:{line}: a pub fn has no #[verus_spec]"));
            assert!(
                spec.contains("ensures"),
                "{path}:{line}: the #[verus_spec] has no ensures"
            );
        }
        total += code.matches("#[verus_spec(").count() as u64;
    }
    assert!(total > 0, "the kernel has spec items");
    let kernels = record("/kernels");
    let kernels = kernels
        .as_object()
        .expect("the record has a kernels object");
    assert!(!kernels.is_empty(), "the record has kernels");
    let mut recorded_items = 0u64;
    for (name, kernel) in kernels {
        let get = |key: &str| kernel.get(key).and_then(Value::as_u64).unwrap_or_default();
        assert!(
            get("verified") >= get("spec_items"),
            "{name}: verified >= spec_items"
        );
        assert_eq!(get("errors"), 0, "{name}: no errors");
        assert_eq!(
            kernel.get("status").and_then(Value::as_str),
            Some("verified"),
            "{name}"
        );
        recorded_items += get("spec_items");
    }
    if record_is_fresh() {
        assert_eq!(
            recorded_items, total,
            "the record counts every spec item of the kernel"
        );
    }
}
