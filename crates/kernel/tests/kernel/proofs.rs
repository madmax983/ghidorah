//! AC-034 and AC-035: the proof record is fresh, and the kernel has no proof cheats.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test helpers fail the test with a message or print a stale-record warning"
)]

/// The kernel table of `xtask verify`. The test and the command read one table.
#[allow(dead_code, reason = "the tests use a part of the included xtask file")]
#[path = "../../../../xtask/src/verify/kernels.rs"]
mod kernels;

use crate::support::json::Value;
use crate::support::rustsrc::strip;
use crate::support::{kernel_sources, proofs_required, results, root, tree};

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
fn proof_record_rows_hold() {
    for kernel in kernels::KERNELS {
        let row = record(&format!("/kernels/{}", kernel.name));
        let get = |key: &str| row.get(key).and_then(Value::as_u64);
        assert_eq!(
            row.get("status").and_then(Value::as_str),
            Some("verified"),
            "{}",
            kernel.name
        );
        assert_eq!(get("errors"), Some(0), "{}: no errors", kernel.name);
        assert!(
            get("verified") >= get("spec_items") && get("spec_items") > Some(0),
            "{}: verified >= spec_items > 0",
            kernel.name
        );
    }
    let negatives = record("/negatives");
    let negatives = negatives.as_array().expect("the record has negative rows");
    let table: Vec<(&str, String, &str)> = kernels::KERNELS
        .iter()
        .flat_map(|k| k.negatives.iter().map(|n| (k.name, n.path(), n.kind)))
        .collect();
    assert_eq!(
        negatives.len(),
        table.len(),
        "one row for each negative patch"
    );
    for (row, (kernel, patch, kind)) in negatives.iter().zip(&table) {
        let text = |key: &str| row.get(key).and_then(Value::as_str);
        assert_eq!(text("kernel"), Some(*kernel), "{patch}");
        assert_eq!(text("patch"), Some(patch.as_str()));
        assert_eq!(
            text("error_kind"),
            Some(*kind),
            "{patch}: the expected error"
        );
        assert_eq!(
            row.get("ok"),
            Some(&Value::Bool(true)),
            "{patch}: the run fails"
        );
        let verified = row.get("verified").and_then(Value::as_u64).unwrap_or(0);
        assert!(verified >= 1, "{patch}: the run verifies an item");
    }
}

/// The proof cheats of AC-035a.
///
/// `--no-cheating` rejects only `assume`, `admit`, `external_body` and `assume_specification`.
/// Verus does not verify an `external` item, so the scan also rejects it.
/// Only the bare `#[verus_verify]` is correct. Any argument of `verus_verify` is a cheat.
const CHEATS: &[&str] = &[
    "assume(",
    "admit(",
    "external_body",
    "assume_specification",
    "external_fn",
    "external_type_specification",
    "external",
    "verifier::",
    "verifier(",
    "verus_verify(",
];

/// Gives the byte offset and the text of each proof cheat in a source text.
///
/// A cheat in a comment or a string does not count. A cheat inside a longer word does not count.
fn cheat_hits(text: &str) -> Vec<(usize, &'static str)> {
    let code = strip(text);
    let mut hits = Vec::new();
    for cheat in CHEATS {
        for (i, _) in code.match_indices(cheat) {
            let before = code.get(..i).and_then(|h| h.chars().next_back());
            let in_word = before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if !in_word {
                hits.push((i, *cheat));
            }
        }
    }
    hits.sort_unstable();
    hits
}

#[test]
fn ac_035a_no_assume() {
    let sources = kernel_sources();
    assert!(!sources.is_empty(), "the kernel has source files");
    for (path, text) in &sources {
        let hits = cheat_hits(text);
        assert!(
            hits.is_empty(),
            "{path}: the kernel has proof cheats {hits:?}"
        );
    }
}

#[test]
fn regress_cheat_scan_catches_external() {
    let hidden = "#[verus_verify(external)]\npub fn f() -> u8 { 1 }\n";
    assert!(
        !cheat_hits(hidden).is_empty(),
        "`#[verus_verify(external)]` makes Verus skip the function"
    );
    for text in [
        "#[verus_verify(external_type_specification)]\npub struct S;\n",
        "#[verifier::external]\nfn f() {}\n",
        "#[verifier(external)]\nfn f() {}\n",
        "#[cfg_attr(verus_only, verus_verify(external))]\nfn f() {}\n",
        "#[verus_verify(rlimit(10))]\nfn f() {}\n",
    ] {
        assert!(!cheat_hits(text).is_empty(), "{text}");
    }
    for text in [
        "#[verus_verify]\nimpl S {}\n",
        "// #[verus_verify(external)] in a comment\nfn f() {}\n",
        "fn f() -> &'static str { \"verifier::external\" }\n",
        "fn no_external_body_here() {}\n",
    ] {
        assert_eq!(cheat_hits(text), Vec::new(), "{text}");
    }
}

/// The allowed starts of a cfg gate in the kernel. Each one names `verus_only` alone.
const VERUS_ONLY_GATES: &[&str] = &[
    "cfg(verus_only)",
    "cfg(not(verus_only))",
    "cfg_attr(verus_only, ",
];

/// Gives one message for each cfg gate of a source text that is not an allowed `verus_only` gate.
///
/// A gate is `cfg(..)`, `cfg_attr(..)` or `cfg!(..)`. Exec code is never cfg-gated (design
/// Section 13.2). So Verus proves the code that a release build ships.
fn gate_findings(path: &str, code: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (i, _) in code.match_indices("cfg") {
        let before = code.get(..i).and_then(|h| h.chars().next_back());
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let rest = code.get(i..).unwrap_or_default();
        let word_end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let word = rest.get(..word_end).unwrap_or_default();
        let after = rest.get(word_end..).unwrap_or_default();
        let after = after.strip_prefix('!').unwrap_or(after).trim_start();
        let is_gate = (word == "cfg" || word == "cfg_attr") && after.starts_with('(');
        if is_gate && !VERUS_ONLY_GATES.iter().any(|g| rest.starts_with(g)) {
            let line = code.get(..i).unwrap_or_default().lines().count().max(1);
            let head = rest.lines().next().unwrap_or_default();
            found.push(format!(
                "{path}:{line}: a cfg gate without `verus_only`: `{head}`"
            ));
        }
    }
    found
}

/// Gives one message for each bad cfg gate and each misplaced `verus_only` gate of a source text.
fn cfg_findings(path: &str, text: &str) -> Vec<String> {
    let code = strip(text);
    let mut found = gate_findings(path, &code);
    for (i, _) in code.match_indices("verus_only") {
        let start = code.get(..i).and_then(|h| h.rfind('#')).unwrap_or(0);
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
                    && code
                        .get(i..)
                        .is_some_and(|t| t.starts_with("verus_only, feature(proc_macro_hygiene))]"))
            }
            _ => false,
        };
        if !ok {
            found.push(format!(
                "{path}: `verus_only` in `{attr}` before `{}`",
                next.lines().next().unwrap_or("")
            ));
        }
    }
    found
}

#[test]
fn ac_035b_cfg_placement() {
    let sources = kernel_sources();
    assert!(!sources.is_empty(), "the kernel has source files");
    for (path, text) in &sources {
        let found = cfg_findings(path, text);
        assert!(found.is_empty(), "{}", found.join("\n"));
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
fn regress_cfg_gate_outside_verus_only() {
    let path = "crates/kernel/src/demo.rs";
    // Verus proves the debug twin. A release build ships the other twin.
    let twins = "#[cfg(debug_assertions)]\n#[verus_spec(r => ensures r == 1)]\npub fn f() -> u8 {\n    1\n}\n\n#[cfg(not(debug_assertions))]\n#[verus_spec(r => ensures r == 1)]\npub fn f() -> u8 {\n    2\n}\n";
    assert_eq!(cfg_findings(path, twins).len(), 2, "{twins}");
    for text in [
        "#[cfg_attr(test, derive(Debug))]\npub struct S;\n",
        "pub fn f() -> bool {\n    cfg!(debug_assertions)\n}\n",
        "#[cfg(target_pointer_width = \"64\")]\nconst W: u32 = 64;\n",
        "#[cfg(all(verus_only, test))]\nuse vstd::prelude::*;\n",
        "#[cfg (test)]\nmod tests;\n",
    ] {
        assert!(!cfg_findings(path, text).is_empty(), "{text}");
    }
    for text in [
        "#[cfg(verus_only)]\nuse vstd::prelude::*;\n",
        "#[cfg(not(verus_only))]\nuse ghidorah_spec::{proof, verus_spec};\n",
        "fn f() {\n    #[cfg_attr(verus_only, verus_spec(invariant true))]\n    loop {}\n}\n",
        "// #[cfg(debug_assertions)] in a comment\nconst S: &str = \"cfg!(test)\";\n",
    ] {
        assert_eq!(cfg_findings(path, text), Vec::<String>::new(), "{text}");
    }
}

/// The qualifiers that can come between `pub` and `fn` of a public function.
const FN_QUALIFIERS: &[&str] = &["const", "unsafe", "async", "extern"];

/// Gives the byte offset of each public function of stripped code, at its `pub` keyword.
///
/// `pub` takes optional `const`, `unsafe`, `async` or `extern ".."` qualifiers before `fn`.
/// `pub(crate)` and `pub(super)` items are not public, so the scan skips them.
fn public_fns(code: &str) -> Vec<usize> {
    let mut found = Vec::new();
    for (at, _) in code.match_indices("pub") {
        let before = code.get(..at).and_then(|head| head.chars().next_back());
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let mut rest = code.get(at + 3..).unwrap_or_default();
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        loop {
            rest = rest.trim_start();
            let Some(word) = FN_QUALIFIERS.iter().find(|w| {
                rest.strip_prefix(**w)
                    .is_some_and(|tail| tail.starts_with(char::is_whitespace))
            }) else {
                break;
            };
            rest = rest.get(word.len()..).unwrap_or_default().trim_start();
            if *word == "extern"
                && let Some(abi) = rest.strip_prefix('"')
            {
                rest = abi.split_once('"').map_or("", |(_, tail)| tail);
            }
        }
        if rest.starts_with("fn")
            && rest
                .get(2..)
                .is_some_and(|t| t.starts_with(char::is_whitespace))
        {
            found.push(at);
        }
    }
    found
}

/// Gives a finding for each public function of `text` without a `#[verus_spec]` that has an `ensures`.
fn missing_specs(path: &str, text: &str) -> Vec<String> {
    let code = strip(text);
    let mut found = Vec::new();
    for at in public_fns(&code) {
        let line = code.get(..at).unwrap_or_default().matches('\n').count() + 1;
        let attrs = attributes_before(&code, at);
        match attrs.iter().find(|a| a.starts_with("#[verus_spec(")) {
            None => found.push(format!("{path}:{line}: a pub fn has no #[verus_spec]")),
            Some(spec) if !spec.contains("ensures") => {
                found.push(format!("{path}:{line}: the #[verus_spec] has no ensures"));
            }
            Some(_) => {}
        }
    }
    found
}

#[test]
fn regress_specs_present_sees_pub_const_fn() {
    let bare = "pub const fn f() {}\n";
    assert_eq!(missing_specs("x.rs", bare).len(), 1, "a bare pub const fn");
    let specced = "#[verus_spec(r => ensures r == 0)]\npub const fn f() -> u8 { 0 }\n";
    assert!(missing_specs("x.rs", specced).is_empty());
    let no_ensures = "#[verus_spec(requires true)]\npub const fn f() {}\n";
    assert_eq!(
        missing_specs("x.rs", no_ensures).len(),
        1,
        "a spec without ensures"
    );
    for item in [
        "pub unsafe fn f() {}",
        "pub async fn f() {}",
        "pub extern \"C\" fn f() {}",
        "pub const unsafe extern \"C\" fn f() {}",
        "pub fn f() {}",
    ] {
        assert_eq!(missing_specs("x.rs", item).len(), 1, "{item}");
    }
    for item in [
        "pub(crate) fn f() {}",
        "pub(super) const fn f() {}",
        "pub const F: u8 = 1;",
        "pub struct S;",
        "fn f() {}",
        "// pub fn f() {}",
        "let s = \"pub fn f() {}\";",
        "pub fnord: u8,",
    ] {
        assert!(missing_specs("x.rs", item).is_empty(), "{item}");
    }
}

#[test]
fn ac_035c_specs_present() {
    let sources = kernel_sources();
    assert!(!sources.is_empty(), "the kernel has source files");
    let mut total = 0u64;
    let mut missing = Vec::new();
    for (path, text) in &sources {
        missing.extend(missing_specs(path, text));
        total += strip(text).matches("#[verus_spec(").count() as u64;
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
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
