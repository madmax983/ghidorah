//! `func_similar` on the PE32+ fixture `pe_main.exe` (WP-29 with WP-30): matches in one PE
//! binary, an import feature through an IAT thunk, and scope `open` over PE and ELF binaries.

use ghidorah_json::Value;

use crate::support::{call, data, int_at, list_at, open, text_at};

/// The PE fixture.
const PE: &str = "pe/pe_main.exe";

/// The functions of `pe_main.exe` from its truth file.
const TWICE: &str = "fn:0x140001090";
const THRICE: &str = "fn:0x1400010a0";
const DISPATCH: &str = "fn:0x1400010b0";
const SLEEP_THUNK: &str = "fn:0x1400011e0";

/// Gives the matches of the one item of a `func_similar` call on `target` with `rest`.
fn matches(session: &mut ghidorah_tools::Session, target: &str, rest: &str) -> Vec<Value> {
    let envelope = call(
        session,
        "func_similar",
        &format!(r#"{{"target":"{target}"{rest}}}"#),
    );
    let items = list_at(data(&envelope), "/items");
    assert_eq!(items.len(), 1, "{envelope}");
    list_at(&items[0], "/matches")
}

#[test]
fn pe_twins_match_in_one_binary() {
    let (mut s, _) = open(&[PE]);
    let found = matches(&mut s, THRICE, r#","min_score":0,"limit":3"#);
    assert_eq!(text_at(&found[0], "/id"), TWICE, "{found:?}");
    assert!(int_at(&found[0], "/score") >= 800, "{found:?}");
}

#[test]
fn pe_thunk_call_shares_the_import_feature() {
    let (mut s, _) = open(&[PE]);
    let found = matches(&mut s, DISPATCH, r#","min_score":0,"limit":20"#);
    let thunk = found
        .iter()
        .find(|m| text_at(m, "/id") == SLEEP_THUNK)
        .unwrap_or_else(|| panic!("the Sleep thunk is a match: {found:?}"));
    let import = list_at(thunk, "/top_features")
        .into_iter()
        .any(|f| text_at(&f, "/kind") == "import" && text_at(&f, "/text").ends_with("!Sleep"));
    assert!(import, "the import Sleep is a shared feature: {thunk}");
}

#[test]
fn scope_open_takes_pe_and_elf_binaries() {
    let (mut s, ids) = open(&[PE, "hello.gcc-O2"]);
    let envelope = call(
        &mut s,
        "func_similar",
        &format!(
            r#"{{"binary_id":"{}","target":"{DISPATCH}","scope":"open","min_score":0,"limit":50}}"#,
            ids[0]
        ),
    );
    let d = data(&envelope);
    assert_eq!(int_at(d, "/corpus/binaries"), 2, "{envelope}");
    let items = list_at(d, "/items");
    let elf = ids[1].to_string();
    let from_elf = list_at(&items[0], "/matches")
        .iter()
        .any(|m| text_at(m, "/binary_id") == elf);
    assert!(from_elf, "a match comes from the ELF binary: {envelope}");
}
