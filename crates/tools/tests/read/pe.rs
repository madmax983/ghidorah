//! AC-249 and the PE parts of the read tools (WP-30): IAT thunks and import sites, the import
//! groups of `binary_survey`, `file_format: "pe"` and `imp:<dll>!<name>` resolution.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::FuncId;
use ghidorah_json::Value;

use crate::support::{
    addr_of, all_items, call, code, data, fixture, json, program, root, str_of, text_at,
};

/// The fixture path of `pe_main.exe` under `fixtures/bin`.
const MAIN: &str = "pe/pe_main.exe";

/// Gives the truth file of `pe_main.exe`.
fn main_truth() -> Value {
    let text = std::fs::read_to_string(root().join("fixtures/truth/pe/pe_main.json"))
        .expect("the truth file reads");
    json(&text)
}

/// Gives the array `name` of a truth value.
fn list<'a>(t: &'a Value, name: &str) -> &'a [Value] {
    t.get(name).and_then(Value::as_array).unwrap_or_default()
}

/// Gives the call sites of the `llvm-objdump -d` golden by target: a direct target or the slot
/// of a `call qword ptr [rip + ..]`.
fn golden_calls() -> (BTreeMap<u64, BTreeSet<u64>>, BTreeMap<u64, BTreeSet<u64>>) {
    let text =
        std::fs::read_to_string(root().join("tests/golden/loader/pe/pe_main.exe.objdump.txt"))
            .expect("the objdump golden reads");
    let mut direct: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut slots: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (Some(at), Some(_), Some(op), Some(arg)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if op != "call" {
            continue;
        }
        let at = u64::from_str_radix(at.trim().trim_end_matches(':'), 16).expect("an address");
        if let Some(rest) = arg.strip_prefix("0x") {
            let to = rest.split_whitespace().next().unwrap_or_default();
            let to = u64::from_str_radix(to, 16).expect("a target");
            direct.entry(to).or_default().insert(at);
        } else if arg.starts_with("qword ptr [rip") {
            let slot = arg.rsplit("# 0x").next().unwrap_or_default();
            let slot = u64::from_str_radix(slot.trim(), 16).expect("a slot");
            slots.entry(slot).or_default().insert(at);
        }
    }
    (direct, slots)
}

#[test]
fn ac_249_iat_naming() {
    let (mut session, id) = fixture(MAIN);
    let t = main_truth();
    let p = program(&session, &id);
    let mut thunk_of: BTreeMap<String, u64> = BTreeMap::new();
    for th in list(&t, "thunks") {
        let at = addr_of(&str_of(th, "addr"));
        let import = str_of(th, "import");
        if th.get("called") == Some(&Value::Bool(true)) {
            let f = p
                .func(FuncId(ghidorah_base::Address::ram(at)))
                .unwrap_or_else(|| panic!("the thunk {import} is a function"));
            assert!(f.func.flags.thunk, "{import}: the thunk flag");
            let name = p.name(ghidorah_base::Address::ram(at)).expect("a name");
            assert_eq!(name.text, str_of(th, "name"), "{import}");
            thunk_of.insert(import, at);
        }
    }
    assert_eq!(thunk_of.len(), 2, "pe_main calls two thunks");
    let (direct, slots) = golden_calls();
    for imp in list(&t, "imports") {
        let import = str_of(imp, "id");
        let slot = addr_of(&str_of(imp, "slot"));
        let thunk_sites = thunk_of
            .get(&import)
            .and_then(|at| direct.get(at))
            .cloned()
            .unwrap_or_default();
        let slot_sites = slots.get(&slot).cloned().unwrap_or_default();
        let args = Value::object([
            ("targets", Value::Array(vec![Value::from(import.as_str())])),
            ("kinds", Value::Array(vec![Value::from("call")])),
        ]);
        let got = all_items(&mut session, "xref_list", &args, 100);
        let mut want = thunk_sites.clone();
        want.extend(slot_sites.iter().copied());
        let sites: BTreeSet<u64> = got.iter().map(|i| addr_of(&str_of(i, "from"))).collect();
        assert_eq!(sites, want, "{import}");
        for item in &got {
            let from = addr_of(&str_of(item, "from"));
            let via = str_of(item, "via");
            let expect = if thunk_sites.contains(&from) {
                "thunk"
            } else {
                "direct"
            };
            assert_eq!(via, expect, "{import}: {item}");
        }
    }
}

#[test]
fn import_ids_resolve_to_thunks_and_slots() {
    let (mut session, _) = fixture(MAIN);
    let thunk = call(
        &mut session,
        "func_get",
        r#"{"target":"imp:kernel32.dll!Sleep","include":["summary"]}"#,
    );
    assert_eq!(text_at(&thunk, "/data/name"), "Sleep", "{thunk}");
    assert_eq!(text_at(&thunk, "/data/id"), "fn:0x1400011e0", "{thunk}");
    let slot = call(
        &mut session,
        "addr_info",
        r#"{"at":"imp:kernel32.dll!GetTickCount"}"#,
    );
    assert_eq!(text_at(&slot, "/data/addr"), "0x140002198", "{slot}");
    let ordinal = call(&mut session, "addr_info", r#"{"at":"imp:alpha.dll!#5"}"#);
    assert_eq!(text_at(&ordinal, "/data/addr"), "0x1400021b0", "{ordinal}");
}

#[test]
fn survey_groups_pe_imports_by_dll() {
    let (mut session, _) = fixture(MAIN);
    let survey = call(
        &mut session,
        "binary_survey",
        r#"{"include":["identity","imports","protections"]}"#,
    );
    let d = data(&survey);
    assert_eq!(text_at(d, "/identity/format"), "pe32+-x86_64");
    let imports = d.get("imports").expect("the imports section");
    let libraries: Vec<String> = imports
        .get("libraries")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|l| l.as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(libraries, vec!["kernel32.dll", "alpha.dll", "beta.dll"]);
    let items = imports
        .get("items")
        .and_then(Value::as_array)
        .expect("the import items");
    let dlls: Vec<String> = items.iter().map(|i| str_of(i, "dll")).collect();
    let mut grouped = dlls.clone();
    grouped.dedup();
    assert_eq!(
        grouped,
        vec!["kernel32.dll", "alpha.dll", "beta.dll"],
        "{dlls:?}"
    );
    let ordinal = items
        .iter()
        .find(|i| str_of(i, "id") == "imp:alpha.dll!#5")
        .expect("the ordinal import");
    assert_eq!(str_of(ordinal, "name"), "#5");
    let delay = items
        .iter()
        .find(|i| str_of(i, "id") == "imp:beta.dll!beta_delayed")
        .expect("the delay import");
    assert_eq!(delay.get("delay"), Some(&Value::Bool(true)));
    assert_eq!(
        d.pointer("/protections/nx_compat"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn binary_load_takes_file_format_pe() {
    let mut session = crate::support::session();
    let ok = call(
        &mut session,
        "binary_load",
        r#"{"path":"fixtures/bin/pe/pe_dll.dll","file_format":"pe","analysis":"none"}"#,
    );
    assert_eq!(text_at(&ok, "/data/format"), "pe32+-x86_64", "{ok}");
    assert_eq!(text_at(&ok, "/data/kind"), "dyn", "{ok}");
    let bad = call(
        &mut session,
        "binary_load",
        r#"{"path":"fixtures/bin/hello.gcc-O2","file_format":"pe","analysis":"none"}"#,
    );
    assert_eq!(code(&bad), "FORMAT_MALFORMED", "{bad}");
}
