//! The metamorphic relations of design Section 13.4 (AC-189a to AC-189e): seed order, strip,
//! rename, rebase and relocate.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

#[path = "common/mod.rs"]
mod common;
#[path = "hardening/mod.rs"]
mod hardening;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use ghidorah_base::FixedClock;
use ghidorah_json::Value;
use ghidorah_testkit::rng::fnv1a64;
use ghidorah_tools::handlers::analysis_run::Engine;
use ghidorah_tools::{Request, Roots, Session, SessionConfig, dispatch_with};

use crate::common::{binary, root};
use crate::hardening::{
    Fixture, args, by_id, first_difference, fixtures, jsonl, map_strings, output_of,
    replace_tokens, request, scratch, without,
};

/// The sections of the `func_get` reads of the rename and rebase relations.
const SECTIONS: &str = r#"["summary","disasm","decomp","xrefs","callers","callees","strings","cfg","jumptables","vars","why"]"#;

/// Loads `path` in a session with `engine` and gives the state hash and the analyzer rows.
fn analyzed(path: &str, engine: Engine) -> (String, Vec<&'static str>) {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root");
    let mut session = Session::new(SessionConfig::new(roots), Box::new(FixedClock::new(0)));
    session.set_engine(Box::new(engine));
    let registry = session.active_registry();
    let load = Request::new("binary_load", args(&format!(r#"{{"path":"{path}"}}"#)));
    let envelope = dispatch_with(&registry, &mut session, &load);
    assert!(envelope.ok(), "{path} loads");
    let binary = session.binaries().next().expect("the binary is open");
    let hash = binary
        .program
        .state_hash()
        .map(|h| h.to_string())
        .expect("the state hash");
    let rows = session
        .analyzer_rows(binary.id)
        .iter()
        .map(|r| r.name)
        .collect();
    (hash, rows)
}

#[test]
fn ac_189a_seed_order() {
    let list = fixtures("T1");
    let shuffled_rows = std::thread::scope(|scope| {
        // Four threads share the fixtures.
        let mut handles = Vec::new();
        for chunk in list.chunks(list.len().div_ceil(4).max(1)) {
            handles.push(scope.spawn(move || {
                let mut moved = 0usize;
                for f in chunk {
                    let (hash, rows) = analyzed(&f.path, Engine::default());
                    let seed = fnv1a64(f.name.as_bytes());
                    let (other, other_rows) = analyzed(&f.path, Engine::with_seed_order(seed));
                    assert_eq!(other, hash, "{}: the seed order changes the state", f.name);
                    let a: BTreeSet<_> = rows.iter().collect();
                    let b: BTreeSet<_> = other_rows.iter().collect();
                    assert_eq!(a, b, "{}: the same analyzers run", f.name);
                    moved += usize::from(rows != other_rows);
                }
                moved
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("a seed-order thread"))
            .sum::<usize>()
    });
    assert_eq!(
        shuffled_rows,
        list.len(),
        "each shuffled run seeds the analyzers in another order"
    );
}

#[test]
fn ac_189b_strip() {
    let t1 = fixtures("T1");
    let by_name: BTreeMap<&str, &Fixture> = t1.iter().map(|f| (f.name.as_str(), f)).collect();
    let pairs: Vec<(&Fixture, &Fixture)> = t1
        .iter()
        .filter_map(|f| {
            by_name
                .get(format!("{}.stripped", f.name).as_str())
                .map(|s| (f, *s))
        })
        .collect();
    assert!(pairs.len() >= 40, "{} pairs", pairs.len());
    let mut lines = Vec::new();
    for f in pairs.iter().flat_map(|(a, b)| [*a, *b]) {
        lines.push(request(
            &format!("l {}", f.name),
            "binary_load",
            args(&format!(r#"{{"path":"{}"}}"#, f.path)),
        ));
        lines.push(request(
            &format!("f {}", f.name),
            "func_list",
            args(&format!(r#"{{"binary_id":"{}","limit":1000}}"#, f.id)),
        ));
        lines.push(request(
            &format!("s {}", f.name),
            "binary_survey",
            args(&format!(
                r#"{{"binary_id":"{}","include":["coverage"]}}"#,
                f.id
            )),
        ));
    }
    let projects = scratch("strip");
    let results = by_id(&jsonl(&projects, &lines));
    let _ = std::fs::remove_dir_all(&projects);
    let starts = |name: &str| -> BTreeSet<String> {
        results[&format!("f {name}")]
            .pointer("/data/items")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|i| i.get("addr").and_then(Value::as_str).map(str::to_owned))
            .collect()
    };
    for (full, stripped) in &pairs {
        let worklist = results[&format!("s {}", full.name)]
            .pointer("/data/coverage/worklist")
            .cloned()
            .unwrap_or_else(|| panic!("{} has a worklist", full.name));
        let items = worklist
            .get("items")
            .and_then(Value::as_array)
            .unwrap_or_default();
        let total = worklist.get("total").and_then(Value::as_u64).unwrap_or(0);
        assert!(
            usize::try_from(total).is_ok_and(|t| t == items.len()) || items.len() >= 5,
            "the worklist items"
        );
        let gaps: BTreeSet<String> = items
            .iter()
            .filter(|i| i.get("kind").and_then(Value::as_str) == Some("gap"))
            .filter_map(|i| i.get("at").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let have = starts(&full.name);
        let extra: Vec<String> = starts(&stripped.name)
            .into_iter()
            .filter(|s| !have.contains(s) && !gaps.contains(s))
            .collect();
        assert!(
            extra.is_empty(),
            "{}: stripped starts {extra:?} are new",
            stripped.name
        );
    }
}

/// Gives the read lines of the binary `id`: the function list, the survey and one `func_get`
/// and one `xref_list` for each function of `funcs`.
fn reads(id: &str, funcs: &[String]) -> Vec<String> {
    let mut lines = vec![
        request(
            "list",
            "func_list",
            args(&format!(r#"{{"binary_id":"{id}","limit":1000}}"#)),
        ),
        request(
            "survey",
            "binary_survey",
            args(&format!(r#"{{"binary_id":"{id}"}}"#)),
        ),
    ];
    for f in funcs {
        lines.push(request(
            &format!("get {f}"),
            "func_get",
            args(&format!(
                r#"{{"binary_id":"{id}","target":"{f}","include":{SECTIONS},"max_chars":60000}}"#
            )),
        ));
        lines.push(request(
            &format!("xrefs {f}"),
            "xref_list",
            args(&format!(
                r#"{{"binary_id":"{id}","target":"{f}","limit":1000}}"#
            )),
        ));
    }
    lines
}

/// Gives the `(id, name)` of each function of the fixture `f`.
fn functions(f: &Fixture, dir: &str) -> Vec<(String, String)> {
    let projects = scratch(dir);
    let lines = [
        request(
            "load",
            "binary_load",
            args(&format!(r#"{{"path":"{}"}}"#, f.path)),
        ),
        request(
            "list",
            "func_list",
            args(&format!(r#"{{"binary_id":"{}","limit":1000}}"#, f.id)),
        ),
    ];
    let results = by_id(&jsonl(&projects, &lines));
    let _ = std::fs::remove_dir_all(&projects);
    results["list"]
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|i| {
            let text = |k: &str| i.get(k).and_then(Value::as_str).expect("a text").to_owned();
            (text("id"), text("name"))
        })
        .collect()
}

/// The `why` of the `binary_survey` hint that names `main`. It depends on the name only.
const WHY_MAIN: &str = "Read the main function.";

/// Gives `envelope` without its hints that depend on the name `main`.
fn unhinted(envelope: &Value) -> Value {
    let mut out = envelope.clone();
    if let Value::Object(members) = &mut out
        && let Some(Value::Array(next)) = members.get_mut("next")
    {
        next.retain(|call| call.get("why").and_then(Value::as_str) != Some(WHY_MAIN));
    }
    out
}

/// Gives a new name of the same length: the first letter changes to `z`, or to `y`.
fn renamed(old: &str) -> String {
    let first = if old.starts_with('z') { 'y' } else { 'z' };
    std::iter::once(first).chain(old.chars().skip(1)).collect()
}

#[test]
fn ac_189c_rename() {
    let t1 = fixtures("T1");
    for name in [
        "hello.gcc-O2.stripped",
        "crackme.gcc-O2",
        "switch.clang-O2",
        "loops.gcc-O0",
    ] {
        let f = t1.iter().find(|f| f.name == name).expect("the fixture");
        let funcs = functions(f, &format!("rename_list_{name}"));
        assert!(funcs.len() > 3, "{name} has functions");
        let ids: Vec<String> = funcs.iter().map(|(id, _)| id.clone()).collect();
        let load = request(
            "load",
            "binary_load",
            args(&format!(r#"{{"path":"{}"}}"#, f.path)),
        );
        let items: Vec<Value> = funcs
            .iter()
            .map(|(id, old)| {
                Value::object([
                    ("target", Value::from(id.as_str())),
                    ("name", Value::from(renamed(old))),
                ])
            })
            .collect();
        let rename = request(
            "rename",
            "symbol_rename",
            Value::object([
                ("binary_id", Value::from(f.id.as_str())),
                ("force", Value::Bool(true)),
                ("items", Value::Array(items)),
            ]),
        );
        let mut before_lines = vec![load.clone()];
        before_lines.extend(reads(&f.id, &ids));
        let mut after_lines = vec![load, rename];
        after_lines.extend(reads(&f.id, &ids));
        let projects = scratch(&format!("rename_{name}"));
        let before = by_id(&jsonl(&projects.join("a"), &before_lines));
        let after = by_id(&jsonl(&projects.join("b"), &after_lines));
        let _ = std::fs::remove_dir_all(&projects);
        assert_eq!(
            after["rename"].get("ok"),
            Some(&Value::Bool(true)),
            "{}",
            after["rename"]
        );
        let back: BTreeMap<String, String> = funcs
            .iter()
            .map(|(_, old)| (renamed(old), old.clone()))
            .collect();
        for (id, b) in &before {
            if id == "load" {
                continue;
            }
            let a = &after[id];
            let rev = |v: &Value| v.get("rev").and_then(Value::as_u64);
            assert_eq!(
                rev(a),
                rev(b).map(|r| r + 1),
                "{name} {id}: the rev rises by one"
            );
            let norm_a = map_strings(&without(&unhinted(a), &["rev", "named"]), &|t| {
                replace_tokens(t, &back)
            });
            let norm_b = without(&unhinted(b), &["rev", "named"]);
            if let Some(diff) = first_difference(&norm_b, &norm_a) {
                panic!("{name} {id} differs modulo names:{diff}");
            }
        }
    }
}

/// Gives every hex number of `text` in `base..base + 0x10_0000` minus `base`, and the
/// default names `FUN_<hex8>` of that range too.
fn unbase(text: &str, base: u64) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(|c: char| c.is_ascii_hexdigit()) {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let len = tail
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(tail.len());
        let (word, after) = tail.split_at(len);
        let named = out.ends_with('_');
        let hex = out.ends_with("0x") || named;
        match u64::from_str_radix(word, 16) {
            Ok(n) if hex && (base..base + 0x10_0000).contains(&n) => {
                let width = if named { len } else { 0 };
                let _ = write!(out, "{:0width$x}", n - base);
            }
            _ => out.push_str(word),
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Gives the normalized reads of the fixture `name` with its image at `base`.
fn rebased(name: &str, base: u64) -> BTreeMap<String, Value> {
    let f = fixtures("T1")
        .into_iter()
        .find(|f| f.name == name)
        .expect("the fixture");
    let ids: Vec<String> = functions(&f, &format!("rebase_list_{name}"))
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let mut lines = vec![request(
        "load",
        "binary_load",
        args(&format!(r#"{{"path":"{}"}}"#, f.path)),
    )];
    lines.extend(reads(&f.id, &ids));
    let projects = scratch(&format!("rebase_{name}"));
    let results = by_id(&jsonl(&projects, &lines));
    let _ = std::fs::remove_dir_all(&projects);
    // Each link gives its own build ID. The survey shows it in the identity and in the notes.
    let build_id = results["survey"]
        .pointer("/data/identity/build_id")
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_owned();
    results
        .into_iter()
        .filter(|(id, _)| id != "load")
        .map(|(id, v)| {
            let id = unbase(&id, base);
            // The row bytes `b` hold absolute addresses of the non-PIE build.
            let v = without(&v, &["binary_id", "sha256", "file_name", "b"]);
            let v = map_strings(&v, &|t| {
                if t == build_id {
                    "<build-id>".to_owned()
                } else {
                    unbase(t, base)
                }
            });
            (id, v)
        })
        .collect()
}

#[test]
fn ac_189d_rebase() {
    let low = rebased("switch.gcc-O2-at400000", 0x40_0000);
    let high = rebased("switch.gcc-O2-at800000", 0x80_0000);
    assert!(low.len() > 4, "the reads of the low build");
    assert_eq!(
        low.keys().collect::<Vec<_>>(),
        high.keys().collect::<Vec<_>>(),
        "the same functions"
    );
    for (id, a) in &low {
        if let Some(diff) = first_difference(a, &high[id]) {
            panic!("{id} differs after the address normalization:{diff}");
        }
    }
}

#[test]
fn ac_189e_relocate() {
    let lines = [
        request(
            "load",
            "binary_load",
            args(r#"{"path":"fixtures/bin/hello.gcc-O2"}"#),
        ),
        request("survey", "binary_survey", args("{}")),
        request(
            "main",
            "func_get",
            args(r#"{"target":"main","include":["summary","decomp"]}"#),
        ),
        request(
            "note",
            "note_write",
            args(r#"{"kind":"note","text":"The main function prints one line."}"#),
        ),
        request("brief", "session_brief", args("{}")),
        request("history", "history_list", args("{}")),
    ];
    let input = format!("{}\n", lines.join("\n"));
    let workspace = root().to_string_lossy().into_owned();
    let outputs: Vec<String> = ["one", "two"]
        .iter()
        .map(|place| {
            let dir = scratch(&format!("relocate_{place}"));
            let cwd = dir.join("cwd").join(place);
            let home = dir.join("home");
            let projects = dir.join("projects").join(place);
            for d in [&cwd, &home, &projects] {
                std::fs::create_dir_all(d).expect("the directory exists");
            }
            let projects = projects.to_string_lossy().into_owned();
            let mut command = binary(&[
                "jsonl",
                "--project-root",
                projects.as_str(),
                "--root",
                workspace.as_str(),
            ]);
            command
                .current_dir(&cwd)
                .env("HOME", &home)
                .env_remove("XDG_DATA_HOME");
            let out = output_of(command, &input);
            let _ = std::fs::remove_dir_all(&dir);
            out
        })
        .collect();
    assert_eq!(outputs[0].lines().count(), lines.len(), "{}", outputs[0]);
    assert!(
        outputs[0] == outputs[1],
        "the output depends on the directories:\n{}\n{}",
        outputs[0],
        outputs[1]
    );
}
