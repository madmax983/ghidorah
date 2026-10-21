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

/// The run of one fixture: the state hash, the analyzer rows and the seed lists.
struct Run {
    /// The state hash.
    hash: String,
    /// The analyzer rows in list order.
    rows: Vec<&'static str>,
    /// The seed lists of the program in insertion order: symbols, FDEs, entry points,
    /// exports and `.pdata` entries.
    seeds: Vec<Vec<String>>,
}

/// Loads `path` in a session with `engine` and gives its [`Run`].
fn analyzed(path: &str, engine: Engine) -> Run {
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
    let b = binary.program.binary();
    let seeds = vec![
        b.symbols
            .iter()
            .map(|s| format!("{} {} {:?}", s.addr, s.index, s.name))
            .collect(),
        b.fdes.iter().map(|f| format!("{:?}", f.range)).collect(),
        b.entry_points.iter().map(|e| format!("{e:?}")).collect(),
        b.exports.iter().map(|e| format!("{e:?}")).collect(),
        b.pdata.iter().map(|r| format!("{r:?}")).collect(),
    ];
    Run { hash, rows, seeds }
}

#[test]
fn ac_189a_seed_order() {
    let list = fixtures("T1");
    let (shuffled_rows, seeded, shuffled_seeds) = std::thread::scope(|scope| {
        // Four threads share the fixtures.
        let mut handles = Vec::new();
        for chunk in list.chunks(list.len().div_ceil(4).max(1)) {
            handles.push(scope.spawn(move || {
                let (mut moved, mut seeded, mut reordered) = (0usize, 0usize, 0usize);
                for f in chunk {
                    let shipped = analyzed(&f.path, Engine::default());
                    let seed = fnv1a64(f.name.as_bytes());
                    let other = analyzed(&f.path, Engine::with_seed_order(seed));
                    assert_eq!(
                        other.hash, shipped.hash,
                        "{}: the seed order changes the state",
                        f.name
                    );
                    let a: BTreeSet<_> = shipped.rows.iter().collect();
                    let b: BTreeSet<_> = other.rows.iter().collect();
                    assert_eq!(a, b, "{}: the same analyzers run", f.name);
                    moved += usize::from(shipped.rows != other.rows);
                    for (x, y) in shipped.seeds.iter().zip(&other.seeds) {
                        let (mut x, mut y) = (x.clone(), y.clone());
                        x.sort();
                        y.sort();
                        assert_eq!(x, y, "{}: the same seeds", f.name);
                    }
                    // The negative control: the shuffled run inserts the seeds in another
                    // order, so the relation tests the seed insertion order.
                    if shipped.seeds.iter().any(|list| list.len() >= 2) {
                        seeded += 1;
                        reordered += usize::from(shipped.seeds != other.seeds);
                    }
                }
                (moved, seeded, reordered)
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("a seed-order thread"))
            .fold((0, 0, 0), |(a, b, c), (x, y, z)| (a + x, b + y, c + z))
    });
    assert_eq!(
        shuffled_rows,
        list.len(),
        "each shuffled run seeds the analyzers in another order"
    );
    assert!(
        seeded > 0,
        "some fixtures have two or more seeds of one kind"
    );
    assert_eq!(
        shuffled_seeds, seeded,
        "each shuffled run inserts the seeds in another order"
    );
    let aliased = ALIAS_FIXTURES
        .iter()
        .filter(|name| alias_order_holds(&list, name))
        .count();
    assert!(
        aliased >= 2,
        "the alias fixtures have two or more symbols at one address"
    );
}

/// The fixtures of the alias part of AC-189a. Each has two or more symbols at one defined
/// address in `.symtab`.
const ALIAS_FIXTURES: [&str; 3] = [
    "switch.gcc-O2",
    "recursion.clang-O2",
    "adversarial_names.clang-O2",
];

/// Gives the little-endian value of `n` bytes at `at` of `bytes`.
fn le(bytes: &[u8], at: usize, n: usize) -> Option<usize> {
    let b = bytes.get(at..at.checked_add(n)?)?;
    let v = b
        .iter()
        .rev()
        .fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
    usize::try_from(v).ok()
}

/// Gives the bytes of the ELF file `bytes` with the `.symtab` entries at each defined address
/// in reverse order. The local entries and the other entries reverse apart. File and section
/// symbols stay. Gives `None` when no address has two entries of one group.
fn aliases_reversed(bytes: &[u8]) -> Option<Vec<u8>> {
    const ENTRY: usize = 24;
    let (shoff, shentsize, shnum) = (
        le(bytes, 0x28, 8)?,
        le(bytes, 0x3a, 2)?,
        le(bytes, 0x3c, 2)?,
    );
    let mut out = bytes.to_vec();
    let mut moved = false;
    for i in 0..shnum {
        let sh = shoff.checked_add(i.checked_mul(shentsize)?)?;
        if le(bytes, sh + 4, 4)? != 2 {
            continue;
        }
        let (off, size, globals) = (
            le(bytes, sh + 0x18, 8)?,
            le(bytes, sh + 0x20, 8)?,
            le(bytes, sh + 0x2c, 4)?,
        );
        let mut groups: BTreeMap<(bool, usize), Vec<usize>> = BTreeMap::new();
        for k in 1..size / ENTRY {
            let e = off + k * ENTRY;
            let kind = le(bytes, e + 4, 1)? & 0xf;
            let (shndx, value) = (le(bytes, e + 6, 2)?, le(bytes, e + 8, 8)?);
            if shndx != 0 && value != 0 && !matches!(kind, 3 | 4) {
                groups.entry((k < globals, value)).or_default().push(k);
            }
        }
        for slots in groups.values().filter(|s| s.len() >= 2) {
            moved = true;
            for (to, from) in slots.iter().zip(slots.iter().rev()) {
                let src = bytes.get(off + from * ENTRY..off + (from + 1) * ENTRY)?;
                out.get_mut(off + to * ENTRY..off + (to + 1) * ENTRY)?
                    .copy_from_slice(src);
            }
        }
    }
    moved.then_some(out)
}

/// The alias part of AC-189a: a copy of the fixture `name` with the symbols at each address
/// in another order gives the same reads, modulo the binary ID and the file hash. Gives
/// `false` when the fixture has no such symbols.
fn alias_order_holds(list: &[Fixture], name: &str) -> bool {
    let f = list.iter().find(|f| f.name == name).expect("the fixture");
    let bytes = std::fs::read(root().join(&f.path)).expect("the fixture bytes");
    let Some(copy) = aliases_reversed(&bytes) else {
        return false;
    };
    let dir = scratch(&format!("seed_alias_{name}"));
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).expect("the directory exists");
    let path = bin.join(name);
    std::fs::write(&path, &copy).expect("the copy");
    let sha = |b: &[u8]| ghidorah_base::hex::encode(&ghidorah_base::sha256(b));
    let (old_sha, new_sha) = (sha(&bytes), sha(&copy));
    let new_id = new_sha.get(..16).expect("an ID").to_owned();
    assert_ne!(new_id, f.id, "{name}: the copy is another file");
    let ids: Vec<String> = functions(f, &format!("seed_alias_list_{name}"))
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let load = |p: &str| {
        request(
            "load",
            "binary_load",
            Value::object([("path", Value::from(p))]),
        )
    };
    let mut lines = vec![load(&f.path)];
    lines.extend(reads(&f.id, &ids));
    let before = by_id(&jsonl(&dir.join("a"), &lines));
    let mut lines = vec![load(&path.to_string_lossy())];
    lines.extend(reads(&new_id, &ids));
    let mut input = lines.join("\n");
    input.push('\n');
    let projects = dir.join("b").to_string_lossy().into_owned();
    let workspace = root().to_string_lossy().into_owned();
    let extra = bin.to_string_lossy().into_owned();
    let command = binary(&[
        "jsonl",
        "--project-root",
        projects.as_str(),
        "--root",
        workspace.as_str(),
        "--root",
        extra.as_str(),
    ]);
    let after = by_id(&output_of(command, &input));
    let _ = std::fs::remove_dir_all(&dir);
    for (id, b) in &before {
        if id == "load" {
            continue;
        }
        let a = map_strings(&after[id], &|t| {
            t.replace(&new_sha, &old_sha).replace(&new_id, &f.id)
        });
        if let Some(diff) = first_difference(b, &a) {
            panic!("{name} {id}: the symbol order at one address changes the read:{diff}");
        }
    }
    true
}

/// The fixtures of the import-order regression. A reverse of the import list moves the
/// varargs or noreturn flags of their PLT stubs when a slot names its import by position.
const IMPORT_FIXTURES: [&str; 4] = [
    "switch.gcc-O2",
    "recursion.clang-O2",
    "adversarial_names.clang-O2",
    "func_ptrs.gcc-O2.noeh",
];

/// Gives the reads of the import facts of `path` after a full analysis with `engine`.
///
/// Each import gives the `func_get` read of its PLT stub and of each function that reads its
/// slot. The read has the name, the flags with `varargs` and `noreturn`, and the parameters.
/// Each EXTERNAL address shows as its import ID, because the import order sets the address.
fn import_reads(path: &str, engine: Engine) -> BTreeMap<String, Value> {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root");
    let mut session = Session::new(SessionConfig::new(roots), Box::new(FixedClock::new(0)));
    session.set_engine(Box::new(engine));
    let registry = session.active_registry();
    let load = Request::new("binary_load", args(&format!(r#"{{"path":"{path}"}}"#)));
    assert!(
        dispatch_with(&registry, &mut session, &load).ok(),
        "{path} loads"
    );
    let program = &session
        .binaries()
        .next()
        .expect("the binary is open")
        .program;
    let mut ext: Vec<(String, String)> = program
        .imports()
        .values()
        .map(|r| (r.ext.to_string(), format!("ext:{}", r.id)))
        .collect();
    // A longer address goes first, so `ext:0x1` does not cut `ext:0x10`.
    ext.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    let mut targets = Vec::new();
    for row in program.imports().values() {
        if let Some(stub) = row.stub {
            targets.push((format!("{} stub", row.id), stub.to_string()));
        }
        for r in row.slot.map(|s| program.refs_to(s)).unwrap_or_default() {
            if let Some(owner) = program.owner_of(r.value.key.from) {
                let key = format!("{} slot {}", row.id, r.value.key.from);
                targets.push((key, owner.0.to_string()));
            }
        }
    }
    let mut out = BTreeMap::new();
    for (key, target) in targets {
        let get = Request::new(
            "func_get",
            args(&format!(
                r#"{{"target":"{target}","include":["summary","decomp","vars"],"max_chars":60000}}"#
            )),
        );
        let read = dispatch_with(&registry, &mut session, &get).to_json();
        let read = map_strings(&read, &|t| {
            ext.iter()
                .fold(t.to_owned(), |acc, (from, to)| acc.replace(from, to))
        });
        out.insert(key, read);
    }
    out
}

#[test]
fn regress_import_order_keeps_stub_facts() {
    let list = fixtures("T1");
    for name in IMPORT_FIXTURES {
        let f = list.iter().find(|f| f.name == name).expect("the fixture");
        let shipped = import_reads(&f.path, Engine::default());
        let reversed = import_reads(
            &f.path,
            Engine::with_model_edit(|binary| binary.imports.reverse()),
        );
        assert!(
            shipped.keys().any(|k| k.ends_with(" stub")),
            "{name} has PLT stubs"
        );
        assert_eq!(
            shipped.keys().collect::<Vec<_>>(),
            reversed.keys().collect::<Vec<_>>(),
            "{name}: the same stubs and slot reads"
        );
        for (key, a) in &shipped {
            assert_eq!(a.get("ok"), Some(&Value::Bool(true)), "{name} {key}: {a}");
            if let Some(diff) = first_difference(a, &reversed[key]) {
                panic!("{name} {key}: the import order changes the read:{diff}");
            }
        }
    }
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

/// The ID of the survey read with the default budget. Its cut can fall at another item after
/// a rename, so the rename relation checks it with [`is_cut_of`].
const SURVEY_CUT: &str = "survey cut";

/// Gives the read lines of the binary `id`: the function list, the survey and one `func_get`
/// and one `xref_list` for each function of `funcs`. Each read has the hard budget cap, so it
/// gives full lists. One more survey read has the default budget.
fn reads(id: &str, funcs: &[String]) -> Vec<String> {
    let mut lines = vec![
        request(
            "list",
            "func_list",
            args(&format!(
                r#"{{"binary_id":"{id}","limit":1000,"max_chars":60000}}"#
            )),
        ),
        request(
            "survey",
            "binary_survey",
            args(&format!(r#"{{"binary_id":"{id}","max_chars":60000}}"#)),
        ),
        request(
            SURVEY_CUT,
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
                r#"{{"binary_id":"{id}","target":"{f}","limit":1000,"max_chars":60000}}"#
            )),
        ));
    }
    lines
}

/// Gives the pointer of the first cut mark of `value` below `at`: an `omitted` member, or
/// `truncated: true`.
fn cut_mark(value: &Value, at: &str) -> Option<String> {
    match value {
        Value::Object(members) => members.iter().find_map(|(key, item)| {
            let path = format!("{at}/{key}");
            let mark = key == "omitted" || (key == "truncated" && *item == Value::Bool(true));
            if mark {
                Some(path)
            } else {
                cut_mark(item, &path)
            }
        }),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, item)| cut_mark(item, &format!("{at}/{i}"))),
        _ => None,
    }
}

/// Tells if `cut` is `full` with some lists cut, for any cut. A cut list is the `items` of an
/// object with `omitted: { count }`. It keeps the first items of the full list, and `count`
/// is the number of the dropped items. Every other value is equal.
fn is_cut_of(cut: &Value, full: &Value) -> bool {
    match (cut, full) {
        (Value::Object(kept), Value::Object(whole)) => {
            let dropped = kept
                .get("omitted")
                .and_then(|o| o.get("count"))
                .and_then(Value::as_u64);
            let same_keys = kept.iter().filter(|(k, _)| *k != "omitted").count() == whole.len();
            same_keys
                && whole.iter().all(|(key, all)| {
                    let Some(part) = kept.get(key) else {
                        return false;
                    };
                    match (dropped, key, part, all) {
                        (Some(count), "items", Value::Array(first), Value::Array(every)) => {
                            let gone = every.len().checked_sub(first.len());
                            gone.and_then(|g| u64::try_from(g).ok()) == Some(count)
                                && every.starts_with(first)
                        }
                        _ => is_cut_of(part, all),
                    }
                })
        }
        (Value::Array(kept), Value::Array(whole)) => {
            kept.len() == whole.len() && kept.iter().zip(whole).all(|(x, y)| is_cut_of(x, y))
        }
        _ => cut == full,
    }
}

/// Makes sure that [`is_cut_of`] keeps a prefix with the count of the dropped items, and
/// nothing else.
fn check_cut_relation() {
    let full = args(r#"{"total":3,"items":[1,2,3]}"#);
    assert!(is_cut_of(&full, &full));
    assert!(is_cut_of(
        &args(r#"{"total":3,"items":[1],"omitted":{"count":2}}"#),
        &full
    ));
    for bad in [
        r#"{"total":3,"items":[2],"omitted":{"count":2}}"#,
        r#"{"total":3,"items":[1],"omitted":{"count":1}}"#,
        r#"{"total":2,"items":[1],"omitted":{"count":2}}"#,
        r#"{"total":3,"items":[1,2]}"#,
    ] {
        assert!(!is_cut_of(&args(bad), &full), "{bad}");
    }
}

/// Compares the reads of fixture `name` before and after the rename. `back` maps each new
/// name to its old name.
///
/// Each full read is equal modulo names, and its `rev` rises by one. The cut of the survey
/// with the default budget can fall at another item in each run. So each run keeps the
/// first items of its own full survey, and the full surveys are equal modulo names.
fn compare_renamed(
    name: &str,
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    back: &BTreeMap<String, String>,
) {
    for (id, b) in before {
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
        if id == SURVEY_CUT {
            for (run, results) in [("before", before), ("after", after)] {
                let data = |v: &Value| v.get("data").cloned().unwrap_or_default();
                let (cut, full) = (data(&results[id]), data(&results["survey"]));
                assert!(
                    is_cut_of(&cut, &full),
                    "{name} {run}: {cut} is not a cut of {full}"
                );
            }
            continue;
        }
        for v in [a, b] {
            assert_eq!(
                cut_mark(v, ""),
                None,
                "{name} {id}: a full read is not cut: {v}"
            );
        }
        let norm_a = map_strings(&without(&unhinted(a), &["rev", "named"]), &|t| {
            replace_tokens(t, back)
        });
        let norm_b = without(&unhinted(b), &["rev", "named"]);
        if let Some(diff) = first_difference(&norm_b, &norm_a) {
            panic!("{name} {id} differs modulo names:{diff}");
        }
    }
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
    check_cut_relation();
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
        compare_renamed(name, &before, &after, &back);
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
