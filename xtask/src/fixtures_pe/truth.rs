//! The truth files of the PE fixtures, `fixtures/truth/pe/<program>.json`.
//!
//! The truth comes from the C sources, the `.def` files, the link map and the debug directory
//! of `llvm-readobj` (design Section 4.15). Addresses are `0x` hex text.
//!
//! | Key | Shape | Source |
//! |---|---|---|
//! | `fixture`, `program`, `tier` | text | the image table |
//! | `generator` | `{ name, version }` | the generator |
//! | `build` | `{ compiler, cflags, ldflags }` | the image table |
//! | `binaries` | `[{ name, sha256 }]` | the image |
//! | `image_base`, `entry` | address | the link map |
//! | `functions` | `[{ name, addr, params, pdata }]` in address order | the map, the sources, `--unwind` |
//! | `thunks` | `[{ name, addr, import, called }]` | the map and the `call` sites of the listing |
//! | `imports` | `[{ id, dll, name, ordinal, delay, slot }]` in ID order | the map and the `.def` files |
//! | `exports` | `[{ id, name, ordinal, addr, forwarder }]` in ordinal order | the `.def` file and the map |
//! | `switch` | `{ func, addr, cases }` or `null` | the sources |
//! | `tls_callbacks` | `[{ name, addr }]` | the `.CRT$XLB` lines of the sources |
//! | `protections` | `{ dynamic_base, high_entropy_va, nx_compat, guard_cf, force_integrity }` | the link flags |
//! | `codeview` | `{ guid, age, pdb }` | `--coff-debug-directory` |

use std::collections::BTreeMap;
use std::path::Path;

use super::parse::{
    DefExport, LinkMap, MapSym, call_targets, parse_def, parse_map, pdata_starts, source_functions,
    switch_of, tls_callbacks,
};
use super::{Image, TIER, TRUTH_DIR};
use crate::Error;
use crate::fixtures::{GENERATOR, VERSION};
use crate::json::{self, Value};

/// Gives the truth path of a program, relative to the workspace root.
#[must_use]
pub fn path(program: &str) -> String {
    format!("{TRUTH_DIR}/{program}.json")
}

/// Reads and parses the truth file of a program.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file does not read, or [`Error::Data`] when it does not parse.
pub fn read(root: &Path, program: &str) -> Result<Value, Error> {
    let rel = path(program);
    let text = std::fs::read_to_string(root.join(&rel)).map_err(|e| Error::io(&rel, e))?;
    json::parse(&text).map_err(|e| Error::data(&rel, e.to_string()))
}

/// The inputs of one truth file.
pub struct Inputs<'a> {
    /// The image.
    pub image: &'a Image,
    /// The SHA-256 of the image in hex.
    pub sha256: &'a str,
    /// The link map text.
    pub map: &'a str,
    /// The `llvm-readobj` text.
    pub readobj: &'a str,
    /// The `llvm-objdump -d` text.
    pub objdump: &'a str,
    /// The sources and the `.def` files: file name and text.
    pub sources: &'a [(String, String)],
    /// The compiler and its version.
    pub compiler: &'a str,
}

/// Gives an address as `0x` hex text.
fn addr(v: u64) -> Value {
    Value::from(format!("{v:#x}"))
}

/// Gives the value after `key` in the first line of `readobj` that holds it.
fn readobj_field<'t>(readobj: &'t str, key: &str) -> Option<&'t str> {
    readobj
        .lines()
        .find_map(|l| l.trim().strip_prefix(key))
        .map(str::trim)
}

fn protections(image: &Image) -> Value {
    let has = |flag: &str| image.flags.contains(&flag);
    Value::object([
        ("dynamic_base", Value::from(!has("/dynamicbase:no"))),
        ("high_entropy_va", Value::from(!has("/highentropyva:no"))),
        ("nx_compat", Value::from(!has("/nxcompat:no"))),
        ("guard_cf", Value::from(has("/guard:cf"))),
        ("force_integrity", Value::from(has("/integritycheck"))),
    ])
}

fn codeview(readobj: &str) -> Result<Value, String> {
    let guid = readobj_field(readobj, "PDBGUID:")
        .map(|g| g.trim_matches(|c| c == '{' || c == '}').to_owned())
        .ok_or("no PDBGUID")?;
    let age: u64 = readobj_field(readobj, "PDBAge:")
        .and_then(|a| a.parse().ok())
        .ok_or("no PDBAge")?;
    let pdb = readobj_field(readobj, "PDBFileName:").ok_or("no PDBFileName")?;
    Ok(Value::object([
        ("guid", Value::from(guid)),
        ("age", Value::from(age)),
        ("pdb", Value::from(pdb)),
    ]))
}

/// The `.def` exports of each DLL name, from the `.def` files of the inputs.
fn defs(sources: &[(String, String)]) -> BTreeMap<String, Vec<DefExport>> {
    sources
        .iter()
        .filter(|(n, _)| has_ext(n, "def"))
        .map(|(_, t)| parse_def(t))
        .collect()
}

fn imports(inputs: &Inputs<'_>, map: &LinkMap) -> Vec<Value> {
    let defs = defs(inputs.sources);
    let mut rows: BTreeMap<String, Value> = BTreeMap::new();
    for s in &map.symbols {
        let (Some(name), Some((_, dll))) =
            (s.name.strip_prefix("__imp_"), s.object.split_once(':'))
        else {
            continue;
        };
        let def = defs
            .get(dll)
            .and_then(|list| list.iter().find(|d| d.name == name));
        let by_ordinal = def.filter(|d| d.noname).and_then(|d| d.ordinal);
        let dll_lower = dll.to_ascii_lowercase();
        let id = by_ordinal.map_or_else(
            || format!("imp:{dll_lower}!{name}"),
            |o| format!("imp:{dll_lower}!#{o}"),
        );
        rows.insert(
            id.clone(),
            Value::object([
                ("id", Value::from(id)),
                ("dll", Value::from(dll)),
                (
                    "name",
                    by_ordinal.map_or_else(|| Value::from(name), |_| Value::Null),
                ),
                (
                    "ordinal",
                    by_ordinal.map_or(Value::Null, |o| Value::from(u64::from(o))),
                ),
                ("delay", Value::from(inputs.image.delay.contains(&dll))),
                ("slot", addr(s.addr)),
            ]),
        );
    }
    rows.into_values().collect()
}

fn exports(inputs: &Inputs<'_>, map: &LinkMap) -> Vec<Value> {
    let own = format!("{}.def", inputs.image.program);
    let Some((_, text)) = inputs.sources.iter().find(|(n, _)| *n == own) else {
        return Vec::new();
    };
    let mut rows: Vec<(u32, Value)> = Vec::new();
    for e in parse_def(text).1 {
        let ordinal = e.ordinal.unwrap_or(0);
        let at = map
            .symbols
            .iter()
            .find(|s| s.name == e.name && e.forwarder.is_none())
            .map(|s| addr(s.addr));
        let id = if e.noname {
            format!("exp:#{ordinal}")
        } else {
            format!("exp:{}", e.name)
        };
        rows.push((
            ordinal,
            Value::object([
                ("id", Value::from(id)),
                (
                    "name",
                    if e.noname {
                        Value::Null
                    } else {
                        Value::from(e.name.as_str())
                    },
                ),
                ("ordinal", Value::from(u64::from(ordinal))),
                ("addr", at.unwrap_or(Value::Null)),
                ("forwarder", e.forwarder.map_or(Value::Null, Value::from)),
            ]),
        ));
    }
    rows.sort_by_key(|(o, _)| *o);
    rows.into_iter().map(|(_, v)| v).collect()
}

/// Tells if the file name `name` has the extension `ext`, in any letter case.
fn has_ext(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Gives the functions of the objects: name, address, parameter count and `.pdata` flag.
fn functions(inputs: &Inputs<'_>, code: &[&MapSym]) -> Value {
    let mut params: BTreeMap<String, u64> = BTreeMap::new();
    for (_, text) in inputs.sources.iter().filter(|(n, _)| has_ext(n, "c")) {
        params.extend(source_functions(text));
    }
    let pdata = pdata_starts(inputs.readobj);
    let mut rows: Vec<(u64, Value)> = code
        .iter()
        .filter(|s| has_ext(&s.object, "obj"))
        .map(|s| {
            (
                s.addr,
                Value::object([
                    ("name", Value::from(s.name.as_str())),
                    ("addr", addr(s.addr)),
                    (
                        "params",
                        params.get(&s.name).map_or(Value::Null, |n| Value::from(*n)),
                    ),
                    ("pdata", Value::from(pdata.contains(&s.addr))),
                ]),
            )
        })
        .collect();
    rows.sort_by_key(|(a, _)| *a);
    Value::from(rows.into_iter().map(|(_, v)| v).collect::<Vec<_>>())
}

/// Gives the linker thunks of the imports: name, address, import ID and call flag.
fn thunks(inputs: &Inputs<'_>, map: &LinkMap, code: &[&MapSym], imports: &[Value]) -> Value {
    let calls = call_targets(inputs.objdump);
    let rows: Vec<Value> = code
        .iter()
        .filter(|s| s.object.contains(':'))
        .filter_map(|s| {
            let slot = map
                .symbols
                .iter()
                .find(|i| i.name == format!("__imp_{}", s.name))?;
            let import = imports
                .iter()
                .find(|i| i.get("slot") == Some(&addr(slot.addr)))?
                .get("id")?
                .clone();
            Some(Value::object([
                ("name", Value::from(s.name.as_str())),
                ("addr", addr(s.addr)),
                ("import", import),
                ("called", Value::from(calls.contains(&s.addr))),
            ]))
        })
        .collect();
    Value::from(rows)
}

/// Gives the `build` object of an image.
fn build(inputs: &Inputs<'_>) -> Value {
    let strings = |v: Vec<String>| Value::from(v.into_iter().map(Value::from).collect::<Vec<_>>());
    Value::object([
        ("compiler", Value::from(inputs.compiler)),
        (
            "cflags",
            strings(super::CFLAGS.iter().map(|s| (*s).to_owned()).collect()),
        ),
        ("ldflags", strings(inputs.image.ldflags())),
    ])
}

/// Assembles the truth value of one image.
///
/// # Errors
///
/// Returns a message when an input lacks a fact, for example the entry symbol.
pub fn assemble(inputs: &Inputs<'_>) -> Result<Value, String> {
    let image = inputs.image;
    let map = parse_map(inputs.map);
    let code: Vec<&MapSym> = map.symbols.iter().filter(|s| s.section == "0001").collect();
    let imports = imports(inputs, &map);
    let find = |name: &str| map.symbols.iter().find(|s| s.name == name).map(|s| s.addr);
    let entry = find(image.entry).ok_or("the map has no entry symbol")?;
    let switch = switch_of(inputs.sources).map_or(Value::Null, |(func, cases)| {
        Value::object([
            ("addr", find(&func).map_or(Value::Null, addr)),
            ("func", Value::from(func)),
            ("cases", Value::from(cases)),
        ])
    });
    let callbacks: Vec<Value> = tls_callbacks(inputs.sources)
        .into_iter()
        .map(|name| {
            Value::object([
                ("addr", find(&name).map_or(Value::Null, addr)),
                ("name", Value::from(name)),
            ])
        })
        .collect();
    Ok(Value::object([
        ("fixture", Value::from(image.name)),
        ("program", Value::from(image.program)),
        ("tier", Value::from(TIER)),
        (
            "generator",
            Value::object([
                ("name", Value::from(GENERATOR)),
                ("version", Value::from(VERSION)),
            ]),
        ),
        ("build", build(inputs)),
        (
            "binaries",
            Value::from(vec![Value::object([
                ("name", Value::from(image.name)),
                ("sha256", Value::from(inputs.sha256)),
            ])]),
        ),
        ("image_base", addr(map.image_base)),
        ("entry", addr(entry)),
        ("functions", functions(inputs, &code)),
        ("thunks", thunks(inputs, &map, &code, &imports)),
        ("imports", Value::from(imports)),
        ("exports", Value::from(exports(inputs, &map))),
        ("switch", switch),
        ("tls_callbacks", Value::from(callbacks)),
        ("protections", protections(image)),
        ("codeview", codeview(inputs.readobj)?),
    ]))
}

/// The top keys of a PE truth file and their JSON kinds: `a` array, `o` object, `t` text,
/// `x` address and `n` object or `null`.
const TOP: &[(&str, char)] = &[
    ("fixture", 't'),
    ("program", 't'),
    ("tier", 't'),
    ("generator", 'o'),
    ("build", 'o'),
    ("binaries", 'a'),
    ("image_base", 'x'),
    ("entry", 'x'),
    ("functions", 'a'),
    ("thunks", 'a'),
    ("imports", 'a'),
    ("exports", 'a'),
    ("switch", 'n'),
    ("tls_callbacks", 'a'),
    ("protections", 'o'),
    ("codeview", 'o'),
];

fn kind_ok(value: &Value, kind: char) -> bool {
    match kind {
        'a' => value.as_array().is_some(),
        'o' => matches!(value, Value::Object(_)),
        't' => value.as_str().is_some(),
        'x' => value
            .as_str()
            .and_then(|t| t.strip_prefix("0x"))
            .is_some_and(|h| u64::from_str_radix(h, 16).is_ok()),
        _ => matches!(value, Value::Object(_) | Value::Null),
    }
}

/// Checks the schema of a PE truth value and the sha256 of its binary. Gives one message per
/// problem.
#[must_use]
pub fn check_value(value: &Value, sha256: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (key, kind) in TOP {
        match value.get(key) {
            Some(v) if kind_ok(v, *kind) => {}
            Some(_) => out.push(format!("`{key}` has a bad type")),
            None => out.push(format!("`{key}` is missing")),
        }
    }
    if value.get("tier").and_then(Value::as_str) != Some(TIER) {
        out.push(format!("`tier` is not {TIER}"));
    }
    if value.pointer("/binaries/0/sha256").and_then(Value::as_str) != Some(sha256) {
        out.push("the sha256 differs from the manifest".to_owned());
    }
    out
}
