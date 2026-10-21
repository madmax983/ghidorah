//! The assembly of one truth file from the build outputs and the source facts.
//!
//! Sources of each truth key:
//!
//! | Key | Source |
//! |---|---|
//! | `functions`, `cold_parts`, `duplicate_names`, `function_count` | `STT_FUNC` symbols of `.symtab`. A `<f>.cold` symbol is a part of `f` when `f` exists. |
//! | `call_edges`, `tail_calls`, `self_calls` | direct calls and jumps of the objdump listing |
//! | `jump_tables` | the object relocations and the link map ([`super::jumptab`]) |
//! | `elf`, `libraries`, `imports`, `protections` | the `readelf` text |
//! | `variant_protections` | the `readelf` text of each variant: the protection fields that differ |
//! | `strings`, `syscalls`, `gaps` | the source facts, placed in the binary |
//! | `leaf_functions` | the `LEAF` lines of the sources |
//! | `facts`, `survey_facts` | the source facts that hold in the build |

use std::collections::{BTreeMap, BTreeSet};

use super::checks::{Ctx, copied_facts, place_string, text_of};
use super::elfinfo::ElfInfo;
use super::facts;
use super::jumptab::JumpTable;
use super::leaf::LeafFn;
use super::objdump::Listing;
use crate::json::Value;

/// One function of the truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Func {
    /// The symbol name.
    pub name: String,
    /// The start address.
    pub addr: u64,
    /// The symbol size.
    pub size: u64,
    /// The extent: the size, or the distance to the next label for a size of 0.
    pub extent: u64,
    /// The function that owns this range: the name, or the parent of a cold part.
    pub owner: String,
}

/// The inputs of one truth file.
#[derive(Debug, Clone)]
pub struct Inputs<'a> {
    /// The build name, for example `hello.gcc-O2`.
    pub name: &'a str,
    /// The fixed header fields: program, tier, generator, build and binaries.
    pub head: Vec<(&'static str, Value)>,
    /// The `readelf` text of the build.
    pub info: &'a ElfInfo,
    /// The objdump listing of the build.
    pub listing: &'a Listing,
    /// The bytes of the build.
    pub bytes: &'a [u8],
    /// The jump tables of the build.
    pub tables: &'a [JumpTable],
    /// The source facts of the program.
    pub facts: &'a Value,
    /// The leaf functions with vectors in this build.
    pub leafs: &'a [LeafFn],
    /// The `readelf` text of each variant of the build, by variant name.
    pub variants: &'a [(&'static str, ElfInfo)],
}

/// The imports that the truth counts as network functions (`network_imports`).
pub const NETWORK: &[&str] = &[
    "accept",
    "bind",
    "connect",
    "getaddrinfo",
    "gethostbyname",
    "getsockopt",
    "htonl",
    "htons",
    "inet_addr",
    "inet_ntop",
    "inet_pton",
    "listen",
    "ntohl",
    "ntohs",
    "recv",
    "recvfrom",
    "recvmsg",
    "send",
    "sendmsg",
    "sendto",
    "setsockopt",
    "shutdown",
    "socket",
];

/// Gives an address as `0x` hex text.
#[must_use]
pub fn hx(addr: u64) -> Value {
    Value::from(format!("0x{addr:x}"))
}

pub(crate) fn strs<I: IntoIterator<Item = S>, S: Into<String>>(items: I) -> Value {
    Value::from(
        items
            .into_iter()
            .map(|s| Value::from(s.into()))
            .collect::<Vec<_>>(),
    )
}

/// Gives the functions and the cold parts of the `.symtab` symbols, in address order.
#[must_use]
pub fn functions(info: &ElfInfo, listing: &Listing) -> (Vec<Func>, Vec<Func>) {
    let syms: Vec<_> = info
        .symbols
        .iter()
        .filter(|s| s.table == ".symtab" && s.kind == "FUNC" && s.is_defined())
        .collect();
    let names: BTreeSet<&str> = syms.iter().map(|s| s.name.as_str()).collect();
    let mut funcs = Vec::new();
    let mut parts = Vec::new();
    let mut seen = BTreeSet::new();
    for s in syms {
        if !seen.insert((s.value, s.name.clone())) {
            continue;
        }
        let section = info
            .section_at(s.value)
            .map(|x| x.name.clone())
            .unwrap_or_default();
        let extent = if s.size > 0 {
            s.size
        } else {
            let end = listing
                .next_label(s.value, &section)
                .or_else(|| listing.section_end(&section))
                .unwrap_or(s.value);
            end.saturating_sub(s.value)
        };
        let parent = s.name.strip_suffix(".cold").filter(|p| names.contains(p));
        let func = Func {
            name: s.name.clone(),
            addr: s.value,
            size: s.size,
            extent,
            owner: parent.unwrap_or(&s.name).to_owned(),
        };
        if parent.is_some() {
            parts.push(func);
        } else {
            funcs.push(func);
        }
    }
    let key = |f: &Func| (f.addr, f.name.clone());
    funcs.sort_by_key(key);
    parts.sort_by_key(key);
    (funcs, parts)
}

/// Gives the owner of an address: the function or the parent of the cold part that holds it.
pub(crate) fn owner(ranges: &[Func], addr: u64) -> Option<&str> {
    ranges
        .iter()
        .find(|f| f.addr <= addr && addr < f.addr.saturating_add(f.extent.max(1)))
        .map(|f| f.owner.as_str())
}

/// The call edges of the listing: `(caller, callee, tail)`.
fn edges(inp: &Inputs<'_>, ranges: &[Func], funcs: &[Func]) -> BTreeSet<(String, String, bool)> {
    let starts: BTreeMap<u64, &str> = funcs.iter().map(|f| (f.addr, f.name.as_str())).collect();
    let mut out = BTreeSet::new();
    for insn in &inp.listing.insns {
        let mnem = insn.mnemonic();
        let tail = mnem == "jmp";
        if mnem != "call" && !tail {
            continue;
        }
        let Some(from) = owner(ranges, insn.addr) else {
            continue;
        };
        let to = if insn.is_memory_indirect() {
            insn.comment_target()
                .and_then(|slot| inp.info.slot_import(slot))
        } else if let Some(target) = insn.direct_target() {
            if let Some(name) = starts.get(&target) {
                let inside = owner(ranges, target) == Some(from) && tail;
                (!inside).then(|| (*name).to_owned())
            } else {
                inp.listing
                    .plt_label(target)
                    .and_then(|l| l.name.strip_suffix("@plt"))
                    .map(str::to_owned)
            }
        } else {
            None
        };
        if let Some(to) = to {
            out.insert((from.to_owned(), to, tail));
        }
    }
    out
}

/// Gives the sorted names of the syscall sites, without duplicates.
fn syscall_names(sites: &Value) -> BTreeSet<String> {
    sites
        .as_array()
        .unwrap_or(&[])
        .iter()
        .map(|s| text_of(s, "name").to_owned())
        .collect()
}

fn func_value(f: &Func, listing: &Listing) -> Value {
    let insns = listing
        .range(f.addr, f.addr.saturating_add(f.extent))
        .count();
    Value::object([
        ("name", Value::from(f.name.as_str())),
        ("addr", hx(f.addr)),
        ("size", Value::from(f.size)),
        ("insns", Value::from(insns)),
    ])
}

/// Gives the `[caller, callee]` pairs of the edges, sorted. With `tail_only`, only tail calls.
fn pairs(all: &BTreeSet<(String, String, bool)>, tail_only: bool) -> Value {
    let set: BTreeSet<[&str; 2]> = all
        .iter()
        .filter(|e| !tail_only || e.2)
        .map(|e| [e.0.as_str(), e.1.as_str()])
        .collect();
    Value::from(set.into_iter().map(strs).collect::<Vec<_>>())
}

/// Gives the names that two or more functions share, with their addresses.
fn duplicates(funcs: &[Func]) -> Value {
    let mut by_name: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for f in funcs {
        by_name.entry(f.name.as_str()).or_default().push(hx(f.addr));
    }
    Value::Object(
        by_name
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(k, v)| (k.to_owned(), Value::from(v)))
            .collect(),
    )
}

fn tables_value(inp: &Inputs<'_>, ranges: &[Func]) -> Value {
    let rows = inp.tables.iter().map(|t| {
        let first = t.refs.first().copied().unwrap_or(0);
        let site = inp.listing.holding(first).map_or(first, |i| i.addr);
        Value::object([
            ("func", Value::from(owner(ranges, first).unwrap_or(""))),
            ("table", hx(t.table)),
            ("lea", hx(site)),
            ("kind", Value::from(t.kind.name())),
            ("entries", Value::from(t.targets.len())),
            (
                "targets",
                Value::from(t.targets.iter().map(|a| hx(*a)).collect::<Vec<_>>()),
            ),
        ])
    });
    Value::from(rows.collect::<Vec<_>>())
}

fn elf_value(info: &ElfInfo) -> Value {
    let image_base = info
        .segments
        .iter()
        .filter(|s| s.kind == "LOAD")
        .map(|s| s.vaddr)
        .min()
        .unwrap_or(0);
    Value::object([
        ("type", Value::from(info.elf_type.as_str())),
        ("entry", hx(info.entry)),
        ("image_base", hx(image_base)),
        (
            "interp",
            Value::from(info.segments.iter().any(|s| s.kind == "INTERP")),
        ),
    ])
}

fn parts_value(parts: &[Func]) -> Value {
    let rows = parts.iter().map(|p| {
        Value::object([
            ("name", Value::from(p.name.as_str())),
            ("addr", hx(p.addr)),
            ("size", Value::from(p.size)),
            ("parent", Value::from(p.owner.as_str())),
        ])
    });
    Value::from(rows.collect::<Vec<_>>())
}

/// Assembles the truth file of one build.
///
/// # Errors
///
/// Returns the list of facts that do not hold in the build.
pub fn assemble(inp: &Inputs<'_>) -> Result<Value, Vec<String>> {
    let (funcs, parts) = functions(inp.info, inp.listing);
    let mut ranges = funcs.clone();
    ranges.extend(parts.iter().cloned());
    let all_edges = edges(inp, &ranges, &funcs);
    let mut ctx = Ctx {
        inp,
        funcs: &funcs,
        ranges: &ranges,
        edges: &all_edges,
        errors: Vec::new(),
    };
    ctx.check_facts();
    let mut strings = Vec::new();
    for fact in facts::list(inp.facts, "strings") {
        match place_string(inp, fact) {
            Ok(v) => strings.push(v),
            Err(e) => ctx.errors.push(format!("strings: {e}")),
        }
    }
    let syscalls = ctx.syscalls();
    let gaps = ctx.gaps();
    let leafs = ctx.leafs();
    let imports = inp.info.imports();
    let libraries = inp.info.libraries();
    let protections = inp.info.protections();
    let survey = ctx.survey(&imports, &libraries, &protections);
    let errors = ctx.errors;
    if !errors.is_empty() {
        return Err(errors);
    }
    let self_calls: BTreeSet<&str> = all_edges
        .iter()
        .filter(|e| e.0 == e.1)
        .map(|e| e.0.as_str())
        .collect();
    let mut map: BTreeMap<String, Value> = inp
        .head
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    let rest = [
        ("fixture", Value::from(inp.name)),
        ("elf", elf_value(inp.info)),
        ("libraries", strs(libraries)),
        (
            "network_imports",
            strs(
                imports
                    .iter()
                    .filter(|i| NETWORK.contains(&i.as_str()))
                    .cloned(),
            ),
        ),
        ("imports", strs(imports)),
        ("protections", protections.clone()),
        (
            "functions",
            Value::from(
                funcs
                    .iter()
                    .map(|f| func_value(f, inp.listing))
                    .collect::<Vec<_>>(),
            ),
        ),
        ("function_count", Value::from(funcs.len())),
        ("cold_parts", parts_value(&parts)),
        ("duplicate_names", duplicates(&funcs)),
        ("call_edges", pairs(&all_edges, false)),
        ("tail_calls", pairs(&all_edges, true)),
        ("self_calls", strs(self_calls)),
        ("jump_tables", tables_value(inp, &ranges)),
        ("strings", Value::from(strings)),
        ("syscall_names", strs(syscall_names(&syscalls))),
        ("syscalls", syscalls),
        ("gaps", gaps),
        ("leaf_functions", leafs),
        ("survey_facts", survey),
        ("facts", copied_facts(inp.facts)),
    ];
    for (k, v) in rest {
        map.insert(k.to_owned(), v);
    }
    let variants: BTreeMap<String, Value> = inp
        .variants
        .iter()
        .map(|(name, info)| {
            let own = info.variant_protections(&protections);
            ((*name).to_owned(), Value::Object(own))
        })
        .filter(|(_, v)| v.as_object().is_some_and(|m| !m.is_empty()))
        .collect();
    if !variants.is_empty() {
        map.insert("variant_protections".to_owned(), Value::Object(variants));
    }
    Ok(Value::Object(map))
}
