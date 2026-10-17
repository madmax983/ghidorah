//! The fact checks of one build: each source fact must hold in the built binary.
//!
//! A string fact must occur in read-only data. A syscall fact must match a `syscall`
//! instruction of its function. A gap symbol must exist outside every function. A claim
//! must hold on the call edges of the listing. Each fault adds one message to the context.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::assemble::{Func, Inputs, hx, owner};
use super::facts::{self, Encoding};
use super::leaf;
use crate::json::Value;

/// Gives the address of the first occurrence of `needle` in allocated read-only data.
fn find_data(inp: &Inputs<'_>, needle: &[u8], align: u64) -> Option<u64> {
    for sec in &inp.info.sections {
        if !sec.is_alloc() || sec.is_exec() || sec.flags.contains('W') || sec.kind == "NOBITS" {
            continue;
        }
        let start = usize::try_from(sec.offset).ok()?;
        let len = usize::try_from(sec.size).ok()?;
        let hay = inp.bytes.get(start..start.checked_add(len)?)?;
        let mut pos = 0;
        while let Some(found) = hay
            .get(pos..)?
            .windows(needle.len())
            .position(|w| w == needle)
        {
            let at = pos + found;
            let addr = sec.addr.checked_add(u64::try_from(at).ok()?)?;
            if addr % align == 0 {
                return Some(addr);
            }
            pos = at + 1;
        }
    }
    None
}

pub(crate) fn place_string(inp: &Inputs<'_>, fact: &Value) -> Result<Value, String> {
    let (bytes, encoding) = facts::string_bytes(fact)?;
    let mut needle = bytes.clone();
    needle.extend_from_slice(encoding.terminator());
    let align = if encoding == Encoding::Utf16le { 2 } else { 1 };
    let addr = find_data(inp, &needle, align).ok_or_else(|| {
        format!(
            "string {:?} is not in read-only data",
            facts::string_text(&bytes, encoding)
        )
    })?;
    let hex = bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    Ok(Value::object([
        ("addr", hx(addr)),
        ("encoding", Value::from(encoding.name())),
        ("hex", Value::from(hex)),
        ("len", Value::from(bytes.len())),
        ("text", Value::from(facts::string_text(&bytes, encoding))),
    ]))
}

fn has_func(funcs: &[Func], name: &str) -> bool {
    funcs.iter().any(|f| f.name == name)
}

pub(crate) fn text_of<'v>(v: &'v Value, key: &str) -> &'v str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// The context of the fact checks of one build.
pub(crate) struct Ctx<'a, 'b> {
    pub(crate) inp: &'a Inputs<'b>,
    pub(crate) funcs: &'a [Func],
    pub(crate) ranges: &'a [Func],
    pub(crate) edges: &'a BTreeSet<(String, String, bool)>,
    pub(crate) errors: Vec<String>,
}

impl Ctx<'_, '_> {
    fn need_func(&mut self, key: &str, name: &str) {
        if !has_func(self.funcs, name) {
            self.errors
                .push(format!("{key}: `{name}` is not a function"));
        }
    }

    fn calls(&self, from: &str, to: &str) -> bool {
        self.edges.iter().any(|(f, t, _)| f == from && t == to)
    }

    fn sites(&self, func: &str) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .inp
            .listing
            .insns
            .iter()
            .filter(|i| i.mnemonic() == "syscall" && owner(self.ranges, i.addr) == Some(func))
            .map(|i| i.addr)
            .collect();
        out.sort_unstable();
        out
    }

    fn claim_holds(&self, claim: &Value) -> bool {
        let args: Vec<&str> = facts::list(claim, "args")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let syscall = |f: &str, n: &str| {
            facts::list(self.inp.facts, "syscalls")
                .iter()
                .any(|s| text_of(s, "func") == f && text_of(s, "name") == n)
        };
        let noreturn = |f: &str| {
            facts::list(self.inp.facts, "noreturn")
                .iter()
                .any(|n| n.as_str() == Some(f))
        };
        match (text_of(claim, "rel"), args.as_slice()) {
            ("calls", [f, g]) => self.calls(f, g),
            ("uses_import", [f, i]) => {
                self.calls(f, i) && self.inp.info.imports().iter().any(|x| x == i)
            }
            ("noreturn", [f]) => noreturn(f) && has_func(self.funcs, f),
            ("has_syscall", [f, n]) => syscall(f, n) && !self.sites(f).is_empty(),
            _ => false,
        }
    }

    pub(crate) fn syscalls(&mut self) -> Value {
        let mut by_func: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
        for s in facts::list(self.inp.facts, "syscalls") {
            by_func
                .entry(text_of(s, "func").to_owned())
                .or_default()
                .push(s);
        }
        let mut out = Vec::new();
        for (func, rows) in by_func {
            let sites = self.sites(&func);
            if sites.len() != rows.len() {
                self.errors.push(format!(
                    "syscalls: `{func}` has {} sites, not {}",
                    sites.len(),
                    rows.len()
                ));
                continue;
            }
            for (site, row) in sites.into_iter().zip(rows) {
                let mut args = Vec::new();
                for arg in facts::list(row, "args") {
                    if text_of(arg, "kind") == "str" {
                        match place_string(self.inp, arg) {
                            Ok(placed) => args.push(Value::object([
                                ("kind", Value::from("str")),
                                ("addr", placed.get("addr").cloned().unwrap_or(Value::Null)),
                                ("text", Value::from(text_of(arg, "text"))),
                            ])),
                            Err(e) => self.errors.push(format!("syscalls: {e}")),
                        }
                    } else {
                        args.push(arg.clone());
                    }
                }
                out.push(Value::object([
                    ("func", Value::from(func.as_str())),
                    ("site", hx(site)),
                    ("nr", row.get("nr").cloned().unwrap_or(Value::Null)),
                    ("name", Value::from(text_of(row, "name"))),
                    ("args", Value::from(args)),
                ]));
            }
        }
        out.sort_by_key(|v| text_of(v, "site").to_owned());
        Value::from(out)
    }

    pub(crate) fn gaps(&mut self) -> Value {
        let mut out = Vec::new();
        for gap in facts::list(self.inp.facts, "gaps") {
            let name = text_of(gap, "symbol");
            let sym = self
                .inp
                .info
                .symbols
                .iter()
                .find(|s| s.table == ".symtab" && s.name == name && s.is_defined());
            let Some(sym) = sym else {
                self.errors.push(format!("gaps: no symbol `{name}`"));
                continue;
            };
            if owner(self.ranges, sym.value).is_some() {
                self.errors.push(format!("gaps: a function holds `{name}`"));
            }
            let first = self
                .inp
                .listing
                .at(sym.value)
                .map_or("", |i| i.text.as_str());
            out.push(Value::object([
                ("name", Value::from(name)),
                ("addr", hx(sym.value)),
                ("size", Value::from(sym.size)),
                ("first_insn", Value::from(first)),
            ]));
        }
        Value::from(out)
    }

    pub(crate) fn leafs(&mut self) -> Value {
        let mut out = Vec::new();
        for f in self.inp.leafs {
            let Some(func) = self.funcs.iter().find(|x| x.name == f.name) else {
                self.errors
                    .push(format!("leaf: `{}` is not a function", f.name));
                continue;
            };
            let calls = self
                .inp
                .listing
                .range(func.addr, func.addr.saturating_add(func.extent))
                .any(|i| i.mnemonic() == "call");
            if calls {
                self.errors.push(format!("leaf: `{}` has a call", f.name));
            }
            out.push(Value::object([
                ("name", Value::from(f.name.as_str())),
                ("sig", Value::from(f.sig())),
                ("vectors", Value::from(leaf::vector_path(self.inp.name))),
            ]));
        }
        Value::from(out)
    }

    pub(crate) fn survey(
        &self,
        imports: &[String],
        libraries: &[String],
        protections: &Value,
    ) -> Value {
        let mut out = BTreeSet::new();
        for lib in libraries {
            out.insert(("library".to_owned(), lib.clone()));
        }
        if let Some(map) = protections.as_object() {
            for (k, v) in map {
                if v.as_bool() == Some(true) {
                    out.insert(("protection".to_owned(), k.clone()));
                }
            }
        }
        for fact in facts::list(self.inp.facts, "survey_facts") {
            let (kind, value) = (text_of(fact, "kind"), text_of(fact, "value"));
            let holds = match kind {
                "import" => imports.iter().any(|i| i == value),
                "function" => has_func(self.funcs, value),
                "string" | "syscall" => true,
                _ => false,
            };
            if holds {
                out.insert((kind.to_owned(), value.to_owned()));
            }
        }
        Value::from(
            out.into_iter()
                .map(|(k, v)| Value::object([("kind", Value::from(k)), ("value", Value::from(v))]))
                .collect::<Vec<_>>(),
        )
    }

    pub(crate) fn check_facts(&mut self) {
        let facts = self.inp.facts;
        for name in facts::list(facts, "noreturn")
            .iter()
            .filter_map(Value::as_str)
        {
            self.need_func("noreturn", name);
        }
        for row in facts::list(facts, "indirect_calls") {
            self.need_func("indirect_calls", text_of(row, "func"));
            for t in facts::list(row, "targets").iter().filter_map(Value::as_str) {
                self.need_func("indirect_calls", t);
            }
        }
        for row in facts::list(facts, "switches") {
            self.need_func("switches", text_of(row, "func"));
        }
        for row in facts::list(facts, "prototypes") {
            self.need_func("prototypes", text_of(row, "name"));
        }
        for claim in facts::list(facts, "claims") {
            if !self.claim_holds(claim) {
                self.errors.push(format!("claims: {claim} does not hold"));
            }
        }
    }
}

pub(crate) fn copied_facts(facts_in: &Value) -> Value {
    let mut map = BTreeMap::new();
    for key in [
        "abstain",
        "claims",
        "constants",
        "indirect_calls",
        "layouts",
        "noreturn",
        "prototypes",
        "secrets",
    ] {
        if let Some(v) = facts_in.get(key) {
            map.insert(key.to_owned(), v.clone());
        }
    }
    let switches: Vec<Value> = facts::list(facts_in, "switches")
        .iter()
        .map(|s| {
            let mut row = s.as_object().cloned().unwrap_or_default();
            row.insert(
                "case_count".to_owned(),
                Value::from(facts::list(s, "cases").len()),
            );
            Value::Object(row)
        })
        .collect();
    if !switches.is_empty() {
        map.insert("switches".to_owned(), Value::from(switches));
    }
    Value::Object(map)
}
