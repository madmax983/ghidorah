//! The sections of `func_get` that are not rows: summary, xrefs, callers, callees, strings,
//! variables, notes, why, CFG and jump tables.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::analyzers::metrics;
use ghidorah_analysis::cfg::{self, EdgeKind};
use ghidorah_analysis::{CallGraph, Callee};
use ghidorah_base::{Address, Caps, FuncId, JumpTableId, StringId, VarId};
use ghidorah_db::{FactKey, Program, VarFact};
use ghidorah_json::{Object, Value};

use super::rows::body_units;
use super::text::{Namer, addr, hex, string_text};

/// Gives `{ id, name }` of a function.
#[must_use]
pub fn func_ref(program: &Program, func: FuncId, namer: &Namer) -> Value {
    Value::object([
        ("id", Value::from(func.to_string())),
        ("name", Value::from(namer.of(program, func.0))),
    ])
}

/// Gives the ID and the name of a callee.
#[must_use]
pub fn callee_ref(program: &Program, callee: &Callee, namer: &Namer) -> (String, String) {
    match callee {
        Callee::Func(f) => (f.to_string(), namer.of(program, f.0)),
        Callee::Import(i) => (i.to_string(), namer.text(i.name().unwrap_or_default())),
    }
}

/// Gives the address list of `sites`.
fn sites(list: &[Address]) -> Value {
    Value::Array(list.iter().map(|a| addr(*a)).collect())
}

/// Gives the summary: the metrics of design Section 7.11.
#[must_use]
pub fn summary(program: &Program, graph: &CallGraph, func: FuncId) -> Value {
    let Some(m) = metrics::func_metrics(program, graph, func) else {
        return Value::Null;
    };
    let calls = m
        .import_calls
        .iter()
        .map(|(c, n)| {
            Value::object([
                ("category", Value::from(c.name())),
                ("count", Value::from(*n)),
            ])
        })
        .collect();
    let mut out = Object::new();
    out.push("blocks", Value::from(m.blocks));
    out.push("insns", Value::from(m.insns));
    out.push("edges", Value::from(m.edges));
    out.push("cyclomatic", Value::from(m.cyclomatic));
    out.push("callers", Value::from(m.callers));
    out.push("callees", Value::from(m.callees));
    out.push("string_refs", Value::from(m.string_refs));
    out.push("import_calls", Value::Array(calls));
    Value::Object(out)
}

/// Gives the references to the entry of `func`: `[{ from, from_func?, kind, op_index }]`.
#[must_use]
pub fn xrefs(program: &Program, func: FuncId, namer: &Namer) -> Value {
    let list = program
        .refs_to(func.0)
        .into_iter()
        .map(|r| {
            let key = r.value.key;
            let mut out = Object::new();
            out.push("from", addr(key.from));
            if let Some(owner) = program.owner_of(key.from) {
                out.push("from_func", func_ref(program, owner, namer));
            }
            out.push("kind", Value::from(key.kind.name()));
            out.push("op_index", Value::from(key.op_index));
            Value::Object(out)
        })
        .collect();
    Value::Array(list)
}

/// Gives the callers of `func`: `[{ id, name, sites }]` in entry order. The stub or thunk of
/// an import also lists the callers of the import.
#[must_use]
pub fn callers(program: &Program, graph: &CallGraph, func: FuncId, namer: &Namer) -> Value {
    let list = graph
        .callers_of_func(func)
        .into_iter()
        .map(|caller| {
            Value::object([
                ("id", Value::from(caller.to_string())),
                ("name", Value::from(namer.of(program, caller.0))),
                ("sites", sites(&graph.sites_of_func(caller, func))),
            ])
        })
        .collect();
    Value::Array(list)
}

/// Gives the callees of `func`: `[{ id, name, sites }]`, functions first, then imports.
#[must_use]
pub fn callees(program: &Program, graph: &CallGraph, func: FuncId, namer: &Namer) -> Value {
    let list = graph
        .callees(func)
        .into_iter()
        .map(|callee| {
            let (id, name) = callee_ref(program, callee, namer);
            Value::object([
                ("id", Value::from(id)),
                ("name", Value::from(name)),
                ("sites", sites(&graph.sites(func, callee))),
            ])
        })
        .collect();
    Value::Array(list)
}

/// Gives the strings that the body of `func` references: `[{ id, addr, text, at }]` in
/// address order.
#[must_use]
pub fn strings(program: &Program, func: FuncId, caps: Caps) -> Value {
    let mut found: BTreeMap<u64, BTreeSet<Address>> = BTreeMap::new();
    for (at, _) in body_units(program, func) {
        let from = Address::ram(at);
        for r in program.refs_from(from) {
            let to = r.value.key.to;
            if !r.value.key.kind.is_flow() && to.is_ram() && program.string(to.off).is_some() {
                found.entry(to.off).or_default().insert(from);
            }
        }
    }
    let list = found
        .into_iter()
        .filter_map(|(at, from)| {
            let text = string_text(program, at, caps)?;
            let from: Vec<Address> = from.into_iter().collect();
            Some(Value::object([
                ("id", Value::from(StringId(Address::ram(at)).to_string())),
                ("addr", hex(at)),
                ("text", text),
                ("at", sites(&from)),
            ]))
        })
        .collect();
    Value::Array(list)
}

/// Gives the C text of a type ID of the program, or `None`.
#[must_use]
pub fn type_text(program: &Program, ty: ghidorah_types::TypeId) -> Option<String> {
    program.types().store().c_text(ty).ok()
}

/// Gives the variable facts of `func`: `[{ id, name?, type? }]` in ID order.
#[must_use]
pub fn vars(program: &Program, func: FuncId) -> Value {
    let mut ids: BTreeSet<VarId> = BTreeSet::new();
    for layer in program.layers() {
        ids.extend(
            layer
                .vars()
                .of_func(func)
                .map(|(id, _): (&VarId, &VarFact)| id.clone()),
        );
    }
    let list = ids
        .into_iter()
        .map(|id| {
            let view = program.var(&id);
            let mut out = Object::new();
            out.push("id", Value::from(id.to_string()));
            if let Some(name) = view.name {
                out.push("name", Value::from(name.value.as_str()));
                out.push("source", Value::from(name.source.name()));
            }
            if let Some(text) = view.ty.and_then(|t| type_text(program, t.value)) {
                out.push("type", Value::from(text));
            }
            Value::Object(out)
        })
        .collect();
    Value::Array(list)
}

/// Gives the notes about `func`: the notes of the function or of an address in its body.
#[must_use]
pub fn notes(program: &Program, func: FuncId) -> Value {
    let body = program.func(func).map(|v| v.func.body.clone());
    let inside = |a: Address| a.is_ram() && body.as_ref().is_some_and(|b| b.contains(a.off));
    let list = program
        .notes()
        .iter()
        .filter(|n| n.func == Some(func) || n.at.is_some_and(inside))
        .map(|n| {
            let mut out = Object::new();
            out.push("id", Value::from(n.id.to_string()));
            out.push("kind", Value::from(n.kind.name()));
            out.push("status", Value::from(n.status.name()));
            out.push("text", Value::from(n.text.as_str()));
            if !n.tags.is_empty() {
                let tags = n.tags.iter().map(|t| Value::from(t.as_str())).collect();
                out.push("tags", Value::Array(tags));
            }
            Value::Object(out)
        })
        .collect();
    Value::Array(list)
}

/// Gives the why-record of the function fact: `{ rule, premises }`, or `null`.
#[must_use]
pub fn why(program: &Program, func: FuncId) -> Value {
    let Some(record) = program.why(&FactKey::Func(func)) else {
        return Value::Null;
    };
    let premises = record
        .premises
        .iter()
        .map(ghidorah_db::codec::key_to_json)
        .collect();
    Value::object([
        ("rule", Value::from(record.rule.as_str())),
        ("premises", Value::Array(premises)),
    ])
}

/// Gives the CFG: `{ blocks: [{ id, start, size, insns }], edges: [{ from, to, kind,
/// case? }] }`.
#[must_use]
pub fn cfg(program: &Program, func: FuncId) -> Value {
    let Some(graph) = cfg::build(program, func) else {
        return Value::Null;
    };
    let blocks = graph
        .blocks
        .iter()
        .map(|b| {
            Value::object([
                ("id", Value::from(format!("bb:{}", Address::ram(b.start)))),
                ("start", hex(b.start)),
                ("size", hex(b.end().saturating_sub(b.start))),
                ("insns", Value::from(b.insns.len())),
            ])
        })
        .collect();
    let edges = graph
        .edges
        .iter()
        .map(|e| {
            let mut out = Object::new();
            out.push("from", Value::from(format!("bb:{}", Address::ram(e.from))));
            out.push("to", e.to.map_or(Value::Null, addr));
            out.push("kind", Value::from(e.kind.name()));
            if let EdgeKind::SwitchCase(case) = e.kind {
                out.push("case", Value::from(case));
            }
            Value::Object(out)
        })
        .collect();
    Value::object([
        ("blocks", Value::Array(blocks)),
        ("edges", Value::Array(edges)),
    ])
}

/// Gives the record of a jump table, or `None` when no table has the ID.
#[must_use]
pub fn jump_table(program: &Program, id: JumpTableId) -> Option<Value> {
    let fact = program.jump_table(id)?;
    let t = &fact.value;
    let mut out = Object::new();
    out.push("id", Value::from(id.to_string()));
    out.push("at", addr(id.0));
    if let Some(base) = t.base {
        out.push("base", addr(base));
    }
    out.push("entry_size", Value::from(t.entry_size));
    out.push("count", Value::from(t.count));
    let targets = t.targets.iter().map(|a| addr(*a)).collect();
    out.push("targets", Value::Array(targets));
    out.push("method", Value::from(t.method.name()));
    out.push("resolved", Value::Bool(t.resolved));
    out.push("source", Value::from(fact.source.name()));
    Some(Value::Object(out))
}

/// Gives the IDs of the jump tables of both layers in address order.
#[must_use]
pub fn table_ids(program: &Program) -> Vec<JumpTableId> {
    let mut ids: BTreeSet<JumpTableId> = BTreeSet::new();
    for layer in program.layers() {
        ids.extend(layer.jumptables().iter().map(|(id, _)| id));
    }
    ids.into_iter().collect()
}

/// Gives the jump tables whose indirect jump is in the body of `func`.
#[must_use]
pub fn jumptables(program: &Program, func: FuncId) -> Value {
    let list = table_ids(program)
        .into_iter()
        .filter(|id| program.owner_of(id.0) == Some(func))
        .filter_map(|id| jump_table(program, id))
        .collect();
    Value::Array(list)
}
