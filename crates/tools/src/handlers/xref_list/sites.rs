//! The sites of `xref_list`: target resolution, the reference classes, import sites, call
//! graph edges and unresolved indirect calls.

use std::collections::BTreeSet;

use ghidorah_analysis::code::slot_of;
use ghidorah_analysis::{CallGraph, Callee};
use ghidorah_base::{Address, ErrorCode, FuncId, ImportId, SyscallId};
use ghidorah_db::{FlowOverride, Program, Ref, RefKey, RefType};
use ghidorah_json::Value;
use ghidorah_loader::Format;

use crate::errors::ToolError;
use crate::handlers::func_sections as fs;
use crate::resolve::{self, Family, Target};

/// One found reference: the target index, the key, the source and the path to an import.
pub struct Found {
    /// The index of the target.
    pub target: usize,
    /// The key of the reference.
    pub key: RefKey,
    /// The source of the reference fact.
    pub source: &'static str,
    /// How the site reaches an import.
    pub via: Option<&'static str>,
}

/// Gives the classes of the reference `key` (see the module docs).
pub fn classes(p: &Program, key: &RefKey) -> Vec<&'static str> {
    let mut out = Vec::new();
    match key.kind {
        RefType::UnconditionalCall | RefType::ConditionalCall | RefType::ComputedCall => {
            out.push("call");
        }
        RefType::UnconditionalJump | RefType::ConditionalJump | RefType::ComputedJump => {
            out.push("jump");
        }
        RefType::Read => out.push("read"),
        RefType::Write => out.push("write"),
        RefType::ReadWrite => out.extend(["read", "write"]),
        _ => {
            let slot = key.from.is_ram() && p.code_unit(key.from.off).is_none();
            out.push(if slot { "ptr" } else { "data" });
        }
    }
    if !key.kind.is_flow() && key.to.is_ram() && p.string(key.to.off).is_some() {
        out.push("string");
    }
    out
}

/// Gives the found references of `refs` for the target `target`.
pub fn found(
    target: usize,
    refs: &[&ghidorah_db::Fact<Ref>],
    via: Option<&'static str>,
) -> Vec<Found> {
    refs.iter()
        .map(|r| Found {
            target,
            key: r.value.key,
            source: r.source.name(),
            via,
        })
        .collect()
}

/// Gives the sites of an import: the stub sites (`plt`), the slot sites (`got`) and the sites
/// of the EXTERNAL address (`got` through the slot, else `direct`). The references from the
/// stub itself are not sites. A PE import gives `thunk` for the sites of its IAT thunk, `iat`
/// for the slot sites and `direct` for a `call [rip+IAT]` site.
pub fn import_sites(p: &Program, target: usize, id: &ImportId) -> Result<Vec<Found>, ToolError> {
    let row = p.imports().get(id).ok_or_else(|| {
        ToolError::new(ErrorCode::NotFound)
            .var("kind", "import")
            .detail("kind", Value::from("import"))
    })?;
    let pe = p.meta().format == Format::Pe32Plus;
    let (stub_via, slot_via) = if pe { ("thunk", "iat") } else { ("plt", "got") };
    let stub = resolve::import_entry(p, row);
    let stub_func = stub.and_then(|s| p.owner_of(s));
    let outside = |r: &&ghidorah_db::Fact<Ref>| {
        stub_func.is_none() || p.owner_of(r.value.key.from) != stub_func
    };
    let mut out = Vec::new();
    if let Some(stub) = stub {
        let refs: Vec<_> = p.refs_to(stub).into_iter().filter(outside).collect();
        out.extend(found(target, &refs, Some(stub_via)));
    }
    if let Some(slot) = row.slot {
        let refs: Vec<_> = p.refs_to(slot).into_iter().filter(outside).collect();
        out.extend(found(target, &refs, Some(slot_via)));
    }
    for r in p.refs_to(row.ext).into_iter().filter(outside) {
        let from = r.value.key.from;
        let through = !pe
            && row.slot.is_some_and(|slot| {
                from == slot
                    || fs::decode(p, from.off)
                        .and_then(|insn| slot_of(&insn))
                        .is_some_and(|s| Address::ram(s) == slot)
            });
        out.extend(found(
            target,
            &[r],
            Some(if through { "got" } else { "direct" }),
        ));
    }
    Ok(out)
}

/// Gives the references of one target.
pub fn refs_of(p: &Program, index: usize, target: &Target) -> Result<Vec<Found>, ToolError> {
    Ok(match target {
        Target::Addr(a) | Target::RefsTo(a) => found(index, &p.refs_to(*a), None),
        Target::Func(f) => found(index, &p.refs_to(f.0), None),
        Target::ImportSites(id) => import_sites(p, index, id)?,
        Target::RefsFromInsn(a) => found(index, &p.refs_from(*a), None),
        Target::RefsFromBody(f) => {
            let mut out = Vec::new();
            for (at, _) in fs::body_units(p, *f) {
                out.extend(found(index, &p.refs_from(Address::ram(at)), None));
            }
            out
        }
        Target::CaseEdges(jt) => {
            let table = p
                .jump_table(*jt)
                .map(|f| f.value.targets.clone())
                .unwrap_or_default();
            table
                .into_iter()
                .zip(0i8..)
                .map(|(to, case)| Found {
                    target: index,
                    key: RefKey {
                        from: jt.0,
                        op_index: case,
                        to,
                        kind: RefType::ComputedJump,
                    },
                    source: "analysis",
                    via: None,
                })
                .collect()
        }
        Target::SyscallSites(_) => Vec::new(),
    })
}

/// The targets of one call after resolution.
#[derive(Default)]
pub struct Targets {
    /// The references of the targets.
    pub refs: Vec<Found>,
    /// The bad targets: `{ input, index, error }`.
    pub errors: Vec<Value>,
    /// The syscall targets with their indexes.
    pub syscalls: Vec<(usize, SyscallId)>,
    /// The start nodes of the call graph.
    pub starts: Vec<Callee>,
    /// The functions whose bodies a `from` call reads.
    pub bodies: Vec<FuncId>,
}

/// Resolves each target of `inputs` for `family`. A bad target goes to `errors`.
#[must_use]
pub fn resolve_all(p: &Program, inputs: &[Value], family: Family) -> Targets {
    let mut out = Targets::default();
    for (i, input) in inputs.iter().enumerate() {
        let path = fs::item_path("targets", i);
        let target = resolve::resolve(p, input, &fs::site(&path))
            .and_then(|r| resolve::target(p, &r, family))
            .and_then(|t| refs_of(p, i, &t).map(|found| (t, found)));
        match target {
            Ok((t, found)) => {
                out.refs.extend(found);
                match t {
                    Target::SyscallSites(id) => out.syscalls.push((i, id)),
                    Target::ImportSites(id) => out.starts.push(Callee::Import(id)),
                    Target::RefsTo(a) if p.func(FuncId(a)).is_some() => {
                        out.starts.push(Callee::Func(FuncId(a)));
                    }
                    Target::RefsFromBody(f) => {
                        out.starts.push(Callee::Func(f));
                        out.bodies.push(f);
                    }
                    _ => {}
                }
            }
            Err(mut error) => {
                if error.field_path.is_none() {
                    error.field_path = Some(path);
                }
                out.errors.push(Value::object([
                    ("input", input.clone()),
                    ("index", Value::from(i)),
                    ("error", error.to_json()),
                ]));
            }
        }
    }
    out
}

/// Gives the call-graph edges from the start nodes, `depth` levels, at most `max` functions.
pub fn edges(graph: &CallGraph, start: &[Callee], to: bool, depth: u64, max: usize) -> Value {
    let mut seen: BTreeSet<Callee> = start.iter().cloned().collect();
    let mut level: Vec<Callee> = start.to_vec();
    let mut out = Vec::new();
    for d in 1..=depth {
        let mut next = Vec::new();
        for node in &level {
            let pairs: Vec<(Callee, Callee)> = if to {
                graph
                    .callers(node)
                    .into_iter()
                    .map(|c| (Callee::Func(c), node.clone()))
                    .collect()
            } else if let Callee::Func(f) = node {
                graph
                    .callees(*f)
                    .into_iter()
                    .map(|c| (node.clone(), c.clone()))
                    .collect()
            } else {
                Vec::new()
            };
            for (from, callee) in pairs {
                let far = if to { from.clone() } else { callee.clone() };
                if !seen.contains(&far) && seen.len() >= max {
                    continue;
                }
                out.push(Value::object([
                    ("from", Value::from(callee_id(&from))),
                    ("to", Value::from(callee_id(&callee))),
                    ("depth", Value::from(d)),
                ]));
                if seen.insert(far.clone()) {
                    next.push(far);
                }
            }
        }
        level = next;
    }
    Value::Array(out)
}

/// Gives the ID text of a call-graph node.
pub fn callee_id(c: &Callee) -> String {
    match c {
        Callee::Func(f) => f.to_string(),
        Callee::Import(i) => i.to_string(),
    }
}

/// Gives the indirect calls with no target: no call reference and no target override.
pub fn unresolved(p: &Program, funcs: Option<&[FuncId]>) -> Vec<Address> {
    let all: Vec<FuncId> = p.funcs().iter().map(ghidorah_db::FuncView::id).collect();
    let mut out = Vec::new();
    for f in funcs.unwrap_or(&all) {
        for (at, _) in fs::body_units(p, *f) {
            let site = Address::ram(at);
            let indirect = p.code_unit(at).is_some_and(|u| {
                matches!(
                    u,
                    ghidorah_db::CodeUnit::Insn {
                        flow: ghidorah_db::FlowKind::ICall,
                        ..
                    }
                )
            });
            let called = p.refs_from(site).iter().any(|r| r.value.key.kind.is_call());
            let targets = p
                .flow_override(site)
                .is_some_and(|o| matches!(o.value, FlowOverride::IndirectTargets(_)));
            if indirect && !called && !targets {
                out.push(site);
            }
        }
    }
    out
}
