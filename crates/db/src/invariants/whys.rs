//! Rule 6: each analysis fact has a why-record, each premise exists and the premises make no
//! cycle.
//!
//! A premise is a fact of either layer or an input of the binary. The inputs are imports,
//! exports, entry points, relocations and FDEs. Only a premise with its own analysis
//! why-record can be on a cycle.

use std::collections::BTreeSet;

use ghidorah_base::{Address, StringId};

use super::{ALL, Violation};
use crate::program::{Program, Tables};
use crate::why::{FactKey, WhyStore};

/// Gives the keys of the facts of a layer, in table order.
fn fact_keys(t: &Tables) -> Vec<FactKey> {
    let mut keys: Vec<FactKey> = t
        .listing()
        .units_in(ALL)
        .map(|(at, _)| FactKey::CodeUnit(at))
        .collect();
    keys.extend(t.listing().data_defs().map(|(at, _)| FactKey::Data(at)));
    keys.extend(t.symbols().iter().map(|s| FactKey::Symbol(s.addr, s.key)));
    for f in t.funcs().iter() {
        keys.push(FactKey::Func(f.id()));
        if f.sig.is_some() {
            keys.push(FactKey::Signature(f.id()));
        }
        if f.flags.noreturn.is_some() {
            keys.push(FactKey::Noreturn(f.id()));
        }
    }
    keys.extend(t.refs().iter().map(|r| FactKey::Ref(r.value.key)));
    keys.extend(t.comments().iter().map(|(a, k, _)| FactKey::Comment(a, k)));
    keys.extend(t.vars().iter().map(|(v, _)| FactKey::Var(v.clone())));
    keys.extend(t.jumptables().iter().map(|(j, _)| FactKey::JumpTable(j)));
    keys.extend(t.overrides().iter().map(|(a, _)| FactKey::FlowOverride(a)));
    keys.extend(
        t.strings()
            .iter()
            .map(|(at, _)| FactKey::Str(StringId(Address::ram(at)))),
    );
    keys
}

/// The inputs of the binary that a premise can name.
struct Inputs {
    entries: BTreeSet<u64>,
    relocs: BTreeSet<u64>,
    fdes: BTreeSet<u64>,
}

impl Inputs {
    fn of(p: &Program) -> Self {
        let b = p.binary();
        Self {
            entries: b.entry_points.iter().map(|e| e.addr).collect(),
            relocs: b.relocs.iter().map(|r| r.offset).collect(),
            fdes: b.fdes.iter().map(|f| f.range.first).collect(),
        }
    }
}

/// Tells if the fact or the input of `key` exists.
fn exists(p: &Program, inputs: &Inputs, key: &FactKey) -> bool {
    let layers = [p.base(), p.analysis()];
    match key {
        FactKey::CodeUnit(at) => p.code_unit(*at).is_some(),
        FactKey::Data(at) => p.data_def(*at).is_some(),
        FactKey::Symbol(a, k) => layers.iter().any(|t| t.symbols().get(*a, *k).is_some()),
        FactKey::Func(f) => p.func(*f).is_some(),
        FactKey::Signature(f) => p.func(*f).is_some_and(|v| v.sig.is_some()),
        FactKey::Noreturn(f) => p.func(*f).is_some_and(|v| v.noreturn.is_some()),
        FactKey::Ref(r) => layers.iter().any(|t| t.refs().get(r).is_some()),
        FactKey::Comment(a, k) => p.comment(*a, *k).is_some(),
        FactKey::JumpTable(j) => p.jump_table(*j).is_some(),
        FactKey::FlowOverride(a) => p.flow_override(*a).is_some(),
        FactKey::Str(s) => s.0.is_ram() && p.string(s.0.off).is_some(),
        FactKey::Var(v) => {
            let view = p.var(v);
            view.name.is_some() || view.ty.is_some()
        }
        FactKey::Import(i) => p.imports().contains_key(i),
        FactKey::Export(e) => p.exports().contains_key(e),
        FactKey::Entry(at) => inputs.entries.contains(at),
        FactKey::Reloc(at) => inputs.relocs.contains(at),
        FactKey::Fde(at) => inputs.fdes.contains(at),
        FactKey::Note(n) => p.notes().get(*n).is_some(),
    }
}

/// Checks rule 6 over the analysis layer.
pub(super) fn check(p: &Program, out: &mut Vec<Violation>) {
    let a = p.analysis();
    let mut facts = fact_keys(a);
    for key in &facts {
        if a.why().get(key).is_none() {
            out.push(Violation::NoWhy { key: key.clone() });
        }
    }
    facts.sort_unstable();
    let inputs = Inputs::of(p);
    for (key, why) in a.why().iter() {
        if facts.binary_search(&key).is_err() {
            out.push(Violation::WhyOrphan { key: key.clone() });
        }
        for premise in &why.premises {
            if !exists(p, &inputs, premise) {
                out.push(Violation::Premise {
                    key: key.clone(),
                    premise: premise.clone(),
                });
            }
        }
    }
    cycles(a.why(), &facts, out);
}

/// Finds the premises that close a cycle among the facts `facts` in key order. A walk in key
/// order visits the premises of each fact first. Each premise that points back to an open
/// fact closes a cycle. The walk reads the premises of a fact when it opens the fact.
fn cycles(whys: &WhyStore, facts: &[FactKey], out: &mut Vec<Violation>) {
    /// The walk state of a fact.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        New,
        Open,
        Done,
    }
    let premises = |i: usize| -> Vec<FactKey> {
        facts
            .get(i)
            .and_then(|k| whys.get(k))
            .map(|w| w.premises)
            .unwrap_or_default()
    };
    let mut marks = vec![Mark::New; facts.len()];
    for root in 0..facts.len() {
        if marks.get(root) != Some(&Mark::New) {
            continue;
        }
        if let Some(m) = marks.get_mut(root) {
            *m = Mark::Open;
        }
        let mut stack: Vec<(usize, Vec<FactKey>, usize)> = vec![(root, premises(root), 0)];
        while let Some((i, list, j)) = stack.pop() {
            let Some(q) = list.get(j).cloned() else {
                if let Some(m) = marks.get_mut(i) {
                    *m = Mark::Done;
                }
                continue;
            };
            stack.push((i, list, j.saturating_add(1)));
            let Ok(k) = facts.binary_search(&q) else {
                continue;
            };
            match marks.get(k) {
                Some(Mark::New) => {
                    if let Some(m) = marks.get_mut(k) {
                        *m = Mark::Open;
                    }
                    stack.push((k, premises(k), 0));
                }
                Some(Mark::Open) => {
                    if let Some(key) = facts.get(i) {
                        out.push(Violation::PremiseCycle {
                            key: key.clone(),
                            premise: q,
                        });
                    }
                }
                Some(Mark::Done) | None => {}
            }
        }
    }
}
