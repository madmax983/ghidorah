//! The publish step: the analysis set of a work state and its `ReplaceAnalysis` commit
//! (design Section 3.9).
//!
//! The step makes the JSON form of the analysis layer and reads it with the codec of
//! `ghidorah-db`. So each row goes through the write rules of its table. Rules of the step:
//!
//! - Each fact has the origin `Analysis`, transaction 0, session `analysis`. So the set does
//!   not depend on the number of commits (AC-092).
//! - A function whose entry is in a code unit of another function does not go into the set.
//! - A premise that is not in the set and not an input of the binary goes.
//! - The creation order puts each premise before its fact. A premise that closes a cycle goes.
//! - A set equal to the committed set gives a no-op commit with no event (AC-093).
//! - The data references, the pointer slots and the strings come from `References` and
//!   `Strings` (WP-17a).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, JumpTableId};
use ghidorah_db::codec::{edit_to_json, key_to_json, tables_from_json};
use ghidorah_db::{
    AnalysisSet, Commit, Edit, Fact, FactKey, FuncRecord, Function, JumpTable, Origin, Part,
    PartKind, Program, Ref, RefKey, SessionLabel, Source, StartReason, StrInfo,
};
use ghidorah_json::Value;

use crate::AnalysisError;
use crate::why::Why;
use crate::work::Work;

/// The change counts of `analysis_run` between two analysis sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changed {
    /// The functions that are new, lost or different.
    pub functions: u64,
    /// The references that are new, lost or different.
    pub refs: u64,
    /// The strings that are new, lost or different.
    pub strings: u64,
    /// The jump tables that are new, lost or different.
    pub jumptables: u64,
}

/// Counts the keys of `old` and `new` that are in one map only or that differ.
fn diff<K: Ord, V: PartialEq>(old: &BTreeMap<K, V>, new: &BTreeMap<K, V>) -> u64 {
    let lost = old.iter().filter(|(k, v)| new.get(*k) != Some(*v)).count();
    let added = new.keys().filter(|k| !old.contains_key(*k)).count();
    u64::try_from(lost.saturating_add(added)).unwrap_or(u64::MAX)
}

impl Changed {
    /// Counts the changes from `old` to `new`.
    #[must_use]
    pub fn between(old: &AnalysisSet, new: &AnalysisSet) -> Self {
        fn funcs(t: &AnalysisSet) -> BTreeMap<Address, &Function> {
            t.funcs().iter().map(|f| (f.entry, f)).collect()
        }
        fn refs(t: &AnalysisSet) -> BTreeMap<RefKey, &Fact<Ref>> {
            t.refs().iter().map(|r| (r.value.key, r)).collect()
        }
        fn strings(t: &AnalysisSet) -> BTreeMap<u64, &StrInfo> {
            t.strings().iter().collect()
        }
        fn tables(t: &AnalysisSet) -> BTreeMap<JumpTableId, &Fact<JumpTable>> {
            t.jumptables().iter().collect()
        }
        Self {
            functions: diff(&funcs(old), &funcs(new)),
            refs: diff(&refs(old), &refs(new)),
            strings: diff(&strings(old), &strings(new)),
            jumptables: diff(&tables(old), &tables(new)),
        }
    }
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

    /// Tells if `key` names an input or a fact of the base layer.
    fn holds(&self, p: &Program, key: &FactKey) -> bool {
        let base = p.base();
        match key {
            FactKey::Entry(at) => self.entries.contains(at),
            FactKey::Reloc(at) => self.relocs.contains(at),
            FactKey::Fde(at) => self.fdes.contains(at),
            FactKey::Import(id) => p.imports().contains_key(id),
            FactKey::Export(id) => p.exports().contains_key(id),
            FactKey::Symbol(addr, k) => base.symbols().get(*addr, *k).is_some(),
            FactKey::Func(f) => base.funcs().get(*f).is_some(),
            FactKey::Noreturn(f) => base
                .funcs()
                .get(*f)
                .is_some_and(|x| x.flags.noreturn.is_some()),
            _ => false,
        }
    }
}

/// The facts of a set with their why-records, before the order step.
struct Facts {
    funcs: Vec<Function>,
    units: Vec<Value>,
    refs: Vec<Ref>,
    whys: BTreeMap<FactKey, Why>,
    kept: BTreeSet<u64>,
}

/// Collects the facts of `work` that go into the set.
fn collect(work: &Work) -> Facts {
    let origin = Origin::analysis();
    let mut out = Facts {
        funcs: Vec::new(),
        units: Vec::new(),
        refs: Vec::new(),
        whys: BTreeMap::new(),
        kept: BTreeSet::new(),
    };
    let mut kept = BTreeSet::new();
    for (entry, f) in &work.funcs {
        let Some((reason, confidence, why)) = f.primary() else {
            continue;
        };
        if work.owner(*entry).is_some_and(|o| o != *entry) {
            continue;
        }
        let id = FuncId(Address::ram(*entry));
        let mut func = Function::new(id.0, reason, confidence, Source::Analysis);
        func.body = work.body(*entry);
        let thunk = f.reasons.contains_key(&StartReason::PltStub);
        let kind = if thunk {
            PartKind::Thunk
        } else {
            PartKind::Main
        };
        func.parts = func
            .body
            .ranges()
            .iter()
            .map(|r| Part { range: *r, kind })
            .collect();
        func.flags.thunk = thunk;
        out.whys.insert(FactKey::Func(id), why.clone());
        if let Some(w) = work.known.get(entry).or_else(|| work.found.get(entry)) {
            func.flags.noreturn = Some(origin.fact(true));
            out.whys.insert(FactKey::Noreturn(id), w.clone());
        }
        out.funcs.push(func);
        kept.insert(*entry);
    }
    for (at, u) in &work.units {
        if !kept.contains(&u.owner) {
            continue;
        }
        out.units.push(Value::object([
            ("at", Value::from(Address::ram(*at).to_string())),
            ("len", Value::from(u.len)),
            ("flow", Value::from(u.flow.name())),
            ("flags", Value::from(u.flags)),
        ]));
        out.whys.insert(FactKey::CodeUnit(*at), u.why.clone());
    }
    for (key, why) in &work.refs {
        let owner = work.units.get(&key.from.off).map(|u| u.owner);
        if owner.is_some_and(|o| kept.contains(&o)) {
            out.refs.push(Ref {
                key: *key,
                primary: true,
            });
            out.whys.insert(FactKey::Ref(*key), why.clone());
        }
    }
    out.kept = kept;
    out
}

/// Gives the creation order of each fact and its kept premises. A walk in key order visits
/// the premises of each fact first. A premise outside the set and the inputs goes, and so
/// does a premise that closes a cycle.
fn order(p: &Program, whys: &BTreeMap<FactKey, Why>) -> BTreeMap<FactKey, (u64, Vec<FactKey>)> {
    let inputs = Inputs::of(p);
    let premises: BTreeMap<&FactKey, Vec<&FactKey>> = whys
        .iter()
        .map(|(k, w)| {
            let kept = w
                .premises
                .iter()
                .filter(|q| whys.contains_key(*q) || inputs.holds(p, q))
                .collect();
            (k, kept)
        })
        .collect();
    let mut out: BTreeMap<FactKey, (u64, Vec<FactKey>)> = BTreeMap::new();
    let mut open: BTreeSet<&FactKey> = BTreeSet::new();
    let mut cut: BTreeSet<(&FactKey, &FactKey)> = BTreeSet::new();
    let mut next = 0u64;
    for root in whys.keys() {
        if out.contains_key(root) {
            continue;
        }
        let mut stack: Vec<(&FactKey, usize)> = vec![(root, 0)];
        open.insert(root);
        while let Some((key, i)) = stack.pop() {
            let list = premises.get(key).map(Vec::as_slice).unwrap_or_default();
            if let Some(q) = list.get(i) {
                stack.push((key, i.saturating_add(1)));
                if !whys.contains_key(*q) || out.contains_key(*q) {
                    continue;
                }
                if open.contains(q) {
                    cut.insert((key, *q));
                } else {
                    open.insert(*q);
                    stack.push((*q, 0));
                }
                continue;
            }
            open.remove(key);
            let kept = list
                .iter()
                .filter(|q| !cut.contains(&(key, **q)))
                .map(|q| (*q).clone())
                .collect();
            out.insert(key.clone(), (next, kept));
            next = next.saturating_add(1);
        }
    }
    out
}

/// Gives the JSON form of one fact of a forward edit: the member `name` of the edit form.
fn member(edit: &Edit, name: &str) -> Value {
    edit_to_json(edit).get(name).cloned().unwrap_or_default()
}

/// Gives the analysis set of `work`.
///
/// # Errors
///
/// Returns [`AnalysisError::Codec`] when a row breaks a table rule.
pub(crate) fn analysis_set(program: &Program, work: &Work) -> Result<AnalysisSet, AnalysisError> {
    let mut facts = collect(work);
    let data = crate::analyzers::refs::collect(
        program,
        work,
        &facts.kept,
        &mut facts.refs,
        &mut facts.whys,
    );
    let strings = crate::analyzers::strings::collect(work, &mut facts.whys);
    let origin = Origin::analysis();
    let ordered = order(program, &facts.whys);
    let mut why_rows = Vec::with_capacity(ordered.len());
    for (key, (n, premises)) in &ordered {
        let Some(why) = facts.whys.get(key) else {
            continue;
        };
        why_rows.push(Value::object([
            ("key", key_to_json(key)),
            ("order", Value::from(*n)),
            ("rule", Value::from(why.rule.code())),
            (
                "premises",
                Value::Array(premises.iter().map(key_to_json).collect()),
            ),
        ]));
    }
    let funcs = facts
        .funcs
        .into_iter()
        .map(|func| {
            let record = FuncRecord {
                func,
                vars: Vec::new(),
                plate: None,
            };
            member(&Edit::CreateFunction(Box::new(record)), "func")
        })
        .collect();
    let refs = facts
        .refs
        .into_iter()
        .map(|r| {
            member(
                &Edit::AddRef {
                    fact: origin.fact(r),
                },
                "ref",
            )
        })
        .collect();
    let empty = || Value::Array(Vec::new());
    let value = Value::object([
        ("comments", empty()),
        ("data", Value::Array(data)),
        ("funcs", Value::Array(funcs)),
        ("jumptables", empty()),
        ("overrides", empty()),
        ("refs", Value::Array(refs)),
        ("strings", Value::Array(strings)),
        ("symbols", empty()),
        ("units", Value::Array(facts.units)),
        ("vars", empty()),
        ("why", Value::Array(why_rows)),
        (
            "why_next",
            Value::from(u64::try_from(ordered.len()).unwrap_or(u64::MAX)),
        ),
    ]);
    Ok(tables_from_json(&value)?)
}

/// Commits the analysis set of `work` with one `ReplaceAnalysis` edit.
///
/// # Errors
///
/// Returns the [`AnalysisError`] of the set, of the transaction or of the edit.
pub(crate) fn publish(program: &mut Program, work: &Work) -> Result<Commit, AnalysisError> {
    let set = analysis_set(program, work)?;
    let label = SessionLabel::new(SessionLabel::ANALYSIS)?;
    let mut tx = program.begin("analysis", Source::Analysis, label)?;
    let _ = tx.apply(Edit::ReplaceAnalysis(Box::new(set)))?;
    Ok(tx.commit()?)
}
