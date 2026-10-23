//! The publish step: the analysis set of a work state and its `ReplaceAnalysis` commit
//! (design Section 3.9).
//!
//! The step makes the typed rows of the analysis layer and gives them to
//! [`tables_from_rows`]. So each row goes through the write rules of its table, with no JSON
//! form between. Rules of the step:
//!
//! - Each fact has the origin `Analysis`, transaction 0, session `analysis`. So the set does
//!   not depend on the number of commits (AC-092).
//! - A function whose entry is in a code unit of another function does not go into the set.
//! - A premise that is not in the set and not an input of the binary goes.
//! - The creation order puts each premise before its fact. A premise that closes a cycle goes.
//! - A set equal to the committed set gives a no-op commit with no event (AC-093).
//! - The data references, the pointer slots and the strings come from `References` and
//!   `Strings` (WP-17a).

#[cfg(test)]
mod tests;
pub(crate) mod whys;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ghidorah_base::{Address, FuncId, JumpTableId};
use ghidorah_db::codec::{SetRows, tables_from_rows};
use ghidorah_db::listing::CodeUnit;
use ghidorah_db::{
    AnalysisSet, Commit, Edit, Fact, FactKey, Function, JumpTable, Origin, Part, PartKind, Program,
    Ref, RefKey, RuleCode, SessionLabel, Source, StartReason, StrInfo, WhyRows,
};

use crate::AnalysisError;
use crate::why::Rule;
use crate::work::Work;
use whys::{Rec, Whys};

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
    units: Vec<(u64, CodeUnit)>,
    refs: Vec<Ref>,
    whys: Whys,
    kept: BTreeSet<u64>,
}

/// Collects the facts of `work` that go into the set.
fn collect(program: &Program, work: &Work) -> Facts {
    let origin = Origin::analysis();
    let mut out = Facts {
        funcs: Vec::new(),
        units: Vec::new(),
        refs: Vec::new(),
        whys: Whys::default(),
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
        let thunk =
            f.reasons.contains_key(&StartReason::PltStub) || work.ir.thunks.contains_key(entry);
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
        crate::irfacts::decorate(program, work, *entry, &mut func);
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
        out.units.push((
            *at,
            CodeUnit::Insn {
                len: u.len,
                flow: u.flow,
                flags: u.flags,
            },
        ));
        out.whys.insert_unit(*at, u.owner);
    }
    for key in &work.refs {
        let owner = work.units.get(&key.from.off).map(|u| u.owner);
        if owner.is_some_and(|o| kept.contains(&o)) {
            out.refs.push(Ref {
                key: *key,
                primary: true,
            });
            out.whys.insert_ref(*key, Rule::FlowRef);
        }
    }
    out.kept = kept;
    out
}

/// Gives the mask bit of premise `j`, or 0 from premise 64.
fn bit(j: usize) -> u64 {
    u32::try_from(j)
        .ok()
        .and_then(|b| 1u64.checked_shl(b))
        .unwrap_or(0)
}

/// Gives the creation order of each fact and a mask of its kept premises, by the position of
/// the fact in key order. Bit `j` of the mask keeps premise `j`. A walk in key order visits
/// the premises of each fact first. A premise outside the set and the inputs goes, and so
/// does a premise that closes a cycle.
///
/// The step works on positions, so it makes no copy of a key. A record has at most 64
/// premises, so its mask fits in a `u64`.
fn order(p: &Program, records: &[Rec<'_>]) -> Vec<(u64, u64)> {
    /// The walk state of a fact.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        New,
        Open,
        Done,
    }
    let inputs = Inputs::of(p);
    let at = |q: &FactKey| records.binary_search_by(|r| r.cmp_key(q)).ok();
    let mut out: Vec<(u64, u64)> = records
        .iter()
        .map(|r| {
            let mask = (0..r.premise_count()).fold(0u64, |m, j| {
                let kept = r
                    .premise(j)
                    .is_some_and(|q| at(&q).is_some() || inputs.holds(p, &q));
                if kept { m | bit(j) } else { m }
            });
            (0, mask)
        })
        .collect();
    let mut marks = vec![Mark::New; records.len()];
    let mut next = 0u64;
    for root in 0..records.len() {
        if marks.get(root) != Some(&Mark::New) {
            continue;
        }
        if let Some(m) = marks.get_mut(root) {
            *m = Mark::Open;
        }
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some((i, j)) = stack.pop() {
            if let Some(q) = records.get(i).and_then(|r| r.premise(j)) {
                stack.push((i, j.saturating_add(1)));
                let Some(k) = at(&q) else {
                    continue;
                };
                match marks.get(k) {
                    Some(Mark::New) => {
                        if let Some(m) = marks.get_mut(k) {
                            *m = Mark::Open;
                        }
                        stack.push((k, 0));
                    }
                    Some(Mark::Open) => {
                        if let Some((_, mask)) = out.get_mut(i) {
                            *mask &= !bit(j);
                        }
                    }
                    Some(Mark::Done) | None => {}
                }
                continue;
            }
            if let (Some((o, _)), Some(m)) = (out.get_mut(i), marks.get_mut(i)) {
                *o = next;
                *m = Mark::Done;
            }
            next = next.saturating_add(1);
        }
    }
    out
}

/// Gives the analysis set of `work`.
///
/// # Errors
///
/// Returns [`AnalysisError::Codec`] when a row breaks a table rule.
pub(crate) fn analysis_set(program: &Program, work: &Work) -> Result<AnalysisSet, AnalysisError> {
    let mut facts = collect(program, work);
    let data = crate::analyzers::refs::collect(
        program,
        work,
        &facts.kept,
        &mut facts.refs,
        &mut facts.whys,
    );
    let strings = crate::analyzers::strings::collect(work, &mut facts.whys);
    let extra = crate::irfacts::rows(program, work, &facts.funcs, &mut facts.whys);
    let origin = Origin::analysis();
    let records = facts.whys.records();
    let ordered = order(program, &records);
    let why_next = u64::try_from(ordered.len()).unwrap_or(u64::MAX);
    let mut why = WhyRows::new();
    let mut codes: BTreeMap<Rule, RuleCode> = BTreeMap::new();
    for (rec, (n, mask)) in records.iter().zip(ordered) {
        let premises: Vec<FactKey> = (0..rec.premise_count())
            .filter(|j| mask & bit(*j) != 0)
            .filter_map(|j| rec.premise(j))
            .collect();
        let rule = if let Some(code) = codes.get(&rec.rule()) {
            code.clone()
        } else {
            let code = rec.rule().rule_code()?;
            codes.insert(rec.rule(), code.clone());
            code
        };
        let record = ghidorah_db::why::Why { rule, premises };
        why.push(rec.key(), n, record)?;
    }
    drop(records);
    // The flow references and the operand references go in key order, so the table of the
    // set takes them in one bulk build.
    facts.refs.sort_unstable_by_key(|r| r.key);
    let mut rows = SetRows {
        data,
        funcs: facts.funcs,
        refs: facts.refs.into_iter().map(|r| origin.fact(r)).collect(),
        strings,
        units: facts.units,
        why,
        why_next,
        ..SetRows::default()
    };
    extra.add_to(&mut rows);
    Ok(tables_from_rows(rows)?)
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
    let _ = tx.apply(Edit::ReplaceAnalysis(Arc::new(set)))?;
    Ok(tx.commit()?)
}
