//! The typed rows of a layer and the tables that they make.
//!
//! The JSON reader of a layer gives [`SetRows`] first. The publish step of the analysis also
//! gives them, with no JSON form between. [`from_rows`] makes one [`Tables`] from the rows.
//! [`set_from_rows`] puts each row in the shard of its key and makes an [`AnalysisSet`].

use std::collections::BTreeMap;
use std::sync::Arc;

use ghidorah_base::{Address, JumpTableId, VarId};

use super::CodecError;
use crate::comments::CommentKind;
use crate::fact::{Fact, WriteError};
use crate::funcs::Function;
use crate::jumptables::JumpTable;
use crate::listing::{CodeUnit, DataDef};
use crate::overrides::FlowOverride;
use crate::program::{AnalysisSet, ShardId, Tables};
use crate::refs::Ref;
use crate::strings::StrInfo;
use crate::symbols::Symbol;
use crate::vars::VarFact;
use crate::why::WhyRows;

/// The typed rows of a layer, each table in the row order of its JSON form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetRows {
    /// The comments: address, kind and text.
    pub comments: Vec<(Address, CommentKind, Fact<String>)>,
    /// The data definitions by RAM offset.
    pub data: Vec<(u64, Fact<DataDef>)>,
    /// The functions.
    pub funcs: Vec<Function>,
    /// The jump tables.
    pub jumptables: Vec<(JumpTableId, Fact<JumpTable>)>,
    /// The flow overrides. The analysis gives none.
    pub overrides: Vec<(Address, Fact<FlowOverride>)>,
    /// The references.
    pub refs: Vec<Fact<Ref>>,
    /// The strings by RAM offset.
    pub strings: Vec<(u64, StrInfo)>,
    /// The symbols.
    pub symbols: Vec<Symbol>,
    /// The code units by RAM offset.
    pub units: Vec<(u64, CodeUnit)>,
    /// The variable facts. The analysis gives none.
    pub vars: Vec<(VarId, VarFact)>,
    /// The why-records: key and record.
    pub why: WhyRows,
}

/// Gives the codec error of a manager write.
pub(super) fn werr<T>(e: WriteError<T>) -> CodecError {
    match e {
        WriteError::Invalid(i) => i.into(),
        WriteError::Blocked(_) => CodecError::text("unique key"),
    }
}

/// Runs `put` on each row of the member `name`. An error gets the path of its row.
fn each<T>(
    name: &str,
    rows: Vec<T>,
    mut put: impl FnMut(T) -> Result<(), CodecError>,
) -> Result<(), CodecError> {
    for (i, row) in rows.into_iter().enumerate() {
        put(row).map_err(|e| e.at_index(i).at(name))?;
    }
    Ok(())
}

/// Makes the tables of a layer from `rows`. Each row goes through the write path of its
/// manager, member by member in the order of the JSON form.
///
/// # Errors
///
/// Returns a [`CodecError`] with the path of the first row that breaks a table rule.
pub(super) fn from_rows(rows: SetRows) -> Result<Tables, CodecError> {
    let mut out = Tables::default();
    each("comments", rows.comments, |(addr, kind, text)| {
        let origin = text.origin();
        out.comments
            .set(addr, kind, Some(text.value), &origin)
            .map_err(werr)
            .map(drop)
    })?;
    each("data", rows.data, |(at, def)| {
        let origin = def.origin();
        out.listing
            .set_data(at, Some(def.value), &origin)
            .map_err(werr)
            .map(drop)
    })?;
    each("funcs", rows.funcs, |f| Ok(out.funcs.insert(f)?))?;
    each("jumptables", rows.jumptables, |(id, table)| {
        let origin = table.origin();
        out.jumptables
            .set(id, Some(table.value), &origin)
            .map_err(werr)
            .map(drop)
    })?;
    each("overrides", rows.overrides, |(at, flow)| {
        let origin = flow.origin();
        out.overrides
            .set(at, Some(flow.value), &origin)
            .map_err(werr)
            .map(drop)
    })?;
    out.refs
        .extend_new(rows.refs)
        .map_err(|(i, e)| werr(e).at_index(i).at("refs"))?;
    for (at, info) in rows.strings {
        out.strings.insert(at, info);
    }
    each("symbols", rows.symbols, |s| {
        Ok(out.symbols.put_exact(s).map(drop)?)
    })?;
    out.listing
        .extend_units(rows.units)
        .map_err(|(i, e)| CodecError::from(e).at_index(i).at("units"))?;
    each("vars", rows.vars, |(var, facts)| {
        if let Some(n) = facts.name {
            let origin = n.origin();
            out.vars
                .set_name(&var, Some(n.value), &origin)
                .map_err(werr)?;
        }
        if let Some(ty) = facts.ty {
            let origin = ty.origin();
            out.vars
                .set_type(&var, Some(ty.value), &origin)
                .map_err(werr)?;
        }
        Ok(())
    })?;
    out.why.extend_rows(rows.why)?;
    Ok(out)
}

/// Puts each row of `rows` in the shard of its key. Each shard keeps the row order.
pub(super) fn split(rows: SetRows) -> BTreeMap<ShardId, SetRows> {
    let mut out: BTreeMap<ShardId, SetRows> = BTreeMap::new();
    for row in rows.comments {
        out.entry(ShardId::of(row.0))
            .or_default()
            .comments
            .push(row);
    }
    for row in rows.data {
        out.entry(ShardId::of_off(row.0))
            .or_default()
            .data
            .push(row);
    }
    for f in rows.funcs {
        out.entry(ShardId::of(f.id().0)).or_default().funcs.push(f);
    }
    for row in rows.jumptables {
        let id = ShardId::of(row.0.0);
        out.entry(id).or_default().jumptables.push(row);
    }
    for row in rows.overrides {
        out.entry(ShardId::of(row.0))
            .or_default()
            .overrides
            .push(row);
    }
    for r in rows.refs {
        let id = ShardId::of(r.value.key.from);
        out.entry(id).or_default().refs.push(r);
    }
    for row in rows.strings {
        out.entry(ShardId::of_off(row.0))
            .or_default()
            .strings
            .push(row);
    }
    for s in rows.symbols {
        out.entry(ShardId::of(s.addr)).or_default().symbols.push(s);
    }
    for row in rows.units {
        out.entry(ShardId::of_off(row.0))
            .or_default()
            .units
            .push(row);
    }
    for row in rows.vars {
        let id = ShardId::of(row.0.func.0);
        out.entry(id).or_default().vars.push(row);
    }
    for (id, why) in rows.why.split() {
        out.entry(id).or_default().why = why;
    }
    out
}

/// Makes an analysis set from `rows`. Each shard gets the rows of its keys. A shard of
/// `old` with the same facts goes into the new set as it is, so the two sets share it.
///
/// # Errors
///
/// Returns a [`CodecError`] with the path of the first row that breaks a table rule. The
/// index of the path counts the rows of one shard.
pub(super) fn set_from_rows(rows: SetRows, old: &AnalysisSet) -> Result<AnalysisSet, CodecError> {
    let mut out = AnalysisSet::new();
    for (id, part) in split(rows) {
        let tables = from_rows(part)?;
        match old.shard_arc(id) {
            Some(o) if ***o == tables => out.keep(id, Arc::clone(o)),
            _ => out.put(id, tables),
        }
    }
    Ok(out)
}

/// Gives the typed rows of the tables `t`, each table in key order.
///
/// # Errors
///
/// Returns [`crate::fact::Invalid::TooMany`] for a why-record above the premise limit. A
/// record in a store passed this check, so the error does not occur.
pub(super) fn rows_of(t: &Tables) -> Result<SetRows, CodecError> {
    let all = ghidorah_base::Range {
        first: 0,
        last: u64::MAX,
    };
    Ok(SetRows {
        comments: t
            .comments
            .iter()
            .map(|(a, k, f)| (a, k, f.clone()))
            .collect(),
        data: t
            .listing
            .data_defs()
            .map(|(at, d)| (at, d.clone()))
            .collect(),
        funcs: t.funcs.iter().cloned().collect(),
        jumptables: t.jumptables.iter().map(|(id, j)| (id, j.clone())).collect(),
        overrides: t.overrides.iter().map(|(at, f)| (at, f.clone())).collect(),
        refs: t.refs.iter().cloned().collect(),
        strings: t.strings.iter().map(|(at, s)| (at, *s)).collect(),
        symbols: t.symbols.iter().cloned().collect(),
        units: t.listing.units_in(all).map(|(at, u)| (at, *u)).collect(),
        vars: t.vars.iter().map(|(v, f)| (v.clone(), f.clone())).collect(),
        why: WhyRows::from_rows(t.why.iter())?,
    })
}
