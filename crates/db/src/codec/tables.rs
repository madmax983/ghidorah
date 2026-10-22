//! The JSON forms of the tables of a layer, the note store, the progress rows and the fact dump.
//!
//! | Member | Row |
//! |---|---|
//! | `comments` | `{"addr","kind","text"}` |
//! | `data` | `{"at","def"}` |
//! | `funcs` | a function record |
//! | `jumptables` | `{"at","table"}` |
//! | `overrides` | `{"at","flow"}` |
//! | `refs` | a reference fact |
//! | `strings` | `{"at","info"}` |
//! | `symbols` | `{"addr","key","kind","primary","name"}` |
//! | `units` | `{"at","len","flow","flags"}` |
//! | `vars` | `{"var","name","ty"}` |
//! | `why` | `{"key","order","rule","premises"}` |
//! | `why_next` | the creation order of the next why-record. The fact dump leaves it out. |

use ghidorah_base::{Address, JumpTableId, Range, Rev};
use ghidorah_json::{JcsError, Value, write_jcs};

use super::edit::{var_from_row, var_row};
use super::values::{Json, Off, obj};
use super::{CodecError, Obj};
use crate::comments::CommentKind;
use crate::fact::{Fact, WriteError};
use crate::funcs::Function;
use crate::jumptables::JumpTable;
use crate::listing::{CodeUnit, DataDef};
use crate::notes::{Note, Notes};
use crate::program::{Program, Tables};
use crate::progress::{FuncProgress, Mark, Progress};
use crate::refs::Ref;
use crate::strings::StrInfo;
use crate::symbols::Symbol;
use crate::why::{FactKey, Why};

/// The member names of the tables of a layer.
const NAMES: [&str; 12] = [
    "comments",
    "data",
    "funcs",
    "jumptables",
    "overrides",
    "refs",
    "strings",
    "symbols",
    "units",
    "vars",
    "why",
    "why_next",
];

/// All RAM offsets.
const ALL: Range = Range {
    first: 0,
    last: u64::MAX,
};

/// Gives the codec error of a manager write.
fn werr<T>(e: WriteError<T>) -> CodecError {
    match e {
        WriteError::Invalid(i) => i.into(),
        WriteError::Blocked(_) => CodecError::text("unique key"),
    }
}

/// The rows of one list member of the JSON form of a layer.
type Rows<'a> = Box<dyn Iterator<Item = Value> + 'a>;

/// Gives the rows of each list member of the JSON form of `t`, in member order. The order is
/// also the JCS order of the member names.
fn member_rows(t: &Tables) -> [(&'static str, Rows<'_>); 11] {
    let comments = t.comments.iter().map(|(addr, kind, text)| {
        obj([
            ("addr", addr.enc()),
            ("kind", kind.enc()),
            ("text", text.enc()),
        ])
    });
    let units = t.listing.units_in(ALL).map(|(at, unit)| {
        let CodeUnit::Insn { len, flow, flags } = unit;
        obj([
            ("at", Off(at).enc()),
            ("len", len.enc()),
            ("flow", flow.enc()),
            ("flags", flags.enc()),
        ])
    });
    let why = t.why.iter().map(|(key, order, why)| {
        obj([
            ("key", key.enc()),
            ("order", order.enc()),
            ("rule", why.rule.enc()),
            ("premises", why.premises.enc()),
        ])
    });
    let pair = |[a, b]: [&'static str; 2]| move |(x, y): (Value, Value)| obj([(a, x), (b, y)]);
    let data = t
        .listing
        .data_defs()
        .map(|(at, d)| (Off(at).enc(), d.enc()))
        .map(pair(["at", "def"]));
    let tables = t
        .jumptables
        .iter()
        .map(|(at, j)| (at.enc(), j.enc()))
        .map(pair(["at", "table"]));
    let flows = t
        .overrides
        .iter()
        .map(|(at, f)| (at.enc(), f.enc()))
        .map(pair(["at", "flow"]));
    let strings = t
        .strings
        .iter()
        .map(|(at, s)| (Off(at).enc(), s.enc()))
        .map(pair(["at", "info"]));
    [
        ("comments", Box::new(comments)),
        ("data", Box::new(data)),
        ("funcs", Box::new(t.funcs.iter().map(Json::enc))),
        ("jumptables", Box::new(tables)),
        ("overrides", Box::new(flows)),
        ("refs", Box::new(t.refs.iter().map(Json::enc))),
        ("strings", Box::new(strings)),
        ("symbols", Box::new(t.symbols.iter().map(symbol_row))),
        ("units", Box::new(units)),
        ("vars", Box::new(t.vars.iter().map(|(v, f)| var_row(v, f)))),
        ("why", Box::new(why)),
    ]
}

/// Gives the JSON form of the tables of a layer. `counters` adds `why_next`.
pub(super) fn encode(t: &Tables, counters: bool) -> Value {
    let mut members: Vec<(&str, Value)> = member_rows(t)
        .into_iter()
        .map(|(name, rows)| (name, Value::Array(rows.collect())))
        .collect();
    if counters {
        members.push(("why_next", t.why.next_order().enc()));
    }
    Value::object(members)
}

/// Writes the JCS text of [`encode`] to `sink` in pieces, one row at a time. The pieces join
/// to the same bytes as `write_jcs(&encode(t, counters))`, but no JSON value of the whole
/// layer exists.
///
/// # Errors
///
/// Returns the [`JcsError`] of a row that has no JCS form.
pub(super) fn write_jcs_to(
    t: &Tables,
    counters: bool,
    sink: &mut dyn FnMut(&str),
) -> Result<(), JcsError> {
    sink("{");
    for (i, (name, rows)) in member_rows(t).into_iter().enumerate() {
        if i > 0 {
            sink(",");
        }
        sink(&format!("\"{name}\":["));
        for (j, row) in rows.enumerate() {
            if j > 0 {
                sink(",");
            }
            sink(&write_jcs(&row)?);
        }
        sink("]");
    }
    if counters {
        sink(",\"why_next\":");
        sink(&write_jcs(&t.why.next_order().enc())?);
    }
    sink("}");
    Ok(())
}

fn symbol_row(s: &Symbol) -> Value {
    obj([
        ("addr", s.addr.enc()),
        ("key", s.key.enc()),
        ("kind", s.kind.enc()),
        ("primary", s.primary.enc()),
        ("name", s.name.enc()),
    ])
}

/// Reads the tables of a layer. Each row goes through the write path of its manager.
pub(super) fn decode(value: &Value) -> Result<Tables, CodecError> {
    let form = Obj::new(value, &NAMES)?;
    let mut out = Tables::default();
    form.each("comments", |row| {
        let cells = Obj::new(row, &["addr", "kind", "text"])?;
        put_comment(
            &mut out,
            cells.get("addr")?,
            cells.get("kind")?,
            cells.get("text")?,
        )
    })?;
    form.each("data", |row| {
        let cells = Obj::new(row, &["at", "def"])?;
        put_data(&mut out, cells.get::<Off>("at")?.0, &cells.get("def")?)
    })?;
    form.each("funcs", |row| Ok(out.funcs.insert(Json::dec(row)?)?))?;
    form.each("jumptables", |row| {
        let cells = Obj::new(row, &["at", "table"])?;
        put_jumptable(&mut out, cells.get("at")?, cells.get("table")?)
    })?;
    form.each("overrides", |row| {
        let cells = Obj::new(row, &["at", "flow"])?;
        let fact: Fact<_> = cells.get("flow")?;
        let origin = fact.origin();
        out.overrides
            .set(cells.get("at")?, Some(fact.value), &origin)
            .map_err(werr)
            .map(drop)
    })?;
    form.each("refs", |row| put_ref(&mut out, &Json::dec(row)?))?;
    records(form, &mut out)?;
    Ok(out)
}

/// The typed rows of an analysis set: the rows of [`crate::codec::tables_from_json`] with no
/// JSON form. A layer of the analysis has no flow overrides and no variables.
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
    /// The references.
    pub refs: Vec<Fact<Ref>>,
    /// The strings by RAM offset.
    pub strings: Vec<(u64, StrInfo)>,
    /// The symbols.
    pub symbols: Vec<Symbol>,
    /// The code units by RAM offset.
    pub units: Vec<(u64, CodeUnit)>,
    /// The why-records: key, creation order and record.
    pub why: Vec<(FactKey, u64, Why)>,
    /// The creation order of the next why-record.
    pub why_next: u64,
}

/// Makes the tables of an analysis set from `rows`. Each row goes through the write path
/// of its manager in the order of [`decode`], so both paths keep the same rules.
pub(super) fn from_rows(rows: SetRows) -> Result<Tables, CodecError> {
    let mut out = Tables::default();
    for (addr, kind, text) in rows.comments {
        put_comment(&mut out, addr, kind, text)?;
    }
    for (at, def) in &rows.data {
        put_data(&mut out, *at, def)?;
    }
    for func in rows.funcs {
        out.funcs.insert(func)?;
    }
    for (id, table) in rows.jumptables {
        put_jumptable(&mut out, id, table)?;
    }
    for fact in &rows.refs {
        put_ref(&mut out, fact)?;
    }
    for (at, info) in rows.strings {
        out.strings.insert(at, info);
    }
    for symbol in rows.symbols {
        out.symbols.put_exact(symbol)?;
    }
    for (at, unit) in rows.units {
        out.listing.insert_unit(at, unit)?;
    }
    for (key, order, why) in rows.why {
        out.why.insert_at(key, order, why)?;
    }
    out.why.set_next(rows.why_next);
    Ok(out)
}

/// Writes one comment row.
fn put_comment(
    out: &mut Tables,
    addr: Address,
    kind: CommentKind,
    text: Fact<String>,
) -> Result<(), CodecError> {
    let origin = text.origin();
    out.comments
        .set(addr, kind, Some(text.value), &origin)
        .map_err(werr)
        .map(drop)
}

/// Writes one data definition row.
fn put_data(out: &mut Tables, at: u64, def: &Fact<DataDef>) -> Result<(), CodecError> {
    let origin = def.origin();
    out.listing
        .set_data(at, Some(def.value), &origin)
        .map_err(werr)
        .map(drop)
}

/// Writes one jump table row.
fn put_jumptable(
    out: &mut Tables,
    id: JumpTableId,
    table: Fact<JumpTable>,
) -> Result<(), CodecError> {
    let origin = table.origin();
    out.jumptables
        .set(id, Some(table.value), &origin)
        .map_err(werr)
        .map(drop)
}

/// Writes one reference row.
fn put_ref(out: &mut Tables, fact: &Fact<Ref>) -> Result<(), CodecError> {
    let origin = fact.origin();
    out.refs.add(fact.value, &origin).map_err(werr).map(drop)
}

/// Reads the string, symbol, unit, variable and why rows of a layer.
fn records(form: Obj<'_>, out: &mut Tables) -> Result<(), CodecError> {
    form.each("strings", |row| {
        let cells = Obj::new(row, &["at", "info"])?;
        out.strings
            .insert(cells.get::<Off>("at")?.0, cells.get("info")?);
        Ok(())
    })?;
    form.each("symbols", |row| {
        let cells = Obj::new(row, &["addr", "key", "kind", "primary", "name"])?;
        let symbol = Symbol {
            addr: cells.get("addr")?,
            key: cells.get("key")?,
            name: cells.get("name")?,
            kind: cells.get("kind")?,
            primary: cells.get("primary")?,
        };
        Ok(out.symbols.put_exact(symbol).map(drop)?)
    })?;
    form.each("units", |row| {
        let cells = Obj::new(row, &["at", "len", "flow", "flags"])?;
        let unit = CodeUnit::Insn {
            len: cells.get("len")?,
            flow: cells.get("flow")?,
            flags: cells.get("flags")?,
        };
        Ok(out.listing.insert_unit(cells.get::<Off>("at")?.0, unit)?)
    })?;
    form.each("vars", |row| {
        let (var, facts) = var_from_row(row)?;
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
    form.each("why", |row| {
        let cells = Obj::new(row, &["key", "order", "rule", "premises"])?;
        let why = Why {
            rule: cells.get("rule")?,
            premises: cells.get("premises")?,
        };
        Ok(out
            .why
            .insert_at(cells.get("key")?, cells.get("order")?, why)
            .map(drop)?)
    })?;
    out.why.set_next(form.get("why_next")?);
    Ok(())
}

/// Gives the JSON form of the note store.
pub(super) fn encode_notes(notes: &Notes) -> Value {
    obj([
        ("next", notes.next_raw().enc()),
        ("notes", Value::Array(notes.iter().map(Json::enc).collect())),
    ])
}

/// Reads a note store. Each note goes through the note rules.
pub(super) fn decode_notes(v: &Value) -> Result<Notes, CodecError> {
    let o = Obj::new(v, &["next", "notes"])?;
    let mut notes = Notes::default();
    o.each("notes", |row| Ok(notes.write(Note::dec(row)?).map(drop)?))?;
    notes.set_next(o.get("next")?);
    Ok(notes)
}

/// Gives the JSON form of the progress rows and the marks.
pub(super) fn encode_progress(p: &Progress) -> Value {
    let funcs = p.iter().map(|(func, row)| {
        obj([
            ("func", func.enc()),
            ("visited", row.visited.enc()),
            ("named", row.named.enc()),
            ("typed", row.typed.enc()),
            ("commented", row.commented.enc()),
        ])
    });
    let marks = p.marks().map(|(session, mark)| {
        obj([
            ("session", session.enc()),
            ("last_brief_rev", mark.last_brief_rev.enc()),
        ])
    });
    obj([
        ("funcs", Value::Array(funcs.collect())),
        ("marks", Value::Array(marks.collect())),
    ])
}

/// Reads progress rows and marks.
pub(super) fn decode_progress(v: &Value) -> Result<Progress, CodecError> {
    let o = Obj::new(v, &["funcs", "marks"])?;
    let mut p = Progress::default();
    o.each("funcs", |row| {
        let r = Obj::new(row, &["func", "visited", "named", "typed", "commented"])?;
        let progress = FuncProgress {
            visited: r.get("visited")?,
            named: r.get("named")?,
            typed: r.get("typed")?,
            commented: r.get("commented")?,
        };
        p.set(r.get("func")?, progress);
        Ok(())
    })?;
    o.each("marks", |row| {
        let r = Obj::new(row, &["session", "last_brief_rev"])?;
        let rev: Rev = r.get("last_brief_rev")?;
        p.set_mark(
            r.get("session")?,
            Mark {
                last_brief_rev: rev,
            },
        );
        Ok(())
    })?;
    Ok(p)
}

/// Gives the fact dump of a program.
pub(super) fn facts(p: &Program) -> Value {
    let sha = ghidorah_base::hex::encode(&p.meta().sha256);
    let notes = Value::Array(p.notes().iter().map(Json::enc).collect());
    obj([
        ("analysis", encode(p.analysis(), false)),
        ("base", encode(p.base(), false)),
        ("binary", Value::from(sha)),
        ("notes", notes),
        ("types", super::types_to_json(p.types())),
    ])
}
