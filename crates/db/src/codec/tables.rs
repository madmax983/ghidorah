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

use ghidorah_base::{Range, Rev};
use ghidorah_json::Value;

use super::edit::{var_from_row, var_row};
use super::values::{Json, Off, obj};
use super::{CodecError, Obj};
use crate::fact::{Fact, WriteError};
use crate::listing::CodeUnit;
use crate::notes::{Note, Notes};
use crate::program::{Program, Tables};
use crate::progress::{FuncProgress, Mark, Progress};
use crate::symbols::Symbol;
use crate::why::Why;

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

/// Gives an array of rows with the two members `names`.
fn pairs(names: [&str; 2], rows: impl Iterator<Item = (Value, Value)>) -> Value {
    let [a, b] = names;
    Value::Array(rows.map(|(x, y)| obj([(a, x), (b, y)])).collect())
}

/// Gives the array of the JSON forms of `items`.
fn list<'a, T: Json + 'a>(items: impl Iterator<Item = &'a T>) -> Value {
    Value::Array(items.map(Json::enc).collect())
}

/// Gives the JSON form of the tables of a layer. `counters` adds `why_next`.
pub(super) fn encode(t: &Tables, counters: bool) -> Value {
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
    let data = t
        .listing
        .data_defs()
        .map(|(at, d)| (Off(at).enc(), d.enc()));
    let tables = t.jumptables.iter().map(|(at, j)| (at.enc(), j.enc()));
    let flows = t.overrides.iter().map(|(at, f)| (at.enc(), f.enc()));
    let strings = t.strings.iter().map(|(at, s)| (Off(at).enc(), s.enc()));
    let mut members = vec![
        ("comments", Value::Array(comments.collect())),
        ("data", pairs(["at", "def"], data)),
        ("funcs", list(t.funcs.iter())),
        ("jumptables", pairs(["at", "table"], tables)),
        ("overrides", pairs(["at", "flow"], flows)),
        ("refs", list(t.refs.iter())),
        ("strings", pairs(["at", "info"], strings)),
        (
            "symbols",
            Value::Array(t.symbols.iter().map(symbol_row).collect()),
        ),
        ("units", Value::Array(units.collect())),
        (
            "vars",
            Value::Array(t.vars.iter().map(|(v, f)| var_row(v, f)).collect()),
        ),
        ("why", Value::Array(why.collect())),
    ];
    if counters {
        members.push(("why_next", t.why.next_order().enc()));
    }
    Value::object(members)
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
        let fact: Fact<String> = cells.get("text")?;
        let origin = fact.origin();
        out.comments
            .set(
                cells.get("addr")?,
                cells.get("kind")?,
                Some(fact.value),
                &origin,
            )
            .map_err(werr)
            .map(drop)
    })?;
    form.each("data", |row| {
        let cells = Obj::new(row, &["at", "def"])?;
        let fact: Fact<_> = cells.get("def")?;
        let origin = fact.origin();
        out.listing
            .set_data(cells.get::<Off>("at")?.0, Some(fact.value), &origin)
            .map_err(werr)
            .map(drop)
    })?;
    form.each("funcs", |row| Ok(out.funcs.insert(Json::dec(row)?)?))?;
    form.each("jumptables", |row| {
        let cells = Obj::new(row, &["at", "table"])?;
        let fact: Fact<_> = cells.get("table")?;
        let origin = fact.origin();
        out.jumptables
            .set(cells.get("at")?, Some(fact.value), &origin)
            .map_err(werr)
            .map(drop)
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
    form.each("refs", |row| {
        let fact: Fact<crate::refs::Ref> = Json::dec(row)?;
        let origin = fact.origin();
        out.refs.add(fact.value, &origin).map_err(werr).map(drop)
    })?;
    records(form, &mut out)?;
    Ok(out)
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
