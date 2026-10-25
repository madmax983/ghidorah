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
//! | `why` | `{"key","rule","premises"}` |
//!
//! A reader also takes the `order` of a why row and the `why_next` member of format version 2
//! and before. It ignores both values (ADR-0031).

use std::collections::BTreeSet;

use ghidorah_base::{Range, Rev};
use ghidorah_json::{JcsError, Value, write_jcs};

use super::edit::{var_from_row, var_row};
use super::rows::{SetRows, from_rows, set_from_rows};
use super::values::{Json, Off, obj};
use super::{CodecError, Obj};
use crate::listing::CodeUnit;
use crate::notes::{Note, Notes};
use crate::program::{AnalysisSet, Program, Tables};
use crate::progress::{FuncProgress, Mark, Progress};
use crate::symbols::Symbol;
use crate::why::{RuleCode, Why, WhyRows};

/// The list members of the tables of a layer, in JCS order.
const LIST: [&str; 11] = [
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
];

/// The member names that a reader takes. A writer leaves out `why_next`.
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
    let why = t.why.iter().map(|(key, why)| {
        obj([
            ("key", key.enc()),
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

/// The rows of each list member of a layer, in member order.
type Members<'a> = [(&'static str, Rows<'a>); 11];

/// Gives the rows of each list member of the set `set`. Each member gives the rows of each
/// shard in address order.
fn set_member_rows(set: &AnalysisSet) -> Members<'_> {
    let mut parts: Vec<std::array::IntoIter<(&'static str, Rows<'_>), 11>> = set
        .shards()
        .map(|(_, t)| member_rows(t).into_iter())
        .collect();
    LIST.map(|name| {
        let rows: Vec<Rows<'_>> = parts
            .iter_mut()
            .filter_map(|p| p.next().map(|(_, r)| r))
            .collect();
        let chained: Rows<'_> = Box::new(rows.into_iter().flatten());
        (name, chained)
    })
}

/// Gives the JSON form of the members `members`.
fn encode_members(members: Members<'_>) -> Value {
    Value::object(
        members
            .into_iter()
            .map(|(name, rows)| (name, Value::Array(rows.collect()))),
    )
}

/// Writes the JCS text of the members `members` to `sink` in pieces, one row at a time.
fn write_members(members: Members<'_>, sink: &mut dyn FnMut(&str)) -> Result<(), JcsError> {
    sink("{");
    for (i, (name, rows)) in members.into_iter().enumerate() {
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
    sink("}");
    Ok(())
}

/// Gives the JSON form of the tables of a layer.
pub(super) fn encode(t: &Tables) -> Value {
    encode_members(member_rows(t))
}

/// Gives the JSON form of an analysis set: the form of one layer with the rows of each
/// shard in address order.
pub(super) fn encode_set(set: &AnalysisSet) -> Value {
    encode_members(set_member_rows(set))
}

/// Writes the JCS text of [`encode`] to `sink` in pieces, one row at a time. The pieces join
/// to the same bytes as `write_jcs(&encode(t))`, but no JSON value of the whole layer exists.
///
/// # Errors
///
/// Returns the [`JcsError`] of a row that has no JCS form.
pub(super) fn write_jcs_to(t: &Tables, sink: &mut dyn FnMut(&str)) -> Result<(), JcsError> {
    write_members(member_rows(t), sink)
}

/// Writes the JCS text of [`encode_set`] to `sink` in pieces, one row at a time.
///
/// # Errors
///
/// Returns the [`JcsError`] of a row that has no JCS form.
pub(super) fn write_set_jcs_to(
    set: &AnalysisSet,
    sink: &mut dyn FnMut(&str),
) -> Result<(), JcsError> {
    write_members(set_member_rows(set), sink)
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
    from_rows(parse(value)?)
}

/// Reads an analysis set. Each row goes in the shard of its key.
pub(super) fn decode_set(value: &Value) -> Result<AnalysisSet, CodecError> {
    set_from_rows(parse(value)?, &AnalysisSet::new())
}

/// Reads the typed rows of a layer.
fn parse(value: &Value) -> Result<SetRows, CodecError> {
    let form = Obj::new(value, &NAMES)?;
    let mut out = SetRows {
        comments: form.each("comments", |row| {
            let cells = Obj::new(row, &["addr", "kind", "text"])?;
            Ok((cells.get("addr")?, cells.get("kind")?, cells.get("text")?))
        })?,
        data: form.each("data", |row| {
            let cells = Obj::new(row, &["at", "def"])?;
            Ok((cells.get::<Off>("at")?.0, cells.get("def")?))
        })?,
        funcs: form.each("funcs", Json::dec)?,
        jumptables: form.each("jumptables", |row| {
            let cells = Obj::new(row, &["at", "table"])?;
            Ok((cells.get("at")?, cells.get("table")?))
        })?,
        overrides: form.each("overrides", |row| {
            let cells = Obj::new(row, &["at", "flow"])?;
            Ok((cells.get("at")?, cells.get("flow")?))
        })?,
        refs: form.each("refs", Json::dec)?,
        ..SetRows::default()
    };
    records(form, &mut out)?;
    Ok(out)
}

/// Reads the string, symbol, unit, variable and why rows of a layer.
fn records(form: Obj<'_>, out: &mut SetRows) -> Result<(), CodecError> {
    out.strings = form.each("strings", |row| {
        let cells = Obj::new(row, &["at", "info"])?;
        Ok((cells.get::<Off>("at")?.0, cells.get("info")?))
    })?;
    out.symbols = form.each("symbols", |row| {
        let cells = Obj::new(row, &["addr", "key", "kind", "primary", "name"])?;
        Ok(Symbol {
            addr: cells.get("addr")?,
            key: cells.get("key")?,
            name: cells.get("name")?,
            kind: cells.get("kind")?,
            primary: cells.get("primary")?,
        })
    })?;
    out.units = form.each("units", |row| {
        let cells = Obj::new(row, &["at", "len", "flow", "flags"])?;
        let unit = CodeUnit::Insn {
            len: cells.get("len")?,
            flow: cells.get("flow")?,
            flags: cells.get("flags")?,
        };
        Ok((cells.get::<Off>("at")?.0, unit))
    })?;
    out.vars = form.each("vars", var_from_row)?;
    let mut whys = WhyRows::new();
    let mut codes: BTreeSet<RuleCode> = BTreeSet::new();
    form.each("why", |row| {
        let cells = Obj::new(row, &["key", "order", "rule", "premises"])?;
        let rule: RuleCode = cells.get("rule")?;
        let rule = if let Some(shared) = codes.get(&rule) {
            shared.clone()
        } else {
            codes.insert(rule.clone());
            rule
        };
        let why = Why {
            rule,
            premises: cells.get("premises")?,
        };
        whys.push(cells.get("key")?, why)?;
        Ok(())
    })?;
    out.why = whys;
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
        ("analysis", encode_set(p.analysis())),
        ("base", encode(p.base())),
        ("binary", Value::from(sha)),
        ("notes", notes),
        ("types", super::types_to_json(p.types())),
    ])
}
