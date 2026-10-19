//! The item lists of each `search` kind and the records of `ids`.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{
    Address, Caps, ErrorCode, Fuel, FuncId, Id, JumpTableId, Limits, NoteId, WarningCode,
};
use ghidorah_db::{CommentKind, Encoding, Note, Program, SetMembers};
use ghidorah_json::{Object, Value};

use super::filter::{Items, Matcher, New};
use super::{STRING_FUNCS, WHY_STRING_REFS};
use crate::dispatch::Item;
use crate::envelope::Warning;
use crate::errors::ToolError;
use crate::handlers::func_sections::{self as fs, Namer};

/// The largest number of byte pattern hits of one call.
pub const MAX_HITS: usize = 10_000;

/// The largest number of bytes of one region that a byte search reads.
pub const MAX_SCAN: u64 = 64 << 20;

/// Adds the functions, imports, exports and symbols whose name matches. Each name costs one
/// work unit.
pub fn names(items: &mut Items<'_>, m: &Matcher, namer: &Namer, fuel: &mut Fuel) {
    let p = items.program;
    let mut taken: BTreeSet<(Address, String)> = BTreeSet::new();
    for f in p.funcs() {
        if fuel.tick().is_err() {
            items.cut = true;
            return;
        }
        let id = f.id();
        let Some(name) = p.name(id.0) else {
            continue;
        };
        if m.matches(&name.text) {
            let mut new = New::item("function", id.to_string());
            new.addr = Some(id.0);
            new.text = Some(Value::from(namer.text(&name.text)));
            new.func = Some(id);
            taken.insert((id.0, name.text.clone()));
            items.push(new, None);
        }
    }
    for row in p.imports().values() {
        let name = row.id.name().unwrap_or_default();
        if fuel.tick().is_err() {
            items.cut = true;
            return;
        }
        if m.matches(name) {
            let mut new = New::item("import", row.id.to_string());
            new.addr = Some(row.stub.or(row.slot).unwrap_or(row.ext));
            new.text = Some(Value::from(namer.text(name)));
            items.push(new, None);
        }
    }
    for row in p.exports().values() {
        let name = row.id.name().unwrap_or_default();
        if fuel.tick().is_err() {
            items.cut = true;
            return;
        }
        if m.matches(name) {
            let mut new = New::item("export", row.id.to_string());
            new.addr = row.addr;
            new.text = Some(Value::from(namer.text(name)));
            items.push(new, None);
        }
    }
    let mut seen: BTreeSet<(Address, String)> = BTreeSet::new();
    for layer in [p.base(), p.analysis()] {
        for (name, addrs) in layer.symbols().names() {
            for a in addrs {
                if fuel.tick().is_err() {
                    items.cut = true;
                    return;
                }
                let pair = (*a, name.to_owned());
                if !m.matches(name) || taken.contains(&pair) || !seen.insert(pair) {
                    continue;
                }
                let mut new = New::item("symbol", format!("sym:{}", namer.text(name)));
                new.addr = Some(*a);
                new.text = Some(Value::from(namer.text(name)));
                new.func = p.owner_of(*a);
                items.push(new, None);
            }
        }
    }
}

/// Gives the addresses of every string of both layers.
fn string_addrs(p: &Program) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for layer in [p.base(), p.analysis()] {
        out.extend(layer.strings().iter().map(|(at, _)| at));
    }
    out
}

/// Gives the characters of the string bytes `raw`, so a query matches the decoded text.
fn decoded(raw: &[u8], encoding: Encoding) -> String {
    if encoding != Encoding::Utf16Le {
        return String::from_utf8_lossy(raw).into_owned();
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| match c {
            [lo, hi] => u16::from_le_bytes([*lo, *hi]),
            _ => 0,
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// Adds the strings whose text matches. Only referenced strings count, unless `all`.
pub fn strings(items: &mut Items<'_>, m: &Matcher, all: bool, caps: Caps) {
    let p = items.program;
    for at in string_addrs(p) {
        let Some(info) = p.string(at) else {
            continue;
        };
        let addr = Address::ram(at);
        let refs = p.refs_to(addr);
        if !all && refs.is_empty() && !info.referenced {
            continue;
        }
        let raw = ghidorah_analysis::analyzers::strings::bytes(p, at, info).unwrap_or_default();
        if !m.matches(&decoded(&raw, info.encoding)) {
            continue;
        }
        let Some(text) = fs::string_text(p, at, caps) else {
            continue;
        };
        let funcs: BTreeSet<FuncId> = refs
            .iter()
            .filter_map(|r| p.owner_of(r.value.key.from))
            .collect();
        let id = ghidorah_base::StringId(addr).to_string();
        let mut new = New::item("string", id.clone());
        new.addr = Some(addr);
        new.text = Some(text);
        new.func = funcs.iter().next().copied();
        new.extra.push("ref_count", Value::from(refs.len()));
        let shown = funcs
            .iter()
            .take(STRING_FUNCS)
            .map(|f| Value::from(f.to_string()));
        new.extra.push("funcs", Value::Array(shown.collect()));
        let next = Value::object([
            ("tool", Value::from("xref_list")),
            (
                "args",
                Value::object([("targets", Value::Array(vec![Value::from(id)]))]),
            ),
            ("why", Value::from(WHY_STRING_REFS)),
        ]);
        items.push(new, Some(next));
    }
}

/// Parses a byte pattern: hex bytes, `??` for any byte and `?` for one nibble.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for an empty pattern or a token that is not a byte.
pub fn pattern(text: &str) -> Result<Vec<(u8, u8)>, ToolError> {
    let bad = || {
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", "pattern")
            .path("/pattern")
            .detail("expected", Value::from("hex bytes such as 48 8b ?? 4?"))
    };
    let nibble = |c: char| -> Option<(u8, u8)> {
        if c == '?' {
            return Some((0, 0));
        }
        c.to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
            .map(|d| (d, 0xf))
    };
    let mut out = Vec::new();
    for token in text.split_ascii_whitespace() {
        let mut chars = token.chars();
        let (Some(hi), Some(lo), None) = (chars.next(), chars.next(), chars.next()) else {
            return Err(bad());
        };
        let ((hv, hm), (lv, lm)) = nibble(hi).zip(nibble(lo)).ok_or_else(bad)?;
        out.push(((hv << 4) | lv, (hm << 4) | lm));
    }
    if out.is_empty() {
        return Err(bad());
    }
    Ok(out)
}

/// Adds the starts of the byte pattern in mapped memory. Each scanned byte costs one work
/// unit.
pub fn bytes(items: &mut Items<'_>, pat: &[(u8, u8)], fuel: &mut Fuel) {
    let p = items.program;
    let mut hits = 0usize;
    for region in p.mem().regions() {
        let size = u64::try_from(region.va.len())
            .unwrap_or(u64::MAX)
            .min(MAX_SCAN);
        let Ok(data) = p.mem().read(region.va.first, size, &Limits::DEFAULT) else {
            continue;
        };
        for (i, window) in data.windows(pat.len()).enumerate() {
            if fuel.tick().is_err() || hits >= MAX_HITS {
                items.cut = true;
                return;
            }
            let hit = window.iter().zip(pat).all(|(b, (v, mask))| b & mask == *v);
            if !hit {
                continue;
            }
            let at = region
                .va
                .first
                .saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
            let addr = Address::ram(at);
            let mut new = New::item("bytes", addr.to_string());
            new.addr = Some(addr);
            new.func = p.owner_of(addr);
            new.extra
                .push("region", Value::from(fs::safe(&region.name)));
            items.push(new, None);
            hits = hits.saturating_add(1);
        }
    }
}

/// Adds the comments whose text matches.
pub fn comments(items: &mut Items<'_>, m: &Matcher) {
    let p = items.program;
    let mut keys: BTreeSet<(Address, CommentKind)> = BTreeSet::new();
    for layer in [p.base(), p.analysis()] {
        keys.extend(layer.comments().iter().map(|(a, k, _)| (a, k)));
    }
    for (addr, kind) in keys {
        let Some(fact) = p.comment(addr, kind) else {
            continue;
        };
        if !m.matches(&fact.value) {
            continue;
        }
        let mut new = New::item("comment", addr.to_string());
        new.addr = Some(addr);
        new.text = Some(Value::from(fact.value.as_str()));
        new.func = p.owner_of(addr);
        new.seq = u64::from(kind.code());
        new.extra.push("kind", Value::from(kind.name()));
        new.extra.push("source", Value::from(fact.source.name()));
        items.push(new, None);
    }
}

/// Gives the item of a note with its full record.
fn note_item(n: &Note) -> New {
    let mut new = New::item("note", n.id.to_string());
    new.addr = n.at;
    new.text = Some(Value::from(n.text.as_str()));
    new.func = n.func;
    new.extra.push("kind", Value::from(n.kind.name()));
    new.extra.push("status", Value::from(n.status.name()));
    let tags = n.tags.iter().map(|t| Value::from(t.as_str())).collect();
    new.extra.push("tags", Value::Array(tags));
    let evidence = n.evidence.iter().map(|e| Value::from(e.as_str())).collect();
    new.extra.push("evidence", Value::Array(evidence));
    let claims = n
        .claims
        .iter()
        .map(|c| {
            let args = c.args.iter().map(|a| Value::from(a.as_str())).collect();
            Value::object([
                ("rel", Value::from(c.rel.as_str())),
                ("args", Value::Array(args)),
            ])
        })
        .collect();
    new.extra.push("claims", Value::Array(claims));
    new.extra.push("src", Value::from(n.src.name()));
    new.extra.push("session", Value::from(n.session.as_str()));
    new.extra.push("rev", Value::from(n.rev.0));
    new
}

/// Adds the notes that pass `note_filter` and whose text matches.
pub fn notes(items: &mut Items<'_>, m: &Matcher, filter: Option<&Value>) {
    let want = |k: &str| filter.and_then(|f| f.get(k)).and_then(Value::as_str);
    let tags: Vec<&str> = filter
        .and_then(|f| f.get("tags"))
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let list: Vec<New> = items
        .program
        .notes()
        .iter()
        .filter(|n| want("kind").is_none_or(|k| n.kind.name() == k))
        .filter(|n| want("status").is_none_or(|s| n.status.name() == s))
        .filter(|n| tags.iter().all(|t| n.tags.iter().any(|x| x == t)))
        .filter(|n| m.matches(&n.text))
        .map(note_item)
        .collect();
    for new in list {
        items.push(new, None);
    }
}

/// Gives one `W_STALE_OP_ID` for the note items of `list` whose `op:` evidence has another
/// lifter version. `at` is the first such op ID. `details` holds its note, its lifter version,
/// the current version and the count of such op IDs.
#[must_use]
pub fn stale_ops(p: &Program, list: &[Item]) -> Option<Warning> {
    let current = ghidorah_analysis::fir::LIFT_VER;
    let mut first: Option<(NoteId, u32, String)> = None;
    let mut count = 0u64;
    for item in list {
        if item.value.get("kind").and_then(Value::as_str) != Some("note") {
            continue;
        }
        let id = item.value.get("id").and_then(Value::as_str).map(Id::parse);
        let Some(Ok(Id::Note(id))) = id else {
            continue;
        };
        let Some(note) = p.notes().get(id) else {
            continue;
        };
        let Some(ver) = note.lift_ver.filter(|v| *v != current) else {
            continue;
        };
        for e in &note.evidence {
            if matches!(Id::parse(e), Ok(Id::Op(_))) {
                count = count.saturating_add(1);
                first.get_or_insert_with(|| (id, ver, e.clone()));
            }
        }
    }
    let (note, ver, op) = first?;
    let mut warning = Warning::new(WarningCode::StaleOpId);
    warning.at = Some(op);
    let mut details = Object::new();
    details.push("note", Value::from(note.to_string()));
    details.push("lift_ver", Value::from(ver));
    details.push("current", Value::from(current));
    details.push("count", Value::from(count));
    warning.details = Some(details);
    Some(warning)
}

/// Adds the named types and typedefs whose name matches.
pub fn types(items: &mut Items<'_>, m: &Matcher) {
    let store = items.program.types().store();
    let mut names: BTreeMap<String, &'static str> = BTreeMap::new();
    for name in store.tag_names() {
        names.entry(name.to_owned()).or_insert("tag");
    }
    for name in store.typedef_names() {
        names.insert(name.to_owned(), "typedef");
    }
    for (name, kind) in names {
        if m.matches(&name) {
            let mut new = New::item("type", format!("t:{name}"));
            new.text = Some(Value::from(name.as_str()));
            new.extra.push("kind", Value::from(kind));
            items.push(new, None);
        }
    }
}

/// Adds the named sets whose name matches.
pub fn sets(items: &mut Items<'_>, m: &Matcher) {
    let p = items.program;
    for (name, note) in p.notes().sets() {
        if !m.matches(name.as_str()) {
            continue;
        }
        let mut new = New::item("set", format!("set:{}", name.as_str()));
        new.text = Some(Value::from(name.as_str()));
        new.extra.push("note", Value::from(note.to_string()));
        if let Some(set) = p.notes().get(note).and_then(|n| n.set.as_ref()) {
            new.extra.push(
                "members",
                Value::from(u64::try_from(set.members.count()).unwrap_or(u64::MAX)),
            );
        }
        items.push(new, None);
    }
}

/// Gives the item of a jump table with its full record.
fn table_item(p: &Program, id: JumpTableId) -> Option<New> {
    let record = fs::jump_table(p, id)?;
    let mut new = New::item("jumptable", id.to_string());
    new.addr = Some(id.0);
    new.func = p.owner_of(id.0);
    if let Value::Object(o) = record {
        new.extra = o;
    }
    Some(new)
}

/// Adds the jump tables.
pub fn jumptables(items: &mut Items<'_>) {
    let p = items.program;
    for id in fs::table_ids(p) {
        if let Some(new) = table_item(p, id) {
            items.push(new, None);
        }
    }
}

/// Gives `NOT_FOUND` for the ID `text` of kind `kind`.
fn missing(kind: &str, index: usize) -> ToolError {
    ToolError::new(ErrorCode::NotFound)
        .var("kind", kind)
        .path(&fs::item_path("ids", index))
        .detail("kind", Value::from(kind))
}

/// Adds the full records of `ids`. A set record comes before one item per member.
///
/// # Errors
///
/// Returns `NOT_FOUND` for an ID that names no record.
pub fn records(items: &mut Items<'_>, ids: &[Value]) -> Result<(), ToolError> {
    let p = items.program;
    for (i, value) in ids.iter().enumerate() {
        let text = value.as_str().unwrap_or_default();
        match Id::parse(text) {
            Ok(Id::Note(NoteId(n))) => {
                let note = p.notes().get(NoteId(n)).ok_or_else(|| missing("note", i))?;
                items.push(note_item(note), None);
            }
            Ok(Id::Set(name)) => {
                let note = p.notes().set(&name).ok_or_else(|| missing("set", i))?;
                let id = format!("set:{}", name.as_str());
                let mut record = New::item("set", id.clone());
                record.addr = note.at;
                record.text = Some(Value::from(name.as_str()));
                record.extra.push("note", Value::from(note.id.to_string()));
                let members: Vec<Value> = match note.set.as_ref().map(|s| &s.members) {
                    Some(SetMembers::Ids(list)) => {
                        list.iter().map(|m| Value::from(m.as_str())).collect()
                    }
                    Some(SetMembers::Addrs(set)) => set
                        .ranges()
                        .iter()
                        .map(|r| {
                            let size = u64::try_from(r.len()).unwrap_or(u64::MAX);
                            Value::object([("start", fs::hex(r.first)), ("size", fs::hex(size))])
                        })
                        .collect(),
                    None => Vec::new(),
                };
                record.extra.push("members", Value::from(members.len()));
                items.push(record, None);
                for (seq, member) in (1u64..).zip(members) {
                    let mut new = New::item("set", id.clone());
                    new.addr = note.at;
                    new.seq = seq;
                    new.extra = Object::new();
                    new.extra.push("member", member);
                    items.push(new, None);
                }
            }
            Ok(Id::JumpTable(jt)) => {
                let new = table_item(p, jt).ok_or_else(|| missing("jumptable", i))?;
                items.push(new, None);
            }
            _ => return Err(missing("record", i)),
        }
    }
    Ok(())
}
