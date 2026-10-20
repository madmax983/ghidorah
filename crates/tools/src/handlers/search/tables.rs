//! The item lists of the `search` kinds of the loader model: imports, exports, sections,
//! segments, libraries and symbols.

use ghidorah_base::{Address, Caps};
use ghidorah_json::Value;
use ghidorah_loader::{SymBind, SymKind, SymTable};

use super::filter::{Items, Matcher, New};
use crate::handlers::addr_info;
use crate::handlers::func_sections::{self as fs, Namer};

/// Gives the text of binary text in the escapes of `BinText`, with no cap.
fn full(text: &ghidorah_base::BinText) -> String {
    text.as_str()
        .map_or_else(|| text.render(Caps::DETAILED).text, str::to_owned)
}

/// Adds the imports of the loader model whose name matches.
pub fn imports(items: &mut Items<'_>, m: &Matcher, namer: &Namer) {
    let p = items.program;
    for row in p.imports().values() {
        let name = row
            .id
            .name()
            .map_or_else(|| row.id.to_string(), str::to_owned);
        if !m.matches(&name) {
            continue;
        }
        let mut new = New::item("import", row.id.to_string());
        new.addr = Some(row.stub.or(row.slot).unwrap_or(row.ext));
        new.text = Some(Value::from(namer.text(&name)));
        if let Some(lib) = row.id.lib() {
            new.extra.push("lib", Value::from(fs::safe(lib)));
        }
        if let Some(slot) = row.slot {
            new.extra.push("slot", fs::addr(slot));
        }
        if let Some(stub) = row.stub {
            new.extra.push("stub", fs::addr(stub));
        }
        new.extra.push("ext", fs::addr(row.ext));
        new.extra.push("delay", Value::Bool(row.delay));
        items.push(new, None);
    }
}

/// Adds the exports of the loader model whose name matches.
pub fn exports(items: &mut Items<'_>, m: &Matcher, namer: &Namer) {
    let p = items.program;
    for row in p.exports().values() {
        let name = row
            .id
            .name()
            .map_or_else(|| row.id.to_string(), str::to_owned);
        if !m.matches(&name) {
            continue;
        }
        let mut new = New::item("export", row.id.to_string());
        new.addr = row.addr;
        new.text = Some(Value::from(namer.text(&name)));
        let export = p.binary().exports.get(row.index);
        if let Some(fwd) = export.and_then(|e| e.forwarder.as_ref()) {
            new.extra
                .push("forwarder", Value::from(fs::safe(&full(fwd))));
        }
        items.push(new, None);
    }
}

/// Adds the sections of the loader model whose name matches.
pub fn sections(items: &mut Items<'_>, m: &Matcher) {
    let list: Vec<New> = items
        .program
        .binary()
        .sections
        .iter()
        .filter_map(|s| {
            let name = addr_info::shown(&s.name);
            if !m.matches(&name) {
                return None;
            }
            let mut new = New::item("section", addr_info::section_id(s));
            new.addr = s.va.map(|r| Address::ram(r.first));
            new.text = Some(Value::from(name));
            new.seq = u64::from(s.index);
            new.extra.push("size", fs::hex(s.size));
            new.extra.push("flags", fs::hex(s.flags));
            Some(new)
        })
        .collect();
    for new in list {
        items.push(new, None);
    }
}

/// Adds the segments of the loader model.
pub fn segments(items: &mut Items<'_>, m: &Matcher) {
    let list: Vec<New> = items
        .program
        .binary()
        .segments
        .iter()
        .filter_map(|s| {
            let id = format!("seg:{}", s.index);
            if !m.matches(&id) {
                return None;
            }
            let mut new = New::item("segment", id);
            new.addr = s.va.map(|r| Address::ram(r.first));
            new.seq = u64::from(s.index);
            new.extra.push("size", fs::hex(s.mem_size));
            new.extra.push("perms", Value::from(s.perms.to_string()));
            new.extra.push("file_off", fs::hex(s.file_off));
            Some(new)
        })
        .collect();
    for new in list {
        items.push(new, None);
    }
}

/// Adds the libraries of the loader model whose name matches.
pub fn libraries(items: &mut Items<'_>, m: &Matcher) {
    let list: Vec<New> = items
        .program
        .binary()
        .libraries
        .iter()
        .zip(0u64..)
        .filter_map(|(lib, seq)| {
            let name = fs::safe(&full(lib));
            if !m.matches(&name) {
                return None;
            }
            let mut new = New::item("library", name.clone());
            new.text = Some(Value::from(name));
            new.seq = seq;
            new.extra.push("index", Value::from(seq));
            Some(new)
        })
        .collect();
    for new in list {
        items.push(new, None);
    }
}

/// Gives the names of a symbol type, a binding and a table.
fn sym_names(
    kind: SymKind,
    bind: SymBind,
    table: SymTable,
) -> (&'static str, &'static str, &'static str) {
    let kind = match kind {
        SymKind::NoType => "notype",
        SymKind::Object => "object",
        SymKind::Func => "func",
        SymKind::Section => "section",
        SymKind::File => "file",
        SymKind::Common => "common",
        SymKind::Tls => "tls",
        SymKind::Ifunc => "ifunc",
        SymKind::Other(_) => "other",
    };
    let bind = match bind {
        SymBind::Local => "local",
        SymBind::Global => "global",
        SymBind::Weak => "weak",
        SymBind::Unique => "unique",
        SymBind::Other(_) => "other",
    };
    let table = match table {
        SymTable::Symtab => "symtab",
        SymTable::Dynsym => "dynsym",
        SymTable::Export => "export",
        SymTable::Iat => "iat",
    };
    (kind, bind, table)
}

/// Adds the named symbols of the symbol tables of the loader model whose name matches.
pub fn symbols(items: &mut Items<'_>, m: &Matcher, namer: &Namer) {
    let program = items.program;
    let list: Vec<New> = program
        .binary()
        .symbols
        .iter()
        .zip(0u64..)
        .filter(|(s, _)| !s.name.is_empty())
        .filter_map(|(s, seq)| {
            let raw = full(&s.name);
            if !m.matches(&raw) {
                return None;
            }
            let name = namer.text(&raw);
            let id = addr_info::symbol_id(program, &raw, Address::ram(s.addr));
            let mut new = New::item("symbol", id);
            new.addr = (s.addr != 0).then(|| Address::ram(s.addr));
            new.text = Some(Value::from(name));
            new.seq = seq;
            let (kind, bind, table) = sym_names(s.kind, s.bind, s.table);
            new.extra.push("index", Value::from(s.index));
            new.extra.push("size", fs::hex(s.size));
            new.extra.push("kind", Value::from(kind));
            new.extra.push("bind", Value::from(bind));
            new.extra.push("table", Value::from(table));
            Some(new)
        })
        .collect();
    for new in list {
        items.push(new, None);
    }
}
