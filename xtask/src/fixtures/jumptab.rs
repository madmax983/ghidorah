//! Jump-table truth from the relocations of the `-c` objects and the link map.
//!
//! In an object, a jump table is a run of relocations in a data section whose symbols are
//! code sections. A code relocation that points at the first entry gives the start of the
//! table, so two tables side by side stay apart. Two forms exist:
//!
//! | Kind | Code relocation | Entry relocation | Target |
//! |---|---|---|---|
//! | `rel32` | `R_X86_64_PC32` to `T - 4` (a RIP-relative `lea`) | `R_X86_64_PC32`, 4 bytes | `S + A - (P - T)` |
//! | `abs64` | `R_X86_64_32S` or `R_X86_64_32` to `T` | `R_X86_64_64`, 8 bytes | `S + A` |
//!
//! The GNU ld link map (`-Wl,-Map`) gives the address of each input section of each object.
//! So each object offset maps to its address in the linked fixture.

use std::collections::{BTreeMap, BTreeSet};

use super::elfinfo::{Reloc, Section};

/// The address of each input section: `(section name, object file name)` to address.
pub type SectionMap = BTreeMap<(String, String), u64>;

/// Parses a GNU ld link map. It keeps input sections of the named object files only.
///
/// An input section line is ` <section> 0x<addr> 0x<size> <file>`. A long section name puts
/// the address, the size and the file on the next line.
#[must_use]
pub fn parse_map(text: &str, objects: &[String]) -> SectionMap {
    let mut out = SectionMap::new();
    let mut pending: Option<String> = None;
    let body = text
        .split_once("Linker script and memory map")
        .map_or(text, |(_, rest)| rest);
    for line in body.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let starts_space = line.starts_with(' ') && !line.starts_with("  ");
        let (name, rest) = match (starts_space, words.as_slice(), pending.take()) {
            (true, [name], _) if name.starts_with('.') => {
                pending = Some((*name).to_owned());
                continue;
            }
            (true, [name, rest @ ..], _) if name.starts_with('.') => ((*name).to_owned(), rest),
            (false, rest @ [_, _, _], Some(name)) => (name, rest),
            _ => continue,
        };
        let [addr, size, file] = rest else {
            continue;
        };
        let (Some(addr), Some(_)) = (parse_hex(addr), parse_hex(size)) else {
            continue;
        };
        let base = file.rsplit('/').next().unwrap_or(file);
        if objects.iter().any(|o| o == base) {
            out.insert((name, base.to_owned()), addr);
        }
    }
    out
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

/// The kind of a jump table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TableKind {
    /// 4-byte entries relative to the table start.
    Rel32,
    /// 8-byte absolute entries.
    Abs64,
}

impl TableKind {
    /// Gives the kind name of the truth file.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rel32 => "rel32",
            Self::Abs64 => "abs64",
        }
    }

    const fn entry_size(self) -> u64 {
        match self {
            Self::Rel32 => 4,
            Self::Abs64 => 8,
        }
    }
}

/// One jump table in final addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    /// The address of the table.
    pub table: u64,
    /// The addresses of the code fields that point at the table, sorted.
    pub refs: Vec<u64>,
    /// The table kind.
    pub kind: TableKind,
    /// The case targets in entry order.
    pub targets: Vec<u64>,
}

/// The relocations and the sections of one object, plus its file name.
#[derive(Debug, Clone)]
pub struct Object<'a> {
    /// The object file name as the link map shows it.
    pub file: &'a str,
    /// The sections of the object.
    pub sections: &'a [Section],
    /// The relocations of the object.
    pub relocs: &'a [Reloc],
}

/// Gives the section that a relocation section applies to: `.rela.text` gives `.text`.
fn target_section(rela: &str) -> &str {
    rela.strip_prefix(".rela").unwrap_or(rela)
}

fn is_exec(obj: &Object<'_>, name: &str) -> bool {
    obj.sections.iter().any(|s| s.name == name && s.is_exec())
}

/// A table start in object terms.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Start {
    data: String,
    offset: u64,
    kind: TableKind,
}

fn start_of(r: &Reloc) -> Option<(u64, TableKind)> {
    match r.kind.as_str() {
        "R_X86_64_PC32" => Some((
            u64::try_from(r.addend.checked_add(4)?).ok()?,
            TableKind::Rel32,
        )),
        "R_X86_64_32S" | "R_X86_64_32" => Some((u64::try_from(r.addend).ok()?, TableKind::Abs64)),
        _ => None,
    }
}

/// Finds the jump tables of one object and maps them to final addresses.
///
/// Tables whose sections are not in `map` are left out.
#[must_use]
pub fn tables(obj: &Object<'_>, map: &SectionMap) -> Vec<JumpTable> {
    let addr = |sec: &str, off: u64| {
        map.get(&(sec.to_owned(), obj.file.to_owned()))
            .and_then(|base| base.checked_add(off))
    };
    // Entries: data section -> offset -> relocation, for relocations to code sections.
    let mut entries: BTreeMap<&str, BTreeMap<u64, &Reloc>> = BTreeMap::new();
    for r in obj.relocs {
        let data = target_section(&r.section);
        if !is_exec(obj, data) && is_exec(obj, &r.sym) {
            entries.entry(data).or_default().insert(r.offset, r);
        }
    }
    // Starts: code relocations to a data section offset that holds an entry.
    let mut starts: BTreeMap<Start, BTreeSet<u64>> = BTreeMap::new();
    for r in obj.relocs {
        let code = target_section(&r.section);
        let Some((offset, kind)) = start_of(r) else {
            continue;
        };
        let first = entries.get(r.sym.as_str()).and_then(|e| e.get(&offset));
        if is_exec(obj, code) && first.is_some() {
            let start = Start {
                data: r.sym.clone(),
                offset,
                kind,
            };
            starts
                .entry(start)
                .or_default()
                .extend(addr(code, r.offset));
        }
    }
    let all_starts: BTreeSet<(String, u64)> =
        starts.keys().map(|s| (s.data.clone(), s.offset)).collect();
    let mut out = Vec::new();
    for (start, refs) in starts {
        let Some(table) = addr(&start.data, start.offset) else {
            continue;
        };
        let Some(rows) = entries.get(start.data.as_str()) else {
            continue;
        };
        let mut targets = Vec::new();
        let mut p = start.offset;
        while let Some(r) = rows.get(&p) {
            if p != start.offset && all_starts.contains(&(start.data.clone(), p)) {
                break;
            }
            let delta = i64::try_from(p - start.offset).unwrap_or(i64::MAX);
            let off = match start.kind {
                TableKind::Rel32 => r.addend.checked_sub(delta),
                TableKind::Abs64 => Some(r.addend),
            };
            let Some(target) = off
                .and_then(|o| u64::try_from(o).ok())
                .and_then(|o| addr(&r.sym, o))
            else {
                break;
            };
            targets.push(target);
            p = p.saturating_add(start.kind.entry_size());
        }
        if !targets.is_empty() {
            out.push(JumpTable {
                table,
                refs: refs.into_iter().collect(),
                kind: start.kind,
                targets,
            });
        }
    }
    out.sort_by_key(|t| t.table);
    out
}
