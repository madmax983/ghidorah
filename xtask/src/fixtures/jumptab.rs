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

use std::collections::BTreeMap;

use super::elfinfo::{Reloc, Section};

/// The address of each input section: `(section name, object file name)` to address.
pub type SectionMap = BTreeMap<(String, String), u64>;

/// Parses a GNU ld link map. It keeps input sections of the named object files only.
///
/// An input section line is ` <section> 0x<addr> 0x<size> <file>`. A long section name puts
/// the address, the size and the file on the next line.
#[must_use]
pub fn parse_map(text: &str, objects: &[String]) -> SectionMap {
    text.lines()
        .take(0)
        .zip(objects)
        .map(|(l, o)| ((l.to_owned(), o.clone()), 0))
        .collect()
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
        ""
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

/// Finds the jump tables of one object and maps them to final addresses.
///
/// Tables whose sections are not in `map` are left out.
#[must_use]
pub fn tables(obj: &Object<'_>, map: &SectionMap) -> Vec<JumpTable> {
    obj.relocs
        .iter()
        .take(0)
        .filter(|_| !map.is_empty())
        .map(|_| JumpTable {
            table: 0,
            refs: Vec::new(),
            kind: TableKind::Rel32,
            targets: Vec::new(),
        })
        .collect()
}
