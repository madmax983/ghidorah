//! [`Program::from_binary`]: the `Imported` facts of a loaded binary.
//!
//! The loader gives each symbol source, then one sort orders the candidates by address and
//! preference. The first candidate of an address becomes its primary symbol:
//!
//! | Preference | Candidates |
//! |---|---|
//! | 0 to 11 | symbol table entries: functions, then objects, then labels; global, weak, local |
//! | 12 | PLT jump stubs `<name>@plt` |
//! | 13 | PLT0 and lazy stubs |
//! | 14 | ELF import slots `<name>@got` |
//! | 15 | the EXTERNAL address of each import |

use std::collections::BTreeMap;

use ghidorah_base::id::MAX_NAME_LEN;
use ghidorah_base::{Address, BinText, Caps, ExportId, ImportId, Limits, Rev};
use ghidorah_loader::elf::consts::SHN_UNDEF;
use ghidorah_loader::stubs::{self, StubKind};
use ghidorah_loader::{Binary, Format, Import, MemoryMap, SymBind, SymTable};

use super::{BinaryMeta, ExportRow, ImportRow, Program, ProgramError, Tables};
use crate::fact::Origin;
use crate::notes::Notes;
use crate::progress::Progress;
use crate::symbols::SymKind;
use crate::tx::Changes;
use crate::typesglue::Types;

/// One symbol before the sort. The field order is the sort order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Candidate {
    addr: Address,
    pref: u8,
    name: String,
    kind: SymKind,
}

/// Gives the text of a name: the exact text, or the escaped text when it is not UTF-8.
///
/// An empty name and a name above [`MAX_NAME_LEN`] bytes give `None`.
pub(super) fn text(name: &BinText) -> Option<String> {
    let out = name
        .as_str()
        .map_or_else(|| name.render(Caps::DETAILED).text, ToString::to_string);
    (!out.is_empty() && out.len() <= MAX_NAME_LEN).then_some(out)
}

/// Gives the ID of an import, or `None` when its parts give no valid ID.
fn import_id(import: &Import) -> Option<ImportId> {
    let name = import.name.as_ref().and_then(text);
    match (import.lib.as_ref().and_then(text), name, import.ordinal) {
        (None, Some(name), _) => ImportId::elf(&name).ok(),
        (Some(dll), Some(name), _) => ImportId::pe_by_name(&dll, &name).ok(),
        (Some(dll), None, Some(ordinal)) => ImportId::pe_by_ordinal(&dll, ordinal).ok(),
        _ => None,
    }
}

/// Gives the symbol name of an import: its name, or `<dll>!#<ordinal>`.
fn import_name(id: &ImportId) -> String {
    match (id.name(), id.lib(), id.ordinal()) {
        (Some(name), _, _) => name.to_string(),
        (None, Some(dll), Some(ordinal)) => format!("{dll}!#{ordinal}"),
        _ => id.to_string(),
    }
}

/// Gives the import rows. Each import gets `ext:` and its index plus 1.
fn import_rows(binary: &Binary) -> BTreeMap<ImportId, ImportRow> {
    let mut rows = BTreeMap::new();
    for (index, import) in binary.imports.iter().enumerate() {
        let Some(id) = import_id(import) else {
            continue;
        };
        let ext = u64::try_from(index).map_or(u64::MAX, |k| k.saturating_add(1));
        rows.entry(id.clone()).or_insert_with(|| ImportRow {
            id,
            index,
            ext: Address::external(ext),
            slot: import.slot.map(Address::ram),
            stub: import.stub.map(Address::ram),
            delay: import.delay,
        });
    }
    rows
}

/// Gives the export rows. An export name of the form `#<digits>` uses the ordinal.
fn export_rows(binary: &Binary) -> BTreeMap<ExportId, ExportRow> {
    let mut rows = BTreeMap::new();
    for (index, export) in binary.exports.iter().enumerate() {
        let by_name = export
            .name
            .as_ref()
            .and_then(text)
            .and_then(|n| ExportId::by_name(&n).ok());
        let Some(id) = by_name.or_else(|| export.ordinal.map(ExportId::by_ordinal)) else {
            continue;
        };
        rows.entry(id.clone()).or_insert_with(|| ExportRow {
            id,
            index,
            addr: export.addr.map(Address::ram),
        });
    }
    rows
}

/// Adds a candidate for each named symbol table entry at a mapped address.
fn table_symbols(binary: &Binary, mem: &MemoryMap, out: &mut Vec<Candidate>) {
    use ghidorah_loader::SymKind as Stt;
    for s in &binary.symbols {
        let (kind, kind_pref) = match s.kind {
            Stt::Func | Stt::Ifunc => (SymKind::Function, 0),
            Stt::Object | Stt::Common => (SymKind::GlobalVar, 4),
            Stt::NoType => (SymKind::Label, 8),
            Stt::Section | Stt::File | Stt::Tls | Stt::Other(_) => continue,
        };
        let elf_table = matches!(s.table, SymTable::Symtab | SymTable::Dynsym);
        if (elf_table && s.shndx == SHN_UNDEF) || mem.region_at(s.addr).is_none() {
            continue;
        }
        let bind_pref = match s.bind {
            SymBind::Global | SymBind::Unique => 0,
            SymBind::Weak => 1,
            SymBind::Other(_) => 2,
            SymBind::Local => 3,
        };
        if let Some(name) = text(&s.name) {
            out.push(Candidate {
                addr: Address::ram(s.addr),
                pref: kind_pref + bind_pref,
                name,
                kind,
            });
        }
    }
}

/// Adds a candidate for each PLT stub: `<name>@plt`, `<name>@plt.lazy` or `.plt0`.
fn stub_symbols(binary: &Binary, mem: &MemoryMap, limits: &Limits, out: &mut Vec<Candidate>) {
    for stub in stubs::find(binary, mem, limits).stubs {
        let (pref, kind) = match stub.kind {
            StubKind::Jump => (12, SymKind::Function),
            StubKind::Lazy | StubKind::Plt0 => (13, SymKind::Label),
        };
        if let Some(name) = text(&stubs::label(binary, &stub)) {
            out.push(Candidate {
                addr: Address::ram(stub.addr),
                pref,
                name,
                kind,
            });
        }
    }
}

/// Adds a candidate at the EXTERNAL address of each import and at each mapped ELF slot.
fn import_symbols(
    binary: &Binary,
    mem: &MemoryMap,
    rows: &BTreeMap<ImportId, ImportRow>,
    out: &mut Vec<Candidate>,
) {
    for row in rows.values() {
        let name = import_name(&row.id);
        if let Some(slot) = row.slot
            && binary.format == Format::Elf64Le
            && mem.region_at(slot.off).is_some()
        {
            out.push(Candidate {
                addr: slot,
                pref: 14,
                name: format!("{name}@got"),
                kind: SymKind::GlobalVar,
            });
        }
        out.push(Candidate {
            addr: row.ext,
            pref: 15,
            name,
            kind: SymKind::Label,
        });
    }
}

/// Makes the program of a loaded binary.
pub(super) fn from_binary(
    binary: Binary,
    mem: MemoryMap,
    limits: &Limits,
) -> Result<Program, ProgramError> {
    let types = Types::for_format(binary.format).map_err(ProgramError::Prelude)?;
    let meta = BinaryMeta {
        binary_id: binary.identity.binary_id(),
        sha256: binary.identity.sha256,
        format: binary.format,
        arch: binary.arch,
        bits: binary.bits,
        kind: binary.kind,
        image_base: binary.image_base,
        file_size: u64::try_from(mem.file().len()).unwrap_or(u64::MAX),
    };
    let imports = import_rows(&binary);
    let exports = export_rows(&binary);
    let mut candidates = Vec::new();
    table_symbols(&binary, &mem, &mut candidates);
    stub_symbols(&binary, &mem, limits, &mut candidates);
    import_symbols(&binary, &mem, &imports, &mut candidates);
    // One candidate per address and name: the one with the best preference.
    candidates.sort_by(|a, b| (a.addr, &a.name, a.pref).cmp(&(b.addr, &b.name, b.pref)));
    candidates.dedup_by(|later, first| later.addr == first.addr && later.name == first.name);
    candidates.sort();
    let mut base = Tables::default();
    let origin = Origin::load();
    for c in candidates {
        // The load skips a refused symbol, for example the 65,536th symbol at one address.
        let _ = base.symbols.add(c.addr, c.name, c.kind, &origin);
    }
    Ok(Program {
        binary,
        mem,
        meta,
        imports,
        exports,
        types,
        base,
        analysis: Box::default(),
        notes: Notes::default(),
        progress: Progress::default(),
        rev: Rev(0),
        changes: Changes::default(),
    })
}
