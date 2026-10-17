//! Malformed knobs and the catalog of malformed variants.

use std::collections::BTreeMap;

use super::consts::{DT_NULL, PT_DYNAMIC, PT_NOTE};
use super::write::{get_u16, get_u32, get_u64, put, u64_of, usize_of};
use super::{ElfBuilder, Fde, HashStyle, ImportKind, Loc, Reloc, RelocTable, Section, Symbol};

/// The tag that replaces `DT_NULL` in a table with no end.
const DT_DEBUG: u64 = 21;

/// A field of the ELF64 file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhdrField {
    /// `e_type`.
    Type,
    /// `e_machine`.
    Machine,
    /// `e_entry`.
    Entry,
    /// `e_phoff`.
    Phoff,
    /// `e_shoff`.
    Shoff,
    /// `e_phentsize`.
    Phentsize,
    /// `e_phnum`.
    Phnum,
    /// `e_shentsize`.
    Shentsize,
    /// `e_shnum`.
    Shnum,
    /// `e_shstrndx`.
    Shstrndx,
}

/// A field of an ELF64 program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhdrField {
    /// `p_type`.
    Type,
    /// `p_flags`.
    Flags,
    /// `p_offset`.
    Offset,
    /// `p_vaddr` and `p_paddr`.
    Vaddr,
    /// `p_filesz`.
    Filesz,
    /// `p_memsz`.
    Memsz,
    /// `p_align`.
    Align,
}

/// A field of an ELF64 section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShdrField {
    /// `sh_type`.
    Type,
    /// `sh_flags`.
    Flags,
    /// `sh_addr`.
    Addr,
    /// `sh_offset`.
    Offset,
    /// `sh_size`.
    Size,
    /// `sh_link`.
    Link,
    /// `sh_info`.
    Info,
    /// `sh_addralign`.
    Align,
    /// `sh_entsize`.
    Entsize,
}

/// A change that the builder makes to the bytes after the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    /// Changes the first magic byte.
    BadMagic,
    /// Cuts the file to this length.
    Truncate(usize),
    /// Sets a file header field.
    Ehdr(EhdrField, u64),
    /// Sets a field of the program header with this index.
    Phdr(usize, PhdrField, u64),
    /// Sets a field of the section header with this name.
    Shdr(String, ShdrField, u64),
    /// Sets the value of the first `.dynamic` entry with this tag.
    Dynamic(u64, u64),
    /// Changes the `DT_NULL` entry of `.dynamic` to `DT_DEBUG`, so the table has no end.
    DropDynamicNull,
    /// Moves `e_phnum`, `e_shnum` and `e_shstrndx` into section 0 with the escape values.
    EscapeCounts,
    /// Clears the end bit of the last `.gnu.hash` chain value, so the chain has no end.
    GnuHashOpenChain,
    /// Writes bytes at a file offset. Bytes past the end of the file are dropped.
    Patch(u64, Vec<u8>),
}

/// One entry of the malformed catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    /// The variant name.
    pub name: &'static str,
    /// The file bytes.
    pub bytes: Vec<u8>,
    /// The `DiagCode` name that a loader gives for the variant, for example `E_BAD_ENTSIZE`.
    pub expect: &'static str,
}

/// Returns the file for the catalog: dynamic symbols, relocations, a note and an FDE.
fn catalog_base(fde: Fde) -> ElfBuilder {
    let code = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0xc3, 0xc3];
    ElfBuilder::dyn_object()
        .section(Section::code(".text", &code))
        .section(Section::data(".data", &[0u8; 16]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 6))
        .export(Symbol::func("f", Loc::section(".text", 0), 6))
        .import("puts", ImportKind::Plt)
        .hash(HashStyle::Both)
        .needed("libc.so.6")
        .build_id(&[0xab; 8])
        .fde(fde)
}

/// Returns the index of the first program header of type `p_type`.
fn phdr_index(bytes: &[u8], p_type: u32) -> usize {
    let snap = Snapshot::of(bytes);
    (0..snap.phnum)
        .find(|i| get_u32(bytes, snap.phoff + i * 56) == Some(p_type))
        .map_or(0, usize_of)
}

fn variant(name: &'static str, expect: &'static str, bytes: Vec<u8>) -> Variant {
    Variant {
        name,
        bytes,
        expect,
    }
}

/// Returns the variants with a broken file header.
fn header_variants(base: &ElfBuilder) -> Vec<Variant> {
    use EhdrField as E;
    let knob = |m: Malformed| base.clone().malformed(m).build();
    let ehdr = |field, value| knob(Malformed::Ehdr(field, value));
    vec![
        variant("empty_file", "E_OOB", Vec::new()),
        variant("truncated_ehdr", "E_OOB", knob(Malformed::Truncate(40))),
        variant("bad_magic", "E_BAD_MAGIC", knob(Malformed::BadMagic)),
        variant("phoff_past_eof", "E_OOB", ehdr(E::Phoff, 1 << 40)),
        variant("phnum_past_eof", "E_OOB", ehdr(E::Phnum, 0xfff0)),
        variant(
            "phoff_overflow",
            "E_OVERFLOW",
            ehdr(E::Phoff, u64::MAX - 15),
        ),
        variant(
            "shoff_overflow",
            "E_OVERFLOW",
            ehdr(E::Shoff, u64::MAX - 15),
        ),
        variant("shstrndx_out_of_range", "E_OOB", ehdr(E::Shstrndx, 0x1234)),
        variant("phentsize_small", "E_BAD_ENTSIZE", ehdr(E::Phentsize, 32)),
        variant("shentsize_small", "E_BAD_ENTSIZE", ehdr(E::Shentsize, 16)),
    ]
}

/// Returns the variants with a broken table, note, relocation or unwind entry.
fn table_variants(base: &ElfBuilder, fde: &Fde) -> Vec<Variant> {
    let good = base.build();
    let knob = |m: Malformed| base.clone().malformed(m).build();
    let shdr = |name: &str, field, value| knob(Malformed::Shdr(name.to_string(), field, value));
    let reloc = Reloc {
        table: RelocTable::Rela,
        at: Loc::section(".data", 0),
        kind: 0x7777,
        sym: None,
        addend: 0,
    };
    let bad_cfa = Fde {
        program: vec![0x0f, 0x02, 0x7f, 0x06],
        ..fde.clone()
    };
    let note = Malformed::Phdr(phdr_index(&good, PT_NOTE), PhdrField::Align, 16);
    vec![
        variant(
            "phdr_vaddr_wrap",
            "E_OVERFLOW",
            knob(Malformed::Phdr(0, PhdrField::Vaddr, u64::MAX - 7)),
        ),
        variant(
            "dynsym_entsize_zero",
            "E_BAD_ENTSIZE",
            shdr(".dynsym", ShdrField::Entsize, 0),
        ),
        variant(
            "symtab_over_limit",
            "E_LIMIT",
            shdr(".symtab", ShdrField::Size, 24 * 5_000_000),
        ),
        variant(
            "gnu_hash_open_chain",
            "E_LOOP",
            knob(Malformed::GnuHashOpenChain),
        ),
        variant("note_align_16", "E_BAD_ALIGN", knob(note)),
        variant(
            "unsupported_reloc",
            "E_UNSUPPORTED_RELOC",
            base.clone().reloc(reloc).build(),
        ),
        variant("cfa_opcode", "E_CFA_OPCODE", catalog_base(bad_cfa).build()),
    ]
}

/// Returns the catalog of malformed variants in a fixed order.
///
/// Each variant has one defect and names the expected diagnostic of design Section 4.8.
#[must_use]
pub fn malformed_variants() -> Vec<Variant> {
    let fde = Fde::frame_pointer(Loc::symbol("f"), 6);
    let base = catalog_base(fde.clone());
    let mut out = header_variants(&base);
    out.extend(table_variants(&base, &fde));
    out
}

/// The table positions of the file before any knob changes it.
struct Snapshot {
    phoff: u64,
    phnum: u64,
    shoff: u64,
    shnum: u64,
    shstrndx: u64,
    sections: BTreeMap<String, u64>,
    dynamic: Option<(u64, u64)>,
}

impl Snapshot {
    fn of(bytes: &[u8]) -> Self {
        let word = |at| get_u64(bytes, at).unwrap_or(0);
        let half = |at| u64::from(get_u16(bytes, at).unwrap_or(0));
        let (phoff, phnum) = (word(32), half(56));
        let (shoff, shnum, shstrndx) = (word(40), half(60), half(62));
        let mut sections = BTreeMap::new();
        let names = word(shoff.saturating_add(shstrndx * 64).saturating_add(24));
        for i in 0..shnum.min(4096) {
            let at = shoff.saturating_add(i * 64);
            let name_off = u64::from(get_u32(bytes, at).unwrap_or(0));
            sections
                .entry(cstr(bytes, names.saturating_add(name_off)))
                .or_insert(at);
        }
        let dynamic = (0..phnum.min(4096))
            .map(|i| phoff.saturating_add(i * 56))
            .find(|at| get_u32(bytes, *at) == Some(PT_DYNAMIC))
            .map(|at| (word(at + 8), word(at + 32)));
        Self {
            phoff,
            phnum,
            shoff,
            shnum,
            shstrndx,
            sections,
            dynamic,
        }
    }

    /// Returns the file offset of the first dynamic entry with `tag`.
    fn dynamic_entry(&self, bytes: &[u8], tag: u64) -> Option<u64> {
        let (offset, size) = self.dynamic?;
        (0..(size / 16).min(4096))
            .map(|i| offset.saturating_add(i * 16))
            .find(|at| get_u64(bytes, *at) == Some(tag))
    }
}

/// Reads a NUL-terminated name. A missing terminator ends the name at the end of the bytes.
fn cstr(bytes: &[u8], offset: u64) -> String {
    let rest = bytes.get(usize_of(offset)..).unwrap_or_default();
    let end = rest.iter().position(|c| *c == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(rest.get(..end).unwrap_or_default()).into_owned()
}

fn put_field(bytes: &mut [u8], at: u64, value: u64, width: usize) {
    if let Some(part) = value.to_le_bytes().get(..width) {
        put(bytes, at, part);
    }
}

fn apply_ehdr(bytes: &mut [u8], field: EhdrField, value: u64) {
    let (at, width) = match field {
        EhdrField::Type => (16, 2),
        EhdrField::Machine => (18, 2),
        EhdrField::Entry => (24, 8),
        EhdrField::Phoff => (32, 8),
        EhdrField::Shoff => (40, 8),
        EhdrField::Phentsize => (54, 2),
        EhdrField::Phnum => (56, 2),
        EhdrField::Shentsize => (58, 2),
        EhdrField::Shnum => (60, 2),
        EhdrField::Shstrndx => (62, 2),
    };
    put_field(bytes, at, value, width);
}

fn apply_phdr(bytes: &mut [u8], snap: &Snapshot, index: usize, field: PhdrField, value: u64) {
    let base = snap.phoff.saturating_add(u64_of(index).saturating_mul(56));
    let (at, width) = match field {
        PhdrField::Type => (0, 4),
        PhdrField::Flags => (4, 4),
        PhdrField::Offset => (8, 8),
        PhdrField::Vaddr => (16, 8),
        PhdrField::Filesz => (32, 8),
        PhdrField::Memsz => (40, 8),
        PhdrField::Align => (48, 8),
    };
    put_field(bytes, base.saturating_add(at), value, width);
    if field == PhdrField::Vaddr {
        put_field(bytes, base.saturating_add(24), value, 8);
    }
}

fn apply_shdr(bytes: &mut [u8], snap: &Snapshot, name: &str, field: ShdrField, value: u64) {
    let Some(base) = snap.sections.get(name).copied() else {
        return;
    };
    let (at, width) = match field {
        ShdrField::Type => (4, 4),
        ShdrField::Flags => (8, 8),
        ShdrField::Addr => (16, 8),
        ShdrField::Offset => (24, 8),
        ShdrField::Size => (32, 8),
        ShdrField::Link => (40, 4),
        ShdrField::Info => (44, 4),
        ShdrField::Align => (48, 8),
        ShdrField::Entsize => (56, 8),
    };
    put_field(bytes, base.saturating_add(at), value, width);
}

fn escape_counts(bytes: &mut [u8], snap: &Snapshot) {
    if snap.shoff == 0 {
        return;
    }
    put_field(bytes, snap.shoff + 32, snap.shnum, 8);
    put_field(bytes, snap.shoff + 40, snap.shstrndx, 4);
    put_field(bytes, snap.shoff + 44, snap.phnum, 4);
    apply_ehdr(bytes, EhdrField::Phnum, 0xffff);
    apply_ehdr(bytes, EhdrField::Shnum, 0);
    apply_ehdr(bytes, EhdrField::Shstrndx, 0xffff);
}

fn apply_one(bytes: &mut Vec<u8>, snap: &Snapshot, knob: &Malformed) {
    match knob {
        Malformed::BadMagic => {
            if let Some(first) = bytes.first_mut() {
                *first ^= 0xff;
            }
        }
        Malformed::Truncate(len) => bytes.truncate(*len),
        Malformed::Ehdr(field, value) => apply_ehdr(bytes, *field, *value),
        Malformed::Phdr(index, field, value) => apply_phdr(bytes, snap, *index, *field, *value),
        Malformed::Shdr(name, field, value) => apply_shdr(bytes, snap, name, *field, *value),
        Malformed::Dynamic(tag, value) => {
            if let Some(at) = snap.dynamic_entry(bytes, *tag) {
                put_field(bytes, at + 8, *value, 8);
            }
        }
        Malformed::DropDynamicNull => {
            if let Some(at) = snap.dynamic_entry(bytes, DT_NULL) {
                put_field(bytes, at, DT_DEBUG, 8);
            }
        }
        Malformed::EscapeCounts => escape_counts(bytes, snap),
        Malformed::GnuHashOpenChain => {
            let section = snap.sections.get(".gnu.hash").copied();
            let table = section.map(|at| {
                (
                    get_u64(bytes, at + 24).unwrap_or(0),
                    get_u64(bytes, at + 32).unwrap_or(0),
                )
            });
            if let Some((offset, size)) = table.filter(|t| t.1 >= 4) {
                let last = offset + size - 4;
                if let Some(word) = get_u32(bytes, last) {
                    put_field(bytes, last, u64::from(word & !1), 4);
                }
            }
        }
        Malformed::Patch(offset, data) => put(bytes, *offset, data),
    }
}

/// Applies the knobs to `bytes`. Each knob reads the table positions of the unchanged file.
pub(crate) fn apply(bytes: &mut Vec<u8>, knobs: &[Malformed]) {
    if knobs.is_empty() {
        return;
    }
    let snap = Snapshot::of(bytes);
    for knob in knobs {
        apply_one(bytes, &snap, knob);
    }
}
