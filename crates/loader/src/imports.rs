//! ELF imports and the import slot map (design Section 4.5).
//!
//! An import is the name of an undefined `.dynsym` symbol. Symbols with the same name
//! give one import. The imports keep the order of their first symbol.
//!
//! An import slot is the place of an `R_X86_64_JUMP_SLOT` (7) or `R_X86_64_GLOB_DAT` (6)
//! relocation whose symbol is an import. The slot map keeps one import per slot: the
//! first relocation in table order wins. A stub or a `call [rip+slot]` site gets its name
//! through this map, never through its position.
//!
//! The slot of an [`Import`] is its first `JUMP_SLOT` slot in address order, else its first
//! `GLOB_DAT` slot. Only x86-64 files have slots.

use std::collections::BTreeMap;

use ghidorah_base::{BinText, Limits};

use crate::binary::{Binary, Import, RelocType, Sym, SymKind, SymTable};
use crate::diag::Diags;
use crate::elf::consts::SHN_UNDEF;
use crate::limits::Budget;

/// `R_X86_64_GLOB_DAT`: a GOT slot that holds the address of a symbol.
pub const R_X86_64_GLOB_DAT: RelocType = RelocType(6);
/// `R_X86_64_JUMP_SLOT`: a GOT slot that a PLT stub jumps through.
pub const R_X86_64_JUMP_SLOT: RelocType = RelocType(7);

/// One import slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot {
    /// The index of the import in [`Binary::imports`].
    pub import: usize,
    /// The relocation type: `JUMP_SLOT` or `GLOB_DAT`.
    pub kind: RelocType,
    /// The index of the relocation in [`Binary::relocs`].
    pub reloc: usize,
}

/// Gives the imports of a loaded ELF file.
///
/// The names are copies of symbol names that the model holds, so the copy has no text cap.
#[must_use]
pub fn collect(binary: &Binary, limits: &Limits) -> Vec<Import> {
    let mut budget = Budget::new(limits, u64::MAX);
    let mut diags = Diags::default();
    load(binary, &mut budget, &mut diags)
}

/// Tells if a `.dynsym` symbol is an import: undefined, with a name, not a section.
fn is_import(s: &Sym) -> bool {
    s.table == SymTable::Dynsym
        && s.index != 0
        && s.shndx == SHN_UNDEF
        && !s.name.is_empty()
        && !matches!(s.kind, SymKind::Section | SymKind::File)
}

/// Gives the import index of each import symbol by its `.dynsym` index.
fn by_symbol(binary: &Binary) -> BTreeMap<u32, usize> {
    let mut names: BTreeMap<&[u8], usize> = BTreeMap::new();
    let mut out = BTreeMap::new();
    for s in binary.symbols.iter().filter(|s| is_import(s)) {
        let next = names.len();
        let import = *names.entry(s.name.as_bytes()).or_insert(next);
        out.insert(s.index, import);
    }
    out
}

/// Gives the slot map from the relocations, with the import indexes of `by_symbol`.
fn slot_map(binary: &Binary, by_symbol: &BTreeMap<u32, usize>) -> BTreeMap<u64, Slot> {
    let mut out = BTreeMap::new();
    if !binary.arch.is_x86_64() {
        return out;
    }
    for (reloc, r) in binary.relocs.iter().enumerate() {
        if !(r.kind == R_X86_64_JUMP_SLOT || r.kind == R_X86_64_GLOB_DAT)
            || r.sym_table != SymTable::Dynsym
        {
            continue;
        }
        let Some(&import) = r.sym.and_then(|i| by_symbol.get(&i)) else {
            continue;
        };
        out.entry(r.offset).or_insert(Slot {
            import,
            kind: r.kind,
            reloc,
        });
    }
    out
}

/// Gives the imports and adds the diagnostics of the text cap to `diags`.
pub(crate) fn load(binary: &Binary, budget: &mut Budget, diags: &mut Diags) -> Vec<Import> {
    let by_symbol = by_symbol(binary);
    let mut out: Vec<Import> = Vec::new();
    for s in binary.symbols.iter().filter(|s| is_import(s)) {
        if by_symbol.get(&s.index) != Some(&out.len()) {
            continue;
        }
        let bytes = s.name.as_bytes();
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let name = if budget.take_text(size, "elf.imports", diags) {
            BinText::new(bytes)
        } else {
            BinText::default()
        };
        out.push(Import {
            lib: None,
            name: Some(name),
            ordinal: None,
            hint: None,
            slot: None,
            stub: None,
            reloc_kind: None,
            delay: false,
        });
    }
    let slots = slot_map(binary, &by_symbol);
    for kind in [R_X86_64_JUMP_SLOT, R_X86_64_GLOB_DAT] {
        for (addr, slot) in slots.iter().filter(|(_, s)| s.kind == kind) {
            if let Some(i) = out.get_mut(slot.import)
                && i.slot.is_none()
            {
                i.slot = Some(*addr);
                i.reloc_kind = Some(kind);
            }
        }
    }
    out
}

/// Gives the import slot map: the slot address to its import.
#[must_use]
pub fn slots(binary: &Binary) -> BTreeMap<u64, Slot> {
    slot_map(binary, &by_symbol(binary))
}
