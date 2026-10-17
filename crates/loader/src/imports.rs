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

use ghidorah_base::Limits;

use crate::binary::{Binary, Import, RelocType};
use crate::diag::Diags;
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

/// Gives the imports and adds the diagnostics of the text cap to `diags`.
pub(crate) fn load(binary: &Binary, budget: &mut Budget, diags: &mut Diags) -> Vec<Import> {
    let _ = (binary, budget, diags);
    Vec::new()
}

/// Gives the import slot map: the slot address to its import.
#[must_use]
pub fn slots(binary: &Binary) -> BTreeMap<u64, Slot> {
    let _ = binary;
    BTreeMap::new()
}
