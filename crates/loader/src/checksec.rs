//! The protections of an ELF file, as `checksec` gives them (design Section 4.6).
//!
//! | Field | Rule |
//! |---|---|
//! | `pie` | `ET_DYN` with an entry point, and `PT_INTERP` or `DF_1_PIE` |
//! | `nx` | `PT_GNU_STACK` without the execute bit |
//! | `relro` | `PT_GNU_RELRO` gives partial. `DF_BIND_NOW`, `DF_1_NOW` or `DT_BIND_NOW` makes it full. |
//! | `canary` | an import named `__stack_chk_fail` |
//! | `fortify` | an import whose name ends with `_chk` |
//! | `ibt`, `shstk` | bits 0 and 1 of `GNU_PROPERTY_X86_FEATURE_1_AND` in a GNU property note |
//! | `rpath`, `runpath` | the `DT_RPATH` and `DT_RUNPATH` texts |
//! | `stripped` | the file has no `SHT_SYMTAB` section |
//!
//! The x86 feature bits count only for x86-64 files. `DT_BIND_NOW` is the old form of
//! `DF_BIND_NOW` (gABI), so it counts too.

#[cfg(test)]
mod tests;

use ghidorah_kernel::{Endian, Reader};

use crate::binary::{
    Binary, ElfProtections, EntryKind, Format, Kind, Note, Protections, Relro, SectionKind,
    SegmentKind,
};
use crate::elf::consts::{
    DT_FLAGS, DT_FLAGS_1, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, SHT_SYMTAB,
};

/// Dynamic tag: process all relocations before the program starts (old form).
const DT_BIND_NOW: u64 = 24;
/// `DT_FLAGS` bit: process all relocations before the program starts.
const DF_BIND_NOW: u64 = 0x8;
/// `DT_FLAGS_1` bit: process all relocations before the program starts.
const DF_1_NOW: u64 = 0x1;
/// `DT_FLAGS_1` bit: the object is a position-independent executable.
const DF_1_PIE: u64 = 0x0800_0000;
/// Note type: GNU properties.
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// Property type: the x86 features that each object has.
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
/// The bit of IBT in `GNU_PROPERTY_X86_FEATURE_1_AND`.
const FEATURE_IBT: u32 = 1;
/// The bit of SHSTK in `GNU_PROPERTY_X86_FEATURE_1_AND`.
const FEATURE_SHSTK: u32 = 2;

/// Gives the protections of a loaded file. Only an ELF file gives a value here.
#[must_use]
pub fn protections(binary: &Binary) -> Option<Protections> {
    (binary.format == Format::Elf64Le).then(|| Protections::Elf(elf(binary)))
}

/// Gives the x86 feature bits of the GNU property notes. Several notes add their bits.
fn x86_features(notes: &[Note]) -> u32 {
    let mut bits = 0;
    for n in notes
        .iter()
        .filter(|n| n.kind == NT_GNU_PROPERTY_TYPE_0 && n.name.as_bytes() == b"GNU")
    {
        let mut r = Reader::new(&n.desc, Endian::Little);
        // Each property is 8 bytes of header, then its data padded to 8 bytes.
        while let (Ok(kind), Ok(size)) = (r.u32(), r.u32()) {
            let Ok(size) = usize::try_from(size) else {
                break;
            };
            let Ok(data) = r.take(size) else {
                break;
            };
            if kind == GNU_PROPERTY_X86_FEATURE_1_AND
                && let Some(word) = data.get(..4).and_then(|w| <[u8; 4]>::try_from(w).ok())
            {
                bits |= u32::from_le_bytes(word);
            }
            let pad = size.wrapping_neg() & 7;
            if r.skip(pad).is_err() {
                break;
            }
        }
    }
    bits
}

/// Gives the protections of an ELF file.
#[must_use]
pub fn elf(binary: &Binary) -> ElfProtections {
    let has_segment = |t| {
        binary
            .segments
            .iter()
            .any(|s| s.kind == SegmentKind::Elf(t))
    };
    let flags = binary.dyn_value(DT_FLAGS).unwrap_or(0);
    let flags_1 = binary.dyn_value(DT_FLAGS_1).unwrap_or(0);
    let entry = binary
        .entry_points
        .iter()
        .any(|e| e.kind == EntryKind::Entry);
    let pie =
        binary.kind == Kind::Dyn && entry && (has_segment(PT_INTERP) || flags_1 & DF_1_PIE != 0);
    let nx = binary
        .segments
        .iter()
        .any(|s| s.kind == SegmentKind::Elf(PT_GNU_STACK) && s.flags & PF_X == 0);
    let now = flags & DF_BIND_NOW != 0
        || flags_1 & DF_1_NOW != 0
        || binary.dyn_value(DT_BIND_NOW).is_some();
    let relro = match (has_segment(PT_GNU_RELRO), now) {
        (false, _) => Relro::None,
        (true, false) => Relro::Partial,
        (true, true) => Relro::Full,
    };
    let names = || {
        binary
            .imports
            .iter()
            .filter_map(|i| i.name.as_ref())
            .map(ghidorah_base::BinText::as_bytes)
    };
    let features = if binary.arch.is_x86_64() {
        x86_features(&binary.notes)
    } else {
        0
    };
    ElfProtections {
        pie,
        nx,
        relro,
        canary: names().any(|n| n == b"__stack_chk_fail"),
        fortify: names().any(|n| n.ends_with(b"_chk")),
        ibt: features & FEATURE_IBT != 0,
        shstk: features & FEATURE_SHSTK != 0,
        rpath: binary.rpath.clone(),
        runpath: binary.runpath.clone(),
        stripped: !binary
            .sections
            .iter()
            .any(|s| s.kind == SectionKind::Elf(SHT_SYMTAB)),
    }
}
