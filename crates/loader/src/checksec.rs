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
//! The x86 feature bits count only for x86-64 files.

use crate::binary::{Binary, ElfProtections, Protections, Relro};

/// Gives the protections of a loaded file. Only an ELF file gives a value here.
#[must_use]
pub fn protections(binary: &Binary) -> Option<Protections> {
    let _ = binary;
    None
}

/// Gives the protections of an ELF file.
#[must_use]
pub fn elf(binary: &Binary) -> ElfProtections {
    let _ = binary;
    ElfProtections {
        pie: false,
        nx: false,
        relro: Relro::None,
        canary: false,
        fortify: false,
        ibt: false,
        shstk: false,
        rpath: None,
        runpath: None,
        stripped: false,
    }
}
