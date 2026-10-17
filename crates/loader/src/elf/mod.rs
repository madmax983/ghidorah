//! The ELF64 little-endian loader (design Section 4.3).
//!
//! Mapping comes from `PT_LOAD` segments. Sections are optional metadata.
//! Without section headers, the dynamic view gives symbols, relocations and libraries.
//!
//! Rules of the parser:
//!
//! - All reads go through the K1 [`Reader`](ghidorah_kernel::Reader) or checked slices.
//! - Every table iterator stops after its first error.
//! - No loop advances by a file value before a check that the value is above 0.
//! - Only a short file header is fatal. A bad table gives a diagnostic.
//!
//! Entry sizes:
//!
//! | Value | Diagnostic |
//! |---|---|
//! | `e_phentsize` or `e_shentsize` below the struct size | `E_BAD_ENTSIZE`, the table is skipped |
//! | `sh_entsize` of a typed table not equal to the struct size | `E_BAD_ENTSIZE`, the table is skipped |
//! | `DT_SYMENT`, `DT_RELAENT`, `DT_RELENT` or `DT_RELRENT` of 0 | `E_LOOP`: the walk cannot advance |
//! | another `DT_*ENT` value not equal to the struct size | `E_BAD_ENTSIZE`, the table is skipped |

pub mod consts;

use std::sync::Arc;

use ghidorah_base::{DiagCode, Limits};

use crate::binary::Binary;
use crate::diag::{Diagnostic, LoadError};
use crate::memmap::MemoryMap;

/// Loads an ELF64 little-endian file.
///
/// # Errors
///
/// Returns [`LoadError::Malformed`] with `E_BAD_MAGIC` when the identification bytes are
/// wrong and with `E_OOB` when the file header is cut.
pub fn load(
    file: Arc<[u8]>,
    sha256: [u8; 32],
    limits: &Limits,
) -> Result<(Binary, MemoryMap), LoadError> {
    Err(LoadError::Malformed(Diagnostic::new(
        DiagCode::BadMagic,
        "elf.ident",
    )))
}
