//! `.eh_frame`: CIE and FDE records, pointer encodings and CFA rows (design Section 4.4).
//!
//! The loader finds `.eh_frame` through its section. Without a `.eh_frame` section, it reads
//! the `eh_frame_ptr` field of `.eh_frame_hdr` through `PT_GNU_EH_FRAME`. It does not read
//! the sorted table of `.eh_frame_hdr`.
//!
//! Records:
//!
//! | Field | Rule |
//! |---|---|
//! | length | 4 bytes. `0xffffffff` escapes to an 8-byte length. 0 ends the list. |
//! | CIE ID | 0 marks a CIE. Another value is the backward CIE pointer of an FDE. |
//! | CIE version | 1, 3 or 4. Another value gives `E_BAD_MAGIC`. |
//! | augmentation | `z`, then `L`, `P`, `R`, `S`, `B` or `G`. An empty text is valid. |
//! | FDE pointers | The `R` encoding. The default is `DW_EH_PE_absptr`. |
//!
//! Each FDE gives its PC range and its CFA rows (see [`cfa`](self) rules below).
//! An FDE with a PC range of 0 gives no record. An FDE with a bad CIE pointer or a bad
//! pointer gives a diagnostic, and the walk goes on with the next record. A record that
//! runs past the data stops the walk with `E_OOB`.
//!
//! CFA rows:
//!
//! - The interpreter reads `DW_CFA_advance_loc*`, `def_cfa*`, `offset*`, `restore*`,
//!   `remember_state`, `restore_state` and `nop`.
//! - It also reads the register-rule opcodes (`undefined`, `same_value`, `register`,
//!   `expression`, `val_*`, `GNU_args_size`, `GNU_negative_offset_extended`). They do not
//!   change the CFA, so the rows do not change.
//! - `def_cfa_expression` and other opcodes stop the FDE with `E_CFA_OPCODE`.
//! - A stopped FDE keeps its PC range and has no CFA rows. So no reader gets a wrong row.
//! - A row starts at each address where the CFA rule changes. Rows at or after the end of
//!   the PC range are not kept.

mod cfa;
mod pointer;
#[cfg(test)]
mod tests;

use ghidorah_base::Limits;

pub use pointer::{Bases, PointerError, read_pointer};

use crate::binary::{Binary, Fde};
use crate::diag::{Diagnostic, Diags};
use crate::memmap::MemoryMap;

/// The place of `.eh_frame` bytes: the address and the file offset of the first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Place {
    /// The virtual address of the first byte.
    pub va: u64,
    /// The file offset of the first byte.
    pub file_off: u64,
}

/// The result of one `.eh_frame` walk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EhFrame {
    /// The FDEs in record order.
    pub fdes: Vec<Fde>,
    /// The kept diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// The count of diagnostics above [`MAX_DIAGNOSTICS`](crate::diag::MAX_DIAGNOSTICS).
    pub dropped: u64,
}

impl EhFrame {
    fn from_parts(fdes: Vec<Fde>, diags: Diags) -> Self {
        let (diagnostics, dropped) = diags.into_parts();
        Self {
            fdes,
            diagnostics,
            dropped,
        }
    }
}

/// Parses the `.eh_frame` of a loaded ELF file.
///
/// The bytes come from the `.eh_frame` section, else from `PT_GNU_EH_FRAME`.
#[must_use]
pub fn parse(binary: &Binary, map: &MemoryMap, limits: &Limits) -> EhFrame {
    let mut diags = Diags::default();
    let fdes = load(binary, map, limits, &mut diags);
    EhFrame::from_parts(fdes, diags)
}

/// Parses `.eh_frame` bytes at `place`.
///
/// The walk has no memory map, so an indirect pointer gives `E_OOB`.
#[must_use]
pub fn parse_bytes(bytes: &[u8], place: Place, limits: &Limits) -> EhFrame {
    let mut diags = Diags::default();
    let fdes = walk(bytes, place, None, limits, &mut diags);
    EhFrame::from_parts(fdes, diags)
}

/// Gives the FDEs of a loaded ELF file and adds the diagnostics to `diags`.
pub(crate) fn load(
    binary: &Binary,
    map: &MemoryMap,
    limits: &Limits,
    diags: &mut Diags,
) -> Vec<Fde> {
    let _ = (binary, map, limits, diags);
    Vec::new()
}

/// Walks the records of `bytes` up to the zero terminator or the end of the bytes.
fn walk(
    bytes: &[u8],
    place: Place,
    mem: Option<&MemoryMap>,
    limits: &Limits,
    diags: &mut Diags,
) -> Vec<Fde> {
    let _ = (bytes, place, mem, limits, diags);
    Vec::new()
}
