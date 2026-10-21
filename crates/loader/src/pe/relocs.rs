//! Base relocation blocks (design Section 4.13).
//!
//! A block is `PageRVA`, `BlockSize` (with the 8-byte header) and `u16` entries with the type
//! in the high 4 bits.
//!
//! | Entry or block | Result |
//! |---|---|
//! | `ABSOLUTE` (0) | padding: no relocation |
//! | `HIGHLOW` (3) | a 4-byte slot: a [`Reloc`] of kind 3 |
//! | `DIR64` (10) | an 8-byte slot: a [`Reloc`] of kind 10 |
//! | another type | `E_UNSUPPORTED_RELOC` once for each type, and the walk skips the entry |
//! | `BlockSize` below 8 | `E_LOOP`: the block never advances, so the walk stops |
//! | a block past the directory | `E_OOB`, and the walk stops |
//!
//! A relocation has the form `Rel`: the value is in the slot. Its source is the section that
//! holds the directory, or the index `u32::MAX` when no section holds it.

use std::collections::BTreeSet;

use ghidorah_base::DiagCode;

use super::Px;
use crate::binary::{Binary, Reloc, RelocForm, RelocSource, RelocType, SymTable};
use crate::diag::Diagnostic;

/// `IMAGE_REL_BASED_ABSOLUTE`.
pub const REL_ABSOLUTE: u32 = 0;
/// `IMAGE_REL_BASED_HIGHLOW`: a 4-byte slot.
pub const REL_HIGHLOW: u32 = 3;
/// `IMAGE_REL_BASED_DIR64`: an 8-byte slot.
pub const REL_DIR64: u32 = 10;

/// The size of a block header.
const BLOCK_HEAD: u32 = 8;

/// Gives the source of the relocations: the section that holds the directory at `rva`.
fn source(b: &Binary, rva: u32, base: u64) -> RelocSource {
    let va = base.checked_add(u64::from(rva));
    let index = b
        .sections
        .iter()
        .find(|s| s.va.zip(va).is_some_and(|(r, v)| r.contains(v)))
        .map_or(u32::MAX, |s| s.index);
    RelocSource::Section(index)
}

/// Reads the base relocation blocks of the directory at `rva` with `size` bytes.
pub(crate) fn load(px: &mut Px<'_>, rva: u32, size: u32, b: &Binary) -> Vec<Reloc> {
    let src = source(b, rva, px.base);
    let end = rva.saturating_add(size);
    let mut out = Vec::new();
    let mut told = BTreeSet::new();
    let mut at = rva;
    let mut block = 0u32;
    while at < end {
        let path = format!("pe.basereloc[{block}]");
        let (Some(page), Some(block_size)) = (
            px.u32_at(at, &path),
            at.checked_add(4).and_then(|a| px.u32_at(a, &path)),
        ) else {
            break;
        };
        if block_size < BLOCK_HEAD {
            px.diag(
                Diagnostic::new(DiagCode::Loop, path)
                    .at(u64::from(at))
                    .need(u64::from(BLOCK_HEAD))
                    .have(u64::from(block_size)),
            );
            break;
        }
        let Some(next) = at.checked_add(block_size).filter(|n| *n <= end) else {
            px.diag(
                Diagnostic::new(DiagCode::Oob, path)
                    .at(u64::from(at))
                    .need(u64::from(block_size))
                    .have(u64::from(end.saturating_sub(at))),
            );
            break;
        };
        let count = (block_size.saturating_sub(BLOCK_HEAD)) / 2;
        let want = px
            .budget
            .take_relocs(u64::from(count), &path, &mut px.diags);
        // The read takes only the entries that the cap keeps, so a huge block allocates little.
        let entries = at
            .checked_add(BLOCK_HEAD)
            .filter(|_| want > 0)
            .and_then(|e| px.read(e, want.saturating_mul(2), &path))
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default();
        for pair in entries.chunks_exact(2) {
            let e = u16::from_le_bytes([
                pair.first().copied().unwrap_or(0),
                pair.get(1).copied().unwrap_or(0),
            ]);
            let kind = u32::from(e >> 12);
            if kind == REL_ABSOLUTE {
                continue;
            }
            if kind != REL_HIGHLOW && kind != REL_DIR64 {
                if told.insert(kind) {
                    px.diag(
                        Diagnostic::new(DiagCode::UnsupportedReloc, path.clone())
                            .have(u64::from(kind)),
                    );
                }
                continue;
            }
            let Some(offset) = page
                .checked_add(u32::from(e & 0xfff))
                .and_then(|r| px.base.checked_add(u64::from(r)))
            else {
                continue;
            };
            out.push(Reloc {
                offset,
                kind: RelocType(kind),
                sym: None,
                sym_table: SymTable::Symtab,
                addend: 0,
                form: RelocForm::Rel,
                source: src,
            });
        }
        at = next;
        block = block.saturating_add(1);
    }
    out
}
