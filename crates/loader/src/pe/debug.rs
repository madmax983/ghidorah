//! The `CodeView` identity of the debug directory (design Section 4.13).
//!
//! The debug directory holds entries of 28 bytes, at most the debug entry limit (64). The first
//! `CODEVIEW` entry (type 2) whose data starts with `RSDS` gives `{ guid, age, pdb }`. The data
//! comes from `AddressOfRawData`, or from `PointerToRawData` when that RVA is 0. The loader
//! skips the other debug types.

use ghidorah_base::{BinText, DiagCode};

use super::Px;
use crate::binary::CodeView;
use crate::diag::Diagnostic;

/// The size of one debug directory entry.
const ENTRY: u32 = 28;

/// The debug type `IMAGE_DEBUG_TYPE_CODEVIEW`.
const TYPE_CODEVIEW: u32 = 2;

/// The bytes of an `RSDS` record before the PDB path: signature, GUID and age.
const RSDS_HEAD: usize = 24;

/// Reads the little-endian `u32` at `at` of `bytes`.
fn word(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at.saturating_add(4))
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Gives the bytes of a record: by RVA, else by file offset.
fn record(px: &mut Px<'_>, rva: u32, file: u32, size: u32) -> Option<Vec<u8>> {
    if rva != 0 {
        return px
            .read(rva, u64::from(size), "pe.debug.AddressOfRawData")
            .map(std::borrow::Cow::into_owned);
    }
    let start = usize::try_from(file).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    let bytes = px.bytes.get(start..end);
    if bytes.is_none() {
        px.diag(
            Diagnostic::new(DiagCode::Oob, "pe.debug.PointerToRawData")
                .at(u64::from(file))
                .need(u64::from(size)),
        );
    }
    bytes.map(<[u8]>::to_vec)
}

/// Parses an `RSDS` record.
fn rsds(px: &mut Px<'_>, data: &[u8]) -> Option<CodeView> {
    if data.get(..4) != Some(b"RSDS") {
        return None;
    }
    let guid: [u8; 16] = data.get(4..20)?.try_into().ok()?;
    let age = word(data, 20);
    let rest = data.get(RSDS_HEAD..).unwrap_or_default();
    let limit = usize::try_from(px.budget.limits.string_len).unwrap_or(usize::MAX);
    let end = rest
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(rest.len())
        .min(limit);
    let path = rest.get(..end).unwrap_or_default();
    let size = u64::try_from(path.len()).unwrap_or(u64::MAX);
    let pdb = if px.budget.take_text(size, "pe.debug.pdb", &mut px.diags) {
        BinText::new(path)
    } else {
        BinText::default()
    };
    Some(CodeView { guid, age, pdb })
}

/// Reads the debug directory at `rva` with `size` bytes and gives the `CodeView` record.
pub(crate) fn load(px: &mut Px<'_>, rva: u32, size: u32) -> Option<CodeView> {
    let mut count = u64::from(size / ENTRY);
    let limit = px.budget.limits.pe_debug_entries;
    if count > limit {
        px.diag(
            Diagnostic::new(DiagCode::Limit, "pe.debug")
                .need(count)
                .have(limit),
        );
        count = limit;
    }
    for i in 0..count {
        let path = format!("pe.debug[{i}]");
        let at = u32::try_from(i)
            .ok()
            .and_then(|k| k.checked_mul(ENTRY))
            .and_then(|o| rva.checked_add(o))?;
        let entry = px.read(at, u64::from(ENTRY), &path)?.into_owned();
        if word(&entry, 12) != TYPE_CODEVIEW {
            continue;
        }
        let (len, data_rva, file) = (word(&entry, 16), word(&entry, 20), word(&entry, 24));
        // The record needs at most its head, the path limit and the NUL byte.
        let cap = u32::try_from(px.budget.limits.string_len)
            .unwrap_or(u32::MAX)
            .saturating_add(u32::try_from(RSDS_HEAD).unwrap_or(0))
            .saturating_add(1);
        let len = len.min(cap);
        let Some(data) = record(px, data_rva, file, len) else {
            continue;
        };
        if let Some(cv) = rsds(px, &data) {
            return Some(cv);
        }
    }
    None
}

/// Gives a GUID in the 8-4-4-4-12 form in upper case. The first three fields are
/// little-endian in the file, as in the Windows `GUID` type.
#[must_use]
pub fn guid_text(guid: &[u8; 16]) -> String {
    use std::fmt::Write;
    let [a0, a1, a2, a3, b0, b1, c0, c1, rest @ ..] = *guid;
    let mut out = format!(
        "{:08X}-{:04X}-{:04X}-",
        u32::from_le_bytes([a0, a1, a2, a3]),
        u16::from_le_bytes([b0, b1]),
        u16::from_le_bytes([c0, c1]),
    );
    for (i, b) in rest.iter().enumerate() {
        if i == 2 {
            out.push('-');
        }
        let _ = write!(out, "{b:02X}");
    }
    out
}
