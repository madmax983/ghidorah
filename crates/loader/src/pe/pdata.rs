//! `.pdata`: `RUNTIME_FUNCTION` entries, fragments and unwind chains (design Section 4.14).
//!
//! The Exception directory holds entries of 12 bytes: `BeginAddress`, `EndAddress` and
//! `UnwindInfoAddress`, all RVAs. `UNWIND_INFO` byte 0 holds the version (bits 0 to 2) and the
//! flags (bits 3 to 7). An entry whose unwind data has `CHAININFO` is a fragment of another
//! function.
//!
//! | Entry | Result |
//! |---|---|
//! | `EndAddress <= BeginAddress`, or a range outside executable memory | `E_OOB`, no entry |
//! | more entries than the `.pdata` limit | `E_LIMIT`, the first entries stay |
//! | a fragment | `fragment: true`, and [`chain_root`] walks to the root of its chain |
//! | a chain with a cycle or deeper than the unwind depth limit | `E_LOOP` |
//!
//! The chained `RUNTIME_FUNCTION` follows the unwind codes: at offset 4 plus 2 bytes for each
//! code, with the code count rounded up to an even number.

use std::collections::BTreeSet;

use ghidorah_base::{DiagCode, Limits};

use super::Px;
use crate::binary::RuntimeFunction;
use crate::diag::Diagnostic;
use crate::memmap::MemoryMap;

/// The `CHAININFO` flag of `UNWIND_INFO`.
pub const UNW_FLAG_CHAININFO: u8 = 4;

/// The size of one `RUNTIME_FUNCTION` entry.
const ENTRY: u64 = 12;

/// The error of a chain walk: a cycle, or a chain deeper than the unwind depth limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainLoop {
    /// The unwind data RVA where the walk stops.
    pub at: u32,
}

impl std::fmt::Display for ChainLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The unwind chain at RVA {:#x} has a cycle or is too deep.",
            self.at
        )
    }
}

impl std::error::Error for ChainLoop {}

/// Reads `len` bytes at the RVA `rva` of a map with the image base `base`.
fn read(map: &MemoryMap, base: u64, rva: u32, len: u64, limits: &Limits) -> Option<Vec<u8>> {
    let va = base.checked_add(u64::from(rva))?;
    map.read(va, len, limits)
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// Gives the little-endian `u32` at `at` of `bytes`.
fn word(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at.saturating_add(4))
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Gives the flags of the unwind data at `unwind`, or `None` when it does not read.
#[must_use]
pub fn unwind_flags(map: &MemoryMap, base: u64, unwind: u32, limits: &Limits) -> Option<u8> {
    read(map, base, unwind, 1, limits)?.first().map(|b| b >> 3)
}

/// Gives the chained `RUNTIME_FUNCTION` of the unwind data at `unwind`: begin, end and unwind.
fn chained(map: &MemoryMap, base: u64, unwind: u32, limits: &Limits) -> Option<(u32, u32, u32)> {
    let head = read(map, base, unwind, 4, limits)?;
    let codes = u32::from(*head.get(2)?);
    let even = codes.checked_add(codes & 1)?;
    let at = unwind.checked_add(4)?.checked_add(even.checked_mul(2)?)?;
    let rf = read(map, base, at, ENTRY, limits)?;
    Some((word(&rf, 0), word(&rf, 4), word(&rf, 8)))
}

/// Walks the unwind chain from the unwind data `unwind` of a fragment. Gives the
/// `BeginAddress` of the root: the first chained entry whose unwind data has no `CHAININFO`.
///
/// The result is `Ok(None)` when a link does not read.
///
/// # Errors
///
/// Returns [`ChainLoop`] for a cycle, or for a chain deeper than `limits.pe_unwind_depth`.
pub fn chain_root(
    map: &MemoryMap,
    base: u64,
    unwind: u32,
    limits: &Limits,
) -> Result<Option<u32>, ChainLoop> {
    let mut seen = BTreeSet::new();
    let mut at = unwind;
    for _ in 0..limits.pe_unwind_depth {
        if !seen.insert(at) {
            return Err(ChainLoop { at });
        }
        let Some((begin, _, next)) = chained(map, base, at, limits) else {
            return Ok(None);
        };
        let Some(flags) = unwind_flags(map, base, next, limits) else {
            return Ok(None);
        };
        if flags & UNW_FLAG_CHAININFO == 0 {
            return Ok(Some(begin));
        }
        at = next;
    }
    Err(ChainLoop { at })
}

/// Tells if the bytes `[begin, end)` of the image are executable.
fn exec_range(px: &Px<'_>, begin: u32, end: u32) -> bool {
    let first = px.base.checked_add(u64::from(begin));
    let last = end
        .checked_sub(1)
        .and_then(|e| px.base.checked_add(u64::from(e)));
    first
        .zip(last)
        .is_some_and(|(f, l)| px.is_exec(f) && px.is_exec(l))
}

/// Reads the Exception directory at `rva` with `size` bytes.
pub(crate) fn load(px: &mut Px<'_>, rva: u32, size: u32) -> Vec<RuntimeFunction> {
    let mut count = u64::from(size) / ENTRY;
    let limit = px.budget.limits.pe_pdata_entries;
    if count > limit {
        px.diag(
            Diagnostic::new(DiagCode::Limit, "pe.pdata")
                .need(count)
                .have(limit),
        );
        count = limit;
    }
    let left = px
        .base
        .checked_add(u64::from(rva))
        .map_or(0, |va| px.avail(va));
    if count > left / ENTRY {
        px.diag(
            Diagnostic::new(DiagCode::Oob, "pe.pdata")
                .at(u64::from(rva))
                .need(count.saturating_mul(ENTRY))
                .have(left),
        );
    }
    let count = count.min(left / ENTRY);
    let Some(table) = px.read(rva, count.saturating_mul(ENTRY), "pe.pdata") else {
        return Vec::new();
    };
    let table = table.into_owned();
    let mut out = Vec::new();
    for (i, raw) in table
        .chunks_exact(usize::try_from(ENTRY).unwrap_or(usize::MAX))
        .enumerate()
    {
        let (begin, end, unwind) = (word(raw, 0), word(raw, 4), word(raw, 8));
        let path = format!("pe.pdata[{i}]");
        if end <= begin || !exec_range(px, begin, end) {
            px.diag(
                Diagnostic::new(DiagCode::Oob, path)
                    .at(u64::from(begin))
                    .have(u64::from(end)),
            );
            continue;
        }
        let limits = px.budget.limits;
        let flags = unwind_flags(px.map, px.base, unwind, &limits).unwrap_or(0);
        let fragment = flags & UNW_FLAG_CHAININFO != 0;
        if fragment && let Err(e) = chain_root(px.map, px.base, unwind, &limits) {
            px.diag(Diagnostic::new(DiagCode::Loop, path).at(u64::from(e.at)));
        }
        out.push(RuntimeFunction {
            begin,
            end,
            unwind,
            fragment,
        });
    }
    out
}
