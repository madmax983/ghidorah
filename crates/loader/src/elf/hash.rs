//! Dynamic symbol counts from `DT_HASH` and `DT_GNU_HASH` (design Section 4.3).
//!
//! `DT_HASH` gives the count in `nchain`. With only `DT_GNU_HASH`, the count comes from
//! the largest bucket value: the walk follows its chain to the entry with bit 0 set.
//! The table length bounds each walk. A walk that runs off the table gives `E_LOOP`.
//!
//! The loader walks both tables when they exist, also with section headers. So a broken
//! chain always gives its diagnostic.

use ghidorah_base::DiagCode;

use super::consts::{DT_GNU_HASH, DT_HASH};
use super::dynamic::Dyn;
use super::view::{Cx, Fields, va_bytes};
use crate::binary::Section;
use crate::diag::Diagnostic;
use crate::memmap::MemoryMap;

/// Gives the bytes of a hash table at `va`. A section at the same address gives the length.
fn table<'a>(
    cx: &mut Cx<'a>,
    map: &MemoryMap,
    sections: &[Section],
    va: u64,
    path: &str,
) -> Option<&'a [u8]> {
    let size = sections
        .iter()
        .find(|s| s.va.is_some() && s.addr == va)
        .map_or(u64::MAX, |s| s.size);
    let found = va_bytes(map, cx.bytes, va, size).map(|(b, _)| b);
    if found.is_none() {
        cx.diag(Diagnostic::new(DiagCode::Oob, path).at(va));
    }
    found
}

/// Gives the `nchain` value of a System V hash table.
fn sysv(cx: &mut Cx<'_>, bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        cx.diag(Diagnostic::new(DiagCode::Oob, "elf.hash").need(8));
        return None;
    }
    let mut f = Fields::new(bytes);
    let _nbucket = f.u32();
    Some(u64::from(f.u32()))
}

/// Reads the `u32` at word index `i` of `bytes`.
fn word(bytes: &[u8], i: u64) -> Option<u32> {
    let at = usize::try_from(i.checked_mul(4)?).ok()?;
    let end = at.checked_add(4)?;
    let b: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// Gives the symbol count of a GNU hash table.
fn gnu(cx: &mut Cx<'_>, bytes: &[u8]) -> Option<u64> {
    let (Some(nbuckets), Some(symoffset), Some(bloom)) =
        (word(bytes, 0), word(bytes, 1), word(bytes, 2))
    else {
        cx.diag(Diagnostic::new(DiagCode::Oob, "elf.gnu_hash").need(16));
        return None;
    };
    let words = u64::try_from(bytes.len() / 4).unwrap_or(u64::MAX);
    // Header of 4 words, then 64-bit bloom words, then buckets, then chains.
    let buckets = u64::from(bloom).saturating_mul(2).saturating_add(4);
    let chains = buckets.saturating_add(u64::from(nbuckets));
    if chains > words {
        cx.diag(
            Diagnostic::new(DiagCode::Oob, "elf.gnu_hash")
                .need(chains.saturating_mul(4))
                .have(words.saturating_mul(4)),
        );
        return None;
    }
    let mut top = 0u32;
    for i in buckets..chains {
        top = top.max(word(bytes, i).unwrap_or(0));
    }
    if top < symoffset {
        return Some(u64::from(symoffset));
    }
    let mut sym = u64::from(top);
    loop {
        let at = chains.saturating_add(sym.saturating_sub(u64::from(symoffset)));
        let Some(value) = word(bytes, at) else {
            cx.diag(
                Diagnostic::new(DiagCode::Loop, "elf.gnu_hash.chain")
                    .at(sym)
                    .hint("the chain has no end bit in the table"),
            );
            return None;
        };
        if value & 1 == 1 {
            return Some(sym.saturating_add(1));
        }
        sym = sym.saturating_add(1);
    }
}

/// Gives the dynamic symbol count of the hash tables. `DT_HASH` wins over `DT_GNU_HASH`.
pub(crate) fn count(
    cx: &mut Cx<'_>,
    map: &MemoryMap,
    sections: &[Section],
    d: &Dyn,
) -> Option<u64> {
    let sysv_count = d.get(DT_HASH).and_then(|va| {
        let bytes = table(cx, map, sections, va, "elf.hash")?;
        sysv(cx, bytes)
    });
    let gnu_count = d.get(DT_GNU_HASH).and_then(|va| {
        let bytes = table(cx, map, sections, va, "elf.gnu_hash")?;
        gnu(cx, bytes)
    });
    sysv_count.or(gnu_count)
}
