//! The gap worklist (design Section 7.3, ADR-0024).
//!
//! The MVP has no prologue-pattern gap fill. Executable code that no function owns becomes a
//! gap item with the remedy `func_edit { action: "create" }`. The items are derived data of the
//! committed facts. They have no band and no work state.
//!
//! Rules:
//!
//! - The scope is the executable sections, or the executable regions of a file with no section
//!   headers, without the PLT area. The PLT area holds the PLT sections and each stub that the
//!   loader finds, up to the next 16-byte boundary.
//! - The function bodies of both layers leave the scope. So do the FDE ranges and the extents of
//!   the function symbols: code after a noreturn call in a known function is no gap.
//! - Padding is not a gap: a `nop` form, `int3` and a 0 byte. Padding splits a range, so each
//!   gap item is a run without padding.
//! - Bytes that do not decode stay in the gap, one byte at a time.
//! - The scan reads at most [`MAX_SCAN`] bytes of each range.

use ghidorah_base::{Limits, Range};
use ghidorah_db::Program;
use ghidorah_kernel::RangeSet;
use ghidorah_loader::{Perms, SectionKind, SymKind};
use ghidorah_x86::{Mnem, NoSymbols, Opts, decode, print};

use crate::analyzers::metrics::Remedy;
use crate::code::plt_area;

/// The size of a PLT entry.
const PLT_ENTRY: u64 = 16;

/// The largest number of bytes that a gap item shows.
pub const SHOW_BYTES: usize = 16;

/// The largest number of bytes of one range that the scan reads.
pub const MAX_SCAN: u64 = 16 << 20;

/// `SHF_EXECINSTR`.
const SHF_EXECINSTR: u64 = 0x4;
/// The PE section flag `IMAGE_SCN_MEM_EXECUTE`.
const SCN_MEM_EXECUTE: u64 = 0x2000_0000;

/// One gap item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gap {
    /// The addresses of the gap.
    pub range: Range,
    /// The first bytes of the gap, at most [`SHOW_BYTES`].
    pub bytes: Vec<u8>,
    /// The display text of the first instruction, or `None` when it does not decode.
    pub first_insn: Option<String>,
}

impl Gap {
    /// Gives the remedy: `func_edit { action: "create" }` at the first address.
    #[must_use]
    pub const fn remedy(&self) -> Remedy {
        Remedy::Create(self.range.first)
    }
}

/// Gives the executable scope of `program`: executable sections, or executable regions.
pub(crate) fn scope(program: &Program) -> RangeSet {
    let mut regions = RangeSet::new();
    for r in program.mem().regions() {
        if r.perms.contains(Perms::EXECUTE) {
            regions.insert(r.va);
        }
    }
    let sections = &program.binary().sections;
    if sections.iter().all(|s| s.va.is_none()) {
        return regions;
    }
    let mut out = RangeSet::new();
    for s in sections {
        let exec = match s.kind {
            SectionKind::Elf(_) => s.flags & SHF_EXECINSTR != 0,
            SectionKind::Pe => s.flags & SCN_MEM_EXECUTE != 0,
        };
        if let Some(va) = s.va
            && exec
        {
            out.insert(va);
        }
    }
    out.intersect(&regions)
}

/// Gives the length of the padding at the start of `rest`, or `None` for code.
pub(crate) fn padding(rest: &[u8], at: u64) -> Option<usize> {
    if rest.first() == Some(&0) {
        return Some(1);
    }
    let insn = decode(rest, at, &Opts::DEFAULT).ok()?;
    (insn.is_nop() || insn.mnem() == Mnem::Int3).then_some(usize::from(insn.len()))
}

/// Gives the length of the code item at the start of `rest`: one instruction or one bad byte.
fn code_len(rest: &[u8], at: u64) -> usize {
    decode(rest, at, &Opts::DEFAULT).map_or(1, |insn| usize::from(insn.len()).max(1))
}

/// Gives the address of the offset `i` from `base`.
fn offset(base: u64, i: usize) -> Option<u64> {
    base.checked_add(u64::try_from(i).ok()?)
}

/// Makes the gap item of `bytes` at `at`.
fn item(at: u64, bytes: &[u8]) -> Option<Gap> {
    let len = u64::try_from(bytes.len()).ok()?;
    let range = Range::with_len(at, len)?;
    let first_insn = decode(bytes, at, &Opts::DEFAULT)
        .ok()
        .map(|insn| print(&insn, &NoSymbols));
    Some(Gap {
        range,
        bytes: bytes.get(..SHOW_BYTES).unwrap_or(bytes).to_vec(),
        first_insn,
    })
}

/// Splits the unowned range `r` at its padding and adds the gap items to `out`.
fn split(program: &Program, r: Range, out: &mut Vec<Gap>) {
    let len = u64::try_from(r.len()).unwrap_or(u64::MAX).min(MAX_SCAN);
    let Ok(bytes) = program.mem().read(r.first, len, &Limits::DEFAULT) else {
        return;
    };
    let mut i = 0usize;
    let mut start: Option<usize> = None;
    while let Some(rest) = bytes.get(i..).filter(|b| !b.is_empty()) {
        let Some(at) = offset(r.first, i) else {
            break;
        };
        if let Some(k) = padding(rest, at) {
            if let Some(s) = start.take() {
                out.extend(bytes.get(s..i).and_then(|b| item(offset(r.first, s)?, b)));
            }
            i = i.saturating_add(k.max(1));
        } else {
            start.get_or_insert(i);
            i = i.saturating_add(code_len(rest, at));
        }
    }
    if let Some(s) = start {
        let end = i.min(bytes.len());
        out.extend(bytes.get(s..end).and_then(|b| item(offset(r.first, s)?, b)));
    }
}

/// Gives the addresses that the facts of the binary own. These are the PLT area up to the
/// next 16-byte boundary, the FDE ranges and the extents of the function symbols.
pub(crate) fn fixed(program: &Program) -> RangeSet {
    let mut owned = Vec::new();
    for r in plt_area(program).ranges() {
        let end = r.last.checked_add(PLT_ENTRY).map(|e| e & !(PLT_ENTRY - 1));
        let last = end
            .and_then(|e| e.checked_sub(1))
            .unwrap_or(r.last)
            .max(r.last);
        owned.push(Range {
            first: r.first,
            last,
        });
    }
    let b = program.binary();
    let symbols = b
        .symbols
        .iter()
        .filter(|s| s.kind == SymKind::Func)
        .filter_map(|s| Range::with_len(s.addr, s.size));
    owned.extend(b.fdes.iter().map(|f| f.range).chain(symbols));
    set_of(owned)
}

/// Gives the set of `ranges`. The ranges go in by start, so each insert lands at the end of
/// the set and the cost stays near linear.
pub(crate) fn set_of(mut ranges: Vec<Range>) -> RangeSet {
    ranges.sort_unstable_by_key(|r| r.first);
    RangeSet::from_ranges(&ranges)
}

/// Gives the gap items of `program` in address order.
#[must_use]
pub fn items(program: &Program) -> Vec<Gap> {
    let mut out = Vec::new();
    if !program.meta().arch.is_x86_64() {
        return out;
    }
    let mut owned = fixed(program);
    for layer in [program.base(), program.analysis()] {
        for f in layer.funcs().iter() {
            for r in f.body.ranges() {
                owned.insert(*r);
            }
        }
    }
    for r in scope(program).subtract(&owned).ranges() {
        split(program, *r, &mut out);
    }
    out
}
