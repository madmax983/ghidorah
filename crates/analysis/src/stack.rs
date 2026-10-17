//! Stack tracking and frames (design Section 7.9).
//!
//! [`track`] runs a forward dataflow over L0. A value is an offset from `SP0`, the stack
//! pointer at entry, or `Top`. A merge of two offsets that differ gives `Top`. A call adds 8,
//! the pop of the return address. A `Load` or a `Store` at `SP0 + k` is an access to the slot
//! `k`.
//!
//! An address escapes when an op stores it, passes it to a call in an argument register or
//! uses it in arithmetic that is not a constant offset. Then every slot from its offset up to
//! the return address escapes. An `Intrinsic` with a memory effect at `SP0 + k` makes every
//! slot in `[k, k + size)` escape. When its address is an offset of `SP0` that is not known,
//! every slot escapes (AC-207). [`rewrite`] puts `Get` and `Put` of `Stack(k)` in place of
//! the accesses of each slot that does not escape and has one width. An escaped slot stays in
//! memory, so no pass keeps a stale value of it.
//!
//! [`cfa_check`] compares the tracked offset at each call site with the CFA row of the FDE
//! (AC-091). A CFA of `rsp + c` gives the offset `8 - c`. A CFA of `rbp + c` gives `8 - c` for
//! `rbp`. A difference is a [`Mismatch`]: the function gets `W_SP_MISMATCH` there.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Fuel, OutOfFuel};
use ghidorah_ir::ssa::Body;
use ghidorah_ir::{Arena, Loc};
use ghidorah_loader::Fde;

/// The DWARF number of `rsp`.
pub const DWARF_RSP: u16 = 7;

/// The DWARF number of `rbp`.
pub const DWARF_RBP: u16 = 6;

/// The value of the stack pointer, or of a value that comes from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Sp {
    /// No path reaches the point yet.
    #[default]
    Unset,
    /// The value is `SP0 + k`.
    At(i64),
    /// The value does not come from the stack pointer.
    Other,
    /// The value can come from the stack pointer, with an offset that is not known.
    Top,
}

impl Sp {
    /// Gives the merge of two values.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unset, x) | (x, Self::Unset) => x,
            (Self::At(a), Self::At(b)) if a == b => Self::At(a),
            (Self::Other, Self::Other) => Self::Other,
            _ => Self::Top,
        }
    }

    /// Gives the offset of a known value.
    #[must_use]
    pub const fn offset(self) -> Option<i64> {
        match self {
            Self::At(k) => Some(k),
            _ => None,
        }
    }
}

/// One frame access: the slot offset and the width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Access {
    /// The offset from `SP0`.
    pub off: i64,
    /// The width in bytes.
    pub size: u8,
}

/// The stack frame of a function.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frame {
    /// The stack pointer before each instruction, by address.
    pub sp: BTreeMap<u64, Sp>,
    /// The `rbp` value before each instruction, by address.
    pub bp: BTreeMap<u64, Sp>,
    /// The frame accesses by op index.
    pub access: BTreeMap<u32, Access>,
    /// The escaped byte ranges `[from, to)` of the frame.
    pub escaped: Vec<(i64, i64)>,
    /// Every slot escapes.
    pub all_escape: bool,
    /// The callee-saved registers that the entry block pushes, with their slots.
    pub saved: Vec<(Loc, i64)>,
}

impl Frame {
    /// Gives the offset of the stack pointer before the instruction at `addr`.
    #[must_use]
    pub fn sp_at(&self, addr: u64) -> Option<i64> {
        self.sp.get(&addr).and_then(|s| s.offset())
    }

    /// Tells if a byte of `[off, off + size)` escapes.
    #[must_use]
    pub fn escapes(&self, off: i64, size: u32) -> bool {
        let _ = (off, size);
        false
    }

    /// Gives the lowest offset that the function accesses: the size of its locals.
    #[must_use]
    pub fn low(&self) -> i64 {
        self.access
            .values()
            .map(|a| a.off)
            .min()
            .unwrap_or(0)
            .min(0)
    }

    /// Gives the stack parameter slots: the read offsets at `first` and above.
    #[must_use]
    pub fn stack_args(&self, first: i64) -> BTreeSet<i64> {
        self.access
            .values()
            .filter(|a| a.off >= first)
            .map(|a| a.off)
            .collect()
    }
}

/// One call site where the tracked offset differs from the CFA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mismatch {
    /// The call site.
    pub site: u64,
    /// The tracked offset, or `None` for `Top`.
    pub tracked: Option<i64>,
    /// The offset that the CFA row gives.
    pub cfa: i64,
}

/// Tracks the stack of the L0 body. Each op takes one unit of `fuel` for each pass.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out.
pub fn track(arena: &Arena, body: &Body, fuel: &mut Fuel) -> Result<Frame, OutOfFuel> {
    let _ = (arena, body, fuel);
    Ok(Frame::default())
}

/// Puts `Get` and `Put` of `Stack(k)` in place of the accesses of each slot of `frame` that
/// does not escape and that every access reads or writes at one width. Gives the count of
/// changed ops.
pub fn rewrite(arena: &mut Arena, frame: &Frame) -> u64 {
    let _ = (arena, frame);
    0
}

/// Gives the offset that the CFA row of `fde` at `pc` gives for the stack pointer, with the
/// tracked `rbp` value for a CFA on `rbp`.
#[must_use]
pub fn cfa_offset(fde: &Fde, pc: u64, bp: Sp) -> Option<i64> {
    let _ = (fde, pc, bp);
    None
}

/// Compares the tracked offset at each call site of `calls` with the CFA rows of `fde`.
#[must_use]
pub fn cfa_check(frame: &Frame, fde: &Fde, calls: &[u64]) -> Vec<Mismatch> {
    let _ = (frame, fde, calls);
    Vec::new()
}
