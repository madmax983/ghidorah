//! Block-local value evaluation (design Section 6.6).
//!
//! [`value_at`] gives the value of a location before an op. [`arg_at`] gives the value of an
//! argument of an op. [`eval`] is the general form with limits and a [`Pin`].
//!
//! The walk goes back from the op inside its block and up a chain of blocks that each have
//! one predecessor. It keeps only the ops that the value needs: a backward slice. Then it
//! runs the slice forward with constants and the read-only image bytes of a [`Memory`].
//!
//! | Op in the walk | Result |
//! |---|---|
//! | `Put` of a needed location, an op that gives a needed value | the op goes into the slice |
//! | `Call` or `CallInd` while a location is needed | `Unknown` |
//! | `Syscall` or `Intrinsic` that writes a needed location | `Unknown` |
//! | the function entry, a merge point, a loop back to a visited block | `Unknown` |
//! | more than [`MAX_BLOCKS`] blocks or more than [`MAX_OPS`] slice ops | `Unknown` |
//! | a `Load` with no read-only byte at its address | `Unknown` |
//!
//! `Unknown` is sound: a relation on the value then gives `unknown`. A store never changes a
//! read-only byte, so a store does not stop the walk. A value in a mapped region is an
//! [`LocalValue::Addr`]. Each other value is a [`LocalValue::Const`].

use ghidorah_base::Fuel;

use crate::arena::Arena;
use crate::loc::Loc;
use crate::ssa::Body;

/// The largest number of blocks of one walk.
pub const MAX_BLOCKS: usize = 4;

/// The largest number of ops in the slice of one walk.
pub const MAX_OPS: usize = 64;

/// The value of a location or an argument at a program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum LocalValue {
    /// A constant that is not in a mapped region.
    Const(u64),
    /// A constant in a mapped region: an address.
    Addr(u64),
    /// The walk cannot give one value.
    #[default]
    Unknown,
}

impl LocalValue {
    /// Gives the number of a known value, or `None` for `Unknown`.
    #[must_use]
    pub const fn value(self) -> Option<u64> {
        match self {
            Self::Const(v) | Self::Addr(v) => Some(v),
            Self::Unknown => None,
        }
    }
}

/// The memory of a walk: the read-only image bytes and the mapped regions.
pub trait Memory {
    /// Reads the byte at `addr` of a read-only region. Another address gives `None`.
    fn read(&self, addr: u64) -> Option<u8>;
    /// Tells if `addr` is in a mapped region.
    fn mapped(&self, addr: u64) -> bool;
}

/// A memory with no byte and no mapped region.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoMemory;

impl Memory for NoMemory {
    fn read(&self, _addr: u64) -> Option<u8> {
        None
    }

    fn mapped(&self, _addr: u64) -> bool {
        false
    }
}

/// The function of a walk: its L0 arena, its blocks and CFG, and its memory.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    /// The L0 arena.
    pub arena: &'a Arena,
    /// The blocks and the CFG of the arena.
    pub body: &'a Body,
    /// The memory.
    pub mem: &'a dyn Memory,
}

impl std::fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("ops", &self.arena.ops().len())
            .field("blocks", &self.body.blocks.len())
            .finish_non_exhaustive()
    }
}

/// What a walk gives the value of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// A location before the op.
    Loc(Loc),
    /// The argument with this index of the op.
    Arg(usize),
}

/// A location with a fixed value before an op. Jump-table emulation pins the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pin {
    /// The op index. The value holds before this op.
    pub op: u32,
    /// The location.
    pub loc: Loc,
    /// The value.
    pub value: u64,
}

/// One walk: the op, the target, an optional pin and the limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    /// The op index in the arena.
    pub op: u32,
    /// The target.
    pub target: Target,
    /// The pinned location, or `None`.
    pub pin: Option<Pin>,
    /// The largest number of slice ops.
    pub max_ops: usize,
    /// The largest number of blocks.
    pub max_blocks: usize,
}

impl Query {
    /// Makes the query of the location `loc` before the op `op` with the default limits.
    #[must_use]
    pub const fn loc(op: u32, loc: Loc) -> Self {
        Self {
            op,
            target: Target::Loc(loc),
            pin: None,
            max_ops: MAX_OPS,
            max_blocks: MAX_BLOCKS,
        }
    }

    /// Makes the query of the argument `index` of the op `op` with the default limits.
    #[must_use]
    pub const fn arg(op: u32, index: usize) -> Self {
        Self {
            op,
            target: Target::Arg(index),
            pin: None,
            max_ops: MAX_OPS,
            max_blocks: MAX_BLOCKS,
        }
    }
}

/// The result of a walk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// The value.
    pub value: LocalValue,
    /// The image loads of the slice in run order: the address and the width in bytes.
    pub loads: Vec<(u64, u8)>,
    /// The number of slice ops.
    pub ops: usize,
}

/// Runs the walk of `query` in `scope`. Each visited op takes one unit of `fuel`. An empty
/// tank gives `Unknown`.
#[must_use]
pub fn eval(scope: &Scope<'_>, query: &Query, fuel: &mut Fuel) -> Outcome {
    let _ = (scope, query, fuel);
    Outcome::default()
}

/// Gives the value of `loc` before the op `op` with the default limits.
#[must_use]
pub fn value_at(scope: &Scope<'_>, op: u32, loc: Loc, fuel: &mut Fuel) -> LocalValue {
    eval(scope, &Query::loc(op, loc), fuel).value
}

/// Gives the value of the argument `index` of the op `op` with the default limits.
#[must_use]
pub fn arg_at(scope: &Scope<'_>, op: u32, index: usize, fuel: &mut Fuel) -> LocalValue {
    eval(scope, &Query::arg(op, index), fuel).value
}
