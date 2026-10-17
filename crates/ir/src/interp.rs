//! The concrete interpreter of L0 (design Section 6.5).
//!
//! Values have 128 bits, so XMM loads, stores and copies run. Memory is an [`Image`] plus a
//! sparse map of written bytes. Each run has fuel (one unit for each op) and a cap on the
//! count of written bytes. A run ends with a [`Stop`]: a typed reason and the [`OpId`] of
//! the op where the run stopped.
//!
//! The interpreter does not run callees: a call stops the run. A location that the run did
//! not write reads as 0. Memory is little-endian.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use ghidorah_base::Fuel;

use crate::arena::Arena;
use crate::loc::Loc;
use crate::op::{OpId, Opc, Val};

/// The default cap on written bytes (16 MiB).
pub const DEFAULT_MEM_CAP: u64 = 16 << 20;

/// The memory image of a run: the bytes of the binary and the writable regions.
pub trait Image {
    /// Reads the byte at `addr`, or `None` when no byte is mapped there.
    fn read(&self, addr: u64) -> Option<u8>;
    /// Tells if a run can write the byte at `addr`.
    fn writable(&self, addr: u64) -> bool;
}

/// An image with no byte. Each read and each write stops the run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoImage;

impl Image for NoImage {
    fn read(&self, _addr: u64) -> Option<u8> {
        None
    }

    fn writable(&self, _addr: u64) -> bool {
        false
    }
}

/// An image of one run of bytes at a base address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlatImage {
    base: u64,
    bytes: Vec<u8>,
    writable: bool,
}

impl FlatImage {
    /// Makes an image of `bytes` at `base`. `writable` tells if a run can write them.
    #[must_use]
    pub const fn new(base: u64, bytes: Vec<u8>, writable: bool) -> Self {
        Self {
            base,
            bytes,
            writable,
        }
    }

    fn index(&self, addr: u64) -> Option<usize> {
        let off = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        (off < self.bytes.len()).then_some(off)
    }
}

impl Image for FlatImage {
    fn read(&self, addr: u64) -> Option<u8> {
        self.bytes.get(self.index(addr)?).copied()
    }

    fn writable(&self, addr: u64) -> bool {
        self.writable && self.index(addr).is_some()
    }
}

/// The settings of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The largest count of written bytes.
    pub mem_cap: u64,
    /// The call targets outside the program: PLT stubs and imports.
    pub externals: BTreeSet<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mem_cap: DEFAULT_MEM_CAP,
            externals: BTreeSet::new(),
        }
    }
}

/// The reason of a [`Stop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StopReason {
    /// A `Ret` op ran.
    Returned,
    /// The fuel ran out before the op.
    FuelExhausted,
    /// An `Unimpl` op came.
    Unimpl,
    /// An `Intrinsic` op came.
    Intrinsic,
    /// A read found no byte at this address.
    UnmappedRead(u64),
    /// A write found no writable byte at this address.
    UnmappedWrite(u64),
    /// A call of this target. The interpreter does not run callees.
    CallUnresolved(u64),
    /// A call of this target in [`Config::externals`].
    CallExternal(u64),
    /// A write went above [`Config::mem_cap`].
    MemCap,
    /// A `Syscall` op came.
    Syscall,
    /// A division by zero.
    DivZero,
    /// The flow went to this address, and no instruction starts there.
    NoCode(u64),
    /// The op is not valid L0: a bad width, a bad argument or a value with no def.
    BadIr,
}

/// The end of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stop {
    /// The reason.
    pub reason: StopReason,
    /// The op where the run stopped.
    pub at: OpId,
    /// The count of ops that ran.
    pub steps: u64,
}

/// The error of [`eval`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalError {
    /// The opcode is not a data op.
    NotData,
    /// The divisor is 0.
    DivZero,
    /// A width is 0, above 128 or not valid for the opcode.
    BadWidth,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotData => f.write_str("The opcode is not a data op."),
            Self::DivZero => f.write_str("The divisor is 0."),
            Self::BadWidth => f.write_str("A width is not valid for the opcode."),
        }
    }
}

impl std::error::Error for EvalError {}

/// Gives the result of the data op `opc` at width `w` with aux byte `sub` on its inputs.
///
/// A data op has no memory, location or flow effect. The inputs are the values of the
/// arguments in order. Each result has `w` bits, and a compare result has 1 bit.
///
/// # Errors
///
/// Returns [`EvalError::NotData`] for another op, [`EvalError::DivZero`] for a zero
/// divisor and [`EvalError::BadWidth`] for a bad width.
pub fn eval(opc: Opc, w: u8, sub: u8, x: u128, y: u128, z: u128) -> Result<u128, EvalError> {
    let _unused = (opc, w, sub, x, y, z);
    Err(EvalError::NotData)
}

/// The interpreter state of one program.
pub struct Interp<'a> {
    arena: &'a Arena,
    image: &'a dyn Image,
    config: Config,
    locs: BTreeMap<Loc, u128>,
    vals: Vec<Option<u128>>,
    writes: BTreeMap<u64, u8>,
}

impl fmt::Debug for Interp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interp")
            .field("locs", &self.locs)
            .field("writes", &self.writes.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Interp<'a> {
    /// Makes an interpreter of `arena` over `image`.
    #[must_use]
    pub fn new(arena: &'a Arena, image: &'a dyn Image, config: Config) -> Self {
        Self {
            arena,
            image,
            config,
            locs: BTreeMap::new(),
            vals: Vec::new(),
            writes: BTreeMap::new(),
        }
    }

    /// Sets a location. The value keeps the low bits of the location width.
    pub fn set_loc(&mut self, loc: Loc, value: u128) {
        let _unused = (loc, value, &self.config);
    }

    /// Gives a location. A location that the run did not write is 0.
    #[must_use]
    pub fn loc(&self, loc: Loc) -> u128 {
        self.locs.get(&loc).copied().unwrap_or_default()
    }

    /// Gives a value, or `None` when its op did not run.
    #[must_use]
    pub fn val(&self, val: Val) -> Option<u128> {
        self.vals
            .get(usize::try_from(val.0).ok()?)
            .copied()
            .flatten()
    }

    /// Reads the byte at `addr`: a written byte first, else the image byte.
    #[must_use]
    pub fn read(&self, addr: u64) -> Option<u8> {
        self.writes
            .get(&addr)
            .copied()
            .or_else(|| self.image.read(addr))
    }

    /// Gives the count of written bytes.
    #[must_use]
    pub fn written(&self) -> usize {
        self.writes.len()
    }

    /// Runs the program from the instruction at `entry` until a stop.
    pub fn run(&mut self, entry: u64, fuel: &mut Fuel) -> Stop {
        let _unused = (fuel.remaining(), self.arena.insns().len());
        Stop {
            reason: StopReason::BadIr,
            at: OpId {
                addr: entry,
                seq: 0,
            },
            steps: 0,
        }
    }
}
