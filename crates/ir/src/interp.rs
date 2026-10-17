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

use crate::arena::{Arena, InsnSpan};
use crate::loc::Loc;
use crate::op::{Arg, Op, OpId, Opc, Val};

mod eval;

use eval::{low64, mask};

/// The default cap on written bytes (16 MiB).
pub const DEFAULT_MEM_CAP: u64 = 16 << 20;

/// The memory image of a run: the bytes of the binary and the writable regions.
pub trait Image {
    /// Reads the byte at `addr`. It gives `None` when the image has no byte there.
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
    eval::eval(opc, w, sub, x, y, z)
}

/// The effect of one op on the flow of a run.
enum Flow {
    /// Go to the next op.
    Next,
    /// Go to the instruction at this address.
    Goto(u64),
    /// Stop the run.
    Stop(StopReason),
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
            vals: vec![None; arena.val_count()],
            writes: BTreeMap::new(),
        }
    }

    /// Sets a location. The value keeps the low bits of the location width.
    pub fn set_loc(&mut self, loc: Loc, value: u128) {
        self.locs.insert(loc, value & mask(loc.width()));
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
    ///
    /// Each op takes one unit of `fuel` before it runs, and an instruction with no op takes
    /// one unit. [`Stop::steps`] is the count of units that the run took.
    pub fn run(&mut self, entry: u64, fuel: &mut Fuel) -> Stop {
        let mut steps = 0u64;
        let mut at = OpId {
            addr: entry,
            seq: 0,
        };
        let mut target = entry;
        loop {
            let Some(span) = self.span_at(target) else {
                return stop(StopReason::NoCode(target), at, steps);
            };
            let ops = self.arena.span_ops(&span).unwrap_or_default();
            if ops.is_empty() {
                at = OpId {
                    addr: span.addr,
                    seq: 0,
                };
                if fuel.tick().is_err() {
                    return stop(StopReason::FuelExhausted, at, steps);
                }
                steps = steps.saturating_add(1);
            }
            let mut jump = None;
            for op in ops {
                at = op.id;
                if fuel.tick().is_err() {
                    return stop(StopReason::FuelExhausted, at, steps);
                }
                steps = steps.saturating_add(1);
                match self.step(op) {
                    Flow::Next => {}
                    Flow::Goto(addr) => {
                        jump = Some(addr);
                        break;
                    }
                    Flow::Stop(reason) => return stop(reason, at, steps),
                }
            }
            target = match jump.or_else(|| span.next_addr()) {
                Some(addr) => addr,
                None => return stop(StopReason::NoCode(0), at, steps),
            };
        }
    }

    /// Gives the instruction that starts at `addr`.
    fn span_at(&self, addr: u64) -> Option<InsnSpan> {
        let index = self.arena.insn_index(addr)?;
        self.arena.insns().get(index).copied()
    }

    /// Gives the value of an argument. `Nil` is 0. A location or a value with no def gives
    /// `None`.
    fn arg(&self, arg: Arg) -> Option<u128> {
        match arg {
            Arg::Nil => Some(0),
            Arg::K(imm) => Some(u128::from(imm.get())),
            Arg::V(val) => self.val(val),
            Arg::L(_) => None,
        }
    }

    /// Gives the values of the three arguments of an op.
    fn args(&self, op: &Op) -> Option<(u128, u128, u128)> {
        let [a, b, c] = op.a;
        Some((self.arg(a)?, self.arg(b)?, self.arg(c)?))
    }

    /// Records the output value of an op.
    fn def(&mut self, op: &Op, value: u128) -> Flow {
        let Some(out) = op.out else {
            return Flow::Next;
        };
        match usize::try_from(out.0)
            .ok()
            .and_then(|i| self.vals.get_mut(i))
        {
            Some(slot) => {
                *slot = Some(value);
                Flow::Next
            }
            None => Flow::Stop(StopReason::BadIr),
        }
    }

    /// Runs one op.
    fn step(&mut self, op: &Op) -> Flow {
        let Some((x, y, z)) = self.args(op) else {
            return self.step_loc(op);
        };
        match op.opc {
            Opc::Load => self.load(op, low64(x)),
            Opc::Store => self.store(op, low64(x), y),
            Opc::Jump | Opc::JumpInd => Flow::Goto(low64(x)),
            Opc::CJump if x != 0 => Flow::Goto(low64(y)),
            Opc::CJump | Opc::Nop => Flow::Next,
            Opc::Call | Opc::CallInd => {
                let t = low64(x);
                Flow::Stop(if self.config.externals.contains(&t) {
                    StopReason::CallExternal(t)
                } else {
                    StopReason::CallUnresolved(t)
                })
            }
            Opc::Ret => Flow::Stop(StopReason::Returned),
            Opc::Syscall => Flow::Stop(StopReason::Syscall),
            Opc::Intrinsic => Flow::Stop(StopReason::Intrinsic),
            Opc::Unimpl => Flow::Stop(StopReason::Unimpl),
            Opc::Get | Opc::Put | Opc::Phi => Flow::Stop(StopReason::BadIr),
            _ => match eval(op.opc, op.w, op.sub, x, y, z) {
                Ok(value) => self.def(op, value),
                Err(EvalError::DivZero) => Flow::Stop(StopReason::DivZero),
                Err(EvalError::NotData | EvalError::BadWidth) => Flow::Stop(StopReason::BadIr),
            },
        }
    }

    /// Runs `Get` and `Put`, the ops with a location argument.
    fn step_loc(&mut self, op: &Op) -> Flow {
        match (op.opc, op.a[0].as_loc()) {
            (Opc::Get, Some(loc)) => {
                let value = self.loc(loc) & mask(op.w);
                self.def(op, value)
            }
            (Opc::Put, Some(loc)) => match self.arg(op.a[1]) {
                Some(value) => {
                    self.set_loc(loc, value & mask(op.w));
                    Flow::Next
                }
                None => Flow::Stop(StopReason::BadIr),
            },
            _ => Flow::Stop(StopReason::BadIr),
        }
    }

    /// Gives the count of bytes of an access of `w` bits, or `None` for a bad width.
    fn access_len(w: u8) -> Option<u8> {
        (w != 0 && w.is_multiple_of(8) && w <= 128).then_some(w / 8)
    }

    /// Runs a `Load` of `op.w` bits at `addr` (little-endian).
    fn load(&mut self, op: &Op, addr: u64) -> Flow {
        let Some(len) = Self::access_len(op.w) else {
            return Flow::Stop(StopReason::BadIr);
        };
        let mut value = 0u128;
        for i in 0..len {
            let at = addr.wrapping_add(u64::from(i));
            let Some(byte) = self.read(at) else {
                return Flow::Stop(StopReason::UnmappedRead(at));
            };
            value |= u128::from(byte) << (8 * u32::from(i));
        }
        self.def(op, value)
    }

    /// Runs a `Store` of `op.w` bits of `value` at `addr` (little-endian).
    ///
    /// The store writes no byte when one byte is not writable or when the cap stops it.
    fn store(&mut self, op: &Op, addr: u64, value: u128) -> Flow {
        let Some(len) = Self::access_len(op.w) else {
            return Flow::Stop(StopReason::BadIr);
        };
        let mut new = 0u64;
        for i in 0..len {
            let at = addr.wrapping_add(u64::from(i));
            if !self.image.writable(at) {
                return Flow::Stop(StopReason::UnmappedWrite(at));
            }
            new += u64::from(!self.writes.contains_key(&at));
        }
        let total = u64::try_from(self.writes.len()).unwrap_or(u64::MAX);
        if total.saturating_add(new) > self.config.mem_cap {
            return Flow::Stop(StopReason::MemCap);
        }
        for (i, byte) in value
            .to_le_bytes()
            .iter()
            .take(usize::from(len))
            .enumerate()
        {
            let off = u64::try_from(i).unwrap_or(u64::MAX);
            self.writes.insert(addr.wrapping_add(off), *byte);
        }
        Flow::Next
    }
}

/// Makes a stop.
const fn stop(reason: StopReason, at: OpId, steps: u64) -> Stop {
    Stop { reason, at, steps }
}
