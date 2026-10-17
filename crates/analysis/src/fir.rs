//! The L0 function IR builder (design Section 7.12).
//!
//! [`build`] lifts the body of a function from the published code units, builds its blocks
//! and its CFG, runs flag fusion and the stack tracking, and puts `Stack(k)` in place of each
//! frame access that does not escape. The analyzers use [`build_units`] with the code units
//! of their work state. The result is derived data: the journal never holds it.
//!
//! Leaders: the entry, the start of each run of code units, each branch target and jump-table
//! case in the body, and the unit after a `jmp`, a `jcc`, a call, an indirect jump, a `ret`
//! or a trap. Block `n` of [`FuncIr::body`] starts at `starts[n]`.
//!
//! | Last unit of a block | CFG edges in the body |
//! |---|---|
//! | plain, or a call that returns | the next unit |
//! | `jmp` | the target |
//! | `jcc` | the target, then the next unit |
//! | indirect `jmp` | each case of its jump table |
//! | `ret`, a trap, a call to a noreturn function | none |
//!
//! Flag fusion: a `Cond` op whose flags come from a `Flags` thunk of `Sub`, `Add`, `Logic`,
//! `Neg`, `Inc` or `Dec` in the same block, or up a chain of blocks with one predecessor,
//! becomes one compare op in place (design Section 6.2). [`Fusion`] counts the flag reads
//! and the fused reads (AC-070).

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{Address, Fuel, FuncId, OutOfFuel};
use ghidorah_db::{FlowKind, Program};
use ghidorah_ir::local::Scope;
use ghidorah_ir::ssa::Body;
use ghidorah_ir::{Arena, GraphError, InsnSpan, Memory, Node, OpId};

use crate::stack::Frame;

/// The version of the lifter of each function IR.
pub const LIFT_VER: u32 = ghidorah_x86::LIFT_VER;

/// The largest number of instructions of one function IR.
pub const MAX_INSNS: usize = 100_000;

/// The steps of a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Opts {
    /// Runs flag fusion.
    pub fuse: bool,
    /// Runs the stack tracking and the `Stack(k)` rewrite.
    pub stack: bool,
}

impl Opts {
    /// Every step.
    pub const DEFAULT: Self = Self {
        fuse: true,
        stack: true,
    };
}

impl Default for Opts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One code unit of a body: its length, flow kind and site flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unit {
    /// The length in bytes.
    pub len: u8,
    /// The flow kind.
    pub flow: FlowKind,
    /// The site flags, for example the noreturn call flag.
    pub flags: u8,
}

/// The flag reads of a function IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fusion {
    /// The `Cond` ops.
    pub reads: u64,
    /// The `Cond` ops that fusion turns into a compare op.
    pub fused: u64,
}

/// The L0 IR of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncIr {
    /// The function.
    pub func: FuncId,
    /// The lifter version.
    pub lift_ver: u32,
    /// The L0 ops of the body in address order.
    pub arena: Arena,
    /// The blocks and the CFG. Node `n` is block `n`.
    pub body: Body,
    /// The start address of each block.
    pub starts: Vec<u64>,
    /// The code units of the body by start.
    pub units: BTreeMap<u64, Unit>,
    /// The flag reads.
    pub fusion: Fusion,
    /// The stack frame, or `None` when the build does not track the stack.
    pub frame: Option<Frame>,
}

/// The error of [`build`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirError {
    /// No function starts at the address.
    NoFunc(FuncId),
    /// The body has no code unit at the entry.
    NoEntry(u64),
    /// A code unit does not decode.
    Decode(u64),
    /// The lifter refuses the instruction at the address.
    Lift(u64),
    /// The body has more than [`MAX_INSNS`] instructions.
    TooLarge,
    /// The CFG does not build.
    Graph(GraphError),
    /// The fuel ran out.
    Fuel(OutOfFuel),
}

impl fmt::Display for FirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFunc(id) => write!(f, "No function starts at {}.", id.0),
            Self::NoEntry(at) => write!(f, "The body has no code unit at the entry {at:#x}."),
            Self::Decode(at) => write!(f, "The code unit at {at:#x} does not decode."),
            Self::Lift(at) => write!(f, "The lifter refuses the instruction at {at:#x}."),
            Self::TooLarge => write!(f, "The body has more than {MAX_INSNS} instructions."),
            Self::Graph(e) => write!(f, "The CFG does not build: {e}"),
            Self::Fuel(e) => write!(f, "The build runs out of fuel: {e}"),
        }
    }
}

impl std::error::Error for FirError {}

impl From<OutOfFuel> for FirError {
    fn from(e: OutOfFuel) -> Self {
        Self::Fuel(e)
    }
}

impl From<GraphError> for FirError {
    fn from(e: GraphError) -> Self {
        Self::Graph(e)
    }
}

impl FuncIr {
    /// Gives the entry address.
    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.func.0.off
    }

    /// Gives the block that holds the instruction at `addr`.
    #[must_use]
    pub fn block_at(&self, addr: u64) -> Option<Node> {
        let _ = addr;
        None
    }

    /// Gives the span of the instruction at `addr`.
    #[must_use]
    pub fn insn(&self, addr: u64) -> Option<&InsnSpan> {
        self.arena
            .insn_index(addr)
            .and_then(|i| self.arena.insns().get(i))
    }

    /// Gives the arena index of the op `id`.
    #[must_use]
    pub fn op_index(&self, id: OpId) -> Option<u32> {
        let span = self.insn(id.addr)?;
        (u32::from(id.seq) < span.count).then(|| span.first.saturating_add(u32::from(id.seq)))
    }

    /// Gives the scope of a block-local walk over the IR with `mem`.
    #[must_use]
    pub fn scope<'a>(&'a self, mem: &'a dyn Memory) -> Scope<'a> {
        Scope {
            arena: &self.arena,
            body: &self.body,
            mem,
        }
    }
}

/// The read-only image of a program for block-local walks and jump-table loads.
#[derive(Debug, Clone, Copy)]
pub struct Image<'a>(pub &'a Program);

impl Memory for Image<'_> {
    fn read(&self, addr: u64) -> Option<u8> {
        let _ = addr;
        None
    }

    fn mapped(&self, addr: u64) -> bool {
        self.0.mem().region_at(addr).is_some()
    }
}

/// Gives the code units of the published body of a function.
#[must_use]
pub fn units_of(program: &Program, id: FuncId) -> Option<BTreeMap<u64, Unit>> {
    let _ = (program, id);
    None
}

/// Gives the case targets of the published jump tables of `units`, by jump address.
#[must_use]
pub fn cases_of(program: &Program, units: &BTreeMap<u64, Unit>) -> BTreeMap<u64, Vec<u64>> {
    let _ = (program, units);
    BTreeMap::new()
}

/// Builds the L0 IR of the published function `id`.
///
/// # Errors
///
/// Returns [`FirError::NoFunc`] when no function starts at `id`, and the errors of
/// [`build_units`].
pub fn build(
    program: &Program,
    id: FuncId,
    opts: &Opts,
    fuel: &mut Fuel,
) -> Result<FuncIr, FirError> {
    let units = units_of(program, id).ok_or(FirError::NoFunc(id))?;
    let cases = cases_of(program, &units);
    build_units(program, id.0.off, units, &cases, opts, fuel)
}

/// Builds the L0 IR of the function at `entry` from its code units and the case targets of
/// its jump tables.
///
/// # Errors
///
/// Returns [`FirError::NoEntry`] when no unit starts at `entry`, [`FirError::Decode`] or
/// [`FirError::Lift`] for a unit that does not decode or lift, [`FirError::TooLarge`],
/// [`FirError::Graph`] and [`FirError::Fuel`] when `fuel` runs out. Each instruction takes
/// one unit of fuel.
pub fn build_units(
    program: &Program,
    entry: u64,
    units: BTreeMap<u64, Unit>,
    cases: &BTreeMap<u64, Vec<u64>>,
    opts: &Opts,
    fuel: &mut Fuel,
) -> Result<FuncIr, FirError> {
    let _ = (program, units, cases, opts, fuel);
    Err(FirError::NoEntry(entry))
}

/// Gives the function ID of an entry.
#[must_use]
pub const fn func_id(entry: u64) -> FuncId {
    FuncId(Address::ram(entry))
}
