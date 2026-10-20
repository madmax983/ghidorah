//! The L0 function IR builder (design Section 7.12).
//!
//! [`build`] lifts the body of a function from the published code units and builds its blocks
//! and its CFG. Then it runs flag fusion and the stack tracking. It puts `Stack(k)` in place
//! of each frame access that does not escape. The analyzers use [`build_units`] with the code
//! units of their work state. The result is derived data: the journal never holds it.
//!
//! Leaders: the entry, the start of each run of code units, each branch target and jump-table
//! case in the body, and the unit after a `jmp`, a `jcc`, a call, an indirect jump, a `ret`
//! or a trap. Block `n` of [`FuncIr::body`] starts at `starts[n]`. These are the blocks of
//! [`crate::cfg::build`].
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
//! becomes one compare op in place (design Section 6.2). A call or an effect op that writes
//! the flags ends the chain. [`Fusion`] counts the flag reads and the fused reads (AC-070).
//!
//! The submodule [`l1`] makes the L1 form: SSA, the L1 passes and the calling convention.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, Fuel, FuncId, JumpTableId, Limits, OutOfFuel};
use ghidorah_db::{CodeUnit, FlowKind, FlowOverride, Program};
use ghidorah_ir::local::Scope;
use ghidorah_ir::ssa::{Block, Body};
use ghidorah_ir::{Arena, Builder, Cfg, GraphError, InsnSpan, Memory, Node, OpId, Opc};
use ghidorah_loader::Perms;

mod fusion;
pub mod l1;

use self::fusion::{count_reads, fuse_flags};
use crate::code::decode_at;
use crate::ctx::UNIT_NORETURN_CALL;
use crate::stack::{self, Frame};

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
        let insn = u32::try_from(self.arena.insn_index(addr)?).ok()?;
        let n = self
            .body
            .blocks
            .iter()
            .position(|b| b.first <= insn && insn < b.first.saturating_add(b.count))?;
        Some(Node(u32::try_from(n).ok()?))
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

    /// Gives the arena index of the first op of the opcode `opc` of the instruction at `addr`.
    #[must_use]
    pub fn find_op(&self, addr: u64, opc: Opc) -> Option<u32> {
        let span = self.insn(addr)?;
        let ops = self.arena.span_ops(span)?;
        let i = ops.iter().position(|o| o.opc == opc)?;
        span.first.checked_add(u32::try_from(i).ok()?)
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
        let mem = self.0.mem();
        let region = mem.region_at(addr)?;
        if region.perms.contains(Perms::WRITE) {
            return None;
        }
        mem.read(addr, 1, &Limits::DEFAULT)
            .ok()
            .and_then(|b| b.first().copied())
    }

    fn mapped(&self, addr: u64) -> bool {
        addr >= MIN_ADDR && self.0.mem().region_at(addr).is_some()
    }
}

/// The lowest value that a walk takes as an address. A PIE file maps its headers at 0, but
/// no code points to the first page, so a smaller value is a number.
pub const MIN_ADDR: u64 = 0x1000;

/// The inputs of one build: the entry, the code units, the case targets of the jump tables
/// and the noreturn test of a callee.
pub struct Input<'a> {
    /// The entry.
    pub entry: u64,
    /// The code units by start.
    pub units: BTreeMap<u64, Unit>,
    /// The case targets of each indirect jump.
    pub cases: BTreeMap<u64, Vec<u64>>,
    /// Tells if the function at an address is noreturn.
    pub noreturn: &'a dyn Fn(u64) -> bool,
}

impl fmt::Debug for Input<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Input")
            .field("entry", &self.entry)
            .field("units", &self.units.len())
            .field("cases", &self.cases.len())
            .finish_non_exhaustive()
    }
}

/// Gives the code units of the published body of a function. A unit of the analysis layer
/// wins over the base layer.
#[must_use]
pub fn units_of(program: &Program, id: FuncId) -> Option<BTreeMap<u64, Unit>> {
    let view = program.func(id)?;
    let mut out = BTreeMap::new();
    for r in view.func.body.ranges() {
        for t in [program.base(), program.analysis()] {
            for (at, unit) in t.listing().units_in(*r) {
                let CodeUnit::Insn { len, flow, flags } = *unit;
                out.insert(at, Unit { len, flow, flags });
            }
        }
    }
    Some(out)
}

/// Gives the case targets of the published jump tables and the `indirect_targets` overrides
/// of the indirect jumps of `units`.
#[must_use]
pub fn cases_of(program: &Program, units: &BTreeMap<u64, Unit>) -> BTreeMap<u64, Vec<u64>> {
    let mut out = BTreeMap::new();
    for (at, u) in units {
        if u.flow != FlowKind::IJmp {
            continue;
        }
        let addr = Address::ram(*at);
        let targets: Option<Vec<u64>> = match program.flow_override(addr).map(|f| &f.value) {
            Some(FlowOverride::IndirectTargets(t)) => Some(ram(t)),
            _ => program
                .jump_table(JumpTableId(addr))
                .filter(|t| t.value.resolved)
                .map(|t| ram(&t.value.targets)),
        };
        if let Some(t) = targets {
            out.insert(*at, t);
        }
    }
    out
}

/// Gives the RAM offsets of `addrs` in order.
fn ram(addrs: &[Address]) -> Vec<u64> {
    addrs.iter().filter(|a| a.is_ram()).map(|a| a.off).collect()
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
    let noreturn = |t: u64| {
        program
            .func(func_id(t))
            .and_then(|f| f.noreturn)
            .is_some_and(|n| n.value)
    };
    let input = Input {
        entry: id.0.off,
        units,
        cases,
        noreturn: &noreturn,
    };
    build_units(program, input, opts, fuel)
}

/// The decoded flow facts of one unit for the block step.
struct Flow {
    target: Option<u64>,
}

/// Builds the L0 IR of a function from its [`Input`].
///
/// # Errors
///
/// Returns [`FirError::NoEntry`] when no unit starts at the entry. Returns
/// [`FirError::Decode`] or [`FirError::Lift`] for a unit that does not decode or lift. Also
/// returns [`FirError::TooLarge`], [`FirError::Graph`], and [`FirError::Fuel`] when `fuel`
/// runs out. Each instruction takes one unit of fuel.
pub fn build_units(
    program: &Program,
    input: Input<'_>,
    opts: &Opts,
    fuel: &mut Fuel,
) -> Result<FuncIr, FirError> {
    let Input {
        entry,
        units,
        cases,
        noreturn,
    } = input;
    if !units.contains_key(&entry) {
        return Err(FirError::NoEntry(entry));
    }
    if units.len() > MAX_INSNS {
        return Err(FirError::TooLarge);
    }
    let mut b = Builder::new();
    // The block context keeps the direction flag rule of `std` and `cld`.
    let mut lifter = ghidorah_x86::lift::BlockLift::new();
    let mut flows: BTreeMap<u64, Flow> = BTreeMap::new();
    for (at, u) in &units {
        fuel.tick()?;
        let insn = decode_at(program, *at)
            .filter(|i| i.len() == u.len)
            .ok_or(FirError::Decode(*at))?;
        lifter
            .lift(&insn, &mut b)
            .map_err(|_| FirError::Lift(*at))?;
        flows.insert(
            *at,
            Flow {
                target: insn.target(),
            },
        );
    }
    let mut arena = b.finish();
    let leaders = leaders(entry, &units, &flows, &cases);
    let Blocks {
        list: blocks,
        starts,
        lasts,
    } = blocks(&units, &leaders)?;
    let cfg = edges(entry, &units, &flows, &cases, (&starts, &lasts), noreturn)?;
    let body = Body { blocks, cfg };
    let fusion = if opts.fuse {
        fuse_flags(&mut arena, &body)
    } else {
        Fusion {
            reads: count_reads(&arena),
            fused: 0,
        }
    };
    let frame = if opts.stack {
        let frame = stack::track(&arena, &body, fuel)?;
        let _ = stack::rewrite(&mut arena, &frame);
        Some(frame)
    } else {
        None
    };
    Ok(FuncIr {
        func: func_id(entry),
        lift_ver: LIFT_VER,
        arena,
        body,
        starts,
        units,
        fusion,
        frame,
    })
}

/// Gives the leaders of a body by the rules of the module doc.
fn leaders(
    entry: u64,
    units: &BTreeMap<u64, Unit>,
    flows: &BTreeMap<u64, Flow>,
    cases: &BTreeMap<u64, Vec<u64>>,
) -> BTreeSet<u64> {
    let mut out = BTreeSet::from([entry]);
    for (at, u) in units {
        if u.flow == FlowKind::Seq {
            continue;
        }
        if let Some(next) = at.checked_add(u64::from(u.len)) {
            out.insert(next);
        }
        if matches!(u.flow, FlowKind::Jmp | FlowKind::Jcc)
            && let Some(t) = flows.get(at).and_then(|f| f.target)
        {
            out.insert(t);
        }
        if u.flow == FlowKind::IJmp {
            out.extend(cases.get(at).into_iter().flatten().copied());
        }
    }
    out
}

/// Gives the blocks over the instruction indexes of the arena and their start addresses.
fn blocks(units: &BTreeMap<u64, Unit>, leaders: &BTreeSet<u64>) -> Result<Blocks, FirError> {
    let mut out = Blocks::default();
    let mut end: Option<u64> = None;
    for (i, (at, u)) in units.iter().enumerate() {
        let i = u32::try_from(i).map_err(|_| FirError::TooLarge)?;
        if leaders.contains(at) || end != Some(*at) || out.list.is_empty() {
            out.list.push(Block { first: i, count: 0 });
            out.starts.push(*at);
            out.lasts.push(*at);
        }
        if let Some(last) = out.list.last_mut() {
            last.count = last.count.saturating_add(1);
        }
        if let Some(last) = out.lasts.last_mut() {
            *last = *at;
        }
        end = at.checked_add(u64::from(u.len));
    }
    Ok(out)
}

/// The blocks of a body with the start and the last unit of each block.
#[derive(Debug, Default)]
struct Blocks {
    list: Vec<Block>,
    starts: Vec<u64>,
    lasts: Vec<u64>,
}

/// Gives the CFG of the blocks with the internal edges of the module table.
fn edges(
    entry: u64,
    units: &BTreeMap<u64, Unit>,
    flows: &BTreeMap<u64, Flow>,
    cases: &BTreeMap<u64, Vec<u64>>,
    (starts, lasts): (&[u64], &[u64]),
    noreturn: &dyn Fn(u64) -> bool,
) -> Result<Cfg, FirError> {
    let node_of: BTreeMap<u64, Node> = starts
        .iter()
        .enumerate()
        .filter_map(|(i, s)| Some((*s, Node(u32::try_from(i).ok()?))))
        .collect();
    let entry_node = node_of.get(&entry).copied().unwrap_or(Node(0));
    let mut cfg = Cfg::new(starts.len(), entry_node)?;
    for (i, at) in lasts.iter().enumerate() {
        let from = Node(u32::try_from(i).map_err(|_| FirError::TooLarge)?);
        let Some(u) = units.get(at) else {
            continue;
        };
        let Some(next) = at.checked_add(u64::from(u.len)) else {
            continue;
        };
        let target = flows.get(at).and_then(|f| f.target);
        let to = |cfg: &mut Cfg, addr: u64| -> Result<(), FirError> {
            if let Some(n) = node_of.get(&addr) {
                cfg.add_edge(from, *n)?;
            }
            Ok(())
        };
        match u.flow {
            FlowKind::Seq => to(&mut cfg, next)?,
            FlowKind::Jmp => {
                if let Some(t) = target {
                    to(&mut cfg, t)?;
                }
            }
            FlowKind::Jcc => {
                if let Some(t) = target {
                    to(&mut cfg, t)?;
                }
                to(&mut cfg, next)?;
            }
            FlowKind::Call | FlowKind::ICall => {
                let callee = target.filter(|_| u.flow == FlowKind::Call);
                if u.flags & UNIT_NORETURN_CALL == 0 && !callee.is_some_and(noreturn) {
                    to(&mut cfg, next)?;
                }
            }
            FlowKind::IJmp => {
                for t in cases.get(at).into_iter().flatten() {
                    to(&mut cfg, *t)?;
                }
            }
            FlowKind::Ret | FlowKind::Trap => {}
        }
    }
    Ok(cfg)
}

/// Gives the function ID of an entry.
#[must_use]
pub const fn func_id(entry: u64) -> FuncId {
    FuncId(Address::ram(entry))
}
