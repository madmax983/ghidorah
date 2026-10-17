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
//! | `Call` or `CallInd` while the slice needs a location | `Unknown` |
//! | `Syscall` or `Intrinsic` that writes a needed location | `Unknown` |
//! | the function entry, a merge point, a loop back to a visited block | `Unknown` |
//! | more than [`MAX_BLOCKS`] blocks or more than [`MAX_OPS`] slice ops | `Unknown` |
//! | a `Load` with no read-only byte at its address | `Unknown` |
//!
//! `Unknown` is sound: a relation on the value then gives `unknown`. A store never changes a
//! read-only byte, so a store does not stop the walk. A value in a mapped region is an
//! [`LocalValue::Addr`]. Each other value is a [`LocalValue::Const`].

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::Fuel;

use crate::arena::Arena;
use crate::graph::Node;
use crate::loc::Loc;
use crate::op::{Arg, Opc, Val};
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

/// One step of a slice in run order: an op, or a pinned value before the next op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// The op with this index.
    Op(u32),
    /// The location gets the value.
    Seed(Loc, u64),
}

/// Gives the mask of the low `w` bits.
const fn mask(w: u8) -> u128 {
    if w >= 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    }
}

/// Gives the value of an argument in the forward run.
fn arg(vals: &BTreeMap<Val, u128>, a: Arg) -> Option<u128> {
    match a {
        Arg::Nil => Some(0),
        Arg::K(k) => Some(u128::from(k.get())),
        Arg::V(v) => vals.get(&v).copied(),
        Arg::L(_) => None,
    }
}

/// The backward walk of one query.
struct Walk<'s, 'a> {
    scope: &'s Scope<'a>,
    query: &'s Query,
    vals: BTreeSet<Val>,
    locs: BTreeSet<Loc>,
    events: Vec<Event>,
    ops: usize,
}

impl Walk<'_, '_> {
    /// Tells if the slice needs no more value.
    fn done(&self) -> bool {
        self.vals.is_empty() && self.locs.is_empty()
    }

    /// Records the pin when the walk is at the point before the op `index`.
    fn pin_point(&mut self, index: u32) {
        if let Some(pin) = self.query.pin
            && pin.op == index
            && self.locs.remove(&pin.loc)
        {
            self.events.push(Event::Seed(pin.loc, pin.value));
        }
    }

    /// Puts the op `index` into the slice. Gives `None` past the op limit.
    fn include(&mut self, index: u32) -> Option<()> {
        self.ops = self.ops.saturating_add(1);
        self.events.push(Event::Op(index));
        (self.ops <= self.query.max_ops).then_some(())
    }

    /// Visits the op `index`. Gives `None` when the value becomes `Unknown`.
    fn visit(&mut self, index: u32) -> Option<()> {
        let arena = self.scope.arena;
        let op = *arena.op(index)?;
        if let Some(out) = op.out
            && self.vals.remove(&out)
        {
            self.include(index)?;
            match op.opc {
                _ if zero_idiom(arena, &op) => {}
                Opc::Get => {
                    self.locs.insert(op.a[0].as_loc()?);
                }
                Opc::Phi => return None,
                _ => {
                    for a in op.a {
                        match a {
                            Arg::V(v) => {
                                self.vals.insert(v);
                            }
                            Arg::L(_) => return None,
                            Arg::K(_) | Arg::Nil => {}
                        }
                    }
                }
            }
            return Some(());
        }
        match op.opc {
            Opc::Put => {
                if let Some(loc) = op.a[0].as_loc()
                    && self.locs.remove(&loc)
                {
                    self.include(index)?;
                    match op.a[1] {
                        Arg::V(v) => {
                            self.vals.insert(v);
                        }
                        Arg::K(_) => {}
                        Arg::L(_) | Arg::Nil => return None,
                    }
                }
            }
            Opc::Call | Opc::CallInd if !self.locs.is_empty() => return None,
            Opc::Syscall | Opc::Intrinsic => {
                let defs = arena.effect(&op)?.defs;
                if self.locs.iter().any(|l| defs.contains(*l)) {
                    return None;
                }
            }
            _ => {}
        }
        Some(())
    }

    /// Gives the first and the end op index of the block `node`.
    fn op_range(&self, node: Node) -> Option<(u32, u32)> {
        let block = self.scope.body.blocks.get(node.index())?;
        let insns = self.scope.arena.insns();
        let first = insns.get(usize::try_from(block.first).ok()?)?;
        let last_index = block.first.checked_add(block.count)?.checked_sub(1)?;
        let last = insns.get(usize::try_from(last_index).ok()?)?;
        Some((first.first, last.first.checked_add(last.count)?))
    }

    /// Gives the block that holds the op `index`.
    fn block_of(&self, index: u32) -> Option<Node> {
        let insns = self.scope.arena.insns();
        let at = insns.partition_point(|s| s.first <= index).checked_sub(1)?;
        let span = insns.get(at)?;
        if index >= span.first.checked_add(span.count)? {
            return None;
        }
        let at = u32::try_from(at).ok()?;
        let n = self
            .scope
            .body
            .blocks
            .iter()
            .position(|b| b.first <= at && at < b.first.saturating_add(b.count))?;
        Some(Node(u32::try_from(n).ok()?))
    }

    /// Runs the backward walk. Gives `None` for `Unknown`.
    fn back(&mut self, fuel: &mut Fuel) -> Option<()> {
        self.pin_point(self.query.op);
        if self.done() {
            return Some(());
        }
        let cfg = &self.scope.body.cfg;
        let preds = cfg.preds();
        let mut node = self.block_of(self.query.op)?;
        let mut visited = BTreeSet::from([node]);
        let mut cursor = self.query.op;
        loop {
            let (first, _) = self.op_range(node)?;
            while cursor > first {
                cursor -= 1;
                fuel.tick().ok()?;
                self.visit(cursor)?;
                self.pin_point(cursor);
                if self.done() {
                    return Some(());
                }
            }
            if node == cfg.entry() || visited.len() >= self.query.max_blocks {
                return None;
            }
            let [pred] = preds.get(node.index())?.as_slice() else {
                return None;
            };
            if !visited.insert(*pred) {
                return None;
            }
            node = *pred;
            cursor = self.op_range(node)?.1;
        }
    }

    /// Runs the slice forward. Gives the value and the loads, or `None` for `Unknown`.
    fn forward(&self) -> Option<(u64, Vec<(u64, u8)>)> {
        let arena = self.scope.arena;
        let mut locs: BTreeMap<Loc, u128> = BTreeMap::new();
        let mut vals: BTreeMap<Val, u128> = BTreeMap::new();
        let mut loads = Vec::new();
        for event in self.events.iter().rev() {
            let index = match *event {
                Event::Seed(loc, value) => {
                    locs.insert(loc, u128::from(value));
                    continue;
                }
                Event::Op(index) => index,
            };
            let op = arena.op(index)?;
            let value = match op.opc {
                _ if zero_idiom(arena, op) => 0,
                Opc::Get => *locs.get(&op.a[0].as_loc()?)? & mask(op.w),
                Opc::Put => {
                    let v = arg(&vals, op.a[1])? & mask(op.w);
                    locs.insert(op.a[0].as_loc()?, v);
                    continue;
                }
                Opc::Load => {
                    let addr = u64::try_from(arg(&vals, op.a[0])? & mask(64)).ok()?;
                    let len = (op.w % 8 == 0 && op.w > 0 && op.w <= 128).then_some(op.w / 8)?;
                    let mut v = 0u128;
                    for i in 0..len {
                        let byte = self.scope.mem.read(addr.checked_add(u64::from(i))?)?;
                        v |= u128::from(byte) << (8 * u32::from(i));
                    }
                    loads.push((addr, len));
                    v
                }
                _ => {
                    let [x, y, z] = op.a.map(|a| arg(&vals, a));
                    crate::interp::eval(op.opc, op.w, op.sub, x?, y?, z?).ok()?
                }
            };
            vals.insert(op.out?, value);
        }
        let value = match self.query.target {
            Target::Loc(loc) => *locs.get(&loc)?,
            Target::Arg(i) => arg(&vals, *arena.op(self.query.op)?.a.get(i)?)?,
        };
        Some((u64::try_from(value).ok()?, loads))
    }
}

/// Runs the walk of `query` in `scope`. Each visited op takes one unit of `fuel`. An empty
/// tank gives `Unknown`.
#[must_use]
pub fn eval(scope: &Scope<'_>, query: &Query, fuel: &mut Fuel) -> Outcome {
    let unknown = Outcome::default();
    let Some(op) = scope.arena.op(query.op) else {
        return unknown;
    };
    let mut walk = Walk {
        scope,
        query,
        vals: BTreeSet::new(),
        locs: BTreeSet::new(),
        events: Vec::new(),
        ops: 0,
    };
    match query.target {
        Target::Loc(loc) => {
            walk.locs.insert(loc);
        }
        Target::Arg(i) => match op.a.get(i) {
            Some(Arg::V(v)) => {
                walk.vals.insert(*v);
            }
            Some(Arg::L(loc)) => {
                walk.locs.insert(*loc);
            }
            Some(Arg::K(k)) => {
                return Outcome {
                    value: classify(scope.mem, k.get()),
                    loads: Vec::new(),
                    ops: 0,
                };
            }
            Some(Arg::Nil) | None => return unknown,
        },
    }
    if walk.back(fuel).is_none() {
        return unknown;
    }
    match walk.forward() {
        Some((value, loads)) => Outcome {
            value: classify(scope.mem, value),
            loads,
            ops: walk.ops,
        },
        None => unknown,
    }
}

/// Gives the kind of a known value: an address in a mapped region, else a constant.
fn classify(mem: &dyn Memory, value: u64) -> LocalValue {
    if mem.mapped(value) {
        LocalValue::Addr(value)
    } else {
        LocalValue::Const(value)
    }
}

/// The largest number of view ops that [`same_value`] follows.
const MAX_VIEWS: usize = 8;

/// Tells if two arguments hold one value.
///
/// They hold one value when they are the same value, or the same chain of `Trunc`, `ZExt` and
/// `SExt` ops over reads of one location in one instruction. A `xor r, r` or a `sub r, r` of
/// such values gives 0.
#[must_use]
pub fn same_value(arena: &Arena, a: Arg, b: Arg) -> bool {
    let def = |x: Arg| {
        x.as_v()
            .and_then(|v| arena.def_of(v))
            .and_then(|d| arena.op(d))
    };
    let (mut a, mut b) = (a, b);
    for _ in 0..MAX_VIEWS {
        if a == b {
            return true;
        }
        let (Some(x), Some(y)) = (def(a), def(b)) else {
            return false;
        };
        if x.id.addr != y.id.addr || x.opc != y.opc || x.w != y.w || x.sub != y.sub {
            return false;
        }
        match x.opc {
            Opc::Get => return x.a[0] == y.a[0],
            Opc::Trunc | Opc::ZExt | Opc::SExt => {
                a = x.a[0];
                b = y.a[0];
            }
            _ => return false,
        }
    }
    false
}

/// Tells if an op is a zero idiom: `Xor` or `Sub` of one value.
fn zero_idiom(arena: &Arena, op: &crate::op::Op) -> bool {
    matches!(op.opc, Opc::Xor | Opc::Sub) && same_value(arena, op.a[0], op.a[1])
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
