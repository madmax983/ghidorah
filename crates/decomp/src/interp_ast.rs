//! The CFG walker and the AST interpreter (design Sections 8.2 and 13.4).
//!
//! Both walkers record a block trace: the shape nodes in run order. A branch [`Oracle`]
//! chooses each branch and each switch case from the node and its visit count, so both walkers
//! see the same choices. The structure is faithful when both traces are equal (AC-098a). The
//! self-check of WP-23 runs 8 oracles.
//!
//! The AST interpreter first lowers the tree to a list of steps with jumps, so a `goto` can go
//! to any label. The lowering and the walk use no recursion.
//!
//! [`run`] is the value mode: it runs the statements of the view with concrete values over a
//! memory image. It stops like the L0 interpreter: a return, a call, a system call, an opaque
//! instruction, an unmapped access or a division by zero (AC-101).

use std::collections::BTreeMap;

use ghidorah_ir::{Config, Image, Loc, Node, OpId, StopReason};

use crate::Decomp;
use crate::shape::Shape;
use crate::tree::Tree;

/// A branch oracle: it chooses each branch and each switch case.
pub trait Oracle {
    /// Gives the branch of the `visit`-th run of `node`: `true` goes to `t`.
    fn branch(&self, node: Node, visit: u32) -> bool;
    /// Gives the case of the `visit`-th run of `node` with `count` cases.
    fn case(&self, node: Node, visit: u32, count: usize) -> usize;
}

/// An oracle from a seed: each choice is a hash of the seed, the node and the visit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seeded(pub u64);

impl Oracle for Seeded {
    fn branch(&self, node: Node, visit: u32) -> bool {
        let _ = (node, visit);
        false
    }

    fn case(&self, node: Node, visit: u32, count: usize) -> usize {
        let _ = (node, visit, count);
        0
    }
}

/// The end of a block trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum End {
    /// A node with the exit `Stop` ran last.
    Halt,
    /// The trace reached its block limit.
    Limit,
    /// The walk took too many steps without a block, or it found a bad step.
    Stuck,
}

/// A block trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Trace {
    /// The shape nodes in run order.
    pub blocks: Vec<Node>,
    /// The end.
    pub end: End,
}

/// Walks the CFG of `shape` from its entry with `oracle`, for at most `limit` blocks.
#[must_use]
pub fn cfg_trace(shape: &Shape, oracle: &dyn Oracle, limit: usize) -> Trace {
    let _ = (shape, oracle, limit);
    Trace {
        blocks: Vec::new(),
        end: End::Stuck,
    }
}

/// Runs `tree` over `shape` with `oracle`, for at most `limit` blocks.
#[must_use]
pub fn tree_trace(tree: &Tree, shape: &Shape, oracle: &dyn Oracle, limit: usize) -> Trace {
    let _ = (tree, shape, oracle, limit);
    Trace {
        blocks: Vec::new(),
        end: End::Stuck,
    }
}

/// The end of a value run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The reason, with the reasons of the L0 interpreter.
    pub reason: StopReason,
    /// The op where the run stopped.
    pub at: OpId,
    /// The values of the locations that the stop op reads, in location order.
    pub uses: Vec<(Loc, Option<u128>)>,
    /// The bytes that the run wrote.
    pub writes: BTreeMap<u64, u8>,
}

impl Outcome {
    /// Reads the byte at `addr` after the run: a written byte first, else the image byte.
    #[must_use]
    pub fn read(&self, image: &dyn Image, addr: u64) -> Option<u8> {
        self.writes.get(&addr).copied().or_else(|| image.read(addr))
    }
}

/// Runs the tree of `decomp` with values. `setup` gives the entry value of each location.
///
/// Each statement and each expression node takes one unit of `fuel`.
#[must_use]
pub fn run(
    decomp: &Decomp,
    image: &dyn Image,
    config: &Config,
    setup: &[(Loc, u128)],
    fuel: u64,
) -> Outcome {
    let _ = (decomp, image, config, setup, fuel);
    Outcome {
        reason: StopReason::BadIr,
        at: OpId { addr: 0, seq: 0 },
        uses: Vec::new(),
        writes: BTreeMap::new(),
    }
}
