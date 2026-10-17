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
use crate::shape::{Exit, Shape};
use crate::tree::Tree;

mod lower;
mod value;

pub(crate) use lower::{Step, lower};

/// A branch oracle: it chooses each branch and each switch case.
pub trait Oracle {
    /// Gives the branch of the `visit`-th run of `node`: `true` goes to `t`.
    fn branch(&self, node: Node, visit: u32) -> bool;
    /// Gives the case of the `visit`-th run of `node` with `count` cases, below `count`.
    fn case(&self, node: Node, visit: u32, count: usize) -> usize;
}

/// An oracle from a seed: each choice is a hash of the seed, the node and the visit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seeded(pub u64);

impl Seeded {
    /// Gives the hash of one choice (the `SplitMix64` finalizer).
    fn mix(self, node: Node, visit: u32) -> u64 {
        let key = (u64::from(node.0) << 32) | u64::from(visit);
        let mut z = self.0 ^ key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl Oracle for Seeded {
    fn branch(&self, node: Node, visit: u32) -> bool {
        self.mix(node, visit) & 1 == 1
    }

    fn case(&self, node: Node, visit: u32, count: usize) -> usize {
        let n = u64::try_from(count).unwrap_or(u64::MAX).max(1);
        usize::try_from(self.mix(node, visit) % n).unwrap_or(0)
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

/// The visit counts of the nodes of one walk.
struct Visits(Vec<u32>);

impl Visits {
    fn new(shape: &Shape) -> Self {
        Self(vec![0; shape.len()])
    }

    /// Counts one more visit of `n`. Gives the new count.
    fn bump(&mut self, n: Node) -> u32 {
        match self.0.get_mut(n.index()) {
            Some(c) => {
                *c = c.saturating_add(1);
                *c
            }
            None => 0,
        }
    }

    fn get(&self, n: Node) -> u32 {
        self.0.get(n.index()).copied().unwrap_or(0)
    }
}

/// Walks the CFG of `shape` from its entry with `oracle`, for at most `limit` blocks.
#[must_use]
pub fn cfg_trace(shape: &Shape, oracle: &dyn Oracle, limit: usize) -> Trace {
    let mut blocks = Vec::new();
    if !shape.is_valid() {
        return Trace {
            blocks,
            end: End::Stuck,
        };
    }
    let mut visits = Visits::new(shape);
    let mut cur = shape.entry;
    loop {
        if blocks.len() >= limit {
            return Trace {
                blocks,
                end: End::Limit,
            };
        }
        blocks.push(cur);
        let visit = visits.bump(cur);
        cur = match shape.exit(cur) {
            Exit::Fall(n) => *n,
            Exit::Cond { t, f } => {
                if oracle.branch(cur, visit) {
                    *t
                } else {
                    *f
                }
            }
            Exit::Switch(list) if !list.is_empty() => {
                let i = oracle.case(cur, visit, list.len());
                list.get(i).copied().unwrap_or(cur)
            }
            Exit::Switch(_) | Exit::Stop => {
                return Trace {
                    blocks,
                    end: End::Halt,
                };
            }
        };
    }
}

/// Runs `tree` over `shape` with `oracle`, for at most `limit` blocks.
#[must_use]
pub fn tree_trace(tree: &Tree, shape: &Shape, oracle: &dyn Oracle, limit: usize) -> Trace {
    let code = lower(tree, shape);
    let mut blocks = Vec::new();
    let mut visits = Visits::new(shape);
    let mut pc = 0usize;
    let mut idle = 0usize;
    let idle_cap = code.steps.len().saturating_add(4);
    let end = loop {
        let Some(step) = code.steps.get(pc) else {
            break End::Stuck;
        };
        idle = idle.saturating_add(1);
        if idle > idle_cap {
            break End::Stuck;
        }
        let mut exec = |n: Node, blocks: &mut Vec<Node>| -> bool {
            if blocks.len() >= limit {
                return false;
            }
            blocks.push(n);
            let _ = visits.bump(n);
            true
        };
        pc = match step {
            Step::Exec(n) => {
                if !exec(*n, &mut blocks) {
                    break End::Limit;
                }
                idle = 0;
                pc.saturating_add(1)
            }
            Step::Test {
                node,
                neg,
                exec: run,
                t,
                f,
            } => {
                if *run {
                    if !exec(*node, &mut blocks) {
                        break End::Limit;
                    }
                    idle = 0;
                }
                if oracle.branch(*node, visits.get(*node)) == *neg {
                    *f
                } else {
                    *t
                }
            }
            Step::Dispatch { node, table } => {
                let count = match shape.exit(*node) {
                    Exit::Switch(list) => list.len(),
                    _ => 0,
                };
                if count == 0 || table.len() != count {
                    break End::Stuck;
                }
                let i = oracle.case(*node, visits.get(*node), count);
                table.get(i).copied().unwrap_or(usize::MAX)
            }
            Step::Jump(t) => *t,
            Step::Halt => break End::Halt,
            Step::Bad => break End::Stuck,
        };
    };
    Trace { blocks, end }
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

/// Runs the tree of `decomp` with values. `setup` gives the entry value of each location, and
/// a location without a value reads as 0.
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
    value::run(decomp, image, config, setup, fuel)
}
