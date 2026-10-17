//! The structurer: Phoenix-lite post-order collapse (design Section 8.1, ADR-0010).
//!
//! [`run`] collapses the nodes of a [`Shape`] into one [`Tree`]. Each pass walks the regions
//! in post-order and tries the schemas in fixed order:
//!
//! | Order | Schemas |
//! |---|---|
//! | 1 | The 4 short-circuit shapes, `Seq`, `IfThen`, `IfThenElse`, `Switch` |
//! | 2 | Self loops (`do .. while`, endless) and two-node loops |
//! | 3 | Greedy: if-no-exit, outside a loop header |
//! | 4 | A natural loop: back edges become `continue`, exits to the loop successor become `break` and other exits become `goto` |
//! | 5 | Last resort: one edge becomes a `goto` |
//!
//! Steps 3 to 5 run only when a pass changes nothing, and one of them runs in each pass.
//! The loop successor is the exit target with the most exit edges, ties to the lowest address.
//! The `goto` rule picks the first edge where neither end dominates the other, in reverse
//! post-order of the source, lowest source address first. A region whose edges all became
//! jumps goes after the entry region, with its label.
//!
//! The output is FLAT ([`crate::flat`]) in four cases: the shape has more than `max_nodes`
//! blocks, the fuel runs out, the tree gets deeper than [`MAX_DEPTH`], or a pass changes
//! nothing.

use ghidorah_base::Fuel;
use ghidorah_ir::Node;

use crate::loops;
use crate::schemas;
use crate::shape::{NodeKind, Shape};
use crate::tree::Tree;

mod region;

pub(crate) use region::{ArmTo, Facts, Graph, Jump, Pending, R, RExit, seq_depth};

/// The largest depth of a structured tree. A deeper tree gives FLAT output.
pub const MAX_DEPTH: usize = 256;

/// The options of [`run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Opts {
    /// The largest count of blocks.
    pub max_nodes: usize,
}

/// The reason of FLAT output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlatReason {
    /// The shape has more than `max_nodes` blocks.
    MaxNodes,
    /// The fuel ran out.
    Fuel,
    /// The tree is deeper than [`MAX_DEPTH`].
    Depth,
    /// A pass of the structurer changed nothing.
    NoProgress,
    /// The self-check found a trace mismatch (WP-23).
    SelfCheck,
}

impl FlatReason {
    /// Tells if the reason is a budget: `max_nodes`, the fuel or the depth.
    #[must_use]
    pub const fn is_budget(self) -> bool {
        matches!(self, Self::MaxNodes | Self::Fuel | Self::Depth)
    }

    /// Gives the reason name, for example `max_nodes`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MaxNodes => "max_nodes",
            Self::Fuel => "fuel",
            Self::Depth => "depth",
            Self::NoProgress => "no_progress",
            Self::SelfCheck => "selfcheck",
        }
    }
}

/// The output mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// The structurer collapsed the shape.
    Structured,
    /// FLAT output, with its reason.
    Flat(FlatReason),
}

impl Mode {
    /// Gives the value of `metrics.fallback_mode`: `none` or `flat`.
    #[must_use]
    pub const fn fallback_mode(self) -> &'static str {
        match self {
            Self::Structured => "none",
            Self::Flat(_) => "flat",
        }
    }
}

/// The result of [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structured {
    /// The tree.
    pub tree: Tree,
    /// The mode.
    pub mode: Mode,
}

/// Gives the nodes that the entry of `shape` reaches.
fn reachable(shape: &Shape) -> Vec<Node> {
    crate::flat::order(shape)
}

/// Gives FLAT output with a reason.
fn flat(shape: &Shape, reason: FlatReason) -> Structured {
    Structured {
        tree: crate::flat::tree(shape),
        mode: Mode::Flat(reason),
    }
}

/// The step result of one pass.
enum Pass {
    Changed,
    Done,
    Stuck,
}

/// Runs one pass over the regions.
fn pass(g: &mut Graph<'_>, fuel: &mut Fuel) -> Result<Pass, FlatReason> {
    let live = g.live();
    fuel.take(u64::try_from(live.len()).unwrap_or(u64::MAX))
        .map_err(|_| FlatReason::Fuel)?;
    if loops::wrap_pending(g) {
        return Ok(Pass::Changed);
    }
    let facts = g.facts().ok_or(FlatReason::NoProgress)?;
    let mut changed = false;
    for &r in facts.post.iter().rev() {
        fuel.tick().map_err(|_| FlatReason::Fuel)?;
        while g.get(r).is_some() && schemas::seq(g, r) {
            fuel.tick().map_err(|_| FlatReason::Fuel)?;
            changed = true;
        }
    }
    for &r in &facts.post {
        if g.get(r).is_none() {
            continue;
        }
        fuel.tick().map_err(|_| FlatReason::Fuel)?;
        if schemas::acyclic(g, r) || loops::simple(g, r) {
            changed = true;
        }
    }
    if changed {
        return Ok(Pass::Changed);
    }
    if schemas::greedy(g, &facts) || loops::refine(g, &facts) || virtualize_one(g, &facts) {
        return Ok(Pass::Changed);
    }
    let edges = g.live().iter().any(|&r| !g.exit(r).targets().is_empty());
    if !edges && g.pending.is_empty() {
        Ok(Pass::Done)
    } else {
        Ok(Pass::Stuck)
    }
}

/// Replaces one edge with a `goto` by the rule of the module doc. Gives `false` when the graph
/// has no edge.
fn virtualize_one(g: &mut Graph<'_>, facts: &Facts) -> bool {
    let mut cross: Vec<(usize, u64, u64, R, R)> = Vec::new();
    let mut joins: Vec<(usize, u64, u64, R, R)> = Vec::new();
    for &u in &facts.post {
        let pos = facts.rpo.get(&u).copied().unwrap_or(usize::MAX);
        for v in g.exit(u).targets() {
            let key = (pos, g.addr(u), g.addr(v), u, v);
            if !facts.dominates(u, v) && !facts.dominates(v, u) {
                cross.push(key);
            } else if g.preds.get(v).is_some_and(|p| p.len() > 1) {
                joins.push(key);
            }
        }
    }
    cross.sort_unstable();
    joins.sort_unstable();
    let Some(&(_, _, _, u, v)) = cross.first().or_else(|| joins.first()) else {
        return false;
    };
    g.virtualize(u, v, Jump::Goto)
}

/// Gives the final tree: the entry region, then each other region in address order.
fn finish(g: &mut Graph<'_>) -> Tree {
    let mut rest: Vec<R> = g.live().into_iter().filter(|&r| r != g.entry).collect();
    rest.sort_by_key(|&r| (g.addr(r), r));
    let mut tree = g.take(g.entry).0;
    for r in rest {
        tree = tree.then(g.take(r).0);
    }
    tree
}

/// Structures `shape`. Each pass takes one unit of `fuel` for each live region, and each
/// region step takes one more.
#[must_use]
pub fn run(shape: &Shape, opts: &Opts, fuel: &mut Fuel) -> Structured {
    if !shape.is_valid() {
        return flat(shape, FlatReason::NoProgress);
    }
    let reach = reachable(shape);
    let blocks = reach
        .iter()
        .filter(|n| matches!(shape.node(**n).map(|s| s.kind), Some(NodeKind::Block(_))))
        .count();
    if blocks > opts.max_nodes {
        return flat(shape, FlatReason::MaxNodes);
    }
    let mut g = Graph::new(shape, &reach);
    loop {
        if g.live()
            .iter()
            .any(|&r| g.get(r).is_some_and(|x| x.depth > MAX_DEPTH))
        {
            return flat(shape, FlatReason::Depth);
        }
        match pass(&mut g, fuel) {
            Ok(Pass::Changed) => {}
            Ok(Pass::Done) => break,
            Ok(Pass::Stuck) => return flat(shape, FlatReason::NoProgress),
            Err(reason) => return flat(shape, reason),
        }
    }
    let tree = loops::finish(finish(&mut g), shape);
    if tree.depth() > MAX_DEPTH {
        return flat(shape, FlatReason::Depth);
    }
    Structured {
        tree,
        mode: Mode::Structured,
    }
}
