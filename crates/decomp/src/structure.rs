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
//! The output is FLAT ([`crate::flat`]) when the shape has more than `max_nodes` blocks, when
//! the fuel runs out, when the tree gets deeper than [`MAX_DEPTH`] or when a pass changes
//! nothing.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::Fuel;
use ghidorah_ir::{Cfg, DomTree, Node, dominators, rpo};

use crate::loops;
use crate::schemas;
use crate::shape::{Exit, NodeKind, Shape};
use crate::tree::{Arm, Cond, LoopKind, Tree};

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

/// A region: an index in [`Graph::regions`], the index of its first shape node.
pub(crate) type R = usize;

/// The target of a switch arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArmTo {
    /// A region.
    Region(R),
    /// A jump tree that replaces the edge.
    Done(Tree),
}

/// A switch arm of a region exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RArm {
    pub(crate) cases: Vec<usize>,
    pub(crate) to: ArmTo,
}

/// The structural exit of a region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RExit {
    Stop,
    Fall(R),
    Cond { cond: Cond, t: R, f: R },
    Switch { on: Node, arms: Vec<RArm> },
}

impl RExit {
    /// Gives the target regions, one for each edge.
    pub(crate) fn targets(&self) -> Vec<R> {
        match self {
            Self::Stop => Vec::new(),
            Self::Fall(x) => vec![*x],
            Self::Cond { t, f, .. } => vec![*t, *f],
            Self::Switch { arms, .. } => arms
                .iter()
                .filter_map(|a| match a.to {
                    ArmTo::Region(r) => Some(r),
                    ArmTo::Done(_) => None,
                })
                .collect(),
        }
    }
}

/// A region of the graph.
#[derive(Debug, Clone)]
pub(crate) struct Region {
    pub(crate) tree: Tree,
    pub(crate) exit: RExit,
    pub(crate) head: Node,
    pub(crate) depth: usize,
}

/// The kind of a jump that replaces an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Jump {
    Goto,
    Break,
    Continue,
}

/// A loop under construction: its follow region and its member regions.
#[derive(Debug, Clone)]
pub(crate) struct Pending {
    pub(crate) follow: Option<R>,
    pub(crate) members: BTreeSet<R>,
}

/// The region graph of one structurer run.
pub(crate) struct Graph<'a> {
    pub(crate) shape: &'a Shape,
    pub(crate) regions: Vec<Option<Region>>,
    pub(crate) preds: Vec<Vec<R>>,
    pub(crate) entry: R,
    pub(crate) pending: BTreeMap<R, Pending>,
}

/// The dominance facts of one pass over the live regions.
pub(crate) struct Facts {
    /// The regions in post-order. The root is not in the list.
    pub(crate) post: Vec<R>,
    /// The position of each region in reverse post-order.
    pub(crate) rpo: BTreeMap<R, usize>,
    index: BTreeMap<R, Node>,
    dom: DomTree,
}

impl Facts {
    /// Tells if `a` dominates `b`.
    pub(crate) fn dominates(&self, a: R, b: R) -> bool {
        match (self.index.get(&a), self.index.get(&b)) {
            (Some(&x), Some(&y)) => self.dom.dominates(x, y),
            _ => false,
        }
    }
}

/// Gives the region exit of a shape exit.
fn region_exit(n: Node, exit: &Exit) -> RExit {
    match exit {
        Exit::Stop => RExit::Stop,
        Exit::Fall(x) => RExit::Fall(x.index()),
        Exit::Cond { t, f } if t == f => RExit::Fall(t.index()),
        Exit::Cond { t, f } => RExit::Cond {
            cond: Cond::leaf(n),
            t: t.index(),
            f: f.index(),
        },
        Exit::Switch(list) => {
            let mut by: BTreeMap<R, Vec<usize>> = BTreeMap::new();
            for (i, t) in list.iter().enumerate() {
                by.entry(t.index()).or_default().push(i);
            }
            match by.len() {
                0 => RExit::Stop,
                1 => by.into_keys().next().map_or(RExit::Stop, RExit::Fall),
                _ => {
                    let mut arms: Vec<RArm> = by
                        .into_iter()
                        .map(|(r, cases)| RArm {
                            cases,
                            to: ArmTo::Region(r),
                        })
                        .collect();
                    arms.sort_by_key(|a| a.cases.first().copied());
                    RExit::Switch { on: n, arms }
                }
            }
        }
    }
}

impl<'a> Graph<'a> {
    /// Makes the graph of the nodes that the entry reaches.
    fn new(shape: &'a Shape, reach: &[Node]) -> Self {
        let mut regions: Vec<Option<Region>> = vec![None; shape.len()];
        for &n in reach {
            if let Some(slot) = regions.get_mut(n.index()) {
                *slot = Some(Region {
                    tree: Tree::Block(n),
                    exit: region_exit(n, shape.exit(n)),
                    head: n,
                    depth: 1,
                });
            }
        }
        let mut g = Self {
            shape,
            regions,
            preds: vec![Vec::new(); shape.len()],
            entry: shape.entry.index(),
            pending: BTreeMap::new(),
        };
        for r in 0..g.regions.len() {
            g.link(r);
        }
        g
    }

    /// Gives a live region.
    pub(crate) fn get(&self, r: R) -> Option<&Region> {
        self.regions.get(r).and_then(Option::as_ref)
    }

    /// Gives the exit of a live region, or `Stop`.
    pub(crate) fn exit(&self, r: R) -> RExit {
        self.get(r).map_or(RExit::Stop, |x| x.exit.clone())
    }

    /// Gives the address of a region.
    pub(crate) fn addr(&self, r: R) -> u64 {
        self.get(r).map_or(u64::MAX, |x| self.shape.addr(x.head))
    }

    /// Gives the head node of a region.
    pub(crate) fn head(&self, r: R) -> Node {
        self.get(r)
            .map_or_else(|| Node(u32::try_from(r).unwrap_or(u32::MAX)), |x| x.head)
    }

    /// Gives the live regions in index order.
    pub(crate) fn live(&self) -> Vec<R> {
        (0..self.regions.len())
            .filter(|&r| self.get(r).is_some())
            .collect()
    }

    /// Tells if the region tree is one pure block: a short-circuit or a `while` condition can
    /// hold it.
    pub(crate) fn is_pure(&self, r: R) -> bool {
        self.get(r).is_some_and(|x| {
            matches!(x.tree, Tree::Block(h) if h == x.head)
                && self.shape.node(x.head).is_some_and(|s| s.pure)
        })
    }

    /// Tells if `x` has exactly one structural predecessor edge, from `n`.
    pub(crate) fn only_pred(&self, x: R, n: R) -> bool {
        self.preds.get(x).is_some_and(|p| p.as_slice() == [n])
    }

    /// Tells if a schema can put `x` into another region: not the entry, not a loop header
    /// under construction and not the follow of one.
    pub(crate) fn absorbable(&self, x: R) -> bool {
        self.get(x).is_some()
            && x != self.entry
            && !self.pending.contains_key(&x)
            && !self.pending.values().any(|p| p.follow == Some(x))
    }

    /// Adds the edges of `r` to the predecessor lists.
    fn link(&mut self, r: R) {
        for t in self.exit(r).targets() {
            if let Some(list) = self.preds.get_mut(t) {
                list.push(r);
            }
        }
    }

    /// Removes the edges of `r` from the predecessor lists.
    fn unlink(&mut self, r: R) {
        for t in self.exit(r).targets() {
            if let Some(list) = self.preds.get_mut(t)
                && let Some(i) = list.iter().position(|&p| p == r)
            {
                list.remove(i);
            }
        }
    }

    /// Sets the tree, the exit and the depth of `r`. Each region of `gone` leaves the graph.
    pub(crate) fn update(&mut self, r: R, tree: Tree, exit: RExit, depth: usize, gone: &[R]) {
        self.unlink(r);
        for &x in gone {
            self.unlink(x);
            if let Some(slot) = self.regions.get_mut(x) {
                *slot = None;
            }
            if let Some(p) = self.preds.get_mut(x) {
                p.clear();
            }
        }
        if let Some(Some(reg)) = self.regions.get_mut(r) {
            reg.tree = tree;
            reg.exit = exit;
            reg.depth = depth;
        }
        self.link(r);
    }

    /// Takes the tree of a live region with its depth. The caller puts a new tree back.
    pub(crate) fn take(&mut self, r: R) -> (Tree, usize) {
        match self.regions.get_mut(r) {
            Some(Some(x)) => (std::mem::replace(&mut x.tree, Tree::empty()), x.depth),
            _ => (Tree::empty(), 0),
        }
    }

    /// Puts the label of `v` at the start of its tree.
    pub(crate) fn label(&mut self, v: R) {
        let Some(Some(reg)) = self.regions.get_mut(v) else {
            return;
        };
        let head = reg.head;
        if !starts_with_label(&reg.tree, head) {
            let old = std::mem::replace(&mut reg.tree, Tree::empty());
            reg.tree = Tree::Label(head).then(old);
        }
    }

    /// Replaces the edge `u -> v` with a jump of kind `kind`. Gives `false` when `u` has no
    /// such edge.
    pub(crate) fn virtualize(&mut self, u: R, v: R, kind: Jump) -> bool {
        let head = self.head(v);
        let jump = match kind {
            Jump::Goto => Tree::Goto(head),
            Jump::Break => Tree::Break(head),
            Jump::Continue => Tree::Continue(head),
        };
        if !self.exit(u).targets().contains(&v) {
            return false;
        }
        let (tree, depth) = self.take(u);
        let (tree, exit) = match self.exit(u) {
            RExit::Fall(x) if x == v => (tree.then(jump), RExit::Stop),
            RExit::Cond { cond, t, f } if t == v => (
                tree.then(Tree::If {
                    cond,
                    then: Box::new(jump),
                    els: None,
                }),
                RExit::Fall(f),
            ),
            RExit::Cond { cond, t, f } if f == v => (
                tree.then(Tree::If {
                    cond: cond.negate(),
                    then: Box::new(jump),
                    els: None,
                }),
                RExit::Fall(t),
            ),
            RExit::Switch { on, mut arms } if arms.iter().any(|a| a.to == ArmTo::Region(v)) => {
                for a in &mut arms {
                    if a.to == ArmTo::Region(v) {
                        a.to = ArmTo::Done(jump.clone());
                    }
                }
                if arms.iter().all(|a| matches!(a.to, ArmTo::Done(_))) {
                    let arms = arms
                        .into_iter()
                        .map(|a| Arm {
                            cases: a.cases,
                            body: match a.to {
                                ArmTo::Done(t) => t,
                                ArmTo::Region(_) => Tree::empty(),
                            },
                        })
                        .collect();
                    let sw = Tree::Switch {
                        on,
                        arms,
                        follow: None,
                    };
                    (tree.then(sw), RExit::Stop)
                } else {
                    (tree, RExit::Switch { on, arms })
                }
            }
            other => (tree, other),
        };
        self.update(u, tree, exit, depth.saturating_add(2), &[]);
        self.label(v);
        true
    }

    /// Gives the dominance facts of the live regions under a root with an edge to the entry
    /// and to each region that the entry does not reach. Gives `None` when the count of
    /// regions does not fit a CFG.
    pub(crate) fn facts(&self) -> Option<Facts> {
        let live = self.live();
        let mut index: BTreeMap<R, Node> = BTreeMap::new();
        for (i, &r) in live.iter().enumerate() {
            index.insert(
                r,
                Node(u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX)),
            );
        }
        let mut roots = vec![self.entry];
        let mut seen: BTreeSet<R> = BTreeSet::new();
        let mut by_addr: Vec<R> = live.clone();
        by_addr.sort_by_key(|&r| (self.addr(r), r));
        let walk = |start: R, seen: &mut BTreeSet<R>| {
            let mut stack = vec![start];
            while let Some(r) = stack.pop() {
                if self.get(r).is_some() && seen.insert(r) {
                    stack.extend(self.exit(r).targets());
                }
            }
        };
        walk(self.entry, &mut seen);
        for &r in &by_addr {
            if !seen.contains(&r) {
                roots.push(r);
                walk(r, &mut seen);
            }
        }
        let mut cfg = Cfg::new(live.len().saturating_add(1), Node(0)).ok()?;
        for r in &roots {
            if let Some(&n) = index.get(r) {
                let _ = cfg.add_edge(Node(0), n);
            }
        }
        for &r in &live {
            let Some(&from) = index.get(&r) else {
                continue;
            };
            for t in self.exit(r).targets() {
                if let Some(&to) = index.get(&t) {
                    let _ = cfg.add_edge(from, to);
                }
            }
        }
        let order = rpo(&cfg);
        let back: BTreeMap<Node, R> = index.iter().map(|(r, n)| (*n, *r)).collect();
        let list: Vec<R> = order.iter().filter_map(|n| back.get(n).copied()).collect();
        let rpo_pos = list.iter().enumerate().map(|(i, r)| (*r, i)).collect();
        let mut post = list;
        post.reverse();
        Some(Facts {
            post,
            rpo: rpo_pos,
            index,
            dom: dominators(&cfg),
        })
    }

    /// Tells if `r` is a loop header: a predecessor edge comes from a region that `r`
    /// dominates.
    pub(crate) fn is_header(&self, r: R, facts: &Facts) -> bool {
        self.preds
            .get(r)
            .is_some_and(|p| p.iter().any(|&u| facts.dominates(r, u)))
    }
}

/// Tells if a tree starts with the label of `head`, through the first items of sequences and
/// the bodies of endless and `do .. while` loops.
fn starts_with_label(t: &Tree, head: Node) -> bool {
    let mut cur = t;
    for _ in 0..=MAX_DEPTH {
        cur = match cur {
            Tree::Label(n) => return *n == head,
            Tree::Seq(items) => match items.first() {
                Some(first) => first,
                None => return false,
            },
            Tree::Loop {
                kind: LoopKind::Endless | LoopKind::DoWhile,
                body,
                ..
            } => body,
            _ => return false,
        };
    }
    false
}

/// Gives the depth of `a.then(b)` from the depths of `a` and `b`.
pub(crate) fn seq_depth(a: &Tree, da: usize, b: &Tree, db: usize) -> usize {
    let item = |t: &Tree, d: usize| {
        if matches!(t, Tree::Seq(_)) {
            d
        } else {
            d.saturating_add(1)
        }
    };
    item(a, da).max(item(b, db))
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
