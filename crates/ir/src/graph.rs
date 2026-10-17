//! Graph algorithms over a CFG (design Sections 6.4 and 7.4).
//!
//! A [`Cfg`] has nodes `0..n`, one entry node and ordered successor lists. Each walk is
//! iterative with an explicit stack, so a deep graph does not overflow the thread stack
//! (AC-075a). Each result is deterministic: it depends only on the successor order.
//!
//! | Function | Result |
//! |---|---|
//! | [`rpo`] | The reverse postorder of the nodes that the entry reaches |
//! | [`dominators`] | The dominator tree (Cooper, Harvey and Kennedy) |
//! | [`loops`] | The natural loops, one for each header |
//! | [`sccs`] | The strongly connected components |
//! | [`irreducible`] | The cycles with more than one entry node |

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

mod scc;

pub use scc::{irreducible, sccs};

/// A node of a [`Cfg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Node(pub u32);

impl Node {
    /// Gives the node as an index.
    #[must_use]
    pub fn index(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

/// Gives the node of an index below the node count of a graph.
fn node(index: usize) -> Node {
    Node(u32::try_from(index).unwrap_or(u32::MAX))
}

/// The error of a [`Cfg`] edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphError {
    /// A node is not in the graph.
    NoNode(Node),
    /// The node count does not fit in a `u32`.
    TooLarge,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNode(n) => write!(f, "The graph has no node {}.", n.0),
            Self::TooLarge => f.write_str("The graph has too many nodes."),
        }
    }
}

impl std::error::Error for GraphError {}

/// A control flow graph with ordered successor lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    succs: Vec<Vec<Node>>,
    entry: Node,
}

impl Cfg {
    /// Makes a graph of `count` nodes and no edge.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NoNode`] when `entry` is not below `count`, and
    /// [`GraphError::TooLarge`] when `count` does not fit in a `u32`.
    pub fn new(count: usize, entry: Node) -> Result<Self, GraphError> {
        if u32::try_from(count).is_err() {
            return Err(GraphError::TooLarge);
        }
        if entry.index() >= count {
            return Err(GraphError::NoNode(entry));
        }
        Ok(Self {
            succs: vec![Vec::new(); count],
            entry,
        })
    }

    /// Adds the edge `from -> to` after the other edges of `from`.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NoNode`] when a node is not in the graph.
    pub fn add_edge(&mut self, from: Node, to: Node) -> Result<(), GraphError> {
        if to.index() >= self.succs.len() {
            return Err(GraphError::NoNode(to));
        }
        self.succs
            .get_mut(from.index())
            .ok_or(GraphError::NoNode(from))?
            .push(to);
        Ok(())
    }

    /// Gives the count of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.succs.len()
    }

    /// Tells if the graph has no node.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.succs.is_empty()
    }

    /// Gives the entry node.
    #[must_use]
    pub const fn entry(&self) -> Node {
        self.entry
    }

    /// Gives the successors of a node. A node outside the graph has none.
    #[must_use]
    pub fn succs(&self, n: Node) -> &[Node] {
        self.succs
            .get(n.index())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Gives the predecessor lists, in edge order.
    #[must_use]
    pub fn preds(&self) -> Vec<Vec<Node>> {
        let mut preds = vec![Vec::new(); self.succs.len()];
        for (from, succs) in self.succs.iter().enumerate() {
            for to in succs {
                if let Some(list) = preds.get_mut(to.index()) {
                    list.push(node(from));
                }
            }
        }
        preds
    }
}

/// Gives the reverse postorder of the nodes that the entry reaches.
///
/// The depth-first walk visits the successors of each node in list order.
#[must_use]
pub fn rpo(cfg: &Cfg) -> Vec<Node> {
    let mut seen = vec![false; cfg.len()];
    let mut post = Vec::new();
    let mut stack = Vec::new();
    if let Some(flag) = seen.get_mut(cfg.entry().index()) {
        *flag = true;
        stack.push((cfg.entry(), 0usize));
    }
    while let Some(top) = stack.last_mut() {
        let (n, i) = *top;
        if let Some(&s) = cfg.succs(n).get(i) {
            top.1 = i + 1;
            if let Some(flag) = seen.get_mut(s.index())
                && !*flag
            {
                *flag = true;
                stack.push((s, 0));
            }
        } else {
            post.push(n);
            stack.pop();
        }
    }
    post.reverse();
    post
}

/// The dominator tree of a [`Cfg`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomTree {
    idom: Vec<Option<Node>>,
    rpo_index: Vec<Option<u32>>,
    /// The preorder and postorder numbers of each reachable node in the tree.
    span: Vec<Option<(u32, u32)>>,
}

impl DomTree {
    /// Gives the immediate dominator of `n`. The entry and the nodes that the entry does not
    /// reach have none.
    #[must_use]
    pub fn idom(&self, n: Node) -> Option<Node> {
        self.idom.get(n.index()).copied().flatten()
    }

    /// Tells if the entry reaches `n`.
    #[must_use]
    pub fn is_reachable(&self, n: Node) -> bool {
        matches!(self.rpo_index.get(n.index()), Some(Some(_)))
    }

    /// Gives the position of `n` in the reverse postorder, or `None` when the entry does not
    /// reach `n`.
    #[must_use]
    pub fn rpo_index(&self, n: Node) -> Option<u32> {
        self.rpo_index.get(n.index()).copied().flatten()
    }

    /// Tells if `a` dominates `b`. A node dominates itself. Only reachable nodes dominate.
    #[must_use]
    pub fn dominates(&self, a: Node, b: Node) -> bool {
        let span = |n: Node| self.span.get(n.index()).copied().flatten();
        match (span(a), span(b)) {
            (Some((pre_a, post_a)), Some((pre_b, post_b))) => pre_a <= pre_b && post_b <= post_a,
            _ => false,
        }
    }

    /// Gives the children of each node in the tree, in node order.
    #[must_use]
    pub fn children(&self) -> Vec<Vec<Node>> {
        let mut children = vec![Vec::new(); self.idom.len()];
        for (v, parent) in self.idom.iter().enumerate() {
            if let Some(list) = parent.and_then(|p| children.get_mut(p.index())) {
                list.push(node(v));
            }
        }
        children
    }
}

/// Gives the nearest common dominator of two positions in the reverse postorder.
fn intersect(mut a: usize, mut b: usize, idom: &[Option<usize>]) -> usize {
    while a != b {
        while a > b {
            a = idom.get(a).copied().flatten().unwrap_or(0);
        }
        while b > a {
            b = idom.get(b).copied().flatten().unwrap_or(0);
        }
    }
    a
}

/// Gives the dominator tree of `cfg`.
///
/// The iteration over the reverse postorder stops when no immediate dominator changes.
/// It takes at most one pass more than the loop depth of the graph.
#[must_use]
pub fn dominators(cfg: &Cfg) -> DomTree {
    let order = rpo(cfg);
    let mut rpo_index = vec![None; cfg.len()];
    for (i, n) in order.iter().enumerate() {
        if let Some(slot) = rpo_index.get_mut(n.index()) {
            *slot = u32::try_from(i).ok();
        }
    }
    let position = |n: Node| rpo_index.get(n.index()).copied().flatten();
    let preds = cfg.preds();
    // `idom[i]` is the position of the immediate dominator of `order[i]`.
    let mut idom: Vec<Option<usize>> = vec![None; order.len()];
    if let Some(first) = idom.first_mut() {
        *first = Some(0);
    }
    for _pass in 0..=order.len() {
        let mut changed = false;
        for (i, n) in order.iter().enumerate().skip(1) {
            let mut new = None;
            for p in preds.get(n.index()).map(Vec::as_slice).unwrap_or_default() {
                let Some(pi) = position(*p).and_then(|x| usize::try_from(x).ok()) else {
                    continue;
                };
                if idom.get(pi).copied().flatten().is_none() {
                    continue;
                }
                new = Some(new.map_or(pi, |cur| intersect(cur, pi, &idom)));
            }
            if let Some(slot) = idom.get_mut(i)
                && *slot != new
            {
                *slot = new;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut tree = vec![None; cfg.len()];
    for (i, n) in order.iter().enumerate().skip(1) {
        let parent = idom.get(i).copied().flatten().and_then(|p| order.get(p));
        if let Some(slot) = tree.get_mut(n.index()) {
            *slot = parent.copied();
        }
    }
    let mut dom = DomTree {
        idom: tree,
        rpo_index,
        span: Vec::new(),
    };
    dom.span = tree_spans(&dom, cfg.entry());
    dom
}

/// Gives the preorder and postorder numbers of the tree nodes under `root`.
fn tree_spans(dom: &DomTree, root: Node) -> Vec<Option<(u32, u32)>> {
    let children = dom.children();
    let mut span = vec![None; children.len()];
    if !dom.is_reachable(root) {
        return span;
    }
    let mut pre = vec![0u32; children.len()];
    let (mut next_pre, mut next_post) = (0u32, 0u32);
    let mut stack = vec![(root, 0usize)];
    if let Some(slot) = pre.get_mut(root.index()) {
        *slot = next_pre;
    }
    while let Some(top) = stack.last_mut() {
        let (n, i) = *top;
        if let Some(&c) = children.get(n.index()).and_then(|list| list.get(i)) {
            top.1 = i + 1;
            next_pre = next_pre.saturating_add(1);
            if let Some(slot) = pre.get_mut(c.index()) {
                *slot = next_pre;
            }
            stack.push((c, 0));
        } else {
            if let Some(slot) = span.get_mut(n.index()) {
                *slot = pre.get(n.index()).map(|&p| (p, next_post));
            }
            next_post = next_post.saturating_add(1);
            stack.pop();
        }
    }
    span
}

/// A natural loop.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Loop {
    /// The header: it dominates each node of the loop.
    pub header: Node,
    /// The nodes of the loop in node order, the header included.
    pub body: Vec<Node>,
    /// The sources of the back edges to the header, in node order.
    pub latches: Vec<Node>,
}

/// Gives the natural loops of `cfg`, one for each header, in header order.
///
/// A back edge is an edge `t -> h` where `h` dominates `t`. The loop of `h` holds each
/// node that reaches a latch of `h` without a walk through `h`.
#[must_use]
pub fn loops(cfg: &Cfg, dom: &DomTree) -> Vec<Loop> {
    let mut latches: BTreeMap<Node, BTreeSet<Node>> = BTreeMap::new();
    for t in (0..cfg.len()).map(node).filter(|&t| dom.is_reachable(t)) {
        for &h in cfg.succs(t) {
            if dom.dominates(h, t) {
                latches.entry(h).or_default().insert(t);
            }
        }
    }
    let preds = cfg.preds();
    latches
        .into_iter()
        .map(|(header, latches)| {
            let mut body = BTreeSet::from([header]);
            let mut work: Vec<Node> = latches.iter().copied().collect();
            while let Some(n) = work.pop() {
                if !body.insert(n) {
                    continue;
                }
                let list = preds.get(n.index()).map(Vec::as_slice).unwrap_or_default();
                work.extend(list.iter().copied().filter(|&p| dom.is_reachable(p)));
            }
            Loop {
                header,
                body: body.into_iter().collect(),
                latches: latches.into_iter().collect(),
            }
        })
        .collect()
}
