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

/// The state of an iterative Tarjan walk over a part of a graph.
struct Tarjan {
    index: Vec<u32>,
    low: Vec<u32>,
    on_stack: Vec<bool>,
}

/// The index of a node that the walk did not visit.
const UNSEEN: u32 = u32::MAX;

impl Tarjan {
    fn new(count: usize) -> Self {
        Self {
            index: vec![UNSEEN; count],
            low: vec![0; count],
            on_stack: vec![false; count],
        }
    }

    /// Gives the components of `nodes` over the edges between nodes for which `alive` is
    /// true. The roots go in the order of `nodes`.
    fn run(&mut self, cfg: &Cfg, nodes: &[Node], alive: &dyn Fn(Node) -> bool) -> Vec<Vec<Node>> {
        for n in nodes {
            if let Some(slot) = self.index.get_mut(n.index()) {
                *slot = UNSEEN;
            }
        }
        let mut next = 0u32;
        let mut stack: Vec<Node> = Vec::new();
        let mut found = Vec::new();
        for &root in nodes {
            if self.index.get(root.index()) != Some(&UNSEEN) {
                continue;
            }
            self.visit(root, &mut next, &mut stack);
            let mut call = vec![(root, 0usize)];
            while let Some(top) = call.last_mut() {
                let (v, i) = *top;
                if let Some(&w) = cfg.succs(v).get(i) {
                    top.1 = i + 1;
                    if !alive(w) {
                        continue;
                    }
                    let wi = self.index.get(w.index()).copied().unwrap_or(UNSEEN);
                    if wi == UNSEEN {
                        self.visit(w, &mut next, &mut stack);
                        call.push((w, 0));
                    } else if self.on_stack.get(w.index()) == Some(&true) {
                        self.lower(v, wi);
                    }
                    continue;
                }
                call.pop();
                let v_low = self.low.get(v.index()).copied().unwrap_or(0);
                if let Some(&(u, _)) = call.last() {
                    self.lower(u, v_low);
                }
                if Some(&v_low) == self.index.get(v.index()) {
                    found.push(self.pop_component(v, &mut stack));
                }
            }
        }
        found
    }

    fn visit(&mut self, n: Node, next: &mut u32, stack: &mut Vec<Node>) {
        let i = n.index();
        if let (Some(index), Some(low), Some(on)) = (
            self.index.get_mut(i),
            self.low.get_mut(i),
            self.on_stack.get_mut(i),
        ) {
            *index = *next;
            *low = *next;
            *on = true;
        }
        *next = next.saturating_add(1);
        stack.push(n);
    }

    fn lower(&mut self, n: Node, value: u32) {
        if let Some(low) = self.low.get_mut(n.index()) {
            *low = (*low).min(value);
        }
    }

    fn pop_component(&mut self, root: Node, stack: &mut Vec<Node>) -> Vec<Node> {
        let mut component = Vec::new();
        while let Some(w) = stack.pop() {
            if let Some(on) = self.on_stack.get_mut(w.index()) {
                *on = false;
            }
            component.push(w);
            if w == root {
                break;
            }
        }
        component.sort_unstable();
        component
    }
}

/// Gives the strongly connected components of all nodes (Tarjan).
///
/// Each component lists its nodes in node order. The list of components is in reverse
/// topological order: a component comes before each component that reaches it.
#[must_use]
pub fn sccs(cfg: &Cfg) -> Vec<Vec<Node>> {
    let all: Vec<Node> = (0..cfg.len()).map(node).collect();
    Tarjan::new(cfg.len()).run(cfg, &all, &|_| true)
}

/// Tells if a component has a cycle: more than one node, or a self loop.
fn has_cycle(cfg: &Cfg, component: &[Node]) -> bool {
    match component {
        [n] => cfg.succs(*n).contains(n),
        _ => component.len() > 1,
    }
}

/// Gives the irreducible regions of the reachable part of `cfg`.
///
/// A region is a cycle with more than one entry node. The search takes each strongly
/// connected component with a cycle. A component with one entry loses its header, and the
/// search goes on inside the rest. A component with more entries is a region, and the
/// search goes on without its entry nodes. Each region lists its nodes in node order.
#[must_use]
pub fn irreducible(cfg: &Cfg, dom: &DomTree) -> Vec<Vec<Node>> {
    let preds = cfg.preds();
    let mut tarjan = Tarjan::new(cfg.len());
    // `group[v]` names the current part of node `v`. A walk keeps to one part.
    let mut group = vec![0u32; cfg.len()];
    let reachable: Vec<Node> = (0..cfg.len())
        .map(node)
        .filter(|&n| dom.is_reachable(n))
        .collect();
    for n in &reachable {
        if let Some(slot) = group.get_mut(n.index()) {
            *slot = 1;
        }
    }
    let mut next_group = 1u32;
    let mut work: Vec<Vec<Node>> = {
        let g = &group;
        tarjan.run(cfg, &reachable, &|n| g.get(n.index()) == Some(&1))
    };
    let mut regions = Vec::new();
    while let Some(component) = work.pop() {
        if !has_cycle(cfg, &component) {
            continue;
        }
        next_group = next_group.saturating_add(1);
        for n in &component {
            if let Some(slot) = group.get_mut(n.index()) {
                *slot = next_group;
            }
        }
        let inside = |n: Node| group.get(n.index()) == Some(&next_group);
        let mut entries: BTreeSet<Node> = component
            .iter()
            .copied()
            .filter(|&v| {
                v == cfg.entry()
                    || preds
                        .get(v.index())
                        .is_some_and(|list| list.iter().any(|&p| dom.is_reachable(p) && !inside(p)))
            })
            .collect();
        if entries.is_empty() {
            entries.extend(component.first().copied());
        }
        if entries.len() > 1 {
            regions.push(component.clone());
        }
        let rest: Vec<Node> = component
            .iter()
            .copied()
            .filter(|n| !entries.contains(n))
            .collect();
        next_group = next_group.saturating_add(1);
        for n in &rest {
            if let Some(slot) = group.get_mut(n.index()) {
                *slot = next_group;
            }
        }
        let g = &group;
        let part = next_group;
        work.extend(tarjan.run(cfg, &rest, &|n| g.get(n.index()) == Some(&part)));
    }
    regions.sort();
    regions
}
