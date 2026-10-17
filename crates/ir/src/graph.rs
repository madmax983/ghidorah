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
        let _unused = count;
        Err(GraphError::NoNode(entry))
    }

    /// Adds the edge `from -> to` after the other edges of `from`.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NoNode`] when a node is not in the graph.
    pub fn add_edge(&mut self, from: Node, to: Node) -> Result<(), GraphError> {
        let _unused = (to, &mut self.succs);
        Err(GraphError::NoNode(from))
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
        Vec::new()
    }
}

/// Gives the reverse postorder of the nodes that the entry reaches.
///
/// The depth-first walk visits the successors of each node in list order.
#[must_use]
pub fn rpo(cfg: &Cfg) -> Vec<Node> {
    let _unused = cfg;
    Vec::new()
}

/// The dominator tree of a [`Cfg`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomTree {
    idom: Vec<Option<Node>>,
    rpo_index: Vec<Option<u32>>,
    entry: Node,
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
        let _unused = (a, b, self.entry);
        false
    }

    /// Gives the children of each node in the tree, in node order.
    #[must_use]
    pub fn children(&self) -> Vec<Vec<Node>> {
        Vec::new()
    }
}

/// Gives the dominator tree of `cfg`.
#[must_use]
pub fn dominators(cfg: &Cfg) -> DomTree {
    DomTree {
        idom: Vec::new(),
        rpo_index: Vec::new(),
        entry: cfg.entry(),
    }
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
    let _unused = (cfg, dom);
    Vec::new()
}

/// Gives the strongly connected components of all nodes (Tarjan).
///
/// Each component lists its nodes in node order. The list of components is in reverse
/// topological order: a component comes before each component that reaches it.
#[must_use]
pub fn sccs(cfg: &Cfg) -> Vec<Vec<Node>> {
    let _unused = cfg;
    Vec::new()
}

/// Gives the irreducible regions of the reachable part of `cfg`.
///
/// A region is a cycle with more than one entry node. The search takes each strongly
/// connected component with a cycle. A component with one entry loses its header, and the
/// search goes on inside the rest. A component with more entries is a region, and the
/// search goes on without its entry nodes. Each region lists its nodes in node order.
#[must_use]
pub fn irreducible(cfg: &Cfg, dom: &DomTree) -> Vec<Vec<Node>> {
    let _unused = (cfg, dom);
    Vec::new()
}
