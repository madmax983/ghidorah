//! The CFG that the structurer reads (design Section 8.1).
//!
//! A [`Shape`] has one node for each reachable block of the L1 form, plus added nodes:
//!
//! - a `Start` node for the copies at the function entry,
//! - an `Edge` node for the copies on a critical edge,
//! - a `Tail` node for a return after a branch in one instruction.
//!
//! Each node has an [`Exit`].
//!
//! | Exit | Meaning |
//! |---|---|
//! | `Stop` | The node ends the run: a return, a call that does not return, a tail call or an unresolved jump. |
//! | `Fall(n)` | The flow goes to `n`. |
//! | `Cond { t, f }` | The branch condition of the node chooses `t` (true) or `f` (false). |
//! | `Switch(list)` | Case `i` of the jump table goes to `list[i]`. |
//!
//! The tests make shapes directly, so the structurer does not need an L1 form.

use ghidorah_ir::Node;

/// The exit of a shape node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Exit {
    /// The node ends the run.
    Stop,
    /// The flow goes to one node.
    Fall(Node),
    /// The branch condition chooses `t` or `f`.
    Cond {
        /// The node when the condition is true.
        t: Node,
        /// The node when the condition is false.
        f: Node,
    },
    /// Case `i` goes to node `i` of the list.
    Switch(Vec<Node>),
}

impl Exit {
    /// Tells if the exit ends the run: `Stop`, or a switch with no case.
    #[must_use]
    pub fn is_stop(&self) -> bool {
        match self {
            Self::Stop => true,
            Self::Switch(list) => list.is_empty(),
            Self::Fall(_) | Self::Cond { .. } => false,
        }
    }

    /// Gives the successors in edge order. A successor can come more than once.
    #[must_use]
    pub fn succs(&self) -> Vec<Node> {
        match self {
            Self::Stop => Vec::new(),
            Self::Fall(n) => vec![*n],
            Self::Cond { t, f } => vec![*t, *f],
            Self::Switch(list) => list.clone(),
        }
    }
}

/// The kind of a shape node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    /// A block of the L1 form.
    Block(Node),
    /// The copies of the phis of the entry block, before the entry block.
    Start,
    /// The ops after a branch in the last instruction of a block, for example a return. The
    /// node is the shape node of the block.
    Tail(Node),
    /// The copies of the phis of `to` on the critical edge from `from`. Both are shape nodes.
    Edge {
        /// The node at the start of the edge.
        from: Node,
        /// The node at the end of the edge.
        to: Node,
    },
}

/// One node of a [`Shape`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShapeNode {
    /// The address for the order of nodes: the block address, or the address of the target
    /// block of an added node.
    pub addr: u64,
    /// The kind.
    pub kind: NodeKind,
    /// The exit.
    pub exit: Exit,
    /// The node has no statement. A short-circuit condition or a `while` condition can hold it.
    pub pure: bool,
}

/// The CFG of the structurer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Shape {
    /// The entry node.
    pub entry: Node,
    /// The nodes. Node `n` is `nodes[n]`.
    pub nodes: Vec<ShapeNode>,
}

impl Shape {
    /// Gives the count of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Tells if the shape has no node.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Gives a node.
    #[must_use]
    pub fn node(&self, n: Node) -> Option<&ShapeNode> {
        self.nodes.get(n.index())
    }

    /// Gives the exit of a node. A node outside the shape stops.
    #[must_use]
    pub fn exit(&self, n: Node) -> &Exit {
        const STOP: &Exit = &Exit::Stop;
        self.node(n).map_or(STOP, |s| &s.exit)
    }

    /// Gives the address of a node, or 0 for a node outside the shape.
    #[must_use]
    pub fn addr(&self, n: Node) -> u64 {
        self.node(n).map_or(0, |s| s.addr)
    }

    /// Gives the count of nodes of the kind `Block`.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, NodeKind::Block(_)))
            .count()
    }

    /// Gives the nodes in shape order.
    pub fn ids(&self) -> impl Iterator<Item = Node> + '_ {
        (0..self.nodes.len()).filter_map(|i| u32::try_from(i).ok().map(Node))
    }

    /// Tells if each exit names only nodes of the shape and the entry is in the shape.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let len = self.nodes.len();
        self.entry.index() < len
            && self
                .nodes
                .iter()
                .all(|n| n.exit.succs().iter().all(|s| s.index() < len))
    }
}
