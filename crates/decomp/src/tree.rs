//! The structured statement tree (design Sections 8.1 and 8.2).
//!
//! A [`Tree`] holds shape nodes as leaves. The statements of a leaf are in the expression view
//! ([`crate::View`]). A [`Cond`] holds the branch conditions of shape nodes with `&&`, `||`
//! and negation.
//!
//! | Tree | Run |
//! |---|---|
//! | `Block(n)` | The statements of `n`. A node with the exit `Stop` ends the run. |
//! | `Seq(list)` | Each item in order. |
//! | `If` | The condition, then one branch. |
//! | `Loop` | `while`, `do .. while` or an endless loop. |
//! | `Switch` | The arm of the case that the switch node chooses. |
//! | `Goto(n)`, `Label(n)` | A jump to the label of `n`. Each label is in the tree once. |
//! | `Break(n)`, `Continue(n)` | The exit or the next turn of the inner loop. `n` is the target node. |
//!
//! Each walk of a tree uses an explicit stack, so a deep tree does not overflow the thread
//! stack.

use ghidorah_ir::Node;

/// A branch condition over the conditions of shape nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Cond {
    /// The branch condition of a node.
    Leaf {
        /// The node with the condition.
        node: Node,
        /// The leaf is the negation of the condition.
        neg: bool,
        /// The statements of the node run before the test. The first leaf of an `if` does
        /// not run them, because the tree runs them before the `if`.
        exec: bool,
    },
    /// Both conditions are true. The second one runs only when the first one is true.
    And(Box<Cond>, Box<Cond>),
    /// One condition is true. The second one runs only when the first one is false.
    Or(Box<Cond>, Box<Cond>),
}

impl Cond {
    /// Gives the plain leaf of `node`: no negation, and the statements run before.
    #[must_use]
    pub const fn leaf(node: Node) -> Self {
        Self::Leaf {
            node,
            neg: false,
            exec: false,
        }
    }

    /// Gives the negation. It flips each leaf, and `&&` and `||` change places (De Morgan).
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Self::Leaf { node, neg, exec } => Self::Leaf {
                node,
                neg: !neg,
                exec,
            },
            Self::And(a, b) => Self::Or(Box::new(a.negate()), Box::new(b.negate())),
            Self::Or(a, b) => Self::And(Box::new(a.negate()), Box::new(b.negate())),
        }
    }

    /// Gives the condition with `exec` set on each leaf.
    #[must_use]
    pub fn with_exec(self) -> Self {
        match self {
            Self::Leaf { node, neg, .. } => Self::Leaf {
                node,
                neg,
                exec: true,
            },
            Self::And(a, b) => Self::And(Box::new(a.with_exec()), Box::new(b.with_exec())),
            Self::Or(a, b) => Self::Or(Box::new(a.with_exec()), Box::new(b.with_exec())),
        }
    }

    /// Gives the nodes of the leaves in order.
    #[must_use]
    pub fn nodes(&self) -> Vec<Node> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(c) = stack.pop() {
            match c {
                Self::Leaf { node, .. } => out.push(*node),
                Self::And(a, b) | Self::Or(a, b) => {
                    stack.push(b);
                    stack.push(a);
                }
            }
        }
        out
    }
}

/// The kind of a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoopKind {
    /// `while (cond) body`: the condition runs before each turn.
    While,
    /// `do body while (cond)`: the condition runs after each turn.
    DoWhile,
    /// `for (;;) body`: only `break`, `goto` and a stop end the loop.
    Endless,
}

/// One arm of a switch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Arm {
    /// The case indexes of the arm, in order.
    pub cases: Vec<usize>,
    /// The body. An empty `Seq` goes to the end of the switch.
    pub body: Tree,
}

/// A structured statement tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tree {
    /// The statements of a shape node.
    Block(Node),
    /// Trees in order.
    Seq(Vec<Tree>),
    /// `if (cond) then else els`.
    If {
        /// The condition.
        cond: Cond,
        /// The branch when the condition is true.
        then: Box<Tree>,
        /// The branch when the condition is false.
        els: Option<Box<Tree>>,
    },
    /// A loop.
    Loop {
        /// The kind.
        kind: LoopKind,
        /// The condition of a `While` or `DoWhile` loop.
        cond: Option<Cond>,
        /// The body.
        body: Box<Tree>,
        /// The header node: the target of `continue`.
        head: Node,
        /// The node after the loop: the target of `break`.
        follow: Option<Node>,
    },
    /// A switch over the cases of a switch node.
    Switch {
        /// The node with the `Switch` exit.
        on: Node,
        /// The arms. Each case index is in one arm.
        arms: Vec<Arm>,
        /// The node after the switch.
        follow: Option<Node>,
    },
    /// A jump to the label of a node.
    Goto(Node),
    /// The label of a node.
    Label(Node),
    /// The exit of the inner loop or switch. The node is the target.
    Break(Node),
    /// The next turn of the inner loop. The node is the target.
    Continue(Node),
}

impl Tree {
    /// Gives the empty sequence.
    #[must_use]
    pub const fn empty() -> Self {
        Self::Seq(Vec::new())
    }

    /// Gives the sequence of `self` then `next`, with nested sequences made flat.
    #[must_use]
    pub fn then(self, next: Self) -> Self {
        let mut items = match self {
            Self::Seq(v) => v,
            other => vec![other],
        };
        match next {
            Self::Seq(v) => items.extend(v),
            other => items.push(other),
        }
        Self::Seq(items)
    }

    /// Gives the direct children in order.
    #[must_use]
    pub fn children(&self) -> Vec<&Self> {
        match self {
            Self::Seq(items) => items.iter().collect(),
            Self::If { then, els, .. } => {
                let mut v = vec![then.as_ref()];
                if let Some(e) = els {
                    v.push(e.as_ref());
                }
                v
            }
            Self::Loop { body, .. } => vec![body.as_ref()],
            Self::Switch { arms, .. } => arms.iter().map(|a| &a.body).collect(),
            Self::Block(_)
            | Self::Goto(_)
            | Self::Label(_)
            | Self::Break(_)
            | Self::Continue(_) => Vec::new(),
        }
    }

    /// Gives each tree of the walk in preorder.
    #[must_use]
    pub fn preorder(&self) -> Vec<&Self> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(t) = stack.pop() {
            out.push(t);
            for c in t.children().into_iter().rev() {
                stack.push(c);
            }
        }
        out
    }

    /// Gives the shape nodes of the tree in preorder: the blocks and the condition leaves.
    #[must_use]
    pub fn nodes(&self) -> Vec<Node> {
        let mut out = Vec::new();
        for t in self.preorder() {
            match t {
                Self::Block(n) => out.push(*n),
                Self::If { cond, .. }
                | Self::Loop {
                    cond: Some(cond), ..
                } => out.extend(cond.nodes().into_iter().filter(|n| cond_runs(cond, *n))),
                _ => {}
            }
        }
        out
    }

    /// Gives the labels of the tree in preorder.
    #[must_use]
    pub fn labels(&self) -> Vec<Node> {
        self.preorder()
            .into_iter()
            .filter_map(|t| match t {
                Self::Label(n) => Some(*n),
                _ => None,
            })
            .collect()
    }

    /// Gives the targets of the gotos of the tree in preorder.
    #[must_use]
    pub fn gotos(&self) -> Vec<Node> {
        self.preorder()
            .into_iter()
            .filter_map(|t| match t {
                Self::Goto(n) => Some(*n),
                _ => None,
            })
            .collect()
    }

    /// Gives the depth of the tree: 1 for a leaf.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut max = 0usize;
        let mut stack = vec![(self, 1usize)];
        while let Some((t, d)) = stack.pop() {
            max = max.max(d);
            for c in t.children() {
                stack.push((c, d.saturating_add(1)));
            }
        }
        max
    }
}

/// Tells if the leaf of `node` in `cond` runs the statements of the node.
fn cond_runs(cond: &Cond, node: Node) -> bool {
    let mut stack = vec![cond];
    while let Some(c) = stack.pop() {
        match c {
            Cond::Leaf { node: n, exec, .. } if *n == node => return *exec,
            Cond::Leaf { .. } => {}
            Cond::And(a, b) | Cond::Or(a, b) => {
                stack.push(b);
                stack.push(a);
            }
        }
    }
    false
}
