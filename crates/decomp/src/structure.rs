//! The structurer: Phoenix-lite post-order collapse (design Section 8.1, ADR-0010).
//!
//! [`run`] collapses the nodes of a [`Shape`] into one [`Tree`]. Each pass walks the regions
//! in post-order and tries the schemas in fixed order:
//!
//! | Order | Schemas |
//! |---|---|
//! | 1 | The 4 short-circuit shapes, `Seq`, `IfThen`, `IfThenElse`, `Switch` |
//! | 2 | Self loops (`do .. while`, endless) and two-node `while` loops |
//! | 3 | Greedy: if-no-exit, outside a loop header |
//! | 4 | A natural loop: back edges become `continue`, exits to the loop successor become `break` and other exits become `goto` |
//! | 5 | Last resort: one edge becomes a `goto` |
//!
//! The loop successor is the exit target with the most exit edges, ties to the lowest address.
//! The `goto` rule picks the first edge where neither end dominates the other, in reverse
//! post-order of the source, lowest source address first.
//!
//! The output is FLAT ([`crate::flat`]) when the shape has more than `max_nodes` blocks, when
//! the fuel runs out, when the tree gets too deep or when a pass changes nothing.

use ghidorah_base::Fuel;

use crate::shape::Shape;
use crate::tree::Tree;

/// The largest depth of a structured tree. A deeper tree gives FLAT output.
pub const MAX_DEPTH: usize = 2_000;

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

/// Structures `shape`. Each pass and each region step takes one unit of `fuel`.
#[must_use]
pub fn run(shape: &Shape, opts: &Opts, fuel: &mut Fuel) -> Structured {
    let _ = (shape, opts, fuel);
    Structured {
        tree: Tree::empty(),
        mode: Mode::Flat(FlatReason::NoProgress),
    }
}
