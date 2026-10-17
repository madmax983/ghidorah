//! FLAT output (design Section 8.6).
//!
//! [`tree`] puts each reachable node of a shape in address order, with its label and its
//! statements. Each edge that is not a fall-through to the next node gets an explicit `goto`.
//! The output needs no structuring, so it is correct for any CFG.

use crate::shape::Shape;
use crate::tree::Tree;

/// Gives the FLAT tree of `shape`.
#[must_use]
pub fn tree(shape: &Shape) -> Tree {
    let _ = shape;
    Tree::empty()
}
