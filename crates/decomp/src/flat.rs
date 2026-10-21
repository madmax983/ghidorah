//! FLAT output (design Section 8.6).
//!
//! [`tree`] puts each reachable node of a shape in address order, with its label and its
//! statements. Each edge that is not a fall-through to the next node gets an explicit `goto`.
//! The output needs no structuring, so it is correct for any CFG.
//!
//! | Exit | FLAT statements after the node |
//! |---|---|
//! | `Stop` | none |
//! | `Fall(x)` | `goto x;` unless `x` comes next |
//! | `Cond { t, f }` | `if (c) goto t;`, then `goto f;` unless `f` comes next |
//! | `Switch(list)` | a switch whose arms each hold one `goto` |
//!
//! When the entry is not the first node, a `goto` to the entry comes first.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_ir::Node;

use crate::shape::{Exit, Shape};
use crate::tree::{Arm, Cond, Tree};

/// Gives the nodes that the entry reaches, in address order. Ties keep the node order.
#[must_use]
pub fn order(shape: &Shape) -> Vec<Node> {
    let mut seen = vec![false; shape.len()];
    let mut stack = vec![shape.entry];
    while let Some(n) = stack.pop() {
        match seen.get_mut(n.index()) {
            Some(flag) if !*flag => *flag = true,
            _ => continue,
        }
        stack.extend(shape.exit(n).succs());
    }
    let mut out: Vec<Node> = shape
        .ids()
        .filter(|n| seen.get(n.index()).copied().unwrap_or(false))
        .collect();
    out.sort_by_key(|n| (shape.addr(*n), n.0));
    out
}

/// Gives the arms of a switch whose cases each jump: one arm for each distinct target.
fn goto_arms(list: &[Node]) -> Vec<Arm> {
    let mut by_target: BTreeMap<Node, Vec<usize>> = BTreeMap::new();
    for (i, t) in list.iter().enumerate() {
        by_target.entry(*t).or_default().push(i);
    }
    let mut arms: Vec<Arm> = by_target
        .into_iter()
        .map(|(t, cases)| Arm {
            cases,
            body: Tree::Goto(t),
        })
        .collect();
    arms.sort_by_key(|a| a.cases.first().copied());
    arms
}

/// Gives the FLAT tree of `shape`.
#[must_use]
pub fn tree(shape: &Shape) -> Tree {
    let list = order(shape);
    let next: BTreeMap<Node, Option<Node>> = list
        .iter()
        .enumerate()
        .map(|(i, n)| (*n, list.get(i.saturating_add(1)).copied()))
        .collect();
    let mut items: Vec<Tree> = Vec::new();
    if list.first() != Some(&shape.entry) {
        items.push(Tree::Goto(shape.entry));
    }
    for &n in &list {
        let follows = next.get(&n).copied().flatten();
        items.push(Tree::Block(n));
        match shape.exit(n) {
            Exit::Stop => {}
            Exit::Fall(x) => {
                if follows != Some(*x) {
                    items.push(Tree::Goto(*x));
                }
            }
            Exit::Cond { t, f } => {
                items.push(Tree::If {
                    cond: Cond::leaf(n),
                    then: Box::new(Tree::Goto(*t)),
                    els: None,
                });
                if follows != Some(*f) {
                    items.push(Tree::Goto(*f));
                }
            }
            Exit::Switch(cases) => {
                if !cases.is_empty() {
                    items.push(Tree::Switch {
                        on: n,
                        arms: goto_arms(cases),
                        follow: None,
                    });
                }
            }
        }
    }
    let targets: BTreeSet<Node> = Tree::Seq(items.clone()).gotos().into_iter().collect();
    let mut out = Vec::with_capacity(items.len().saturating_add(targets.len()));
    for item in items {
        if let Tree::Block(n) = item
            && targets.contains(&n)
        {
            out.push(Tree::Label(n));
        }
        out.push(item);
    }
    Tree::Seq(out)
}
