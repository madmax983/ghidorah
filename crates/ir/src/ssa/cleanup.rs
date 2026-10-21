//! The removal of redundant phis (Braun, Section 3.2, the SCC method).
//!
//! The phis and their phi operands make a graph. Each strongly connected component of that
//! graph with exactly one operand from outside is redundant: each of its phis has the value
//! of that operand. A component with more outside operands can hold a smaller redundant
//! component. Its inner phis read only phis of the component, and the method looks at them
//! again. The components come in topological order, so an operand component comes before
//! its users. A single phi with one outside operand is a trivial phi.
//!
//! The method uses an explicit stack for the inner components, so no step recurses.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::Fuel;

use crate::graph::{Cfg, Node, sccs};
use crate::op::{Arg, Opc, Val};

use super::edit::find;
use super::{Ssa, SsaError};

/// Gives the components of the phi graph of `list`, operand components first.
fn components(ssa: &Ssa, list: &[u32], repl: &BTreeMap<Val, Arg>) -> Vec<Vec<u32>> {
    let index: BTreeMap<Val, u32> = list
        .iter()
        .zip(0u32..)
        .filter_map(|(&op, i)| ssa.arena.op(op).and_then(|o| o.out).map(|v| (v, i)))
        .collect();
    let Ok(mut graph) = Cfg::new(list.len(), Node(0)) else {
        return Vec::new();
    };
    for (&phi, i) in list.iter().zip(0u32..) {
        for &arg in ssa.phi_args_of(phi) {
            if let Arg::V(v) = find(repl, arg)
                && let Some(&j) = index.get(&v)
            {
                // Both nodes are below the node count, so the edge is valid.
                let _valid = graph.add_edge(Node(i), Node(j));
            }
        }
    }
    sccs(&graph)
        .into_iter()
        .map(|c| {
            c.into_iter()
                .filter_map(|n| list.get(n.index()).copied())
                .collect()
        })
        .collect()
}

/// Gives the replacement of each redundant phi value among the phi ops `phis`.
///
/// Each phi of a component takes one unit of `fuel`.
///
/// # Errors
///
/// Returns [`SsaError::OutOfFuel`].
pub(crate) fn redundant_phis(
    ssa: &Ssa,
    phis: &[u32],
    fuel: &mut Fuel,
) -> Result<BTreeMap<Val, Arg>, SsaError> {
    let live: Vec<u32> = phis
        .iter()
        .copied()
        .filter(|&i| {
            ssa.arena
                .op(i)
                .is_some_and(|op| op.opc == Opc::Phi && op.out.is_some())
        })
        .collect();
    let mut repl = BTreeMap::new();
    let mut stack = vec![(components(ssa, &live, &repl), 0usize)];
    while let Some(top) = stack.last_mut() {
        let Some(comp) = top.0.get(top.1).cloned() else {
            stack.pop();
            continue;
        };
        top.1 = top.1.saturating_add(1);
        fuel.take(u64::try_from(comp.len()).unwrap_or(u64::MAX))?;
        let members: BTreeSet<Val> = comp
            .iter()
            .filter_map(|&i| ssa.arena.op(i).and_then(|op| op.out))
            .collect();
        let mut outer = BTreeSet::new();
        let mut inner = Vec::new();
        for &phi in &comp {
            let mut all_inside = true;
            for &arg in ssa.phi_args_of(phi) {
                match find(&repl, arg) {
                    Arg::V(v) if members.contains(&v) => {}
                    other => {
                        outer.insert(other);
                        all_inside = false;
                    }
                }
            }
            if all_inside {
                inner.push(phi);
            }
        }
        if let (1, Some(&value)) = (outer.len(), outer.first()) {
            for v in members {
                repl.insert(v, value);
            }
        } else if outer.len() > 1 && !inner.is_empty() && inner.len() < comp.len() {
            let sub = components(ssa, &inner, &repl);
            stack.push((sub, 0));
        }
    }
    Ok(repl)
}

/// Removes the phis of `repl` and replaces their uses. Gives the count of removed phis.
pub(crate) fn apply(ssa: &mut Ssa, phis: &[u32], repl: &BTreeMap<Val, Arg>) -> u64 {
    let mut removed = 0u64;
    for &phi in phis {
        if ssa
            .arena
            .op(phi)
            .and_then(|op| op.out)
            .is_some_and(|v| repl.contains_key(&v))
        {
            ssa.remove_op(phi);
            removed = removed.saturating_add(1);
        }
    }
    ssa.replace_uses(repl);
    removed
}

/// Gives every phi op of `ssa`.
pub(crate) fn all_phis(ssa: &Ssa) -> Vec<u32> {
    ssa.anchors
        .iter()
        .filter(|(anchor, _)| matches!(anchor, super::Anchor::Head(_)))
        .flat_map(|(_, list)| list.iter().copied())
        .collect()
}
