//! The switch of a jump table: its selector, its labels and its default (design Section 8.1).
//!
//! The analysis gives the guard `cmp idx, N; ja default` of each table ([`GuardInfo`]). The
//! view uses it in two steps:
//!
//! | Step | Result |
//! |---|---|
//! | [`Ex::selector`] | the selector is the compared index. An index `x - b` or `x + c` gives the selector `x` with the bias `b` or `-c`, so case `i` has the label `bias + i`. The view does not show a selector that reads memory or calls. |
//! | [`fold_guard`] | the guard branch goes into the switch: its out-of-range edge is the default case |
//!
//! The fold needs four conditions. The guard block ends with the guard branch, and its two
//! edges go straight to the switch block and to the default block. The default edge can hold
//! the copies of the phis of the default block. The guard block is the only predecessor of the
//! switch block. The switch block has no statement. So the switch
//! block computes only the jump target, and the switch with a default runs the same blocks
//! as the guard and the switch.

use std::collections::BTreeMap;

use ghidorah_analysis::jumptable::GuardInfo;
use ghidorah_ir::{Arg, Node, OpId, Opc};

use crate::expr::Expr;
use crate::shape::{Exit, NodeKind, ShapeNode};
use crate::view::NodeView;
use crate::view::facts::Facts;
use crate::view::stmts::{Ex, Selector};

/// The largest count of extensions that the selector walk looks through.
const MAX_VIEWS: usize = 4;

/// Tells if an expression reads no memory and calls nothing, so the switch line can show it
/// again at a later place.
fn pure(e: &Expr) -> bool {
    e.preorder()
        .iter()
        .all(|x| !matches!(x, Expr::Load { .. } | Expr::Call(_)))
}

/// Gives the mask of `w` bits.
const fn mask(w: u8) -> u64 {
    if w >= 64 { u64::MAX } else { (1u64 << w) - 1 }
}

impl Ex<'_> {
    /// Gives the value of `arg` at `w` bits without the `Trunc` of an extension from `w` bits.
    fn narrow(&self, arg: Arg, w: u8) -> Arg {
        let mut cur = self.f.ssa.root(arg);
        for _ in 0..MAX_VIEWS {
            let Some(op) = cur.as_v().and_then(|v| self.f.ssa.live_def(v)) else {
                return cur;
            };
            let inner = op.a[0].as_v().and_then(|v| self.f.ssa.live_def(v));
            match (op.opc, inner) {
                (Opc::Trunc, Some(ext))
                    if op.w == w && matches!(ext.opc, Opc::ZExt | Opc::SExt) && ext.sub == w =>
                {
                    cur = self.f.ssa.root(ext.a[0]);
                }
                _ => return cur,
            }
        }
        cur
    }

    /// Gives the selector of the jump table with the guard `g` (see the module doc).
    pub(crate) fn selector(&self, g: &GuardInfo) -> Option<Selector> {
        let op = *self.f.op(g.cmp)?;
        if !matches!(op.opc, Opc::ULt | Opc::ULe) {
            return None;
        }
        let w = op.w;
        let index = self.narrow(*op.a.get(usize::from(g.operand))?, w);
        let def = index.as_v().and_then(|v| self.f.ssa.live_def(v)).copied();
        let (base, bias) = match def {
            Some(d) if d.w == w && d.opc == Opc::Sub => match d.a[1].as_k() {
                Some(b) => (d.a[0], b & mask(w)),
                None => (index, 0),
            },
            Some(d) if d.w == w && d.opc == Opc::Add => match d.a[1].as_k() {
                Some(c) => (d.a[0], c.wrapping_neg() & mask(w)),
                None => (index, 0),
            },
            _ => (index, 0),
        };
        let (expr, bias) = match self.arg(self.narrow(base, w), w) {
            e if pure(&e) => (e, bias),
            _ => (self.arg(index, w), 0),
        };
        pure(&expr).then_some(Selector {
            expr,
            bias,
            guard: *g,
        })
    }
}

/// Puts the guard branch of the switch node `on` into the switch.
///
/// The guard node falls to `on`, and the default block is the last case of `on`. Gives
/// `false` when a condition of the module doc is not true. `index` maps each reachable block
/// to its shape node.
pub(crate) fn fold_guard(
    facts: &Facts<'_>,
    index: &BTreeMap<Node, Node>,
    nodes: &mut [ShapeNode],
    views: &mut [NodeView],
    (on, guard): (Node, &GuardInfo),
) -> bool {
    let ssa = facts.ssa;
    let node_at = |addr: u64| ssa.block_at(addr).and_then(|b| index.get(&b).copied());
    let guard_block = ssa
        .arena()
        .insn_index(guard.branch)
        .and_then(|k| ssa.block_of_insn(k));
    let (Some(guard_block), Some(default)) = (guard_block, node_at(guard.default)) else {
        return false;
    };
    let Some(&guard_node) = index.get(&guard_block) else {
        return false;
    };
    let Some(NodeKind::Block(on_block)) = nodes.get(on.index()).map(|n| n.kind) else {
        return false;
    };
    if ssa.preds(on_block) != [guard_block] || guard_node == on {
        return false;
    }
    // The default edge can hold the copies of the phis of the default block.
    let reaches_default = |n: Node| {
        n == default
            || matches!(nodes.get(n.index()).map(|x| x.kind),
                Some(NodeKind::Edge { to, .. }) if to == default)
    };
    let other = match nodes.get(guard_node.index()).map(|n| &n.exit) {
        Some(Exit::Cond { t, f }) if *t == on && reaches_default(*f) => *f,
        Some(Exit::Cond { t, f }) if *f == on && reaches_default(*t) => *t,
        _ => return false,
    };
    let pure = views.get(on.index()).is_some_and(|v| v.stmts.is_empty());
    let mut list = match nodes.get(on.index()).map(|n| &n.exit) {
        Some(Exit::Switch(list)) if pure && !list.is_empty() => list.clone(),
        _ => return false,
    };
    let mut ops: Vec<OpId> = Vec::new();
    if let Some(view) = views.get_mut(guard_node.index()) {
        if let Some(cond) = view.cond.take() {
            ops.extend(cond.preorder().iter().filter_map(|e| e.at()));
        }
        ops.extend(view.term.take());
    }
    if let Some(n) = nodes.get_mut(guard_node.index()) {
        n.exit = Exit::Fall(on);
    }
    list.push(other);
    if let Some(n) = nodes.get_mut(on.index()) {
        n.exit = Exit::Switch(list);
    }
    let default_addr = nodes.get(default.index()).map_or(guard.default, |n| n.addr);
    if let Some(view) = views.get_mut(on.index()) {
        view.guard = ops;
        view.default = true;
        view.cases.push(default_addr);
    }
    true
}
