//! The shape of a view: the block nodes, their exits and the added nodes.
//!
//! The exit of a block comes from its terminator and its CFG successors. The copies of an
//! edge go to the end of the source block when it has one successor. Else an `Edge` node holds
//! them. The copies of the function entry go to a `Start` node.

use std::collections::BTreeMap;

use ghidorah_ir::Node;

use crate::expr::{Call, Callee, Expr, Stmt, VarIdx};
use crate::shape::{Exit, NodeKind, Shape, ShapeNode};
use crate::vars::Assigned;
use crate::view::facts::Facts;
use crate::view::stmts::{Raw, Term};
use crate::view::{NodeView, View};

/// Maps the placeholder variables of an expression to their variables.
fn remap_expr(e: &mut Expr, of: &BTreeMap<ghidorah_ir::Val, VarIdx>) {
    match e {
        Expr::Var { var, .. } => {
            if let Some(&v) = of.get(&ghidorah_ir::Val(var.0)) {
                *var = v;
            }
        }
        Expr::Const { .. } | Expr::Str { .. } => {}
        Expr::Load { addr, .. } => remap_expr(addr, of),
        Expr::Un { x, .. } => remap_expr(x, of),
        Expr::Bin { x, y, .. } => {
            remap_expr(x, of);
            remap_expr(y, of);
        }
        Expr::Ite { a, b, c, .. } => {
            remap_expr(a, of);
            remap_expr(b, of);
            remap_expr(c, of);
        }
        Expr::Call(c) => remap_call(c, of),
    }
}

/// Maps the placeholder variables of a call.
fn remap_call(c: &mut Call, of: &BTreeMap<ghidorah_ir::Val, VarIdx>) {
    if let Callee::Indirect(t) = &mut c.callee {
        remap_expr(t, of);
    }
    for (_, a) in &mut c.args {
        remap_expr(a, of);
    }
    if let Some(m) = &mut c.mem {
        remap_expr(m, of);
    }
    for (_, v) in &mut c.rets {
        if let Some(&x) = of.get(&ghidorah_ir::Val(v.0)) {
            *v = x;
        }
    }
}

/// Maps the placeholder variables of a statement.
pub(crate) fn remap_stmt(s: &mut Stmt, of: &BTreeMap<ghidorah_ir::Val, VarIdx>) {
    match s {
        Stmt::Assign { var, value, .. } => {
            if let Some(&v) = of.get(&ghidorah_ir::Val(var.0)) {
                *var = v;
            }
            remap_expr(value, of);
        }
        Stmt::Store { addr, value, .. } => {
            remap_expr(addr, of);
            remap_expr(value, of);
        }
        Stmt::Call(c) => remap_call(c, of),
        Stmt::Return { uses, .. } => {
            for (_, e) in uses {
                remap_expr(e, of);
            }
        }
        Stmt::Goto { target, .. } => remap_expr(target, of),
    }
}

/// Maps the placeholder variables of a raw block.
pub(crate) fn remap_raw(raw: &mut Raw, of: &BTreeMap<ghidorah_ir::Val, VarIdx>) {
    for s in &mut raw.stmts {
        remap_stmt(s, of);
    }
    match &mut raw.term {
        Term::Plain => {}
        Term::Branch { cond, .. } => remap_expr(cond, of),
        Term::BranchStop { cond, tail, .. } => {
            remap_expr(cond, of);
            remap_stmt(tail, of);
        }
        Term::Switch { target } => remap_expr(target, of),
    }
}

/// The shape under construction with the views of its nodes.
struct Build {
    nodes: Vec<ShapeNode>,
    views: Vec<NodeView>,
}

impl Build {
    fn add(&mut self, node: ShapeNode, view: NodeView) -> Node {
        let n = Node(u32::try_from(self.nodes.len()).unwrap_or(u32::MAX));
        self.nodes.push(node);
        self.views.push(view);
        n
    }
}

/// Gives the distinct values of a list in order.
fn distinct(list: &[Node]) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::new();
    for n in list {
        if !out.contains(n) {
            out.push(*n);
        }
    }
    out
}

/// The exit of a block over its block-level successors.
enum BExit {
    Stop,
    Fall(Node),
    Cond {
        t: Node,
        f: Node,
    },
    /// A branch whose false side is the tail statement of the block.
    CondTail {
        t: Node,
        tail: Stmt,
    },
    Switch(Vec<Node>),
}

/// Gives the exit of a block and its view without the copies.
#[expect(
    clippy::many_single_char_names,
    reason = "t and f name the branch targets of the shape table"
)]
fn block_exit(f: &Facts<'_>, raw: &mut Raw, succs: &[Node]) -> (BExit, NodeView) {
    let mut view = NodeView {
        stmts: std::mem::take(&mut raw.stmts),
        term: raw.term_op,
        ops: raw.ops.clone(),
        span: Some(raw.span),
        ..NodeView::default()
    };
    let d = distinct(succs);
    let at = |addr: u64| f.ssa.block_at(addr).filter(|n| d.contains(n));
    let plain = || match d.as_slice() {
        [] => BExit::Stop,
        [x] => BExit::Fall(*x),
        _ => BExit::Switch(succs.to_vec()),
    };
    let exit = match std::mem::replace(&mut raw.term, Term::Plain) {
        Term::Plain => plain(),
        Term::Branch { cond, taken } => match (at(taken), d.as_slice()) {
            (Some(t), [x, y]) => {
                view.cond = Some(cond);
                BExit::Cond {
                    t,
                    f: if *x == t { *y } else { *x },
                }
            }
            _ => plain(),
        },
        Term::BranchStop { cond, taken, tail } => {
            if let Some(t) = at(taken) {
                view.cond = Some(cond);
                BExit::CondTail { t, tail }
            } else {
                view.stmts.push(tail);
                BExit::Stop
            }
        }
        Term::Switch { target } => {
            if d.len() > 1 {
                view.target = Some(target);
                view.cases = succs
                    .iter()
                    .map(|n| f.ssa.block_addr(*n).unwrap_or_default())
                    .collect();
                BExit::Switch(succs.to_vec())
            } else {
                plain()
            }
        }
    };
    (exit, view)
}

/// The facts of the edges of one block.
struct Edges<'a> {
    index: &'a BTreeMap<Node, Node>,
    assigned: &'a Assigned,
    block: Node,
    me: Node,
    single: bool,
}

/// Gives the shape node for the edge from the block to `s`. A copy list goes to the block
/// when it has one successor, else to a new `Edge` node.
fn through(
    e: &Edges<'_>,
    s: Node,
    memo: &mut BTreeMap<Node, Node>,
    b: &mut Build,
    view: &mut NodeView,
) -> Node {
    if let Some(&n) = memo.get(&s) {
        return n;
    }
    let to = e.index.get(&s).copied().unwrap_or(s);
    let n = match e.assigned.copies.get(&(Some(e.block), s)) {
        None => to,
        Some(copies) if e.single => {
            view.stmts.extend(copies.iter().cloned());
            to
        }
        Some(copies) => {
            let node = ShapeNode {
                addr: b.nodes.get(to.index()).map_or(0, |n| n.addr),
                kind: NodeKind::Edge { from: e.me, to },
                exit: Exit::Fall(to),
                pure: copies.is_empty(),
            };
            let edge_view = NodeView {
                stmts: copies.clone(),
                ..NodeView::default()
            };
            b.add(node, edge_view)
        }
    };
    memo.insert(s, n);
    n
}

/// Gives the instructions of the reachable blocks in address order.
fn insns_of(f: &Facts<'_>) -> Vec<(u64, u8)> {
    let arena = f.ssa.arena();
    let mut out: Vec<(u64, u8)> = Vec::new();
    for &b in &f.reach {
        let Some(block) = f.ssa.blocks().get(b.index()) else {
            continue;
        };
        let first = usize::try_from(block.first).unwrap_or(usize::MAX);
        let count = usize::try_from(block.count).unwrap_or(0);
        out.extend(
            arena
                .insns()
                .iter()
                .skip(first)
                .take(count)
                .map(|s| (s.addr, s.len)),
        );
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Adds the `Start` node with the copies of the function entry, when they exist. Gives the
/// entry node of the shape.
fn start_node(f: &Facts<'_>, assigned: &Assigned, entry: u64, b: &mut Build) -> Node {
    let Some(copies) = f
        .reach
        .first()
        .and_then(|eb| assigned.copies.get(&(None, *eb)))
    else {
        return Node(0);
    };
    let node = ShapeNode {
        addr: entry,
        kind: NodeKind::Start,
        exit: Exit::Fall(Node(0)),
        pure: copies.is_empty(),
    };
    let view = NodeView {
        stmts: copies.clone(),
        ..NodeView::default()
    };
    b.add(node, view)
}

/// Gives the shape and the node views of a function.
pub(crate) fn shape(f: &Facts<'_>, raws: &mut [Raw], assigned: &Assigned, entry: u64) -> View {
    let index: BTreeMap<Node, Node> = f
        .reach
        .iter()
        .enumerate()
        .map(|(i, b)| (*b, Node(u32::try_from(i).unwrap_or(u32::MAX))))
        .collect();
    let mut b = Build {
        nodes: Vec::new(),
        views: Vec::new(),
    };
    for raw in raws.iter() {
        let node = ShapeNode {
            addr: raw.span.0,
            kind: NodeKind::Block(raw.block),
            exit: Exit::Stop,
            pure: false,
        };
        let _ = b.add(node, NodeView::default());
    }
    for (i, raw) in raws.iter_mut().enumerate() {
        let me = Node(u32::try_from(i).unwrap_or(u32::MAX));
        let succs: Vec<Node> = f
            .ssa
            .cfg()
            .succs(raw.block)
            .iter()
            .filter(|s| index.contains_key(s))
            .copied()
            .collect();
        let (bexit, mut view) = block_exit(f, raw, &succs);
        let e = Edges {
            index: &index,
            assigned,
            block: raw.block,
            me,
            single: matches!(bexit, BExit::Fall(_)),
        };
        let mut memo = BTreeMap::new();
        let exit = match bexit {
            BExit::Stop => Exit::Stop,
            BExit::Fall(s) => Exit::Fall(through(&e, s, &mut memo, &mut b, &mut view)),
            BExit::Cond { t, f: fl } => Exit::Cond {
                t: through(&e, t, &mut memo, &mut b, &mut view),
                f: through(&e, fl, &mut memo, &mut b, &mut view),
            },
            BExit::CondTail { t, tail } => {
                let t = through(&e, t, &mut memo, &mut b, &mut view);
                let node = ShapeNode {
                    addr: raw.span.1,
                    kind: NodeKind::Tail(me),
                    exit: Exit::Stop,
                    pure: false,
                };
                let tail_view = NodeView {
                    stmts: vec![tail],
                    ..NodeView::default()
                };
                Exit::Cond {
                    t,
                    f: b.add(node, tail_view),
                }
            }
            BExit::Switch(list) => Exit::Switch(
                list.into_iter()
                    .map(|s| through(&e, s, &mut memo, &mut b, &mut view))
                    .collect(),
            ),
        };
        if let Some(n) = b.nodes.get_mut(i) {
            n.exit = exit;
            n.pure = view.stmts.is_empty();
        }
        if let Some(v) = b.views.get_mut(i) {
            *v = view;
        }
    }
    let start = start_node(f, assigned, entry, &mut b);
    View {
        entry,
        shape: Shape {
            entry: start,
            nodes: b.nodes,
        },
        nodes: b.views,
        vars: assigned.vars.clone(),
        insns: insns_of(f),
    }
}
