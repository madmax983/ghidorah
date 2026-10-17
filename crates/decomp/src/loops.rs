//! The cyclic schemas of the structurer and the loop clean-up (design Section 8.1).
//!
//! | Step | Shape | Result |
//! |---|---|---|
//! | Self loop | `n` falls to itself | `for (;;) n` |
//! | Self loop | `n` branches to itself and to `x` | `do n while (c)`, then `x` |
//! | Two-node loop | `n` branches to `b` and `x`, and `b` falls to `n` | `while (c) b` for a pure `n`, else `for (;;) { n; if (!c) break; b }` |
//! | Natural loop | a header with back edges | back edges become `continue`, exits to the successor become `break`, other exits become `goto` |
//!
//! A natural loop stays under construction until its body collapses into the header. Then
//! it becomes an endless loop with the successor as its exit.
//!
//! [`finish`] cleans the tree: a `break` or `continue` whose inner loop or switch is not its
//! target becomes a `goto`, endless loops become `while` and `do .. while` loops where the
//! shape allows, a `continue` at the end of a body goes, and labels without a `goto` go.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_ir::Node;

use crate::shape::Shape;
use crate::structure::{Facts, Graph, Jump, Pending, R, RExit};
use crate::tree::{Arm, Cond, LoopKind, Tree};

/// Makes an endless loop tree.
fn endless(body: Tree, head: Node, follow: Option<Node>) -> Tree {
    Tree::Loop {
        kind: LoopKind::Endless,
        cond: None,
        body: Box::new(body),
        head,
        follow,
    }
}

/// Tries the self loops and the two-node loops at `n`. Gives `true` when one matches.
#[expect(
    clippy::many_single_char_names,
    reason = "the region names follow the schema table of the module doc"
)]
pub(crate) fn simple(g: &mut Graph<'_>, n: R) -> bool {
    let head = g.head(n);
    match g.exit(n) {
        RExit::Fall(x) if x == n => {
            let (a, d) = g.take(n);
            g.update(
                n,
                endless(a, head, None),
                RExit::Stop,
                d.saturating_add(1),
                &[],
            );
            true
        }
        RExit::Cond { cond, t, f } if t == n || f == n => {
            let (x, c) = if t == n {
                (f, cond)
            } else {
                (t, cond.negate())
            };
            let (a, d) = g.take(n);
            let tree = Tree::Loop {
                kind: LoopKind::DoWhile,
                cond: Some(c),
                body: Box::new(a),
                head,
                follow: Some(g.head(x)),
            };
            g.update(n, tree, RExit::Fall(x), d.saturating_add(1), &[]);
            true
        }
        RExit::Cond { cond, t, f } => {
            for (b, x, c) in [(t, f, cond.clone()), (f, t, cond.negate())] {
                if two_node(g, n, b, x, c) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// The two-node loop: `n` goes to `b` when `c` is true and to `x` otherwise, and `b` falls
/// back to `n`.
#[expect(
    clippy::many_single_char_names,
    reason = "the region names follow the schema table of the module doc"
)]
fn two_node(g: &mut Graph<'_>, n: R, b: R, x: R, c: Cond) -> bool {
    if b == n || b == x || !g.absorbable(b) || !g.only_pred(b, n) || g.exit(b) != RExit::Fall(n) {
        return false;
    }
    let head = g.head(n);
    let follow = g.head(x);
    let pure = g.is_pure(n);
    let (a, da) = g.take(n);
    let (body, db) = g.take(b);
    let depth = da.max(db).saturating_add(2);
    let tree = if pure {
        Tree::Loop {
            kind: LoopKind::While,
            cond: Some(c.with_exec()),
            body: Box::new(body),
            head,
            follow: Some(follow),
        }
    } else {
        let stop = Tree::If {
            cond: c.negate(),
            then: Box::new(Tree::Break(follow)),
            els: None,
        };
        endless(a.then(stop).then(body), head, Some(follow))
    };
    g.update(n, tree, RExit::Fall(x), depth, &[b]);
    g.label(x);
    true
}

/// Gives the natural loop of the header `h`: `h` and each region that reaches a back edge
/// source without `h`.
fn natural(g: &Graph<'_>, h: R, facts: &Facts) -> BTreeSet<R> {
    let mut body = BTreeSet::from([h]);
    let mut stack: Vec<R> = g
        .preds
        .get(h)
        .map(|p| {
            p.iter()
                .copied()
                .filter(|&u| facts.dominates(h, u))
                .collect()
        })
        .unwrap_or_default();
    while let Some(u) = stack.pop() {
        if body.insert(u) {
            stack.extend(g.preds.get(u).into_iter().flatten().copied());
        }
    }
    body
}

/// Starts the natural loop of the first header in post-order (the inner loops first). Only
/// one loop is under construction at a time.
pub(crate) fn refine(g: &mut Graph<'_>, facts: &Facts) -> bool {
    if !g.pending.is_empty() {
        return false;
    }
    let Some(h) = facts
        .post
        .iter()
        .copied()
        .find(|&r| g.get(r).is_some() && g.is_header(r, facts))
    else {
        return false;
    };
    let members = natural(g, h, facts);
    let mut edges: Vec<(R, R)> = Vec::new();
    for &u in &members {
        for v in g.exit(u).targets() {
            edges.push((u, v));
        }
    }
    let mut counts: BTreeMap<R, usize> = BTreeMap::new();
    for &(_, v) in &edges {
        if !members.contains(&v) {
            *counts.entry(v).or_default() += 1;
        }
    }
    let follow = counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| g.addr(*b.0).cmp(&g.addr(*a.0))))
        .map(|(v, _)| *v);
    for (u, v) in edges {
        let kind = if v == h {
            Jump::Continue
        } else if Some(v) == follow {
            Jump::Break
        } else if members.contains(&v) {
            continue;
        } else {
            Jump::Goto
        };
        let _ = g.virtualize(u, v, kind);
    }
    g.pending.insert(h, Pending { follow, members });
    true
}

/// Wraps each loop under construction whose body collapsed into its header. Gives `true` when
/// one wraps.
pub(crate) fn wrap_pending(g: &mut Graph<'_>) -> bool {
    let ready: Vec<R> = g
        .pending
        .iter()
        .filter(|(h, p)| {
            p.members.iter().all(|m| m == *h || g.get(*m).is_none())
                && g.exit(**h).targets().is_empty()
        })
        .map(|(h, _)| *h)
        .collect();
    for &h in &ready {
        let Some(p) = g.pending.remove(&h) else {
            continue;
        };
        let head = g.head(h);
        let follow = p.follow.map(|f| g.head(f));
        let (a, d) = g.take(h);
        let exit = p.follow.map_or(RExit::Stop, RExit::Fall);
        g.update(h, endless(a, head, follow), exit, d.saturating_add(1), &[]);
    }
    !ready.is_empty()
}

/// The kind of an enclosing loop or switch of the jump fix-up.
#[derive(Debug, Clone, Copy)]
enum Ctx {
    Loop { head: Node, follow: Option<Node> },
    Switch { follow: Option<Node> },
}

/// Replaces each `break` and `continue` whose inner loop or switch is not its target with a
/// `goto`.
fn fix_jumps(t: Tree, ctx: &mut Vec<Ctx>) -> Tree {
    match t {
        Tree::Break(n) => {
            let ok = match ctx.last() {
                Some(Ctx::Loop { follow, .. } | Ctx::Switch { follow }) => *follow == Some(n),
                None => false,
            };
            if ok { Tree::Break(n) } else { Tree::Goto(n) }
        }
        Tree::Continue(n) => {
            let ok = ctx.iter().rev().find_map(|c| match c {
                Ctx::Loop { head, .. } => Some(*head == n),
                Ctx::Switch { .. } => None,
            });
            if ok == Some(true) {
                Tree::Continue(n)
            } else {
                Tree::Goto(n)
            }
        }
        Tree::Seq(items) => Tree::Seq(items.into_iter().map(|i| fix_jumps(i, ctx)).collect()),
        Tree::If { cond, then, els } => Tree::If {
            cond,
            then: Box::new(fix_jumps(*then, ctx)),
            els: els.map(|e| Box::new(fix_jumps(*e, ctx))),
        },
        Tree::Loop {
            kind,
            cond,
            body,
            head,
            follow,
        } => {
            ctx.push(Ctx::Loop { head, follow });
            let body = fix_jumps(*body, ctx);
            let _ = ctx.pop();
            Tree::Loop {
                kind,
                cond,
                body: Box::new(body),
                head,
                follow,
            }
        }
        Tree::Switch { on, arms, follow } => {
            ctx.push(Ctx::Switch { follow });
            let arms = arms
                .into_iter()
                .map(|a| Arm {
                    cases: a.cases,
                    body: fix_jumps(a.body, ctx),
                })
                .collect();
            let _ = ctx.pop();
            Tree::Switch { on, arms, follow }
        }
        other => other,
    }
}

/// Gives the items of a tree as a list.
fn items_of(t: Tree) -> Vec<Tree> {
    match t {
        Tree::Seq(v) => v,
        other => vec![other],
    }
}

/// Tells if a tree jumps to `head`: a `continue` or a `goto` with that target.
fn jumps_to(t: &Tree, head: Node) -> bool {
    t.preorder()
        .iter()
        .any(|x| matches!(x, Tree::Continue(n) | Tree::Goto(n) if *n == head))
}

/// Gives the condition and the target of `if (c) break;`.
fn if_break(t: &Tree) -> Option<(&Cond, Node)> {
    match t {
        Tree::If {
            cond,
            then,
            els: None,
        } => match then.as_ref() {
            Tree::Break(n) => Some((cond, *n)),
            _ => None,
        },
        _ => None,
    }
}

/// Converts an endless loop into a `while` or `do .. while` loop where the shape allows.
/// Gives the trees that take its place.
fn convert(body: Tree, head: Node, follow: Option<Node>, shape: &Shape) -> Vec<Tree> {
    let mut items = items_of(body);
    let label = matches!(items.first(), Some(Tree::Label(n)) if *n == head);
    let skip = usize::from(label);
    let pure = shape.node(head).is_some_and(|s| s.pure);
    let at_top = matches!(items.get(skip), Some(Tree::Block(n)) if *n == head && pure)
        && items
            .get(skip.saturating_add(1))
            .and_then(if_break)
            .is_some_and(|(_, n)| Some(n) == follow);
    if at_top && let Some((cond, _)) = items.get(skip.saturating_add(1)).and_then(if_break) {
        let cond = cond.clone().negate().with_exec();
        let rest: Vec<Tree> = items.drain(skip.saturating_add(2)..).collect();
        let mut out = Vec::new();
        if label {
            out.push(Tree::Label(head));
        }
        out.push(Tree::Loop {
            kind: LoopKind::While,
            cond: Some(cond),
            body: Box::new(trim(Tree::Seq(rest), head)),
            head,
            follow,
        });
        return out;
    }
    let at_end = items
        .last()
        .and_then(if_break)
        .is_some_and(|(_, n)| Some(n) == follow);
    let rest = Tree::Seq(items[..items.len().saturating_sub(1)].to_vec());
    if at_end
        && !jumps_to(&rest, head)
        && items.len() > 1
        && let Some((cond, _)) = items.last().and_then(if_break)
    {
        return vec![Tree::Loop {
            kind: LoopKind::DoWhile,
            cond: Some(cond.clone().negate()),
            body: Box::new(rest),
            head,
            follow,
        }];
    }
    vec![endless(trim(Tree::Seq(items), head), head, follow)]
}

/// Removes a `continue` to `head` at the end of a loop body.
fn trim(body: Tree, head: Node) -> Tree {
    let mut items = items_of(body);
    if matches!(items.last(), Some(Tree::Continue(n)) if *n == head) {
        let _ = items.pop();
    }
    Tree::Seq(items)
}

/// Converts the loops of a tree, the inner loops first.
fn convert_all(t: Tree, shape: &Shape) -> Vec<Tree> {
    match t {
        Tree::Seq(items) => vec![Tree::Seq(
            items
                .into_iter()
                .flat_map(|i| convert_all(i, shape))
                .collect(),
        )],
        Tree::If { cond, then, els } => vec![Tree::If {
            cond,
            then: Box::new(seq_of(convert_all(*then, shape))),
            els: els.map(|e| Box::new(seq_of(convert_all(*e, shape)))),
        }],
        Tree::Loop {
            kind,
            cond,
            body,
            head,
            follow,
        } => {
            let body = seq_of(convert_all(*body, shape));
            match kind {
                LoopKind::Endless => convert(body, head, follow, shape),
                LoopKind::While => vec![Tree::Loop {
                    kind,
                    cond,
                    body: Box::new(trim(body, head)),
                    head,
                    follow,
                }],
                LoopKind::DoWhile => vec![Tree::Loop {
                    kind,
                    cond,
                    body: Box::new(body),
                    head,
                    follow,
                }],
            }
        }
        Tree::Switch { on, arms, follow } => vec![Tree::Switch {
            on,
            arms: arms
                .into_iter()
                .map(|a| Arm {
                    cases: a.cases,
                    body: seq_of(convert_all(a.body, shape)),
                })
                .collect(),
            follow,
        }],
        other => vec![other],
    }
}

/// Gives one tree of a list.
fn seq_of(mut list: Vec<Tree>) -> Tree {
    if list.len() == 1 {
        list.pop().unwrap_or_else(Tree::empty)
    } else {
        Tree::Seq(list)
    }
}

/// Removes each label without a `goto`, and flattens nested sequences.
fn drop_labels(t: Tree, used: &BTreeSet<Node>) -> Tree {
    match t {
        Tree::Seq(items) => {
            let mut out = Vec::with_capacity(items.len());
            for i in items {
                match drop_labels(i, used) {
                    Tree::Seq(inner) => out.extend(inner),
                    Tree::Label(n) if !used.contains(&n) => {}
                    other => out.push(other),
                }
            }
            Tree::Seq(out)
        }
        Tree::Label(n) if !used.contains(&n) => Tree::empty(),
        Tree::If { cond, then, els } => Tree::If {
            cond,
            then: Box::new(drop_labels(*then, used)),
            els: els.map(|e| Box::new(drop_labels(*e, used))),
        },
        Tree::Loop {
            kind,
            cond,
            body,
            head,
            follow,
        } => Tree::Loop {
            kind,
            cond,
            body: Box::new(drop_labels(*body, used)),
            head,
            follow,
        },
        Tree::Switch { on, arms, follow } => Tree::Switch {
            on,
            arms: arms
                .into_iter()
                .map(|a| Arm {
                    cases: a.cases,
                    body: drop_labels(a.body, used),
                })
                .collect(),
            follow,
        },
        other => other,
    }
}

/// Cleans a structured tree (see the module doc). The tree depth is at most
/// [`crate::structure::MAX_DEPTH`], so the recursion is bounded.
pub(crate) fn finish(tree: Tree, shape: &Shape) -> Tree {
    let fixed = fix_jumps(tree, &mut Vec::new());
    let converted = seq_of(convert_all(fixed, shape));
    let used: BTreeSet<Node> = converted.gotos().into_iter().collect();
    drop_labels(converted, &used)
}
