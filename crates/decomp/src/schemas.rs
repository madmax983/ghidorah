//! The acyclic schemas of the structurer (design Section 8.1).
//!
//! Each schema looks at one region `n` and its successors. A successor that a schema puts into
//! `n` must have `n` as its only predecessor.
//!
//! | Schema | Shape | Result |
//! |---|---|---|
//! | Short circuit | `n` branches to a pure node `m`, and `m` branches to a target of `n` | one condition with `&&` or `\|\|` |
//! | `Seq` | `n` falls to `s` | `n; s` |
//! | `IfThen` | `n` branches to `t` and `f`, and `t` falls to `f` | `n; if (c) t` |
//! | `IfThenElse` | both branches fall to one node, or both stop | `n; if (c) t else f` |
//! | `Switch` | each case body falls to one follow node, or stops | `n; switch` |
//! | if-no-exit (greedy) | one branch stops | `n; if (c) t`, then the other branch |

use ghidorah_ir::Node;

use crate::structure::{ArmTo, Facts, Graph, R, RExit, seq_depth};
use crate::tree::{Arm, Cond, Tree};

/// Tries the acyclic schemas at `n` in fixed order. Gives `true` when one matches.
pub(crate) fn acyclic(g: &mut Graph<'_>, n: R) -> bool {
    short_circuit(g, n) || seq(g, n) || if_then(g, n) || if_then_else(g, n) || switch(g, n)
}

/// Tells if `x` can go into `n`: `x` is another region and `n` is its only predecessor.
fn takes(g: &Graph<'_>, n: R, x: R) -> bool {
    x != n && g.absorbable(x) && g.only_pred(x, n)
}

/// The `Seq` schema.
#[expect(
    clippy::many_single_char_names,
    reason = "the region names follow the schema table of the module doc"
)]
pub(crate) fn seq(g: &mut Graph<'_>, n: R) -> bool {
    let RExit::Fall(s) = g.exit(n) else {
        return false;
    };
    if !takes(g, n, s) {
        return false;
    }
    let (a, da) = g.take(n);
    let (b, db) = g.take(s);
    let depth = seq_depth(&a, da, &b, db);
    g.update(n, a.then(b), g.exit(s), depth, &[s]);
    true
}

/// Gives `a` then `if (c) then`, with its depth.
fn then_if(
    a: Tree,
    da: usize,
    cond: Cond,
    then: Tree,
    dt: usize,
    els: Option<(Tree, usize)>,
) -> (Tree, usize) {
    let de = els.as_ref().map_or(0, |e| e.1);
    let it = Tree::If {
        cond,
        then: Box::new(then),
        els: els.map(|e| Box::new(e.0)),
    };
    let di = dt.max(de).saturating_add(1);
    let depth = seq_depth(&a, da, &it, di);
    (a.then(it), depth)
}

/// The `IfThen` schema in both directions.
fn if_then(g: &mut Graph<'_>, n: R) -> bool {
    let RExit::Cond { cond, t, f } = g.exit(n) else {
        return false;
    };
    for (body, other, c) in [(t, f, cond.clone()), (f, t, cond.negate())] {
        if takes(g, n, body) && g.exit(body) == RExit::Fall(other) {
            let (a, da) = g.take(n);
            let (b, db) = g.take(body);
            let (tree, depth) = then_if(a, da, c, b, db, None);
            g.update(n, tree, RExit::Fall(other), depth, &[body]);
            return true;
        }
    }
    false
}

/// The `IfThenElse` schema: both branches fall to one node, or both stop.
fn if_then_else(g: &mut Graph<'_>, n: R) -> bool {
    let RExit::Cond { cond, t, f } = g.exit(n) else {
        return false;
    };
    if !takes(g, n, t) || !takes(g, n, f) {
        return false;
    }
    let (et, ef) = (g.exit(t), g.exit(f));
    let joined = match (&et, &ef) {
        (RExit::Fall(x), RExit::Fall(y)) => x == y && *x != t && *x != f,
        (RExit::Stop, RExit::Stop) => true,
        _ => false,
    };
    if !joined {
        return false;
    }
    let (a, da) = g.take(n);
    let (bt, dt) = g.take(t);
    let (bf, df) = g.take(f);
    let (tree, depth) = then_if(a, da, cond, bt, dt, Some((bf, df)));
    g.update(n, tree, et, depth, &[t, f]);
    true
}

/// The 4 short-circuit shapes: `n` branches to a pure node `m` with a shared target.
fn short_circuit(g: &mut Graph<'_>, n: R) -> bool {
    let RExit::Cond {
        cond: c1,
        t: t1,
        f: f1,
    } = g.exit(n)
    else {
        return false;
    };
    for m in [t1, f1] {
        if !takes(g, n, m) || !g.is_pure(m) {
            continue;
        }
        let RExit::Cond {
            cond: c2,
            t: t2,
            f: f2,
        } = g.exit(m)
        else {
            continue;
        };
        if t2 == m || f2 == m {
            continue;
        }
        let c2 = c2.with_exec();
        let joined = if m == t1 && f2 == f1 {
            Some((and(c1.clone(), c2), t2, f1))
        } else if m == t1 && t2 == f1 {
            Some((and(c1.clone(), c2.negate()), f2, f1))
        } else if m == f1 && t2 == t1 {
            Some((or(c1.clone(), c2), t1, f2))
        } else if m == f1 && f2 == t1 {
            Some((or(c1.clone(), c2.negate()), t1, t2))
        } else {
            None
        };
        if let Some((cond, t, f)) = joined {
            let (a, da) = g.take(n);
            g.update(n, a, RExit::Cond { cond, t, f }, da, &[m]);
            return true;
        }
    }
    false
}

/// Gives `a && b`.
fn and(a: Cond, b: Cond) -> Cond {
    Cond::And(Box::new(a), Box::new(b))
}

/// Gives `a || b`.
fn or(a: Cond, b: Cond) -> Cond {
    Cond::Or(Box::new(a), Box::new(b))
}

/// The `Switch` schema: each case body has `n` as its only predecessor and falls to one
/// follow node or stops. A case that goes to the follow node is an empty arm.
#[expect(
    clippy::many_single_char_names,
    reason = "the region names follow the schema table of the module doc"
)]
fn switch(g: &mut Graph<'_>, n: R) -> bool {
    let RExit::Switch { on, arms } = g.exit(n) else {
        return false;
    };
    let mut follow: Option<R> = None;
    let mut bodies: Vec<R> = Vec::new();
    let agree = |x: R, follow: &mut Option<R>| {
        if let Some(f) = follow {
            *f == x
        } else {
            *follow = Some(x);
            true
        }
    };
    for a in &arms {
        let ArmTo::Region(t) = a.to else {
            continue;
        };
        if t == n {
            return false;
        }
        let body = takes(g, n, t) && matches!(g.exit(t), RExit::Fall(x) if x != t) || {
            takes(g, n, t) && g.exit(t) == RExit::Stop
        };
        if body {
            bodies.push(t);
            if let RExit::Fall(x) = g.exit(t)
                && !agree(x, &mut follow)
            {
                return false;
            }
        } else if !agree(t, &mut follow) {
            return false;
        }
    }
    if follow.is_some_and(|f| bodies.contains(&f)) {
        return false;
    }
    let (a, da) = g.take(n);
    let mut depth = 2usize;
    let mut out = Vec::with_capacity(arms.len());
    for arm in arms {
        let body = match arm.to {
            ArmTo::Done(t) => t,
            ArmTo::Region(t) if bodies.contains(&t) => {
                let (b, d) = g.take(t);
                depth = depth.max(d.saturating_add(1));
                b
            }
            ArmTo::Region(_) => Tree::empty(),
        };
        out.push(Arm {
            cases: arm.cases,
            body,
        });
    }
    let follow_node: Option<Node> = follow.map(|f| g.head(f));
    let sw = Tree::Switch {
        on,
        arms: out,
        follow: follow_node,
    };
    let depth = seq_depth(&a, da, &sw, depth);
    let tree = a.then(sw);
    let exit = follow.map_or(RExit::Stop, RExit::Fall);
    bodies.sort_unstable();
    bodies.dedup();
    g.update(n, tree, exit, depth, &bodies);
    true
}

/// The greedy if-no-exit schema at the first region of the post-order that is not a loop
/// header: a branch that stops goes into an `if`.
pub(crate) fn greedy(g: &mut Graph<'_>, facts: &Facts) -> bool {
    for &n in &facts.post {
        if g.get(n).is_none() || g.is_header(n, facts) {
            continue;
        }
        let RExit::Cond { cond, t, f } = g.exit(n) else {
            continue;
        };
        for (body, other, c) in [(t, f, cond.clone()), (f, t, cond.negate())] {
            if takes(g, n, body) && g.exit(body) == RExit::Stop {
                let (a, da) = g.take(n);
                let (b, db) = g.take(body);
                let (tree, depth) = then_if(a, da, c, b, db, None);
                g.update(n, tree, RExit::Fall(other), depth, &[body]);
                return true;
            }
        }
    }
    false
}
