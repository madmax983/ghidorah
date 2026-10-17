//! The SAILR-lite passes (design Section 8.2, ADR-0010).
//!
//! | Pass | Switches | Effect |
//! |---|---|---|
//! | Stack-canary removal | `sailr`, `canary` | The check of the `fs:0x28` value and the `__stack_chk_fail` branch go. Their instructions are elided. |
//! | Per-call-site noreturn | `sailr` | A call at the end of a node that stops does not return. A callee without a noreturn fact gives `W_NORETURN_ASSUMED`. |
//! | Tail calls | `sailr`, `tailcall` | A tail jump prints as `return f(..);`. Without the switches, it prints as a call. |
//!
//! A canary value is a 64-bit load of `fs:0x28`, a variable or a stack store of such a value,
//! or the difference (`-` or `^`) of two canary values. A canary check is a branch on a
//! compare where one side holds a canary value, and one branch calls `__stack_chk_fail`.
//!
//! Each pass edits the view. No pass edits L1.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::WarningCode;
use ghidorah_ir::{Loc, Node, OpId, Opc};

use crate::expr::{Callee, Expr, Stmt, VarIdx};
use crate::shape::Exit;
use crate::view::{Env, View};
use crate::{ElideReason, Elided, Passes, Warning};

/// The name of the canary failure function.
const FAIL: &str = "__stack_chk_fail";

/// The offset of the canary in the `fs` segment.
const CANARY_OFF: u64 = 0x28;

/// The findings of [`run`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// The ranges that the passes leave out.
    pub elided: Vec<Elided>,
    /// The warnings.
    pub warnings: Vec<Warning>,
}

/// Runs each pass that `passes` turns on.
pub fn run(view: &mut View, env: &dyn Env, passes: &Passes) -> Found {
    let mut found = Found::default();
    if !(passes.sailr && passes.tailcall) {
        for n in &mut view.nodes {
            for s in &mut n.stmts {
                if let Stmt::Call(c) = s {
                    c.tail = false;
                }
            }
        }
    }
    if passes.sailr && passes.canary {
        canary(view, env, &mut found);
    }
    if passes.sailr {
        noreturn(view, env, &mut found);
    }
    found
}

/// Marks the calls that end a node with no successor.
fn noreturn(view: &mut View, env: &dyn Env, found: &mut Found) {
    for (i, n) in view.nodes.iter_mut().enumerate() {
        let stops = view.shape.nodes.get(i).is_some_and(|s| s.exit.is_stop());
        let Some(Stmt::Call(c)) = n.stmts.last_mut() else {
            continue;
        };
        if !stops || c.tail {
            continue;
        }
        let known = match c.callee {
            Callee::Direct(t) => env.is_noreturn(t),
            Callee::Indirect(_) => false,
            Callee::Syscall | Callee::Intrinsic(_) | Callee::Unimpl => continue,
        };
        c.noreturn = true;
        if !known {
            found.warnings.push(Warning {
                code: WarningCode::NoreturnAssumed,
                at: c.at.addr,
            });
        }
    }
}

/// Tells if two expressions have the same shape: the same ops and leaves, any op IDs.
fn same(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Var { var: x, .. }, Expr::Var { var: y, .. }) => x == y,
        (Expr::Const { value: x, .. }, Expr::Const { value: y, .. })
        | (Expr::Str { addr: x }, Expr::Str { addr: y }) => x == y,
        (Expr::Load { w: wa, addr: x, .. }, Expr::Load { w: wb, addr: y, .. }) => {
            wa == wb && same(x, y)
        }
        (
            Expr::Un {
                op: oa, w: wa, x, ..
            },
            Expr::Un {
                op: ob,
                w: wb,
                x: y,
                ..
            },
        ) => oa == ob && wa == wb && same(x, y),
        (
            Expr::Bin {
                op: oa,
                w: wa,
                x: xa,
                y: ya,
                ..
            },
            Expr::Bin {
                op: ob,
                w: wb,
                x: xb,
                y: yb,
                ..
            },
        ) => oa == ob && wa == wb && same(xa, xb) && same(ya, yb),
        _ => false,
    }
}

/// The canary facts of a view.
struct Canary<'a> {
    view: &'a View,
    fs: BTreeSet<VarIdx>,
    defs: BTreeMap<VarIdx, &'a Expr>,
    slots: Vec<&'a Expr>,
}

impl<'a> Canary<'a> {
    fn new(view: &'a View) -> Self {
        let fs = view
            .vars
            .iter()
            .enumerate()
            .filter(|(_, v)| v.input == Some(Loc::FS_BASE))
            .filter_map(|(i, _)| u32::try_from(i).ok().map(VarIdx))
            .collect();
        let mut count: BTreeMap<VarIdx, usize> = BTreeMap::new();
        let mut defs = BTreeMap::new();
        for s in view.nodes.iter().flat_map(|n| &n.stmts) {
            if let Stmt::Assign { var, value, .. } = s {
                *count.entry(*var).or_default() += 1;
                defs.insert(*var, value);
            }
        }
        defs.retain(|v, _| count.get(v) == Some(&1));
        let mut me = Self {
            view,
            fs,
            defs,
            slots: Vec::new(),
        };
        let slots = view
            .nodes
            .iter()
            .flat_map(|n| &n.stmts)
            .filter_map(|s| match s {
                Stmt::Store {
                    w: 64, addr, value, ..
                } if me.is(value, 0) => Some(addr),
                _ => None,
            })
            .collect();
        me.slots = slots;
        me
    }

    /// Tells if `e` is the `fs:0x28` load.
    fn fs_load(&self, e: &Expr) -> bool {
        let Expr::Load { w: 64, addr, .. } = e else {
            return false;
        };
        let Expr::Bin {
            op: Opc::Add, x, y, ..
        } = addr.as_ref()
        else {
            return false;
        };
        let is_fs = |e: &Expr| matches!(e, Expr::Var { var, .. } if self.fs.contains(var));
        let is_off = |e: &Expr| matches!(e, Expr::Const { value, .. } if *value == CANARY_OFF);
        (is_fs(x) && is_off(y)) || (is_fs(y) && is_off(x))
    }

    /// Tells if `e` is a canary value. The depth bounds the walk.
    fn is(&self, e: &Expr, depth: u32) -> bool {
        if depth > 8 {
            return false;
        }
        match e {
            Expr::Load { w: 64, addr, .. } => {
                self.fs_load(e) || self.slots.iter().any(|s| same(s, addr))
            }
            Expr::Var { var, .. } => self
                .defs
                .get(var)
                .is_some_and(|d| self.is(d, depth.saturating_add(1))),
            Expr::Bin {
                op: Opc::Sub | Opc::Xor,
                x,
                y,
                ..
            } => self.is(x, depth.saturating_add(1)) && self.is(y, depth.saturating_add(1)),
            _ => false,
        }
    }

    /// Tells if `e` holds a canary value: the value itself, or a difference with one.
    fn holds(&self, e: &Expr, depth: u32) -> bool {
        if depth > 8 {
            return false;
        }
        match e {
            Expr::Var { var, .. } => self
                .defs
                .get(var)
                .is_some_and(|d| self.holds(d, depth.saturating_add(1))),
            Expr::Bin {
                op: Opc::Sub | Opc::Xor,
                x,
                y,
                ..
            } => self.holds(x, depth.saturating_add(1)) || self.holds(y, depth.saturating_add(1)),
            other => self.is(other, depth),
        }
    }

    /// Tells if a branch condition is a canary check: a compare where one side holds a canary
    /// value. The caller also needs a failure call on one side of the branch.
    fn check(&self, e: &Expr) -> bool {
        match e {
            Expr::Bin {
                op: Opc::Eq | Opc::Ne | Opc::TestZ | Opc::TestNZ,
                x,
                y,
                ..
            } => self.holds(x, 0) || self.holds(y, 0),
            _ => false,
        }
    }

    /// Tells if node `n`, or the node it falls to, calls the failure function.
    fn fails(&self, n: Node, env: &dyn Env) -> bool {
        let mut cur = n;
        for _ in 0..4 {
            let calls = self.view.node(cur).is_some_and(|v| {
                v.stmts.iter().any(|s| match s {
                    Stmt::Call(c) => match c.callee {
                        Callee::Direct(t) => env.callee_name(t).is_some_and(|x| x.contains(FAIL)),
                        _ => false,
                    },
                    _ => false,
                })
            });
            if calls {
                return true;
            }
            match self.view.shape.exit(cur) {
                Exit::Fall(next) => cur = *next,
                _ => return false,
            }
        }
        false
    }
}

/// Gives the elided range of the instruction at `addr`.
fn insn_range(view: &View, addr: u64) -> Option<Elided> {
    view.insn_len(addr).map(|len| Elided {
        start: addr,
        size: u64::from(len),
        reason: ElideReason::Canary,
    })
}

/// Removes the canary checks and the canary loads and stores (see the module doc).
fn canary(view: &mut View, env: &dyn Env, found: &mut Found) {
    let mut checks: Vec<(usize, Node, Node)> = Vec::new();
    {
        let facts = Canary::new(view);
        for (i, node) in view.nodes.iter().enumerate() {
            let Some(cond) = &node.cond else {
                continue;
            };
            let Exit::Cond { t, f } = *view.shape.exit(Node(u32::try_from(i).unwrap_or(u32::MAX)))
            else {
                continue;
            };
            if !facts.check(cond) {
                continue;
            }
            if facts.fails(t, env) {
                checks.push((i, f, t));
            } else if facts.fails(f, env) {
                checks.push((i, t, f));
            }
        }
    }
    if checks.is_empty() {
        return;
    }
    let mut addrs: BTreeSet<u64> = BTreeSet::new();
    for &(i, keep, fail) in &checks {
        if let Some(n) = view.nodes.get_mut(i) {
            if let Some(cond) = n.cond.take() {
                addrs.extend(
                    cond.preorder()
                        .iter()
                        .filter_map(|e| e.at())
                        .map(|a| a.addr),
                );
            }
            addrs.extend(n.term.map(|t| t.addr));
        }
        if let Some(s) = view.shape.nodes.get_mut(i) {
            s.exit = Exit::Fall(keep);
        }
        if let Some(span) = view.node(fail).and_then(|v| v.span) {
            found.elided.push(Elided {
                start: span.0,
                size: span.1.saturating_sub(span.0),
                reason: ElideReason::Canary,
            });
        }
    }
    let removed = remove_defs(view);
    addrs.extend(removed.iter().map(|a| a.addr));
    found
        .elided
        .extend(addrs.into_iter().filter_map(|a| insn_range(view, a)));
}

/// Removes the canary assignments and stores that nothing reads after the checks go. Gives
/// the ops of the removed statements.
fn remove_defs(view: &mut View) -> Vec<OpId> {
    let mut removed = Vec::new();
    for _ in 0..4 {
        let used: BTreeSet<VarIdx> = view
            .nodes
            .iter()
            .flat_map(|n| {
                n.stmts
                    .iter()
                    .flat_map(Stmt::exprs)
                    .chain(n.cond.iter())
                    .chain(n.target.iter())
                    .flat_map(Expr::vars)
                    .collect::<Vec<_>>()
            })
            .collect();
        let facts = Canary::new(view);
        let mut gone: BTreeSet<OpId> = BTreeSet::new();
        for s in view.nodes.iter().flat_map(|n| &n.stmts) {
            match s {
                Stmt::Assign { var, value, at } if !used.contains(var) && facts.is(value, 0) => {
                    gone.insert(*at);
                }
                Stmt::Store {
                    w: 64, value, at, ..
                } if facts.is(value, 0) => {
                    gone.insert(*at);
                }
                _ => {}
            }
        }
        if gone.is_empty() {
            break;
        }
        for n in &mut view.nodes {
            n.stmts.retain(|s| {
                !gone.contains(&s.at()) || !matches!(s, Stmt::Assign { .. } | Stmt::Store { .. })
            });
        }
        removed.extend(gone);
    }
    removed
}
