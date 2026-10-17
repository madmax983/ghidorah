//! Safe folding (design Section 8.2, the angr rule).
//!
//! A value folds into its use when each condition is true:
//!
//! 1. The value has exactly one use, and the use is not a phi.
//! 2. The use is in the same block, after the def. So the def never leaves a loop body.
//! 3. No store, call, system call or opaque instruction runs between the def and the use.
//! 4. A load and a division can stop a run. Between such a value and its use, no other op
//!    that can stop a run runs. So the run stops at the same op as L0.
//!
//! The plan walks each block once. A deferred value runs at the place of its use. A barrier
//! makes each deferred value that conflicts with it run at its own place: such a value becomes
//! a variable. At most one deferred value that can stop a run waits at a time. The expression
//! depth stays at most [`MAX_FOLD_DEPTH`], so each walk of an expression is short.
//!
//! A call whose one location def has one use in the same block can fold too: the call becomes
//! an expression.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_ir::{Arg, Op, Opc, Val};

use crate::view::facts::{Facts, Kind, Site, inputs};

/// The largest depth of a folded expression.
pub const MAX_FOLD_DEPTH: u32 = 16;

/// The effects of an op, or of a deferred value with its folded inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Props {
    stops: bool,
    reads: bool,
    writes: bool,
}

impl Props {
    fn union(self, o: Self) -> Self {
        Self {
            stops: self.stops || o.stops,
            reads: self.reads || o.reads,
            writes: self.writes || o.writes,
        }
    }

    /// Tells if a deferred value `self` must run before an op with the effects `at`.
    const fn conflicts(self, at: Self) -> bool {
        at.writes || (self.stops && at.stops) || (self.writes && (at.reads || at.stops))
    }
}

/// Gives the effects of one op.
fn props(op: &Op) -> Props {
    let none = Props::default();
    match op.opc {
        Opc::Load => Props {
            stops: true,
            reads: true,
            writes: false,
        },
        Opc::UDiv | Opc::SDiv | Opc::URem | Opc::SRem => {
            let mask = if op.w >= 64 {
                u64::MAX
            } else {
                (1u64 << op.w) - 1
            };
            let safe = op.a[1].as_k().is_some_and(|d| d & mask != 0);
            Props {
                stops: !safe,
                ..none
            }
        }
        Opc::Store => Props {
            stops: true,
            reads: false,
            writes: true,
        },
        Opc::Call | Opc::CallInd | Opc::Syscall | Opc::Intrinsic | Opc::Unimpl => Props {
            stops: true,
            reads: true,
            writes: true,
        },
        Opc::Ret => Props {
            stops: true,
            ..none
        },
        _ => none,
    }
}

/// The fold plan of a function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The values that go into their use. A folded call def is here too.
    pub(crate) folded: BTreeSet<Val>,
    /// The calls that become an expression at the use of their one def.
    pub(crate) calls: BTreeSet<u32>,
}

/// A deferred value of the walk: its value, its def op and its effects.
#[derive(Debug, Clone, Copy)]
struct Root {
    val: Val,
    op: u32,
    props: Props,
    depth: u32,
}

/// Gives the one used def of a call, when the call can fold.
fn call_def(f: &Facts<'_>, i: u32, op: &Op) -> Option<Val> {
    if !matches!(op.opc, Opc::Call | Opc::CallInd) {
        return None;
    }
    let live: Vec<Val> = f
        .ssa
        .defs_at(i)
        .iter()
        .map(|&(_, v)| v)
        .filter(|v| f.use_count(*v) > 0)
        .collect();
    match live.as_slice() {
        [v] => Some(*v),
        _ => None,
    }
}

/// Tells if the value `v` has one use at a later op of the same block.
fn later_use(f: &Facts<'_>, v: Val, pos: &BTreeMap<u32, usize>, at: usize) -> bool {
    match f.site.get(&v) {
        Some(Site::Op(u)) => pos.get(u).is_some_and(|&p| p > at),
        Some(Site::Phi) | None => false,
    }
}

/// Makes the fold plan. With `on` false, no value folds.
pub(crate) fn plan(f: &Facts<'_>, on: bool) -> Plan {
    let mut out = Plan::default();
    if !on {
        return out;
    }
    for (b, list) in &f.ops {
        let mut succs = f.ssa.cfg().succs(*b).to_vec();
        succs.sort_unstable();
        succs.dedup();
        walk_block(f, list, succs.len(), &mut out);
    }
    out
}

/// Plans one block with `succs` distinct successors. With one successor, the view drops the
/// branch condition or the switch target of the block, so no value folds into them.
fn walk_block(f: &Facts<'_>, list: &[u32], succs: usize, out: &mut Plan) {
    let pos: BTreeMap<u32, usize> = list.iter().enumerate().map(|(k, i)| (*i, k)).collect();
    let mut pending: Vec<Root> = Vec::new();
    for (k, &i) in list.iter().enumerate() {
        let Some(op) = f.op(i) else {
            continue;
        };
        if op.opc == Opc::Phi || (op.opc == Opc::Get && f.ssa.place(i).is_some()) {
            continue;
        }
        let used: BTreeSet<Val> = inputs(f.ssa, i, op)
            .into_iter()
            .filter_map(|a| match a {
                Arg::V(v) => Some(v),
                _ => None,
            })
            .collect();
        let mut here = props(op);
        let mut depth = 1u32;
        let dropped = match op.opc {
            Opc::CJump => succs <= 1,
            Opc::JumpInd => succs == 1,
            _ => false,
        };
        pending.retain(|r| {
            if !dropped && used.contains(&r.val) && f.site.get(&r.val) == Some(&Site::Op(i)) {
                here = here.union(r.props);
                depth = depth.max(r.depth.saturating_add(1));
                false
            } else {
                true
            }
        });
        let value = match op.out {
            Some(v) if f.kind_of(v) == Kind::Op => Some(v),
            Some(_) => None,
            None => call_def(f, i, op),
        };
        let defer = value.filter(|&v| depth <= MAX_FOLD_DEPTH && later_use(f, v, &pos, k));
        if let Some(v) = defer {
            if here.stops {
                force(&mut pending, out, |r| r.props.stops);
            }
            if op.out.is_none() {
                out.calls.insert(i);
            }
            out.folded.insert(v);
            pending.push(Root {
                val: v,
                op: i,
                props: here,
                depth,
            });
        } else {
            force(&mut pending, out, |r| r.props.conflicts(here));
        }
    }
    force(&mut pending, out, |_| true);
}

/// Makes each deferred value that `hit` selects run at its own place.
fn force(pending: &mut Vec<Root>, out: &mut Plan, hit: impl Fn(&Root) -> bool) {
    pending.retain(|r| {
        if hit(r) {
            out.folded.remove(&r.val);
            out.calls.remove(&r.op);
            false
        } else {
            true
        }
    });
}
