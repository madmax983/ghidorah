//! The SSA checker (design Section 6.4, AC-073 and AC-256).
//!
//! [`check`] reports each break of the SSA rules of an [`Ssa`].
//!
//! | Rule | Statement |
//! |---|---|
//! | [`Rule::SingleDef`] | Each value has one def op, and the arena gives that op. |
//! | [`Rule::DefDominatesUse`] | The def of each use comes before it in its block, or its block dominates the block of the use. A phi argument is a use at the end of its predecessor. |
//! | [`Rule::PhiArity`] | Each phi has one argument for each predecessor, plus one for the function entry in the entry block. |
//! | [`Rule::RemovedValue`] | Each value that an op reads still has its def op. |
//! | [`Rule::Shape`] | No instruction op is a `Get`, `Put` or `Phi`. A block head holds only phis. An added `Get` is at the anchor `Start` or after an op. |
//!
//! The entry does not reach an unreachable block, so no run reads its values. The checker
//! does not apply [`Rule::DefDominatesUse`] to a use in such a block.

use std::collections::BTreeMap;
use std::fmt;

use crate::graph::{DomTree, Node, dominators};
use crate::op::{Arg, Op, OpId, Opc, Val};
use crate::ssa::{Anchor, Ssa};

/// A rule of the SSA checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// Each value has one def op.
    SingleDef,
    /// The def of a value dominates each use.
    DefDominatesUse,
    /// A phi has one argument for each incoming edge.
    PhiArity,
    /// No op reads a removed value.
    RemovedValue,
    /// The ops have the L1 shape.
    Shape,
}

impl Rule {
    /// Gives the name of the rule, for example `phi_arity`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SingleDef => "single_def",
            Self::DefDominatesUse => "def_dominates_use",
            Self::PhiArity => "phi_arity",
            Self::RemovedValue => "removed_value",
            Self::Shape => "shape",
        }
    }
}

/// One break of an SSA rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Violation {
    /// The rule.
    pub rule: Rule,
    /// The op with the break.
    pub at: OpId,
    /// The value of the break, when one applies.
    pub val: Option<Val>,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {:#x}:{}",
            self.rule.name(),
            self.at.addr,
            self.at.seq
        )?;
        if let Some(val) = self.val {
            write!(f, " ({val})")?;
        }
        Ok(())
    }
}

/// The place of an op or a use: the function start, or a block and a rank in its run order.
///
/// The phis of a block have rank 0, and the end of a block has rank `u32::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pos {
    Start,
    In(Node, u32),
}

/// The state of one check.
struct Checker<'a> {
    ssa: &'a Ssa,
    dom: DomTree,
    pos: BTreeMap<u32, Pos>,
    found: Vec<Violation>,
}

impl Checker<'_> {
    /// Tells if a def at `def` comes before a use at `use_at` on every path.
    fn dominates(&self, def: Pos, use_at: Pos) -> bool {
        match (def, use_at) {
            (Pos::Start, _) => true,
            (Pos::In(..), Pos::Start) => false,
            (Pos::In(db, dk), Pos::In(ub, uk)) => {
                !self.dom.is_reachable(ub)
                    || if db == ub {
                        dk < uk
                    } else {
                        self.dom.dominates(db, ub)
                    }
            }
        }
    }

    fn report(&mut self, rule: Rule, at: OpId, val: Option<Val>) {
        self.found.push(Violation { rule, at, val });
    }

    /// Checks one use of `arg` by the op `at` at the place `use_at`.
    fn use_of(&mut self, at: OpId, arg: Arg, use_at: Pos) {
        let Arg::V(v) = arg else {
            return;
        };
        let def = self.ssa.arena().def_of(v);
        let Some(def) = def.filter(|_| self.ssa.live_def(v).is_some()) else {
            self.report(Rule::RemovedValue, at, Some(v));
            return;
        };
        let Some(&def_at) = self.pos.get(&def) else {
            self.report(Rule::RemovedValue, at, Some(v));
            return;
        };
        if !self.dominates(def_at, use_at) {
            self.report(Rule::DefDominatesUse, at, Some(v));
        }
    }

    /// Tells if an op has a bad L1 shape at its place.
    fn bad_shape(&self, index: u32, op: &Op) -> bool {
        match self.ssa.place(index) {
            None => matches!(op.opc, Opc::Get | Opc::Put | Opc::Phi),
            Some(Anchor::Head(_)) => op.opc != Opc::Phi,
            Some(Anchor::Start | Anchor::After(_)) => matches!(op.opc, Opc::Put | Opc::Phi),
            Some(Anchor::Before(_) | Anchor::Tail(_)) => {
                matches!(op.opc, Opc::Get | Opc::Put | Opc::Phi)
            }
        }
    }

    /// Checks one L1 op.
    fn op(&mut self, index: u32) {
        let Some(&op) = self.ssa.arena().op(index) else {
            return;
        };
        let here = self.pos.get(&index).copied().unwrap_or(Pos::Start);
        if self.bad_shape(index, &op) {
            self.report(Rule::Shape, op.id, None);
        }
        if let Some(v) = op.out
            && self.ssa.arena().def_of(v) != Some(index)
        {
            self.report(Rule::SingleDef, op.id, Some(v));
        }
        if op.opc == Opc::Phi {
            self.phi(&op, here);
        } else {
            for arg in op.a {
                self.use_of(op.id, arg, here);
            }
        }
        for &(_, arg) in self.ssa.uses_at(index) {
            self.use_of(op.id, arg, here);
        }
    }

    /// Checks the arity and the arguments of a phi.
    fn phi(&mut self, op: &Op, here: Pos) {
        let Pos::In(block, _) = here else {
            return;
        };
        let args = self.ssa.arena().phi_args(op).unwrap_or_default().to_vec();
        if args.len() != self.ssa.phi_arity(block) {
            self.report(Rule::PhiArity, op.id, op.out);
        }
        let preds = self.ssa.preds(block).to_vec();
        for (j, arg) in args.into_iter().enumerate() {
            let end = preds.get(j).map_or(Pos::Start, |&p| Pos::In(p, u32::MAX));
            self.use_of(op.id, arg, end);
        }
    }
}

/// Gives each break of the SSA rules, in the run order of [`Ssa::order`].
#[must_use]
pub fn check(ssa: &Ssa) -> Vec<Violation> {
    let mut pos = BTreeMap::new();
    for &i in ssa.anchored(Anchor::Start) {
        pos.insert(i, Pos::Start);
    }
    for block in ssa.block_order() {
        let mut list = Vec::new();
        ssa.block_ops(block, &mut list);
        let mut rank = 1u32;
        for i in list {
            if ssa.place(i) == Some(Anchor::Head(block)) {
                pos.insert(i, Pos::In(block, 0));
            } else {
                pos.insert(i, Pos::In(block, rank));
                rank = rank.saturating_add(1);
            }
        }
    }
    let mut checker = Checker {
        ssa,
        dom: dominators(ssa.cfg()),
        pos,
        found: Vec::new(),
    };
    for index in ssa.order() {
        checker.op(index);
    }
    checker.found
}
