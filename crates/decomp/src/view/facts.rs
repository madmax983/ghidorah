//! The facts of an L1 form that the view reads. The facts are the reachable blocks, the ops of
//! each block, the kind of each value and its uses.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_ir::ssa::{Anchor, Ssa};
use ghidorah_ir::{Arg, Loc, Node, Op, Opc, Val, rpo};

/// The kind of an L1 value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A phi.
    Phi,
    /// The entry value of a location: a `Get` at the anchor `Start`.
    Input(Loc),
    /// A location def of the flow op `call`: a `Get` after it.
    Def { call: u32, loc: Loc },
    /// The value of a data op or a load.
    Op,
}

/// The use of a value with exactly one use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Site {
    /// An input or a location use of the op with this index.
    Op(u32),
    /// A phi argument.
    Phi,
}

/// The facts of one L1 form.
pub(crate) struct Facts<'a> {
    /// The L1 form.
    pub(crate) ssa: &'a Ssa,
    /// The blocks that the entry reaches, in reverse postorder.
    pub(crate) reach: Vec<Node>,
    /// The ops of each reachable block in run order.
    pub(crate) ops: BTreeMap<Node, Vec<u32>>,
    /// The ops at the anchor `Start`.
    pub(crate) start: Vec<u32>,
    /// The kind of each value of a live op.
    pub(crate) kind: BTreeMap<Val, Kind>,
    /// The def op of each value of a live op.
    pub(crate) def: BTreeMap<Val, u32>,
    /// The use count of each value.
    pub(crate) uses: BTreeMap<Val, u32>,
    /// The use of each value with exactly one use.
    pub(crate) site: BTreeMap<Val, Site>,
}

impl<'a> Facts<'a> {
    /// Collects the facts of `ssa`.
    pub(crate) fn collect(ssa: &'a Ssa) -> Self {
        let reach = rpo(ssa.cfg());
        let mut ops: BTreeMap<Node, Vec<u32>> = reach.iter().map(|b| (*b, Vec::new())).collect();
        let mut start = Vec::new();
        for i in ssa.order() {
            if ssa.place(i) == Some(Anchor::Start) {
                start.push(i);
            } else if let Some(list) = ssa.block_of_op(i).and_then(|b| ops.get_mut(&b)) {
                list.push(i);
            }
        }
        let mut f = Self {
            ssa,
            reach,
            ops,
            start,
            kind: BTreeMap::new(),
            def: BTreeMap::new(),
            uses: BTreeMap::new(),
            site: BTreeMap::new(),
        };
        let all: Vec<u32> = f
            .start
            .iter()
            .chain(f.ops.values().flatten())
            .copied()
            .collect();
        for i in all {
            f.scan(i);
        }
        f
    }

    /// Records the value and the uses of the op `i`.
    fn scan(&mut self, i: u32) {
        let Some(&op) = self.ssa.arena().op(i) else {
            return;
        };
        if let Some(v) = op.out {
            let kind = match (op.opc, self.ssa.place(i)) {
                (Opc::Phi, _) => Kind::Phi,
                (Opc::Get, Some(Anchor::After(call))) => Kind::Def {
                    call,
                    loc: op.a[0].as_loc().unwrap_or(Loc::Flags),
                },
                (Opc::Get, _) => Kind::Input(op.a[0].as_loc().unwrap_or(Loc::Flags)),
                _ => Kind::Op,
            };
            self.kind.insert(v, kind);
            self.def.insert(v, i);
        }
        if op.opc == Opc::Phi {
            for a in self.ssa.arena().phi_args(&op).unwrap_or_default().to_vec() {
                self.count(a, Site::Phi);
            }
            return;
        }
        for a in inputs(self.ssa, i, &op) {
            self.count(a, Site::Op(i));
        }
    }

    /// Counts one use of `a` at `site`.
    fn count(&mut self, a: Arg, site: Site) {
        let Arg::V(v) = a else {
            return;
        };
        let n = self.uses.entry(v).or_insert(0);
        *n = n.saturating_add(1);
        if *n == 1 {
            self.site.insert(v, site);
        } else {
            self.site.remove(&v);
        }
    }

    /// Gives the kind of a value. A value without a live def is an op value.
    pub(crate) fn kind_of(&self, v: Val) -> Kind {
        self.kind.get(&v).copied().unwrap_or(Kind::Op)
    }

    /// Gives the use count of a value.
    pub(crate) fn use_count(&self, v: Val) -> u32 {
        self.uses.get(&v).copied().unwrap_or(0)
    }

    /// Gives the op with this index.
    pub(crate) fn op(&self, i: u32) -> Option<&'a Op> {
        self.ssa.arena().op(i)
    }

    /// Gives the addresses of the instructions of the reachable blocks with an effect that a
    /// line must show. An instruction has an effect when one of its live ops has one. An
    /// effect is a store, a call, a return, a branch or an opaque memory op. The def of a
    /// value that a return reads is an effect too.
    ///
    /// A push or a pop of a callee-saved register has no live op with an effect. The same is
    /// true for the frame setup and teardown, `nop` and `endbr64`.
    pub(crate) fn effects(&self) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        for &i in self.ops.values().flatten() {
            let Some(op) = self.op(i).filter(|_| self.ssa.is_insn_op(i)) else {
                continue;
            };
            let shows = match op.opc {
                Opc::Store
                | Opc::Call
                | Opc::CallInd
                | Opc::Syscall
                | Opc::Unimpl
                | Opc::Ret
                | Opc::CJump
                | Opc::JumpInd => true,
                Opc::Intrinsic => op.a[1] != Arg::Nil,
                _ => false,
            };
            if shows {
                out.insert(op.id.addr);
            }
            if op.opc != Opc::Ret {
                continue;
            }
            for &(_, a) in self.ssa.uses_at(i) {
                let Arg::V(v) = a else {
                    continue;
                };
                if let Some(def) = self
                    .def
                    .get(&v)
                    .filter(|d| self.ssa.is_insn_op(**d))
                    .and_then(|d| self.op(*d))
                {
                    out.insert(def.id.addr);
                }
            }
        }
        out
    }
}

/// Gives the value inputs of the op `i`: its arguments and its location uses. A location
/// argument of `Get` and `Put` and the effect index of an effect op are not inputs.
pub(crate) fn inputs(ssa: &Ssa, i: u32, op: &Op) -> Vec<Arg> {
    let mut out: Vec<Arg> = match op.opc {
        Opc::Syscall | Opc::Intrinsic => vec![op.a[1]],
        Opc::Get | Opc::Phi | Opc::Nop => Vec::new(),
        _ => op.a.to_vec(),
    };
    out.extend(ssa.uses_at(i).iter().map(|&(_, a)| a));
    out.retain(|a| matches!(a, Arg::V(_)));
    out
}
