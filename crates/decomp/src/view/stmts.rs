//! The statements and the terminator of each block, before the variables exist.
//!
//! A variable of this step is a placeholder: `VarIdx(v)` names the L1 value `v`. The out-of-SSA
//! step maps each placeholder to its variable.
//!
//! The flow ops of the last instruction give the terminator:
//!
//! | Flow ops | Terminator |
//! |---|---|
//! | none, or `Jump` | the one successor, or a stop |
//! | `CJump(c, t)`, then nothing or `Jump` | a branch on `c` |
//! | `CJump(c, t)`, then `Ret` | a branch on `c` whose false side returns |
//! | `JumpInd(x)` | a switch over the cases of the CFG, or `goto *(x);` without a case |
//! | `JumpInd(Load(slot))` of a thunk in one instruction, through an import slot | a tail call of the import |
//! | `Ret` | a stop |
//!
//! A call through an import slot, `Call(Load(slot))` in one instruction, calls the import.
//! The load of the slot gets no statement: the call line shows it.
//!
//! The store of the return address of a `call` gets no statement: the call line shows it. An
//! example is the push of a call after `and rsp, -16` in `_start`, where the stack offset is
//! unknown, so the store stays in memory.
//!
//! An indirect jump without a case gets `W_JUMPTABLE_UNRESOLVED` only when the facts of the
//! environment hold an unresolved table at it ([`Env::jumptable_unresolved`]). So a thunk
//! or a jump through an import slot gets no such warning.
//!
//! An instruction that jumps to its own address without a CFG edge is a `rep` loop. L1 cannot show its loop, so
//! its flow ops are not control flow, and it gets `W_LIFT_UNSUPPORTED`.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::cc::is_scalar_into;
use ghidorah_analysis::jumptable::GuardInfo;
use ghidorah_base::WarningCode;
use ghidorah_ir::{
    Arena, Arg, EffectOperand, InsnSpan, IntrinsicId, Loc, LocSet, Node, Op, OpId, Opc, Val,
};

use crate::Warning;
use crate::expr::{Call, Callee, Expr, Stmt, VarIdx};
use crate::fold::Plan;
use crate::view::Env;
use crate::view::facts::{Facts, Kind, Site};

/// The terminator of a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Term {
    /// The flow goes to the one successor of the CFG, or stops.
    Plain,
    /// A branch: true goes to the block at `taken`.
    Branch { cond: Expr, taken: u64 },
    /// A branch whose false side runs `tail` (a return) in the same instruction.
    BranchStop {
        cond: Expr,
        taken: u64,
        tail: Box<Stmt>,
    },
    /// An indirect jump with cases in the CFG, with the selector of its jump table.
    Switch {
        target: Expr,
        selector: Option<Selector>,
    },
}

/// The selector of a jump table: the value that the guard bounds, before its bias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Selector {
    /// The selector value.
    pub(crate) expr: Expr,
    /// The selector value of the first table entry.
    pub(crate) bias: u64,
    /// The guard of the table.
    pub(crate) guard: GuardInfo,
}

/// The view of one block before the variables exist.
#[derive(Debug, Clone)]
pub(crate) struct Raw {
    /// The block.
    pub(crate) block: Node,
    /// The statements with placeholder variables.
    pub(crate) stmts: Vec<Stmt>,
    /// The terminator.
    pub(crate) term: Term,
    /// The flow op of the terminator.
    pub(crate) term_op: Option<OpId>,
    /// The warnings of the block.
    pub(crate) warnings: Vec<Warning>,
    /// The L1 ops of the block in run order.
    pub(crate) ops: Vec<u32>,
    /// The address range of the instructions.
    pub(crate) span: (u64, u64),
}

/// The expression builder of one view.
pub(crate) struct Ex<'a> {
    pub(crate) f: &'a Facts<'a>,
    /// The L0 arena: the `Put` ops that L1 turns into `Nop`.
    pub(crate) l0: &'a Arena,
    pub(crate) plan: &'a Plan,
    pub(crate) env: &'a dyn Env,
    pub(crate) tails: &'a BTreeSet<u64>,
    /// The guard of each indirect jump with a jump table.
    pub(crate) guards: &'a BTreeMap<u64, GuardInfo>,
    /// The function is a thunk, so it passes its arguments on to the target of its jump.
    pub(crate) thunk: bool,
}

/// Gives the opcodes with one input.
const fn unary(opc: Opc) -> bool {
    matches!(
        opc,
        Opc::Copy
            | Opc::Neg
            | Opc::Not
            | Opc::Popcnt
            | Opc::Clz
            | Opc::Ctz
            | Opc::Bswap
            | Opc::ZExt
            | Opc::SExt
            | Opc::Trunc
            | Opc::Cond
            | Opc::FlagsGet
            | Opc::FlagsSet
    )
}

/// Gives the opcodes with three inputs.
const fn ternary(opc: Opc) -> bool {
    matches!(opc, Opc::Ite | Opc::Insert | Opc::Flags | Opc::FlagsSel)
}

/// Gives the expression of the constant `value` with the width `w`. A 64-bit value at the
/// start of a string literal is that string.
pub(crate) fn konst(env: &dyn Env, value: u64, w: u8) -> Expr {
    if w == 64 && value != 0 && env.is_string(value) {
        Expr::Str { addr: value }
    } else {
        Expr::Const { value, w }
    }
}

impl Ex<'_> {
    /// Gives the width of a value, or 64 bits.
    fn width(&self, v: Val) -> u8 {
        self.f.ssa.value_width(v).unwrap_or(64)
    }

    /// Gives the expression of an argument with the width `w` for a constant.
    pub(crate) fn arg(&self, a: Arg, w: u8) -> Expr {
        match a {
            Arg::K(imm) => konst(self.env, imm.get(), w),
            Arg::V(v) => self.value(v),
            Arg::Nil | Arg::L(_) => Expr::Const { value: 0, w },
        }
    }

    /// Gives the expression of a value: its folded expression or its variable.
    pub(crate) fn value(&self, v: Val) -> Expr {
        if self.plan.folded.contains(&v)
            && let Some(&i) = self.f.def.get(&v)
        {
            if let Kind::Def { call, loc } = self.f.kind_of(v) {
                let mut c = self.call(call);
                c.ret = Some(loc);
                c.rets.clear();
                return Expr::Call(Box::new(c));
            }
            return self.op_expr(i);
        }
        Expr::Var {
            var: VarIdx(v.0),
            w: self.width(v),
        }
    }

    /// Gives the expression of the value op `i`.
    pub(crate) fn op_expr(&self, i: u32) -> Expr {
        let Some(&op) = self.f.op(i) else {
            return Expr::Const { value: 0, w: 64 };
        };
        let at = op.id;
        let (w, sub) = (op.w, op.sub);
        match op.opc {
            Opc::Load => Expr::Load {
                w,
                addr: Box::new(self.arg(op.a[0], 64)),
                at,
            },
            Opc::Copy
                if matches!(op.a[0], Arg::V(x) if self.width(x) <= w)
                    || matches!(op.a[0], Arg::K(_)) =>
            {
                self.arg(op.a[0], w)
            }
            opc if unary(opc) => {
                let xw = match opc {
                    Opc::ZExt | Opc::SExt => sub,
                    Opc::Cond | Opc::FlagsGet => 16,
                    _ => w,
                };
                Expr::Un {
                    op: opc,
                    w,
                    sub,
                    x: Box::new(self.arg(op.a[0], xw)),
                    at,
                }
            }
            opc if ternary(opc) => Expr::Ite {
                op: opc,
                w,
                sub,
                a: Box::new(self.arg(op.a[0], w)),
                b: Box::new(self.arg(op.a[1], w)),
                c: Box::new(self.arg(op.a[2], w)),
                at,
            },
            opc => Expr::Bin {
                op: opc,
                w,
                sub,
                x: Box::new(self.arg(op.a[0], w)),
                y: Box::new(self.arg(op.a[1], w)),
                at,
            },
        }
    }

    /// Tells if `a` is the entry value of a location.
    fn is_entry(&self, a: Arg) -> bool {
        matches!(self.f.ssa.root(a), Arg::V(v) if matches!(self.f.kind_of(v), Kind::Input(_)))
    }

    /// Gives the call of the flow op `i`, with its used defs as results. A scalar conversion
    /// into an XMM register writes the scalar lane of its destination. No caller leaves a
    /// value in the other lanes. So the entry value of the destination is no input.
    pub(crate) fn call(&self, i: u32) -> Call {
        let op = self.f.op(i).copied().unwrap_or(Op {
            id: OpId { addr: 0, seq: 0 },
            opc: Opc::Unimpl,
            w: 0,
            sub: 0,
            out: None,
            a: [Arg::Nil; 3],
        });
        let callee = match (op.opc, op.a[0]) {
            (Opc::Call, Arg::K(t)) => Callee::Direct(t.get()),
            (Opc::Call | Opc::CallInd, target) => self
                .slot_target(target, op.id.addr)
                .map_or_else(|| Callee::Indirect(self.arg(target, 64)), Callee::Direct),
            (Opc::Syscall, _) => Callee::Syscall,
            (Opc::Intrinsic, _) => Callee::Intrinsic(
                self.f
                    .ssa
                    .arena()
                    .effect(&op)
                    .map_or(IntrinsicId(0), |e| e.name),
            ),
            _ => Callee::Unimpl,
        };
        let uses = self.f.ssa.uses_at(i);
        let set = if matches!(op.opc, Opc::Call | Opc::CallInd | Opc::Syscall) {
            self.set_args(i, &op, uses)
        } else {
            LocSet::EMPTY
        };
        let scalar = op.opc == Opc::Intrinsic
            && self
                .f
                .ssa
                .arena()
                .effect(&op)
                .is_some_and(|e| is_scalar_into(e.name));
        let mut args: Vec<(Loc, Expr)> = uses
            .iter()
            .filter(|&&(loc, a)| !(scalar && loc.is_xmm() && self.is_entry(a)))
            .map(|&(loc, a)| (loc, self.arg(a, loc.width())))
            .collect();
        let imm = match self.f.ssa.arena().effect(&op) {
            Some(effect) if op.opc == Opc::Intrinsic => {
                in_operand_order(&mut args, &effect.operands)
            }
            _ => Vec::new(),
        };
        let mem = (op.opc == Opc::Intrinsic && op.a[1] != Arg::Nil).then(|| self.arg(op.a[1], 64));
        let rets = self
            .f
            .ssa
            .defs_at(i)
            .iter()
            .filter(|(_, v)| self.f.use_count(*v) > 0 && !self.plan.folded.contains(v))
            .map(|&(loc, v)| (loc, VarIdx(v.0)))
            .collect();
        let tail = op.opc == Opc::Call && self.tails.contains(&op.id.addr);
        let push = matches!(op.opc, Opc::Call | Opc::CallInd)
            .then(|| self.push_of(op.id.addr))
            .flatten();
        Call {
            callee,
            args,
            set,
            push,
            imm,
            mem,
            rets,
            ret: None,
            noreturn: false,
            tail,
            at: op.id,
        }
    }

    /// Gives the call target of the import whose slot `target` loads. The target must be a
    /// load of a constant slot address in the instruction at `addr`. An example is the
    /// `call [rip+x]` of a `-fno-plt` build: it calls the import, not a data address.
    fn slot_target(&self, target: Arg, addr: u64) -> Option<u64> {
        let Arg::V(v) = target else {
            return None;
        };
        let op = self.f.def.get(&v).and_then(|&i| self.f.op(i))?;
        if op.opc != Opc::Load || op.id.addr != addr {
            return None;
        }
        self.env.import_at_slot(op.a[0].as_k()?)
    }

    /// Tells if the value of the load `op` is only the target of a call through an import
    /// slot. The call line shows the load, so the load has no statement of its own.
    fn loads_slot_target(&self, op: &Op) -> bool {
        let Some(Site::Op(i)) = op.out.and_then(|v| self.f.site.get(&v)) else {
            return false;
        };
        self.f.op(*i).is_some_and(|call| {
            matches!(call.opc, Opc::Call | Opc::CallInd)
                && call.a[0] == op.out.map_or(Arg::Nil, Arg::V)
                && self.slot_target(call.a[0], call.id.addr).is_some()
        })
    }

    /// Gives the call target of the indirect jump of a thunk through an import slot. Another
    /// function with such a jump at stack height 0 has a call in L1 in its place.
    fn import_jump(&self, target: Arg, addr: u64) -> Option<u64> {
        self.slot_target(target, addr).filter(|_| self.thunk)
    }

    /// Gives the statement of an indirect jump with no case: the tail call of the import of
    /// a thunk, else `goto *(x);`. A `goto` gets `W_JUMPTABLE_UNRESOLVED` when the facts hold
    /// an unresolved table at it.
    fn jump_end(&self, jump: &Op, warnings: &mut Vec<Warning>) -> Stmt {
        if let Some(callee) = self.import_jump(jump.a[0], jump.id.addr) {
            return Stmt::Call(forward(callee, jump.id));
        }
        if self.env.jumptable_unresolved(jump.id.addr) {
            warnings.push(Warning {
                code: WarningCode::JumptableUnresolved,
                at: jump.id.addr,
            });
        }
        Stmt::Goto {
            target: self.arg(jump.a[0], 64),
            at: jump.id,
        }
    }

    /// Gives the statement of the op `i`, or `None` for an op without one.
    fn stmt(&self, i: u32, op: &Op) -> Option<Stmt> {
        match op.opc {
            Opc::Phi | Opc::Nop | Opc::Get | Opc::Jump | Opc::CJump | Opc::JumpInd => None,
            Opc::Store if self.return_push(op) => None,
            Opc::Load if self.loads_slot_target(op) => None,
            Opc::Store => Some(Stmt::Store {
                w: op.w,
                addr: self.arg(op.a[0], 64),
                value: self.arg(op.a[1], op.w),
                at: op.id,
            }),
            Opc::Ret => Some(self.ret(i, op)),
            Opc::Call | Opc::CallInd | Opc::Syscall | Opc::Intrinsic | Opc::Unimpl => {
                (!self.plan.calls.contains(&i)).then(|| Stmt::Call(self.call(i)))
            }
            _ => {
                let v = op.out?;
                (!self.plan.folded.contains(&v)).then(|| Stmt::Assign {
                    var: VarIdx(v.0),
                    value: self.op_expr(i),
                    at: op.id,
                })
            }
        }
    }

    /// Gives the store of the return address of the call at `addr`. It is a `Store` of the
    /// address after the instruction, and the instruction has a `Call` or `CallInd` op.
    fn push_of(&self, addr: u64) -> Option<OpId> {
        let arena = self.f.ssa.arena();
        let next = arena
            .insn_index(addr)
            .and_then(|k| arena.insns().get(k))
            .and_then(InsnSpan::next_addr)?;
        let ops = arena.insn_ops(addr);
        if !ops
            .iter()
            .any(|o| matches!(o.opc, Opc::Call | Opc::CallInd))
        {
            return None;
        }
        ops.iter()
            .find(|o| o.opc == Opc::Store && o.a[1].as_k() == Some(next))
            .map(|o| o.id)
    }

    /// Tells if a store is the push of the return address of a call. The call line shows
    /// the push, so the store has no statement of its own.
    fn return_push(&self, op: &Op) -> bool {
        self.push_of(op.id.addr) == Some(op.id)
    }

    /// Gives the return statement of the op `i`.
    fn ret(&self, i: u32, op: &Op) -> Stmt {
        Stmt::Return {
            uses: self
                .f
                .ssa
                .uses_at(i)
                .iter()
                .map(|&(loc, a)| (loc, self.arg(a, loc.width())))
                .collect(),
            at: op.id,
        }
    }
}

/// Gives the tail call of a jump through an import slot to `callee`. The jump passes the
/// argument registers on, so the call has no argument list of its own: the printer shows the
/// parameters of the function.
const fn forward(callee: u64, at: OpId) -> Call {
    Call {
        callee: Callee::Direct(callee),
        args: Vec::new(),
        set: LocSet::EMPTY,
        push: None,
        imm: Vec::new(),
        mem: None,
        rets: Vec::new(),
        ret: None,
        noreturn: false,
        tail: true,
        at,
    }
}

/// Puts the register uses of an opaque instruction in the operand order of `operands`, the
/// destination first. The other uses follow in location order. Gives the immediates in
/// operand order.
fn in_operand_order(args: &mut Vec<(Loc, Expr)>, operands: &[EffectOperand]) -> Vec<u64> {
    let mut ordered: Vec<(Loc, Expr)> = Vec::with_capacity(args.len());
    let mut imm = Vec::new();
    for operand in operands {
        match *operand {
            EffectOperand::Loc(l) => {
                if let Some(k) = args.iter().position(|(x, _)| *x == l) {
                    ordered.push(args.remove(k));
                }
            }
            EffectOperand::Imm(v) => imm.push(v),
            EffectOperand::Mem | EffectOperand::None => {}
        }
    }
    ordered.append(args);
    *args = ordered;
    imm
}

/// Tells if the instruction with these ops jumps to its own address: a `rep` loop.
fn loops_on_itself(ops: &[(u32, Op)], addr: u64) -> bool {
    ops.iter().any(|(_, o)| {
        matches!(o.opc, Opc::Jump | Opc::CJump)
            && o.a[usize::from(o.opc == Opc::CJump)].as_k() == Some(addr)
    })
}

/// Builds the raw view of one reachable block.
pub(crate) fn block(ex: &Ex<'_>, b: Node) -> Raw {
    let f = ex.f;
    let ops = f.ops.get(&b).cloned().unwrap_or_default();
    let last = f.ssa.last_insn(b);
    let first = f.ssa.block_addr(b).unwrap_or_default();
    let end = last.and_then(|s| s.next_addr()).unwrap_or(first);
    let last_addr = last.map_or(first, |s| s.addr);
    let tagged: Vec<(u32, Op)> = ops
        .iter()
        .filter_map(|&i| f.op(i).map(|o| (i, *o)))
        .collect();
    let mut warnings = Vec::new();
    let mut addrs: Vec<u64> = tagged.iter().map(|(_, o)| o.id.addr).collect();
    addrs.dedup();
    // One pass groups the instruction ops by address, so a long block costs no square time.
    let mut by_addr: BTreeMap<u64, Vec<(u32, Op)>> = BTreeMap::new();
    for &(i, o) in tagged.iter().filter(|(i, _)| f.ssa.is_insn_op(*i)) {
        by_addr.entry(o.id.addr).or_default().push((i, o));
    }
    let mut looping: BTreeSet<u64> = BTreeSet::new();
    for addr in addrs {
        let insn = by_addr.get(&addr).map_or(&[][..], Vec::as_slice);
        let modeled = f.ssa.block_at(addr) == Some(b) && f.ssa.cfg().succs(b).contains(&b);
        if !modeled && loops_on_itself(insn, addr) {
            looping.insert(addr);
            warnings.push(Warning {
                code: WarningCode::LiftUnsupported,
                at: addr,
            });
        }
    }
    let flows: Vec<(usize, Op)> = tagged
        .iter()
        .enumerate()
        .filter(|(_, (i, o))| {
            f.ssa.is_insn_op(*i)
                && o.id.addr == last_addr
                && !looping.contains(&last_addr)
                && matches!(o.opc, Opc::Jump | Opc::CJump | Opc::JumpInd | Opc::Ret)
        })
        .map(|(k, (_, o))| (k, *o))
        .collect();
    let mut term = Term::Plain;
    let mut term_op = None;
    let mut cut = tagged.len();
    let mut goto = None;
    if let Some(&(k, f0)) = flows.first() {
        term_op = Some(f0.id);
        cut = k;
        match f0.opc {
            Opc::CJump => {
                let taken = f0.a[1].as_k().unwrap_or(u64::MAX);
                let cond = ex.arg(f0.a[0], 1);
                term = match flows.get(1) {
                    Some(&(r, ret)) if ret.opc == Opc::Ret => Term::BranchStop {
                        cond,
                        taken,
                        tail: Box::new(ex.ret(tagged.get(r).map_or(0, |t| t.0), &ret)),
                    },
                    _ => Term::Branch { cond, taken },
                };
            }
            Opc::JumpInd if f.ssa.cfg().succs(b).is_empty() => {
                goto = Some(ex.jump_end(&f0, &mut warnings));
            }
            Opc::JumpInd => {
                term = Term::Switch {
                    target: ex.arg(f0.a[0], 64),
                    selector: ex.guards.get(&f0.id.addr).and_then(|g| ex.selector(g)),
                };
            }
            Opc::Ret => {
                term_op = None;
                cut = k.saturating_add(1);
            }
            _ => {}
        }
    }
    let mut stmts: Vec<Stmt> = tagged
        .iter()
        .enumerate()
        .filter(|(k, (i, op))| *k < cut || !(f.ssa.is_insn_op(*i) && op.id.addr == last_addr))
        .filter_map(|(_, (i, op))| ex.stmt(*i, op))
        .collect();
    stmts.extend(goto);
    Raw {
        block: b,
        stmts,
        term,
        term_op,
        warnings,
        ops,
        span: (first, end),
    }
}
