//! The argument registers that the caller sets for a call.
//!
//! The caller sets a register use of a call when one of two rules is true:
//!
//! | Rule | Example |
//! |---|---|
//! | its L1 value can be a new value: not the entry value of the register and not the value that a call leaves in it | `mov rdi, rbx` in a loop |
//! | an L0 `Put` of the register runs in the block of the call after the call before it | `mov rax,[rbp-8]; mov rdi,rax` of a copy through a stack slot |
//!
//! A phi is a new value when one of its arguments is one. The register that holds the target
//! of an indirect call is not an argument. The printer counts the arguments of a call with
//! no known argument count from this set.
//!
//! A register that an op reads after its last L0 `Put` in the block of the call is a staging
//! register, not an argument. An example is `rdx` in `mov rdx,[rbp-0x18]; mov rsi,rdx` of
//! `-O0` code.

use std::collections::BTreeSet;

use ghidorah_ir::{Arg, Loc, LocSet, Op, Opc, Val};

use crate::view::facts::Kind;
use crate::view::stmts::Ex;

/// The largest count of values that one check of a new value visits.
const MAX_VISIT: usize = 256;

impl Ex<'_> {
    /// Tells if the L1 value `arg` of the register `loc` can be a new value. Examples are a
    /// constant, an op value and the entry value of another register.
    fn new_value(&self, arg: Arg, loc: Loc) -> bool {
        let mut stack = vec![self.f.ssa.root(arg)];
        let mut seen: BTreeSet<Val> = BTreeSet::new();
        while let Some(a) = stack.pop() {
            let v = match a {
                Arg::V(v) => v,
                Arg::K(_) => return true,
                Arg::Nil | Arg::L(_) => continue,
            };
            if !seen.insert(v) || seen.len() > MAX_VISIT {
                continue;
            }
            match self.f.kind_of(v) {
                Kind::Input(l) | Kind::Def { loc: l, .. } if l == loc => {}
                Kind::Input(_) | Kind::Def { .. } => return true,
                Kind::Phi => {
                    let Some(op) = self.f.ssa.live_def(v) else {
                        continue;
                    };
                    let args = self.f.ssa.arena().phi_args(op).unwrap_or_default();
                    stack.extend(args.iter().map(|&x| self.f.ssa.root(x)));
                }
                Kind::Op => {
                    // A `Copy` that keeps the value is a root already, so this is a new value.
                    return true;
                }
            }
        }
        false
    }

    /// Tells if an L0 `Put` of `loc` runs in the block of the call op `call` after the call
    /// before it.
    fn written_before(&self, call: u32, loc: Loc) -> bool {
        let Some(block) = self.f.ssa.block_of_op(call) else {
            return false;
        };
        let range = self
            .f
            .ops
            .get(&block)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let before = range
            .iter()
            .take_while(|&&i| i != call)
            .filter(|&&i| self.f.ssa.is_insn_op(i));
        let mut set = false;
        for &i in before {
            let Some(op) = self.l0.op(i) else {
                continue;
            };
            match op.opc {
                Opc::Call | Opc::CallInd => set = false,
                Opc::Put if op.a[0].as_loc() == Some(loc) => set = true,
                _ => {}
            }
        }
        set
    }

    /// Tells if an L0 op reads `loc` after its last `Put` in the block of the call op `call`
    /// (see the module doc).
    fn staged(&self, call: u32, loc: Loc) -> bool {
        let Some(block) = self.f.ssa.block_of_op(call) else {
            return false;
        };
        let range = self
            .f
            .ops
            .get(&block)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let before = range
            .iter()
            .take_while(|&&i| i != call)
            .filter(|&&i| self.f.ssa.is_insn_op(i));
        let (mut put, mut read) = (false, false);
        for &i in before {
            let Some(op) = self.l0.op(i) else {
                continue;
            };
            let reads = match op.opc {
                Opc::Get => op.a[0].as_loc() == Some(loc),
                Opc::Intrinsic | Opc::Syscall => {
                    self.l0.effect(op).is_some_and(|e| e.uses.contains(loc))
                }
                _ => false,
            };
            match op.opc {
                Opc::Call | Opc::CallInd => (put, read) = (false, false),
                Opc::Put if op.a[0].as_loc() == Some(loc) => (put, read) = (true, false),
                _ if reads && put => read = true,
                _ => {}
            }
        }
        read
    }

    /// Gives the argument registers that the caller sets for the call op `i` (see the module
    /// doc). The uses are the location uses of the op.
    pub(crate) fn set_args(&self, i: u32, op: &Op, uses: &[(Loc, Arg)]) -> LocSet {
        let target = match (op.opc, op.a[0]) {
            (Opc::CallInd | Opc::Call, a @ Arg::V(_)) => Some(self.f.ssa.root(a)),
            _ => None,
        };
        let mut out = LocSet::EMPTY;
        for &(loc, arg) in uses {
            if matches!(loc, Loc::Stack(_)) || target == Some(self.f.ssa.root(arg)) {
                continue;
            }
            let set = self.new_value(arg, loc) || self.written_before(i, loc);
            if set && !self.staged(i, loc) {
                let _ = out.insert(loc);
            }
        }
        out
    }
}
