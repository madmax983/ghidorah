//! The text of calls: direct calls, indirect calls, system calls and opaque instructions.
//!
//! The argument count of a direct call comes from the signature or the Tier-0 prototype of
//! the callee, then from the parameter recovery. Else it is the count of the argument
//! registers that the caller sets.
//!
//! A slot of a positional convention prints its floating register when the caller sets only
//! that register of the slot. Else it prints its integer register.
//!
//! A call of another convention (`SysV`) that is not variadic takes its arguments from the
//! slots of the callee ([`Printer::callee_slots`]). A signature or a prototype gives each
//! parameter the next register of its class. The recovery gives its integer registers, then
//! its floating registers, then its stack slots. So `scale(double x, int k)` with no
//! signature prints `scale(k, x)`. Each stack slot takes the next stack argument of the call.
//!
//! A variadic call of a convention with a varargs register (`al` in `SysV`) passes its
//! floating arguments in the floating argument registers. They follow the integer arguments in
//! the text. A constant `al`, or the low byte of a `mov al, k`, gives their count. Else the
//! count is the floating argument registers that the caller sets. The text keeps no order
//! between the integer and the floating arguments.
//!
//! The result of a call is a def of the register that the `env` module gives: `rax`, or
//! `xmm0` for a floating result. The result of an opaque instruction is its `rax` def, else
//! its first def.

use ghidorah_analysis::cc::loc_of;
use ghidorah_analysis::fir::ret::{FloatRet, RetValue};
use ghidorah_base::WarningCode;
use ghidorah_ir::{Loc, Opc};

use super::expr::{safe, wrap};
use super::{Arity, Buf, CallRow, CallTarget, Printer, env};
use crate::Warning;
use crate::expr::{Call, Callee, Expr, Stmt, VarIdx};
use crate::lattice::{calls_of, sig_regs};
use crate::precedence::UNARY;

/// The registers of the arguments of a system call in order.
const SYSCALL_ARGS: [&str; 6] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];

/// Gives the low byte of the value `e` of the varargs register. A constant gives it. So does
/// a constant that a `mov al, k` writes to the low byte. Another value gives `None`.
fn low_byte(e: &Expr) -> Option<u8> {
    let value = match e {
        Expr::Const { value, .. } => *value,
        Expr::Ite {
            op: Opc::Insert,
            sub: 8,
            b,
            c,
            ..
        } => match (b.as_ref(), c.as_ref()) {
            (Expr::Const { value, .. }, Expr::Const { value: 0, .. }) => *value,
            _ => return None,
        },
        _ => return None,
    };
    Some(value.to_le_bytes()[0])
}

/// Tells if a name is a mangled C++ or Rust name.
fn is_mangled(name: &str) -> bool {
    name.starts_with("_Z") || name.starts_with("_R") || name.starts_with('?')
}

impl Printer<'_> {
    /// Gives the register of the result of the call `c` (see the module doc). A direct callee
    /// whose signature has no return value gives `None`.
    fn result_loc(&self, c: &Call) -> Option<Loc> {
        let conv = self.env.conv();
        match c.callee {
            Callee::Intrinsic(_) => c
                .rets
                .iter()
                .find(|(l, _)| *l == Loc::RAX)
                .or_else(|| c.rets.first())
                .map(|(l, _)| *l),
            Callee::Direct(t) => match self.env.signature(t) {
                Some(sig) => env::ret_loc(&sig, &self.stores, conv),
                None => match self.env.ret_value(t) {
                    Some(RetValue::Void) => None,
                    Some(RetValue::Float(_)) => env::float_ret(conv).or(Some(Loc::RAX)),
                    Some(RetValue::Int) | None => Some(env::caller_ret_loc(c, &self.reads, conv)),
                },
            },
            Callee::Indirect(_) => Some(env::caller_ret_loc(c, &self.reads, conv)),
            Callee::Syscall | Callee::Unimpl => Some(Loc::RAX),
        }
    }

    /// Gives the return value of the direct callee of `c`: the return type of its signature,
    /// else its facts ([`super::PrintEnv::ret_value`]). Another callee gives `None`.
    pub(super) fn callee_value(&self, c: &Call) -> Option<RetValue> {
        let Callee::Direct(t) = c.callee else {
            return None;
        };
        let Some(sig) = self.env.signature(t) else {
            return self.env.ret_value(t);
        };
        Some(match sig.ret {
            None => RetValue::Void,
            Some(ty) if self.stores.is_float(ty) => {
                let kind = self.stores.float_kind(ty).unwrap_or(FloatRet::Double);
                RetValue::Float(kind)
            }
            Some(_) => RetValue::Int,
        })
    }

    /// Tells if the statement `s` is a tail call with no return value of a callee that
    /// returns. Its line is `f(..);`, so a `return;` line follows it.
    pub(super) fn tail_return(&self, s: &Stmt) -> bool {
        let Stmt::Call(c) = s else {
            return false;
        };
        let returns = match c.callee {
            Callee::Direct(t) => !c.noreturn && !self.env.is_noreturn(t),
            _ => !c.noreturn,
        };
        c.tail && returns && self.callee_value(c) == Some(RetValue::Void)
    }

    /// Gives the variable that gets the result of a call statement. A direct callee whose
    /// signature has no return value gives `None`. Its `rax` holds no result: a return of it
    /// gives no value ([`Self::mark_call_values`]).
    pub(super) fn result_var(&self, c: &Call) -> Option<VarIdx> {
        let loc = self.result_loc(c)?;
        c.rets.iter().find(|(l, _)| *l == loc).map(|(_, v)| *v)
    }

    /// Updates the values that a call leaves behind.
    ///
    /// The `rax` def of each call with no result in `rax` is such a value. Examples are a call
    /// with a result in another register and a call of a `void` callee. A return of that def
    /// gives no value, and the head gets no return type from it. The result of a call is no
    /// such value, so a floating return of it gives the result.
    pub(super) fn mark_call_values(&mut self) {
        let mut left = Vec::new();
        let mut results = Vec::new();
        let calls = self.view().nodes.iter().flat_map(|n| &n.stmts);
        for c in calls.flat_map(calls_of) {
            if matches!(c.callee, Callee::Intrinsic(_)) {
                continue;
            }
            if self.result_loc(c) != Some(Loc::RAX) {
                let rax = c.rets.iter().filter(|(l, _)| *l == Loc::RAX);
                left.extend(rax.map(|(_, v)| *v));
            }
            results.extend(self.result_var(c));
        }
        self.clobbers.extend(left);
        for v in results {
            self.clobbers.remove(&v);
        }
    }

    /// Gives the printed name of the callee `t` and adds a mangled-name warning at `site`.
    fn callee_name(&mut self, t: u64, site: u64) -> String {
        match self.env.callee_name(t) {
            Some(raw) => {
                if is_mangled(&raw) {
                    self.warnings.push(Warning {
                        code: WarningCode::NotDemangled,
                        at: site,
                    });
                }
                safe(&raw)
            }
            None => format!("FUN_{t:08x}"),
        }
    }

    /// Gives the argument count of the direct callee `t`.
    fn arity(&mut self, t: u64) -> Option<Arity> {
        if let Some(found) = self.arity.get(&t) {
            return *found;
        }
        let found = self
            .env
            .signature(t)
            .map(|s| Arity {
                named: s.params.len(),
                variadic: s.variadic,
            })
            .or_else(|| {
                self.env.param_info(t).map(|i| Arity {
                    named: usize::from(i.count),
                    variadic: i.varargs,
                })
            });
        self.arity.insert(t, found);
        found
    }

    /// Gives the slots of the direct callee `t` in a convention that numbers its integer and
    /// floating slots apart. A signature gives the registers of the classes of its parameters.
    /// Else the parameter facts give the slots ([`crate::Env::param_slots`]). A positional
    /// convention and a callee with no facts give `None`.
    fn callee_slots(&self, t: u64) -> Option<Vec<Loc>> {
        let conv = self.env.conv();
        if conv.positional {
            return None;
        }
        match self.env.signature(t) {
            Some(sig) => Some(sig_regs(&sig, &self.stores, conv)),
            None => self.env.param_slots(t),
        }
    }

    /// Gives the argument texts of the call `c` from the slots `slots` of its callee. A
    /// register slot prints the value that the call passes in it, or `0`. A stack slot prints
    /// the next stack argument of the call. A tail call with no argument list passes the
    /// parameters of the function on, so a missing value prints as `param_N`.
    fn slot_args(&mut self, c: &Call, slots: &[Loc], buf: &mut Buf) -> String {
        let forward = c.tail && c.args.is_empty();
        let mut stack = c
            .args
            .iter()
            .filter(|(l, _)| matches!(l, Loc::Stack(_)))
            .map(|(_, e)| e);
        let mut out = Vec::new();
        for (k, slot) in slots.iter().enumerate() {
            let value = if matches!(slot, Loc::Stack(_)) {
                stack.next()
            } else {
                c.args.iter().find(|(l, _)| l == slot).map(|(_, e)| e)
            };
            let text = match value {
                Some(e) => self.expr(e, buf).0,
                None if forward => format!("param_{}", k.saturating_add(1)),
                None if matches!(slot, Loc::Stack(_)) => break,
                None => "0".to_owned(),
            };
            out.push(text);
        }
        out.join(", ")
    }

    /// Gives the argument register of each slot of the call `c` (see the module doc).
    fn slot_regs(&self, c: &Call) -> Vec<Loc> {
        let conv = self.env.conv();
        let ints = conv.int_args.iter().filter_map(|n| loc_of(n));
        if !conv.positional {
            return ints.collect();
        }
        let floats: Vec<Loc> = conv.float_args.iter().filter_map(|n| loc_of(n)).collect();
        ints.enumerate()
            .map(|(k, int)| match floats.get(k) {
                Some(&f) if !c.set.contains(int) && c.set.contains(f) => f,
                _ => int,
            })
            .collect()
    }

    /// Gives the floating argument registers of the variadic call `c` (see the module doc). A
    /// convention with no varargs register gives none.
    fn vararg_floats(&self, c: &Call) -> Vec<Loc> {
        let conv = self.env.conv();
        let Some(al) = conv.varargs_reg.and_then(loc_of) else {
            return Vec::new();
        };
        let floats: Vec<Loc> = conv.float_args.iter().filter_map(|n| loc_of(n)).collect();
        let known = c
            .args
            .iter()
            .find(|(l, _)| *l == al)
            .and_then(|(_, e)| low_byte(e));
        let count = known.map_or_else(|| Self::set_count(c, &floats), usize::from);
        floats.into_iter().take(count).collect()
    }

    /// Gives the count of the argument registers that the caller sets: one more than the
    /// last one in the set of the call.
    fn set_count(c: &Call, regs: &[Loc]) -> usize {
        regs.iter()
            .rposition(|r| c.set.contains(*r))
            .map_or(0, |i| i.saturating_add(1))
    }

    /// Gives the argument texts of a call: `count` registers, then at most `stack` stack
    /// arguments. A tail call with no argument list passes the parameters of the function on,
    /// so a missing register prints as `param_N`.
    fn args(
        &mut self,
        c: &Call,
        regs: &[Loc],
        (count, stack): (usize, usize),
        buf: &mut Buf,
    ) -> String {
        let forward = c.tail && c.args.is_empty();
        let mut out = Vec::new();
        for (k, r) in regs.iter().take(count).enumerate() {
            let text = match c.args.iter().find(|(l, _)| l == r) {
                Some((_, e)) => self.expr(e, buf).0,
                None if forward => format!("param_{}", k.saturating_add(1)),
                None => "0".to_owned(),
            };
            out.push(text);
        }
        if count >= regs.len() {
            let slots = c
                .args
                .iter()
                .filter(|(l, _)| matches!(l, Loc::Stack(_)))
                .take(stack);
            for (_, e) in slots {
                out.push(self.expr(e, buf).0);
            }
        }
        out.join(", ")
    }

    /// Gives the count of the stack arguments of a call to print. A known count gives the
    /// arguments after the registers. When the caller sets every argument register and the
    /// count can be larger, the count is each stack argument of the call.
    fn stack_count(c: &Call, regs: &[Loc], arity: Option<Arity>) -> usize {
        let all = c
            .args
            .iter()
            .filter(|(l, _)| matches!(l, Loc::Stack(_)))
            .count();
        let full = Self::set_count(c, regs) >= regs.len();
        match arity {
            Some(a) if !a.variadic => a.named.saturating_sub(regs.len()),
            _ if full => all,
            Some(a) => a.named.saturating_sub(regs.len()),
            None => 0,
        }
    }

    /// Gives the text of a system call: `sys_<name>(..)` for a known number, else
    /// `syscall(nr, ..)`.
    fn syscall_text(&mut self, c: &Call, buf: &mut Buf) -> String {
        let regs: Vec<Loc> = SYSCALL_ARGS.iter().filter_map(|n| loc_of(n)).collect();
        let nr = c.args.iter().find_map(|(l, e)| match (l, e) {
            (&Loc::RAX, Expr::Const { value, .. }) => Some(*value),
            _ => None,
        });
        let count = Self::set_count(c, &regs);
        let args = self.args(c, &regs, (count, 0), buf);
        if let Some(nr) = nr {
            let id = self
                .env
                .syscall_name(nr)
                .map_or_else(|| nr.to_string(), str::to_owned);
            let name = format!("sys_{id}");
            buf.calls.push(CallRow {
                target: CallTarget::Syscall(format!("sys:{id}")),
                name: name.clone(),
            });
            return format!("{name}({args})");
        }
        let rax = c
            .args
            .iter()
            .find(|(l, _)| *l == Loc::RAX)
            .map_or_else(|| "0".to_owned(), |(_, e)| self.expr(e, buf).0);
        let sep = if args.is_empty() { "" } else { ", " };
        format!("syscall({rax}{sep}{args})")
    }

    /// Gives the text of a call and adds its parts to `buf`.
    pub(super) fn call_text(&mut self, c: &Call, buf: &mut Buf) -> String {
        buf.op(c.at);
        if let Some(push) = c.push {
            buf.op(push);
        }
        let site = c.at.addr;
        let regs = self.slot_regs(c);
        match &c.callee {
            Callee::Direct(t) => {
                let name = self.callee_name(*t, site);
                let set = Self::set_count(c, &regs);
                let arity = self.arity(*t);
                let slots = self
                    .callee_slots(*t)
                    .filter(|_| !arity.is_some_and(|a| a.variadic));
                if let Some(slots) = slots {
                    buf.calls.push(CallRow {
                        target: CallTarget::Addr(*t),
                        name: name.clone(),
                    });
                    let args = self.slot_args(c, &slots, buf);
                    return format!("{name}({args})");
                }
                let count = match arity {
                    Some(a) if a.variadic => a.named.max(set),
                    Some(a) => a.named,
                    None => set,
                };
                let stack = Self::stack_count(c, &regs, arity);
                buf.calls.push(CallRow {
                    target: CallTarget::Addr(*t),
                    name: name.clone(),
                });
                let mut list: Vec<Loc> = regs.iter().take(count).copied().collect();
                if arity.is_some_and(|a| a.variadic) {
                    list.extend(self.vararg_floats(c));
                }
                let args = self.args(c, &list, (list.len(), stack), buf);
                format!("{name}({args})")
            }
            Callee::Indirect(target) => {
                let targets = self.env.call_targets(site);
                if targets.is_empty() {
                    self.warnings.push(Warning {
                        code: WarningCode::IndirectCallUnresolved,
                        at: site,
                    });
                }
                for t in targets {
                    let name = self.callee_name(t, site);
                    buf.calls.push(CallRow {
                        target: CallTarget::Addr(t),
                        name,
                    });
                }
                let (t, p) = self.expr(target, buf);
                let count = Self::set_count(c, &regs);
                let stack = Self::stack_count(c, &regs, None);
                let args = self.args(c, &regs, (count, stack), buf);
                format!("(*{})({args})", wrap(&t, p, UNARY, true))
            }
            Callee::Syscall => self.syscall_text(c, buf),
            Callee::Intrinsic(id) => {
                let name = self
                    .names
                    .name(*id)
                    .map_or_else(|| format!("intrinsic_{}", id.0), str::to_owned);
                let imm: Vec<Expr> = c
                    .imm
                    .iter()
                    .map(|&value| Expr::Const { value, w: 64 })
                    .collect();
                let mut inputs: Vec<&Expr> = c.args.iter().map(|(_, e)| e).collect();
                if let Some(m) = &c.mem {
                    inputs.push(m);
                }
                inputs.extend(imm.iter());
                self.helper(&name, &inputs, buf).0
            }
            Callee::Unimpl => "__unimpl()".to_owned(),
        }
    }
}
