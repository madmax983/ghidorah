//! The text of calls: direct calls, indirect calls, system calls and opaque instructions.
//!
//! The argument count of a direct call comes from the signature or the Tier-0 prototype of
//! the callee, then from the parameter recovery. Else it is the count of the argument
//! registers that the caller sets.

use ghidorah_analysis::cc::loc_of;
use ghidorah_base::WarningCode;
use ghidorah_ir::Loc;

use super::expr::{safe, wrap};
use super::{Arity, Buf, CallRow, CallTarget, Printer};
use crate::Warning;
use crate::expr::{Call, Callee, Expr, VarIdx};
use crate::precedence::UNARY;

/// The registers of the arguments of a system call in order.
const SYSCALL_ARGS: [&str; 6] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];

/// Tells if a name is a mangled C++ or Rust name.
fn is_mangled(name: &str) -> bool {
    name.starts_with("_Z") || name.starts_with("_R") || name.starts_with('?')
}

/// Gives the variable that gets the result of a call statement: the `rax` result, or the
/// first result of an opaque instruction.
fn call_ret(c: &Call) -> Option<VarIdx> {
    c.rets
        .iter()
        .find(|(l, _)| *l == Loc::RAX)
        .or_else(|| match c.callee {
            Callee::Intrinsic(_) => c.rets.first(),
            _ => None,
        })
        .map(|(_, v)| *v)
}

impl Printer<'_> {
    /// Gives the variable that gets the result of a call statement. A direct callee whose
    /// signature has no return value gives `None`. Its `rax` holds no result. So a later read
    /// of the variable reads a value with no def.
    pub(super) fn result_var(&self, c: &Call) -> Option<VarIdx> {
        if let Callee::Direct(t) = c.callee
            && self.env.signature(t).is_some_and(|s| s.ret.is_none())
        {
            return None;
        }
        call_ret(c)
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
                self.env.param_count(t).map(|n| Arity {
                    named: usize::from(n),
                    variadic: false,
                })
            });
        self.arity.insert(t, found);
        found
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
        let regs: Vec<Loc> = self
            .env
            .conv()
            .int_args
            .iter()
            .filter_map(|n| loc_of(n))
            .collect();
        match &c.callee {
            Callee::Direct(t) => {
                let name = self.callee_name(*t, site);
                let set = Self::set_count(c, &regs);
                let arity = self.arity(*t);
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
                let args = self.args(c, &regs, (count, stack), buf);
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
