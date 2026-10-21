//! The value mode of the AST interpreter (AC-101).
//!
//! The walk follows the lowered code. A node step runs its statements. A test evaluates the
//! branch condition of its node, and a dispatch evaluates the switch index or target. Values have 128
//! bits, and memory is the image plus a sparse map of written bytes, as in the L0 interpreter.

use std::collections::BTreeMap;

use ghidorah_ir::{Config, EvalError, Image, Loc, Node, OpId, StopReason, eval};

use super::{Outcome, Step, lower};
use crate::expr::{Call, Callee, Expr, Stmt};
use crate::{Decomp, NodeView};

/// The end of a run, before the outcome takes the written bytes.
struct Stop {
    reason: StopReason,
    at: OpId,
    uses: Vec<(Loc, Option<u128>)>,
}

/// The result of one step of the machine: `Err` ends the run.
type Res<T> = Result<T, Stop>;

/// Gives a stop with no use.
const fn stop(reason: StopReason, at: OpId) -> Stop {
    Stop {
        reason,
        at,
        uses: Vec::new(),
    }
}

/// Gives the low 64 bits of a value.
fn low64(x: u128) -> u64 {
    u64::try_from(x & u128::from(u64::MAX)).unwrap_or(u64::MAX)
}

/// Gives the value mask of a width from 1 to 128.
const fn mask(w: u8) -> u128 {
    if w >= 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    }
}

/// The state of one value run.
struct Machine<'a> {
    d: &'a Decomp,
    image: &'a dyn Image,
    config: &'a Config,
    vars: Vec<Option<u128>>,
    writes: BTreeMap<u64, u8>,
    fuel: u64,
    last: OpId,
}

impl Machine<'_> {
    /// Takes one unit of fuel at the op `at`.
    fn tick(&mut self, at: OpId) -> Res<()> {
        self.last = at;
        if self.fuel == 0 {
            return Err(stop(StopReason::FuelExhausted, at));
        }
        self.fuel -= 1;
        Ok(())
    }

    /// Gives the result of a data op.
    fn data(op: ghidorah_ir::Opc, w: u8, sub: u8, xyz: [u128; 3], at: OpId) -> Res<u128> {
        let [x, y, z] = xyz;
        eval(op, w, sub, x, y, z).map_err(|e| match e {
            EvalError::DivZero => stop(StopReason::DivZero, at),
            EvalError::NotData | EvalError::BadWidth => stop(StopReason::BadIr, at),
        })
    }

    /// Gives the count of bytes of an access of `w` bits.
    fn access_len(w: u8, at: OpId) -> Res<u8> {
        if w != 0 && w.is_multiple_of(8) && w <= 128 {
            Ok(w / 8)
        } else {
            Err(stop(StopReason::BadIr, at))
        }
    }

    /// Reads `w` bits at `addr` (little-endian).
    fn load(&self, w: u8, addr: u64, at: OpId) -> Res<u128> {
        let len = Self::access_len(w, at)?;
        let mut value = 0u128;
        for i in 0..len {
            let a = addr.wrapping_add(u64::from(i));
            let byte = self
                .writes
                .get(&a)
                .copied()
                .or_else(|| self.image.read(a))
                .ok_or_else(|| stop(StopReason::UnmappedRead(a), at))?;
            value |= u128::from(byte) << (8 * u32::from(i));
        }
        Ok(value)
    }

    /// Writes `w` bits of `value` at `addr`. No byte changes when one byte is not writable or
    /// when the cap stops the write.
    fn store(&mut self, w: u8, addr: u64, value: u128, at: OpId) -> Res<()> {
        let len = Self::access_len(w, at)?;
        let mut new = 0u64;
        for i in 0..len {
            let a = addr.wrapping_add(u64::from(i));
            if !self.image.writable(a) {
                return Err(stop(StopReason::UnmappedWrite(a), at));
            }
            new += u64::from(!self.writes.contains_key(&a));
        }
        let total = u64::try_from(self.writes.len()).unwrap_or(u64::MAX);
        if total.saturating_add(new) > self.config.mem_cap {
            return Err(stop(StopReason::MemCap, at));
        }
        for (i, byte) in value
            .to_le_bytes()
            .iter()
            .take(usize::from(len))
            .enumerate()
        {
            let off = u64::try_from(i).unwrap_or(u64::MAX);
            self.writes.insert(addr.wrapping_add(off), *byte);
        }
        Ok(())
    }

    /// Evaluates an expression.
    fn eval(&mut self, e: &Expr) -> Res<u128> {
        match e {
            Expr::Var { var, .. } => self
                .vars
                .get(var.index())
                .copied()
                .flatten()
                .ok_or_else(|| stop(StopReason::BadIr, self.last)),
            Expr::Const { value, .. } => Ok(u128::from(*value)),
            Expr::Str { addr } => Ok(u128::from(*addr)),
            Expr::Load { w, addr, at } => {
                let a = low64(self.eval(addr)?);
                self.tick(*at)?;
                self.load(*w, a, *at)
            }
            Expr::Un {
                op, w, sub, x, at, ..
            } => {
                let x = self.eval(x)?;
                self.tick(*at)?;
                Self::data(*op, *w, *sub, [x, 0, 0], *at)
            }
            Expr::Bin {
                op,
                w,
                sub,
                x,
                y,
                at,
            } => {
                let x = self.eval(x)?;
                let y = self.eval(y)?;
                self.tick(*at)?;
                Self::data(*op, *w, *sub, [x, y, 0], *at)
            }
            Expr::Ite {
                op,
                w,
                sub,
                a,
                b,
                c,
                at,
            } => {
                let a = self.eval(a)?;
                let b = self.eval(b)?;
                let c = self.eval(c)?;
                self.tick(*at)?;
                Self::data(*op, *w, *sub, [a, b, c], *at)
            }
            Expr::Call(c) => Err(self.call(c)),
        }
    }

    /// Runs a call: its inputs, then the stop of the call.
    fn call(&mut self, c: &Call) -> Stop {
        match self.call_inner(c) {
            Ok(s) | Err(s) => s,
        }
    }

    fn call_inner(&mut self, c: &Call) -> Res<Stop> {
        let target = match &c.callee {
            Callee::Direct(t) => Some(*t),
            Callee::Indirect(e) => Some(low64(self.eval(e)?)),
            Callee::Syscall | Callee::Intrinsic(_) | Callee::Unimpl => None,
        };
        let mut uses = Vec::with_capacity(c.args.len());
        for (loc, e) in &c.args {
            uses.push((*loc, Some(self.eval(e)?)));
        }
        if let Some(m) = &c.mem {
            let _ = self.eval(m)?;
        }
        self.tick(c.at)?;
        let reason = match (&c.callee, target) {
            (Callee::Syscall, _) => StopReason::Syscall,
            (Callee::Intrinsic(_), _) => StopReason::Intrinsic,
            (Callee::Unimpl, _) => StopReason::Unimpl,
            (_, Some(t)) if self.config.externals.contains(&t) => StopReason::CallExternal(t),
            (_, t) => StopReason::CallUnresolved(t.unwrap_or_default()),
        };
        Ok(Stop {
            reason,
            at: c.at,
            uses,
        })
    }

    /// Runs one statement.
    fn exec(&mut self, s: &Stmt) -> Res<()> {
        match s {
            Stmt::Assign { var, value, at } => {
                let v = self.eval(value)?;
                self.tick(*at)?;
                match self.vars.get_mut(var.index()) {
                    Some(slot) => {
                        *slot = Some(v & mask(value.width()));
                        Ok(())
                    }
                    None => Err(stop(StopReason::BadIr, *at)),
                }
            }
            Stmt::Store { w, addr, value, at } => {
                let a = low64(self.eval(addr)?);
                let v = self.eval(value)?;
                self.tick(*at)?;
                self.store(*w, a, v, *at)
            }
            Stmt::Call(c) => Err(self.call(c)),
            Stmt::Return { uses, at } => {
                let mut out = Vec::with_capacity(uses.len());
                for (loc, e) in uses {
                    out.push((*loc, Some(self.eval(e)?)));
                }
                self.tick(*at)?;
                Err(Stop {
                    reason: StopReason::Returned,
                    at: *at,
                    uses: out,
                })
            }
            Stmt::Goto { target, at } => {
                let t = low64(self.eval(target)?);
                self.tick(*at)?;
                let known = self
                    .d
                    .view
                    .nodes
                    .iter()
                    .any(|n| n.span.is_some_and(|s| s.0 == t));
                let reason = if known {
                    StopReason::BadIr
                } else {
                    StopReason::NoCode(t)
                };
                Err(stop(reason, *at))
            }
        }
    }

    /// Runs the statements of a node.
    fn node(&mut self, n: Node) -> Res<()> {
        let d = self.d;
        let Some(view) = d.view.node(n) else {
            return Err(stop(StopReason::BadIr, self.last));
        };
        for s in &view.stmts {
            self.exec(s)?;
        }
        Ok(())
    }

    /// Gives the op of the flow op that ends a node, or the last op of the run.
    fn term(&self, n: Node) -> OpId {
        self.d
            .view
            .node(n)
            .and_then(|v| v.term)
            .unwrap_or(self.last)
    }

    /// Evaluates the branch condition of a node.
    fn cond(&mut self, n: Node) -> Res<bool> {
        let d = self.d;
        let at = self.term(n);
        let c = d
            .view
            .node(n)
            .and_then(|v| v.cond.as_ref())
            .ok_or_else(|| stop(StopReason::BadIr, at))?;
        Ok(self.eval(c)? != 0)
    }

    /// Gives the case index of the switch node `n`. A selector gives the case `index - bias`
    /// when it is in the table, else the default case. A switch over the target gives the case
    /// of the target address.
    fn case(&mut self, n: Node) -> Res<usize> {
        let d = self.d;
        let at = self.term(n);
        let view = d.view.node(n).ok_or_else(|| stop(StopReason::BadIr, at))?;
        if let Some(index) = &view.index {
            return self.index_case(view, index, at);
        }
        let target = view
            .target
            .as_ref()
            .ok_or_else(|| stop(StopReason::BadIr, at))?;
        let t = low64(self.eval(target)?);
        view.cases
            .iter()
            .position(|&a| a == t)
            .ok_or_else(|| stop(StopReason::NoCode(t), at))
    }

    /// Gives the case of the selector `index` of a switch view: `index - bias` in the table, else
    /// the default case.
    fn index_case(&mut self, view: &NodeView, index: &Expr, at: OpId) -> Res<usize> {
        let width = index.width();
        let value = low64(self.eval(index)? & mask(width));
        let pos = value.wrapping_sub(view.bias) & low64(mask(width));
        let table = view.cases.len().saturating_sub(usize::from(view.default));
        match usize::try_from(pos) {
            Ok(case) if case < table => Ok(case),
            _ if view.default => Ok(table),
            _ => Err(stop(StopReason::NoCode(value), at)),
        }
    }

    /// Gives the stop of a node that ends with no stop statement.
    fn halt(&self) -> Stop {
        stop(StopReason::BadIr, self.last)
    }
}

/// Runs the tree of `d` with values (see [`super::run`]).
pub(super) fn run(
    d: &Decomp,
    image: &dyn Image,
    config: &Config,
    setup: &[(Loc, u128)],
    fuel: u64,
) -> Outcome {
    let code = lower(&d.tree, &d.view.shape);
    let start = OpId {
        addr: d.view.entry,
        seq: 0,
    };
    let vars = d
        .view
        .vars
        .iter()
        .map(|v| {
            v.input.map(|loc| {
                let raw = setup.iter().find(|(l, _)| *l == loc).map_or(0, |(_, x)| *x);
                raw & mask(loc.width())
            })
        })
        .collect();
    let mut m = Machine {
        d,
        image,
        config,
        vars,
        writes: BTreeMap::new(),
        fuel,
        last: start,
    };
    let end = walk(&mut m, &code.steps);
    Outcome {
        reason: end.reason,
        at: end.at,
        uses: end.uses,
        writes: m.writes,
    }
}

/// Walks the lowered steps until a stop. Each step takes one unit of fuel, so a loop of pure
/// nodes ends on fuel.
fn walk(m: &mut Machine<'_>, steps: &[Step]) -> Stop {
    let mut pc = 0usize;
    loop {
        let Some(step) = steps.get(pc) else {
            return stop(StopReason::BadIr, m.last);
        };
        let at = m.last;
        if let Err(s) = m.tick(at) {
            return s;
        }
        let next = match step {
            Step::Exec(n) => m.node(*n).map(|()| pc.saturating_add(1)),
            Step::Test {
                node,
                neg,
                exec,
                t,
                f,
            } => {
                let ran = if *exec { m.node(*node) } else { Ok(()) };
                ran.and_then(|()| m.cond(*node))
                    .map(|b| if b == *neg { *f } else { *t })
            }
            Step::Dispatch { node, table } => m
                .case(*node)
                .map(|i| table.get(i).copied().unwrap_or(usize::MAX)),
            Step::Jump(t) => Ok(*t),
            Step::Halt => Err(m.halt()),
            Step::Bad => Err(stop(StopReason::BadIr, m.last)),
        };
        match next {
            Ok(p) => pc = p,
            Err(s) => return s,
        }
    }
}
