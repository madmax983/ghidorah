//! The text of expressions, statements and calls.
//!
//! The expression depth stays small, because safe folding limits it (the `fold` module), so
//! these functions call themselves on the inputs of a node.

use std::fmt::Write as _;

use ghidorah_base::{BinText, Caps};
use ghidorah_ir::{Cc, FlagOp, Loc, OpId, Opc};

use super::{Buf, Printer, width_type};
use crate::expr::{Callee, Expr, Stmt, VarIdx};
use crate::lattice;
use crate::precedence::{self, ATOM, EQ, POSTFIX, TERNARY, UNARY};

/// The largest number of bytes of a string literal in the text.
pub const MAX_STRING: usize = 200;

/// The largest number of characters of a name from the binary.
pub const MAX_NAME: usize = 256;

/// The names of the flag operations in code order.
const FLAG_OPS: [&str; 17] = [
    "add", "sub", "adc", "sbb", "logic", "inc", "dec", "neg", "shl", "shr", "sar", "rol", "ror",
    "umul", "smul", "bt", "copy",
];

/// Gives `text` in parentheses when it needs them under an operator with the number `parent`.
pub(super) fn wrap(text: &str, prec: u8, parent: u8, right: bool) -> String {
    if precedence::parens(prec, parent, right) {
        format!("({text})")
    } else {
        text.to_owned()
    }
}

/// Gives the mask of `w` bits.
const fn mask(w: u8) -> u64 {
    if w >= 64 { u64::MAX } else { (1u64 << w) - 1 }
}

/// Gives the text of a constant: decimal below 10, else hex.
pub(super) fn konst(value: u64, w: u8) -> String {
    let v = value & mask(w);
    if v < 10 {
        v.to_string()
    } else {
        format!("{v:#x}")
    }
}

/// Gives the text of a constant as a signed value of `w` bits.
pub(super) fn signed_konst(value: u64, w: u8) -> String {
    let v = value & mask(w);
    let top = w.clamp(1, 64) - 1;
    if v >> top & 1 == 1 {
        let magnitude = (v ^ mask(w)).wrapping_add(1) & mask(w);
        format!("-{}", konst(magnitude, 64))
    } else {
        konst(v, w)
    }
}

/// Gives the output text of a name from the binary: the escapes of `BinText`.
pub(super) fn safe(raw: &str) -> String {
    BinText::new(raw.as_bytes())
        .render(Caps::new(MAX_NAME, 0))
        .text
}

/// Gives a C string literal of `bytes`, at most [`MAX_STRING`] bytes, with `...` after a
/// cut. Each byte outside the printable ASCII range prints as an escape.
fn c_string(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in bytes.iter().take(MAX_STRING) {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push('"');
    if bytes.len() > MAX_STRING {
        out.push_str("...");
    }
    out
}

/// Gives the variable and the offset of an address `v` or `v + k`, with the op of the sum.
fn base_offset(addr: &Expr) -> Option<(VarIdx, u64, Option<OpId>)> {
    match addr {
        Expr::Var { var, .. } => Some((*var, 0, None)),
        Expr::Bin {
            op: Opc::Add,
            x,
            y,
            at,
            ..
        } => match (x.as_ref(), y.as_ref()) {
            (Expr::Var { var, .. }, Expr::Const { value, .. }) => Some((*var, *value, Some(*at))),
            _ => None,
        },
        _ => None,
    }
}

impl Printer<'_> {
    /// Gives the name of a variable and marks it used.
    pub(super) fn var(&mut self, v: VarIdx) -> String {
        self.used.insert(v);
        let count = self.refs.entry(v).or_insert(0);
        *count = count.saturating_add(1);
        self.vnames
            .get(v.index())
            .map_or_else(|| format!("v_{}", v.0), |n| n.0.clone())
    }

    /// Tells if `e` is the entry value of `loc` or a value that a call leaves behind in it. The
    /// entry value of an XMM register is a floating parameter, so it is no such value.
    pub(super) fn untouched(&self, e: &Expr, loc: Loc) -> bool {
        let Expr::Var { var, .. } = e else {
            return false;
        };
        let entry = !loc.is_xmm() && self.view().var(*var).is_some_and(|v| v.input == Some(loc));
        self.clobbers.contains(var) || entry
    }

    /// Gives the text of a statement with its `;` and adds its parts to `buf`.
    pub(super) fn stmt(&mut self, s: &Stmt, buf: &mut Buf) -> String {
        buf.op(s.at());
        match s {
            Stmt::Assign { var, value, .. } => {
                let name = self.var(*var);
                let (text, _) = self.expr(value, buf);
                format!("{name} = {text};")
            }
            Stmt::Store { w, addr, value, .. } => {
                let (lhs, _) = self.access(*w, addr, buf);
                let (text, _) = self.expr(value, buf);
                format!("{lhs} = {text};")
            }
            Stmt::Call(c) => {
                let text = self.call_text(c, buf);
                if c.tail {
                    let void = match c.callee {
                        Callee::Direct(t) => self.env.signature(t).is_some_and(|s| s.ret.is_none()),
                        _ => false,
                    };
                    if !void {
                        self.rets.push(64);
                    }
                    return format!("return {text};");
                }
                match self.result_var(c) {
                    Some(v) => format!("{} = {text};", self.var(v)),
                    None => format!("{text};"),
                }
            }
            Stmt::Return { uses, .. } => {
                let loc = self.ret_loc;
                let value = uses.iter().find(|(l, _)| *l == loc).map(|(_, e)| e);
                match value {
                    Some(e) if !self.void_ret && !self.untouched(e, loc) => {
                        self.rets.push(e.width());
                        format!("return {};", self.expr(e, buf).0)
                    }
                    _ => "return;".to_owned(),
                }
            }
            Stmt::Goto { target, .. } => format!("goto *({});", self.expr(target, buf).0),
        }
    }

    /// Gives the text of a memory access of `w` bits: `v->field` for a typed pointer, else
    /// `*(T *)(addr)`.
    fn access(&mut self, w: u8, addr: &Expr, buf: &mut Buf) -> (String, u8) {
        if let Some((v, off, at)) = base_offset(addr)
            && let Some(ty) = self.types.get(v.index()).copied().flatten()
            && let Some(field) = lattice::field(&self.stores, ty, off, w)
        {
            if let Some(at) = at {
                buf.op(at);
            }
            return (format!("{}->{field}", self.var(v)), POSTFIX);
        }
        let (text, prec) = self.expr(addr, buf);
        (
            format!("*({} *){}", width_type(w), wrap(&text, prec, UNARY, false)),
            UNARY,
        )
    }

    /// Gives the text of `e` as a signed value of `bits` bits.
    fn signed(&mut self, e: &Expr, bits: u8, buf: &mut Buf) -> String {
        match e {
            Expr::Const { value, .. } => signed_konst(*value, bits),
            Expr::Var { var, .. }
                if self
                    .types
                    .get(var.index())
                    .copied()
                    .flatten()
                    .is_some_and(|t| self.stores.is_signed(t, bits)) =>
            {
                self.var(*var)
            }
            Expr::Un {
                op: Opc::Trunc,
                w,
                x,
                at,
                ..
            } if *w == bits => {
                buf.op(*at);
                let (text, prec) = self.expr(x, buf);
                format!("(int{bits}_t){}", wrap(&text, prec, UNARY, false))
            }
            _ => {
                let (text, prec) = self.expr(e, buf);
                format!("(int{bits}_t){}", wrap(&text, prec, UNARY, false))
            }
        }
    }

    /// Gives the text of a call of a helper: `__name(a, b)`.
    pub(super) fn helper(&mut self, name: &str, inputs: &[&Expr], buf: &mut Buf) -> (String, u8) {
        let args: Vec<String> = inputs.iter().map(|x| self.expr(x, buf).0).collect();
        (format!("__{name}({})", args.join(", ")), POSTFIX)
    }

    /// Gives the text of a negated condition: a flipped compare, or `!(c)`.
    pub(super) fn negated(&mut self, e: &Expr, buf: &mut Buf) -> (String, u8) {
        match e {
            Expr::Bin {
                op, w, x, y, at, ..
            } => {
                if let (Some(text), Some(b)) = (precedence::negated(*op), precedence::binary(*op)) {
                    buf.op(*at);
                    return self.compare(text, b, *w, x, y, buf);
                }
                if matches!(op, Opc::TestZ | Opc::TestNZ) {
                    buf.op(*at);
                    // The negation of `TestZ` is `TestNZ`, so a negated `TestNZ` prints `== 0`.
                    return self.test(*op == Opc::TestNZ, x, y, buf);
                }
            }
            Expr::Un {
                op: Opc::Not,
                w: 1,
                x,
                at,
                ..
            } => {
                buf.op(*at);
                return self.expr(x, buf);
            }
            _ => {}
        }
        let (text, prec) = self.expr(e, buf);
        (format!("!{}", wrap(&text, prec, UNARY, true)), UNARY)
    }

    /// Gives the text of `x op y` for a binary operator.
    fn compare(
        &mut self,
        text: &str,
        b: precedence::Binary,
        w: u8,
        x: &Expr,
        y: &Expr,
        buf: &mut Buf,
    ) -> (String, u8) {
        let (lx, ly) = if b.signed {
            let sx = self.signed(x, w, buf);
            let sy = if b.prec == precedence::SHIFT {
                self.expr(y, buf).0
            } else {
                self.signed(y, w, buf)
            };
            (
                wrap(&sx, UNARY, b.prec, false),
                wrap(&sy, UNARY, b.prec, true),
            )
        } else {
            let (tx, px) = self.expr(x, buf);
            let (ty, py) = self.expr(y, buf);
            (wrap(&tx, px, b.prec, false), wrap(&ty, py, b.prec, true))
        };
        (format!("{lx} {text} {ly}"), b.prec)
    }

    /// Gives the text of `TestZ` (`zero`) or `TestNZ`: `x == 0` when both inputs are equal,
    /// else `(x & y) == 0`.
    fn test(&mut self, zero: bool, x: &Expr, y: &Expr, buf: &mut Buf) -> (String, u8) {
        let op = if zero { "==" } else { "!=" };
        if x == y || x.same_value(y) {
            let (tx, px) = self.expr(x, buf);
            return (format!("{} {op} 0", wrap(&tx, px, EQ, false)), EQ);
        }
        let (tx, px) = self.expr(x, buf);
        let (ty, py) = self.expr(y, buf);
        let and = precedence::BIT_AND;
        (
            format!(
                "({} & {}) {op} 0",
                wrap(&tx, px, and, false),
                wrap(&ty, py, and, true)
            ),
            EQ,
        )
    }

    /// Gives the text of an expression with its precedence number, and adds its parts to
    /// `buf`.
    pub(super) fn expr(&mut self, e: &Expr, buf: &mut Buf) -> (String, u8) {
        match e {
            Expr::Var { var, .. } => (self.var(*var), ATOM),
            Expr::Const { value, w } => (konst(*value, *w), ATOM),
            Expr::Str { addr } => {
                buf.strings.push(*addr);
                match self.env.string_bytes(*addr) {
                    Some(bytes) => (c_string(&bytes), ATOM),
                    None => (format!("(char *){addr:#x}"), UNARY),
                }
            }
            Expr::Load { w, addr, at } => {
                buf.op(*at);
                self.access(*w, addr, buf)
            }
            Expr::Un {
                op, w, sub, x, at, ..
            } => {
                buf.op(*at);
                self.unary(*op, *w, *sub, x, buf)
            }
            Expr::Bin {
                op, w, x, y, at, ..
            } => {
                buf.op(*at);
                self.binary(*op, *w, x, y, buf)
            }
            Expr::Ite {
                op,
                sub,
                a: first,
                b: second,
                c: third,
                at,
                ..
            } => {
                buf.op(*at);
                self.three(*op, *sub, [first, second, third], buf)
            }
            Expr::Call(c) => (self.call_text(c, buf), POSTFIX),
        }
    }

    /// Gives the text of a data op with three inputs: `Ite`, `Flags`, `Insert` or `FlagsSel`.
    fn three(&mut self, op: Opc, sub: u8, inputs: [&Expr; 3], buf: &mut Buf) -> (String, u8) {
        match op {
            Opc::Ite => {
                let [cond, yes, no] = inputs.map(|x| self.expr(x, buf));
                (
                    format!(
                        "{} ? {} : {}",
                        wrap(&cond.0, cond.1, TERNARY, true),
                        wrap(&yes.0, yes.1, TERNARY, false),
                        wrap(&no.0, no.1, TERNARY, false)
                    ),
                    TERNARY,
                )
            }
            Opc::Flags => {
                let name = FLAG_OPS
                    .get(usize::from(
                        FlagOp::from_code(sub).map_or(255, FlagOp::code),
                    ))
                    .copied()
                    .unwrap_or("op");
                self.helper(&format!("flags_{name}"), &inputs, buf)
            }
            Opc::Insert => {
                let [base, part, low] = inputs.map(|x| self.expr(x, buf).0);
                (format!("__insert({base}, {part}, {low}, {sub})"), POSTFIX)
            }
            other => self.helper(&other.name().to_ascii_lowercase(), &inputs, buf),
        }
    }

    /// Gives the text of a data op with one input.
    fn unary(&mut self, op: Opc, w: u8, sub: u8, x: &Expr, buf: &mut Buf) -> (String, u8) {
        match op {
            Opc::Copy => self.expr(x, buf),
            Opc::Neg | Opc::Not => {
                let sign = match (op, w) {
                    (Opc::Neg, _) => "-",
                    (_, 1) => "!",
                    _ => "~",
                };
                let (t, p) = self.expr(x, buf);
                (format!("{sign}{}", wrap(&t, p, UNARY, true)), UNARY)
            }
            Opc::ZExt | Opc::Trunc => {
                if x.width() == w {
                    return self.expr(x, buf);
                }
                if op == Opc::Trunc
                    && let Expr::Un {
                        op: Opc::ZExt | Opc::SExt,
                        sub: from,
                        x: inner,
                        at,
                        ..
                    } = x
                    && *from == w
                {
                    buf.op(*at);
                    return self.expr(inner, buf);
                }
                let (t, p) = self.expr(x, buf);
                (
                    format!("({}){}", width_type(w), wrap(&t, p, UNARY, false)),
                    UNARY,
                )
            }
            Opc::SExt => {
                let inner = self.signed(x, sub, buf);
                (
                    format!("(int{w}_t){}", wrap(&inner, UNARY, UNARY, false)),
                    UNARY,
                )
            }
            Opc::Cond => {
                let cc = Cc::x86(sub).map_or("cc", Cc::name);
                self.helper(&format!("cond_{cc}"), &[x], buf)
            }
            Opc::Popcnt => self.helper("popcount", &[x], buf),
            other => self.helper(&other.name().to_ascii_lowercase(), &[x], buf),
        }
    }

    /// Gives the text of a data op with two inputs.
    fn binary(&mut self, op: Opc, w: u8, x: &Expr, y: &Expr, buf: &mut Buf) -> (String, u8) {
        if matches!(op, Opc::Xor | Opc::Sub) && (x == y || x.same_value(y)) {
            for node in x.preorder() {
                if let Some(at) = node.at() {
                    buf.op(at);
                }
            }
            return (konst(0, w), ATOM);
        }
        if let (Opc::Add | Opc::Sub, Expr::Const { value, w: cw }) = (op, y) {
            let bits = *value & mask(*cw);
            let top = (*cw).clamp(1, 64) - 1;
            if bits >> top & 1 == 1 && bits != 1u64 << top {
                let flipped = if op == Opc::Add { Opc::Sub } else { Opc::Add };
                let magnitude = Expr::Const {
                    value: (bits ^ mask(*cw)).wrapping_add(1) & mask(*cw),
                    w: *cw,
                };
                if let Some(found) = precedence::binary(flipped) {
                    return self.compare(found.text, found, w, x, &magnitude, buf);
                }
            }
        }
        if let Some(found) = precedence::binary(op) {
            return self.compare(found.text, found, w, x, y, buf);
        }
        match op {
            Opc::TestZ | Opc::TestNZ => self.test(op == Opc::TestZ, x, y, buf),
            Opc::Extract => {
                let (text, prec) = if matches!(y, Expr::Const { value: 0, .. }) {
                    self.expr(x, buf)
                } else {
                    let (low, low_prec) = self.expr(x, buf);
                    let (count, count_prec) = self.expr(y, buf);
                    let shift = precedence::SHIFT;
                    (
                        format!(
                            "{} >> {}",
                            wrap(&low, low_prec, shift, false),
                            wrap(&count, count_prec, shift, true)
                        ),
                        shift,
                    )
                };
                (
                    format!("({}){}", width_type(w), wrap(&text, prec, UNARY, false)),
                    UNARY,
                )
            }
            Opc::UMulHi => self.helper("mulhi_u", &[x, y], buf),
            Opc::SMulHi => self.helper("mulhi_s", &[x, y], buf),
            other => self.helper(&other.name().to_ascii_lowercase(), &[x, y], buf),
        }
    }
}
