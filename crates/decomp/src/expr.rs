//! The expression view: expressions and statements (design Section 8.2).
//!
//! The decompiler builds the view again on demand from L1. Passes never edit L1. Each node
//! that comes from an op holds the [`OpId`] of the op, so a printer can map lines to ops.
//!
//! | Expression | Meaning |
//! |---|---|
//! | `Var` | A variable of the view |
//! | `Const` | A constant of `w` bits |
//! | `Str` | The address of a string literal |
//! | `Load` | A memory read of `w` bits |
//! | `Un`, `Bin`, `Ite` | A data op of L1 with one, two or three inputs |
//! | `Call` | A call whose one result has one use |
//!
//! | Statement | Meaning |
//! |---|---|
//! | `Assign` | A variable gets a value: an op result or an out-of-SSA copy |
//! | `Store` | A memory write |
//! | `Call` | A call, a system call, an opaque instruction or an instruction that does not lift |
//! | `Return` | A return with the values of the return registers |
//! | `Goto` | An unresolved indirect jump: `goto *(target);` |

use ghidorah_ir::{IntrinsicId, Loc, OpId, Opc};

/// The index of a variable in [`crate::View::vars`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarIdx(pub u32);

impl VarIdx {
    /// Gives the index as a `usize`.
    #[must_use]
    pub fn index(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

/// An expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    /// A variable.
    Var {
        /// The variable.
        var: VarIdx,
        /// The width of the value in bits.
        w: u8,
    },
    /// A constant.
    Const {
        /// The value.
        value: u64,
        /// The width in bits.
        w: u8,
    },
    /// The address of a string literal.
    Str {
        /// The address.
        addr: u64,
    },
    /// A memory read.
    Load {
        /// The width in bits.
        w: u8,
        /// The address.
        addr: Box<Self>,
        /// The `Load` op.
        at: OpId,
    },
    /// A data op with one input, for example `Not` or `ZExt`.
    Un {
        /// The opcode.
        op: Opc,
        /// The width of the op.
        w: u8,
        /// The aux byte of the op.
        sub: u8,
        /// The input.
        x: Box<Self>,
        /// The op.
        at: OpId,
    },
    /// A data op with two inputs, for example `Add` or `ULt`.
    Bin {
        /// The opcode.
        op: Opc,
        /// The width of the op.
        w: u8,
        /// The aux byte of the op.
        sub: u8,
        /// The first input.
        x: Box<Self>,
        /// The second input.
        y: Box<Self>,
        /// The op.
        at: OpId,
    },
    /// A data op with three inputs: `Ite`, `Insert`, `Flags` or `FlagsSel`.
    Ite {
        /// The opcode.
        op: Opc,
        /// The width of the op.
        w: u8,
        /// The aux byte of the op.
        sub: u8,
        /// The first input.
        a: Box<Self>,
        /// The second input.
        b: Box<Self>,
        /// The third input.
        c: Box<Self>,
        /// The op.
        at: OpId,
    },
    /// A call whose result is the value of the expression.
    Call(Box<Call>),
}

impl Expr {
    /// Gives the width of the value in bits. A compare and a `Cond` give 1 bit, and a flags
    /// word gives 16 bits.
    #[must_use]
    pub fn width(&self) -> u8 {
        match self {
            Self::Var { w, .. } | Self::Const { w, .. } | Self::Load { w, .. } => *w,
            Self::Str { .. } => 64,
            Self::Un { op, w, .. } | Self::Bin { op, w, .. } | Self::Ite { op, w, .. } => {
                out_width(*op, *w)
            }
            Self::Call(c) => c.ret.map_or(64, Loc::width),
        }
    }

    /// Gives the op of the node, or `None` for a variable, a constant or a string.
    #[must_use]
    pub fn at(&self) -> Option<OpId> {
        match self {
            Self::Load { at, .. }
            | Self::Un { at, .. }
            | Self::Bin { at, .. }
            | Self::Ite { at, .. } => Some(*at),
            Self::Call(c) => Some(c.at),
            Self::Var { .. } | Self::Const { .. } | Self::Str { .. } => None,
        }
    }

    /// Gives the direct inputs in order.
    #[must_use]
    pub fn inputs(&self) -> Vec<&Self> {
        match self {
            Self::Load { addr, .. } => vec![addr.as_ref()],
            Self::Un { x, .. } => vec![x.as_ref()],
            Self::Bin { x, y, .. } => vec![x.as_ref(), y.as_ref()],
            Self::Ite { a, b, c, .. } => vec![a.as_ref(), b.as_ref(), c.as_ref()],
            Self::Call(c) => c.inputs(),
            Self::Var { .. } | Self::Const { .. } | Self::Str { .. } => Vec::new(),
        }
    }

    /// Gives each node of the expression in preorder.
    #[must_use]
    pub fn preorder(&self) -> Vec<&Self> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(e) = stack.pop() {
            out.push(e);
            for i in e.inputs().into_iter().rev() {
                stack.push(i);
            }
        }
        out
    }

    /// Tells if two expressions have the same value: the same tree with each op ID ignored.
    /// Two reads of memory or two calls can give different values, so a tree with a load or a
    /// call gives `false`.
    #[must_use]
    pub fn same_value(&self, other: &Self) -> bool {
        let mut stack = vec![(self, other)];
        while let Some((a, b)) = stack.pop() {
            let same = match (a, b) {
                (Self::Var { var: x, w: wx }, Self::Var { var: y, w: wy }) => x == y && wx == wy,
                (Self::Const { value: x, w: wx }, Self::Const { value: y, w: wy }) => {
                    x == y && wx == wy
                }
                (Self::Str { addr: x }, Self::Str { addr: y }) => x == y,
                (
                    Self::Un {
                        op: ox,
                        w: wx,
                        sub: sx,
                        ..
                    },
                    Self::Un {
                        op: oy,
                        w: wy,
                        sub: sy,
                        ..
                    },
                )
                | (
                    Self::Bin {
                        op: ox,
                        w: wx,
                        sub: sx,
                        ..
                    },
                    Self::Bin {
                        op: oy,
                        w: wy,
                        sub: sy,
                        ..
                    },
                )
                | (
                    Self::Ite {
                        op: ox,
                        w: wx,
                        sub: sx,
                        ..
                    },
                    Self::Ite {
                        op: oy,
                        w: wy,
                        sub: sy,
                        ..
                    },
                ) => ox == oy && wx == wy && sx == sy,
                _ => false,
            };
            let (xs, ys) = (a.inputs(), b.inputs());
            if !same || xs.len() != ys.len() {
                return false;
            }
            stack.extend(xs.into_iter().zip(ys));
        }
        true
    }

    /// Gives the variables that the expression reads, in preorder.
    #[must_use]
    pub fn vars(&self) -> Vec<VarIdx> {
        self.preorder()
            .into_iter()
            .filter_map(|e| match e {
                Self::Var { var, .. } => Some(*var),
                _ => None,
            })
            .collect()
    }
}

/// Gives the output width of an L1 op with opcode `op` and width `w`.
#[must_use]
pub const fn out_width(op: Opc, w: u8) -> u8 {
    match op {
        Opc::Cond => 1,
        Opc::Flags | Opc::FlagsSel | Opc::FlagsSet => 16,
        _ if op.is_compare() => 1,
        _ => w,
    }
}

/// The target of a call statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Callee {
    /// A call of a fixed address.
    Direct(u64),
    /// A call of a computed address.
    Indirect(Expr),
    /// A system call.
    Syscall,
    /// An instruction that the lifter keeps opaque.
    Intrinsic(IntrinsicId),
    /// An instruction that the lifter does not handle.
    Unimpl,
}

/// A call, a system call or an opaque instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Call {
    /// The target.
    pub callee: Callee,
    /// The values of the locations that the op reads, in location order.
    pub args: Vec<(Loc, Expr)>,
    /// The memory address of an `Intrinsic` with a memory effect.
    pub mem: Option<Expr>,
    /// The locations that the op writes and that a later statement reads.
    pub rets: Vec<(Loc, VarIdx)>,
    /// For a call in an expression: the location of its value.
    pub ret: Option<Loc>,
    /// The call does not return (per call site, a SAILR-lite pass).
    pub noreturn: bool,
    /// The call is a tail call: a printer shows `return f(..);` (a SAILR-lite pass).
    pub tail: bool,
    /// The op.
    pub at: OpId,
}

impl Call {
    /// Gives the expression inputs: the computed target, the arguments and the address.
    #[must_use]
    pub fn inputs(&self) -> Vec<&Expr> {
        let mut out = Vec::new();
        if let Callee::Indirect(t) = &self.callee {
            out.push(t);
        }
        out.extend(self.args.iter().map(|(_, e)| e));
        if let Some(m) = &self.mem {
            out.push(m);
        }
        out
    }
}

/// A statement of a shape node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Stmt {
    /// `var = value`.
    Assign {
        /// The variable.
        var: VarIdx,
        /// The value.
        value: Expr,
        /// The op of the value, or the phi of an out-of-SSA copy.
        at: OpId,
    },
    /// `*(addr) = value` with `w` bits.
    Store {
        /// The width in bits.
        w: u8,
        /// The address.
        addr: Expr,
        /// The value.
        value: Expr,
        /// The op.
        at: OpId,
    },
    /// A call.
    Call(Call),
    /// A return with the values of the return registers.
    Return {
        /// The values of the locations that the return reads.
        uses: Vec<(Loc, Expr)>,
        /// The op.
        at: OpId,
    },
    /// An unresolved indirect jump: `goto *(target);`. It never prints as a return.
    Goto {
        /// The computed target.
        target: Expr,
        /// The op.
        at: OpId,
    },
}

impl Stmt {
    /// Gives the op of the statement.
    #[must_use]
    pub const fn at(&self) -> OpId {
        match self {
            Self::Assign { at, .. }
            | Self::Store { at, .. }
            | Self::Return { at, .. }
            | Self::Goto { at, .. } => *at,
            Self::Call(c) => c.at,
        }
    }

    /// Gives the expressions of the statement in order.
    #[must_use]
    pub fn exprs(&self) -> Vec<&Expr> {
        match self {
            Self::Assign { value, .. } => vec![value],
            Self::Store { addr, value, .. } => vec![addr, value],
            Self::Call(c) => c.inputs(),
            Self::Return { uses, .. } => uses.iter().map(|(_, e)| e).collect(),
            Self::Goto { target, .. } => vec![target],
        }
    }

    /// Tells if the statement ends the run: a return, a goto, a call that does not return or a
    /// tail call.
    #[must_use]
    pub const fn ends(&self) -> bool {
        match self {
            Self::Return { .. } | Self::Goto { .. } => true,
            Self::Call(c) => c.noreturn || c.tail,
            Self::Assign { .. } | Self::Store { .. } => false,
        }
    }
}
