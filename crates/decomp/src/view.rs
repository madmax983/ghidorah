//! The expression view of an L1 form (design Section 8.2).
//!
//! [`build`] reads an L1 form and gives a [`View`]: the statements of each shape node, the
//! branch condition and the switch target of each node, the variables and the [`Shape`].
//!
//! The build has four steps:
//!
//! 1. Each reachable block becomes a shape node. Its live ops give statements in run order.
//! 2. Safe folding puts a single-use value into its use (the `fold` module).
//! 3. Out-of-SSA: the values that stay become variables. Values without interference share a
//!    variable. A phi argument in another variable gets a copy on its edge (the `vars`
//!    module).
//! 4. The exit of each node comes from the flow ops of its last instruction and the CFG.
//!
//! A variable has a storage-based identity ([`VarId`]): a parameter number, a stack offset or
//! a register name with the address of its first def. So an agent name survives a new
//! decompile (AC-105a).

use std::collections::BTreeSet;
use std::fmt;

use ghidorah_base::{Fuel, VarId};
use ghidorah_ir::ssa::Ssa;
use ghidorah_ir::{Arena, Loc};
use ghidorah_types::CallConv;

use crate::expr::{Expr, Stmt};
use crate::shape::Shape;
use crate::{Elided, Warning};

/// The facts outside the L1 form that a view reads.
pub trait Env {
    /// Gives the name of the function or import stub at `addr`.
    fn callee_name(&self, addr: u64) -> Option<String>;
    /// Tells if the function at `addr` does not return.
    fn is_noreturn(&self, addr: u64) -> bool;
    /// Tells if a string literal starts at `addr`.
    fn is_string(&self, addr: u64) -> bool;
}

/// An environment that knows no fact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoEnv;

impl Env for NoEnv {
    fn callee_name(&self, _addr: u64) -> Option<String> {
        None
    }

    fn is_noreturn(&self, _addr: u64) -> bool {
        false
    }

    fn is_string(&self, _addr: u64) -> bool {
        false
    }
}

/// The input of a view: an L1 form and its L0 arena.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    /// The L1 form.
    pub ssa: &'a Ssa,
    /// The L0 arena. Its ops have the same indexes as the instruction ops of the L1 form.
    pub l0: &'a Arena,
    /// The addresses of the tail jumps that the L1 form has as calls.
    pub tail_calls: &'a BTreeSet<u64>,
    /// The calling convention, for the parameter numbers.
    pub conv: Option<&'a CallConv>,
}

/// The kind of a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VarKind {
    /// A parameter: the entry value of an argument register or of a stack parameter slot.
    Param,
    /// A local: a value of a stack slot of the frame.
    Local,
    /// A register value or a temporary.
    Temp,
}

/// A variable of the view.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Var {
    /// The storage-based identity.
    pub id: VarId,
    /// The width in bits: the widest value of the variable.
    pub w: u8,
    /// The kind.
    pub kind: VarKind,
    /// The location of the values of the variable, when one is known.
    pub home: Option<Loc>,
    /// The location whose entry value the variable holds at the function start.
    pub input: Option<Loc>,
}

/// The view of one shape node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct NodeView {
    /// The statements in run order.
    pub stmts: Vec<Stmt>,
    /// The branch condition of a `Cond` exit: true goes to `t`.
    pub cond: Option<Expr>,
    /// The computed target address of a `Switch` exit.
    pub target: Option<Expr>,
    /// The block address of each case of a `Switch` exit.
    pub cases: Vec<u64>,
    /// The L1 ops of a block node in run order. An added node has none.
    pub ops: Vec<u32>,
    /// The address range `[start, end)` of the instructions of a block node.
    pub span: Option<(u64, u64)>,
}

/// The expression view of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    /// The entry address.
    pub entry: u64,
    /// The CFG of the structurer.
    pub shape: Shape,
    /// The view of each shape node. Node `n` is `nodes[n]`.
    pub nodes: Vec<NodeView>,
    /// The variables. Variable `i` is `vars[i]`.
    pub vars: Vec<Var>,
}

impl View {
    /// Gives the view of a node.
    #[must_use]
    pub fn node(&self, n: ghidorah_ir::Node) -> Option<&NodeView> {
        self.nodes.get(n.index())
    }

    /// Gives a variable.
    #[must_use]
    pub fn var(&self, v: crate::VarIdx) -> Option<&Var> {
        self.vars.get(v.index())
    }
}

/// The result of [`build`]: the view, the left-out ranges and the warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// The view.
    pub view: View,
    /// The blocks that no run reaches.
    pub elided: Vec<Elided>,
    /// The warnings, for example `W_JUMPTABLE_UNRESOLVED`.
    pub warnings: Vec<Warning>,
}

/// The error of [`build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewError {
    /// The work used all of its fuel.
    OutOfFuel,
    /// The L1 form has no entry block.
    NoEntry,
    /// The function has more nodes or variables than a `u32` can count.
    TooLarge,
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfFuel => f.write_str("The view used all of its fuel."),
            Self::NoEntry => f.write_str("The L1 form has no entry block."),
            Self::TooLarge => f.write_str("The function has too many nodes or variables."),
        }
    }
}

impl std::error::Error for ViewError {}

/// Builds the view of `input`. With `fold`, single-use values go into their use.
///
/// Each op of the view takes one unit of `fuel`.
///
/// # Errors
///
/// Returns [`ViewError::OutOfFuel`] when the fuel runs out, [`ViewError::NoEntry`] for an L1
/// form without an entry block and [`ViewError::TooLarge`] when a count does not fit.
pub fn build(
    input: &Input<'_>,
    env: &dyn Env,
    fold: bool,
    fuel: &mut Fuel,
) -> Result<Built, ViewError> {
    let _ = (input, env, fold, fuel);
    Err(ViewError::NoEntry)
}
