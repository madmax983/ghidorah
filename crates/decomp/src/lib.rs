//! The decompiler core of ghidorah (design Section 8, ADR-0010).
//!
//! The crate is a pure core crate. It does no I/O and reads no clock.
//! It turns the L1 form of a function into a structured statement tree over an expression
//! view. The C printer, the self-check and the cache of WP-23 read the result.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`expr`] | [`Expr`], [`Stmt`] and [`Call`]: the expression view | Section 8.2 |
//! | [`view`] | [`View`] and [`view::build`]: the view of an L1 form, its variables and its shape | Section 8.2 |
//! | [`shape`] | [`Shape`]: the CFG that the structurer reads | Section 8.1 |
//! | [`tree`] | [`Tree`] and [`Cond`]: the structured statement tree | Section 8.1 |
//! | [`structure`] | [`structure::run`]: Phoenix-lite post-order collapse | Section 8.1 |
//! | [`flat`] | [`flat::tree`]: the FLAT output | Section 8.6 |
//! | [`sailr`] | The SAILR-lite passes: canary removal, per-call-site noreturn, tail calls | Section 8.2 |
//! | [`interp_ast`] | The CFG walker and the AST interpreter: block traces and values | Sections 8.2, 13.4 |
//! | `fold` | Safe folding: the fold plan of each block | Section 8.2 |
//! | `vars`, `vars_names` | Out-of-SSA variables with storage-based identity | Section 8.2 |
//! | `schemas`, `loops` | The acyclic and cyclic schemas of the structurer | Section 8.1 |
//!
//! [`decompile`] runs the steps in order: the L1 form, the view (with safe folding and the
//! out-of-SSA variables), the SAILR-lite passes and the structurer.

pub mod expr;
pub mod flat;
mod fold;
pub mod interp_ast;
mod loops;
pub mod sailr;
mod schemas;
pub mod shape;
pub mod structure;
pub mod tree;
mod vars;
mod vars_names;
pub mod view;

use std::fmt;

use ghidorah_analysis::cc::conv_of;
use ghidorah_analysis::fir::Opts as FirOpts;
use ghidorah_analysis::fir::l1::{self, L1Error, L1Ir};
use ghidorah_base::{Address, Fuel, FuncId, WarningCode};
use ghidorah_db::Program;
use ghidorah_ir::Switches;

pub use expr::{Call, Callee, Expr, Stmt, VarIdx};
pub use shape::{Exit, NodeKind, Shape, ShapeNode};
pub use structure::{FlatReason, Mode};
pub use tree::{Arm, Cond, LoopKind, Tree};
pub use view::{Env, Input, NoEnv, NodeView, Var, VarKind, View, ViewError};

/// The default largest count of blocks that the structurer takes.
pub const DEFAULT_MAX_NODES: usize = 500;

/// The switches of the decompiler passes (`passes` in `decomp_opts`).
#[expect(
    clippy::struct_excessive_bools,
    reason = "one switch for each pass of decomp_opts"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Passes {
    /// Safe folding of single-use values into their use.
    pub fold: bool,
    /// The SAILR-lite group. The per-call-site noreturn pass needs only this switch.
    pub sailr: bool,
    /// Stack-canary removal. It needs `sailr` too.
    pub canary: bool,
    /// Tail calls as `return f(..);`. It needs `sailr` too.
    pub tailcall: bool,
}

impl Passes {
    /// Every pass on.
    pub const ALL: Self = Self {
        fold: true,
        sailr: true,
        canary: true,
        tailcall: true,
    };

    /// Every pass off.
    pub const NONE: Self = Self {
        fold: false,
        sailr: false,
        canary: false,
        tailcall: false,
    };
}

impl Default for Passes {
    fn default() -> Self {
        Self::ALL
    }
}

/// The options of a decompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Opts {
    /// The largest count of blocks that the structurer takes. Above it, the output is FLAT.
    pub max_nodes: usize,
    /// The pass switches.
    pub passes: Passes,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            passes: Passes::ALL,
        }
    }
}

/// The reason of an [`Elided`] range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElideReason {
    /// The stack-canary load, check and failure call.
    Canary,
    /// A block that no run from the entry reaches.
    Unreachable,
}

impl ElideReason {
    /// Gives the reason text, for example `stack canary`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Canary => "stack canary",
            Self::Unreachable => "unreachable",
        }
    }
}

/// A range of instructions that the output leaves out, with its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Elided {
    /// The address of the first instruction.
    pub start: u64,
    /// The size in bytes.
    pub size: u64,
    /// The reason.
    pub reason: ElideReason,
}

/// A warning of a decompile, at an instruction address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Warning {
    /// The code.
    pub code: WarningCode,
    /// The address.
    pub at: u64,
}

/// The result of a decompile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decomp {
    /// The expression view, its variables and its shape.
    pub view: View,
    /// The statement tree over the shape nodes.
    pub tree: Tree,
    /// The output mode: structured, or FLAT with its reason.
    pub mode: Mode,
    /// The instruction ranges that the output leaves out, in address order.
    pub elided: Vec<Elided>,
    /// The warnings in address order.
    pub warnings: Vec<Warning>,
}

/// The error of a decompile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompError {
    /// The L1 form does not build.
    L1(L1Error),
    /// The view does not build.
    View(ViewError),
}

impl fmt::Display for DecompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::L1(e) => write!(f, "The decompile has no L1 form: {e}"),
            Self::View(e) => write!(f, "The decompile has no view: {e}"),
        }
    }
}

impl std::error::Error for DecompError {}

impl From<L1Error> for DecompError {
    fn from(e: L1Error) -> Self {
        Self::L1(e)
    }
}

impl From<ViewError> for DecompError {
    fn from(e: ViewError) -> Self {
        Self::View(e)
    }
}

/// The facts of a program that a decompile reads: callee names, noreturn flags and strings.
#[derive(Debug, Clone, Copy)]
pub struct ProgramEnv<'a>(pub &'a Program);

impl Env for ProgramEnv<'_> {
    fn callee_name(&self, addr: u64) -> Option<String> {
        let at = Address::ram(addr);
        if let Some(name) = self
            .0
            .imports()
            .values()
            .find(|r| r.stub == Some(at))
            .and_then(|r| r.id.name())
        {
            return Some(name.to_owned());
        }
        self.0.name(at).map(|n| n.text)
    }

    fn is_noreturn(&self, addr: u64) -> bool {
        self.0
            .func(FuncId(Address::ram(addr)))
            .and_then(|f| f.noreturn)
            .is_some_and(|n| n.value)
    }

    fn is_string(&self, addr: u64) -> bool {
        self.0.string(addr).is_some()
    }
}

/// Decompiles the published function `id` of `program`.
///
/// The L1 build, the view and the structurer take their work from `fuel`. The structurer
/// gives FLAT output when the fuel runs out.
///
/// # Errors
///
/// Returns [`DecompError::L1`] when the L1 form does not build, and [`DecompError::View`]
/// when the view does not build.
pub fn decompile(
    program: &Program,
    id: FuncId,
    opts: &Opts,
    fuel: &mut Fuel,
) -> Result<Decomp, DecompError> {
    let ir = l1::build(program, id, &FirOpts::DEFAULT, &Switches::all(), fuel)?;
    from_l1(
        &ir,
        &ProgramEnv(program),
        Some(conv_of(program)),
        opts,
        fuel,
    )
}

/// Decompiles the L1 form `ir` of a function.
///
/// # Errors
///
/// Returns [`DecompError::View`] when the view does not build.
pub fn from_l1(
    ir: &L1Ir,
    env: &dyn Env,
    conv: Option<&ghidorah_types::CallConv>,
    opts: &Opts,
    fuel: &mut Fuel,
) -> Result<Decomp, DecompError> {
    let input = Input {
        ssa: &ir.ssa,
        l0: &ir.l0.arena,
        tail_calls: &ir.tail_calls,
        conv,
    };
    from_input(&input, env, opts, fuel)
}

/// Decompiles an L1 form with its L0 arena.
///
/// # Errors
///
/// Returns [`DecompError::View`] when the view does not build.
pub fn from_input(
    input: &Input<'_>,
    env: &dyn Env,
    opts: &Opts,
    fuel: &mut Fuel,
) -> Result<Decomp, DecompError> {
    let built = view::build(input, env, opts.passes.fold, fuel)?;
    let mut view = built.view;
    let mut elided = built.elided;
    let mut warnings = built.warnings;
    let found = sailr::run(&mut view, env, &opts.passes);
    elided.extend(found.elided);
    warnings.extend(found.warnings);
    let out = structure::run(
        &view.shape,
        &structure::Opts {
            max_nodes: opts.max_nodes,
        },
        fuel,
    );
    if let Mode::Flat(reason) = out.mode
        && reason.is_budget()
    {
        warnings.push(Warning {
            code: WarningCode::BudgetFlat,
            at: view.entry,
        });
    }
    elided.sort_unstable();
    elided.dedup();
    warnings.sort_unstable();
    warnings.dedup();
    Ok(Decomp {
        view,
        tree: out.tree,
        mode: out.mode,
        elided,
        warnings,
    })
}
