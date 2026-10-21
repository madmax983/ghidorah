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
//! | [`selfcheck`] | The self-check: 8 branch oracles over the tree and the CFG | Section 8.2 |
//! | [`lattice`] | The minimal type lattice and the field names of typed pointers | Section 8.4 |
//! | [`precedence`] | The C operator precedence numbers | Section 8.3 |
//! | [`print`](mod@print) | [`print::print`]: the C printer with the ops of each line | Section 8.3 |
//! | [`linemap`] | The line map and the coverage of each instruction | Section 8.3 |
//! | [`window`] | [`Window`]: line windows | Section 8.3 |
//! | [`metrics`], [`warnings`] | The metrics and the warning rows with their remedies | Section 8.5 |
//! | [`cache`] | [`Cache`]: the decompile cache by function epoch | Section 8.5 |
//!
//! [`decompile`] runs the steps in order: the L1 form, the view (with safe folding and the
//! out-of-SSA variables), the SAILR-lite passes and the structurer. [`render`] then runs the
//! self-check, the type lattice, the printer and the line map, and gives an [`Output`].

pub mod cache;
pub mod expr;
pub mod flat;
mod fold;
pub mod interp_ast;
pub mod lattice;
pub mod linemap;
mod loops;
pub mod metrics;
pub mod precedence;
pub mod print;
pub mod sailr;
mod schemas;
pub mod selfcheck;
pub mod shape;
pub mod structure;
pub mod tree;
mod vars;
mod vars_names;
pub mod view;
pub mod warnings;
pub mod window;

use std::fmt;

use ghidorah_analysis::cc::conv_of;
use ghidorah_analysis::fir::Opts as FirOpts;
use ghidorah_analysis::fir::callsite::Memo;
use ghidorah_analysis::fir::l1::{self, L1Error, L1Ir};
use ghidorah_base::{Address, Fuel, FuncId, JumpTableId, WarningCode};
use ghidorah_db::Program;
use ghidorah_ir::{IntrinsicNames, Switches};

pub use cache::{Cache, Key};
pub use expr::{Call, Callee, Expr, Stmt, VarIdx};
pub use metrics::Metrics;
pub use print::{CallRow, CallTarget, Line, LineKind, PrintEnv, Signature, VarRow};
pub use selfcheck::Validation;
pub use shape::{Exit, NodeKind, Shape, ShapeNode};
pub use structure::{FlatReason, Mode};
pub use tree::{Arm, Cond, LoopKind, Tree};
pub use view::{Env, Input, NoEnv, NodeView, ParamInfo, Var, VarKind, View, ViewError};
pub use warnings::{Remedy, WarningRow};
pub use window::Window;

/// The default largest count of blocks that the structurer takes.
pub const DEFAULT_MAX_NODES: usize = 500;

/// The fuel of the parameter recovery of one function.
const PARAM_FUEL: u64 = 1_000_000;

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
    /// A jump at the end of a block. The structure of the text shows it.
    Flow,
    /// An instruction of a reachable block with no effect that a line must show, for example
    /// a push of a callee-saved register. See [`linemap`] for the effects.
    NoEffect,
    /// An instruction of the body outside every block, for example alignment bytes.
    Padding,
}

impl ElideReason {
    /// Gives the reason text, for example `stack canary`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Canary => "stack canary",
            Self::Unreachable => "unreachable",
            Self::Flow => "control flow",
            Self::NoEffect => "no effect",
            Self::Padding => "padding",
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

impl ProgramEnv<'_> {
    /// Gives the parameter facts of the function at `addr` with a fresh memo and fuel tank.
    fn param_facts(self, addr: u64) -> Option<ghidorah_analysis::fir::callsite::ParamFacts> {
        let mut fuel = Fuel::new(PARAM_FUEL);
        cache::param_facts(self.0, addr, &mut Memo::default(), &mut fuel)
    }
}

impl Env for ProgramEnv<'_> {
    fn callee_name(&self, addr: u64) -> Option<String> {
        let at = Address::ram(addr);
        if let Some(name) = self
            .0
            .imports()
            .values()
            .find(|r| r.stub == Some(at) || (r.stub.is_none() && r.slot == Some(at)))
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

    fn is_thunk(&self, entry: u64) -> bool {
        self.0
            .func(FuncId(Address::ram(entry)))
            .is_some_and(|f| f.func.flags.thunk)
    }

    fn import_at_slot(&self, slot: u64) -> Option<u64> {
        let at = Address::ram(slot);
        let row = self.0.imports().values().find(|r| r.slot == Some(at))?;
        Some(row.stub.unwrap_or(at).off)
    }

    fn param_count(&self, addr: u64) -> Option<u8> {
        cache::slot_count(self.0, &self.param_facts(addr)?)
    }

    fn param_slots(&self, addr: u64) -> Option<Vec<ghidorah_ir::Loc>> {
        cache::param_slots(self.0, &self.param_facts(addr)?)
    }

    fn param_info(&self, addr: u64) -> Option<ParamInfo> {
        cache::param_info(self.0, &self.param_facts(addr)?)
    }

    fn jumptable_unresolved(&self, site: u64) -> bool {
        let at = Address::ram(site);
        let Some(owner) = self.0.owner_of(at).and_then(|f| self.0.func(f)) else {
            return false;
        };
        if owner.func.flags.thunk {
            return false;
        }
        let table = self
            .0
            .jump_table(JumpTableId(at))
            .is_some_and(|t| !t.value.resolved);
        table
            || owner
                .func
                .caveats
                .iter()
                .any(|c| c.code == WarningCode::JumptableUnresolved && c.at == Some(at))
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
    let env = cache::RenderEnv::new(program, fuel);
    let out = decompile_in(program, id, opts, &env, fuel);
    env.charge(fuel);
    out
}

/// Decompiles like [`decompile`] with the facts of `env`. The L1 build and the view share the
/// solve memo of `env`.
fn decompile_in(
    program: &Program,
    id: FuncId,
    opts: &Opts,
    env: &cache::RenderEnv<'_>,
    fuel: &mut Fuel,
) -> Result<Decomp, DecompError> {
    let switches = Switches::all();
    let ir = l1::build_in(
        program,
        id,
        &FirOpts::DEFAULT,
        &switches,
        &mut env.memo(),
        fuel,
    )?;
    from_l1(&ir, env, Some(conv_of(program)), opts, fuel)
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
        guards: &ir.guards,
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

/// The printed result of a decompile (design Section 8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The entry address of the function.
    pub entry: u64,
    /// The name of the function in the text.
    pub name: String,
    /// The lines of the full text.
    pub lines: Vec<Line>,
    /// The instruction ranges that no line shows, with their reasons, in address order.
    pub elided: Vec<Elided>,
    /// The variables that the text names.
    pub vars: Vec<VarRow>,
    /// The warnings in output order.
    pub warnings: Vec<WarningRow>,
    /// The metrics.
    pub metrics: Metrics,
}

impl Output {
    /// Gives the window of `count` lines from the line `start` (from 1).
    #[must_use]
    pub fn window(&self, start: usize, count: usize) -> Window<'_> {
        Window::new(self, start, count)
    }

    /// Gives the full text: each line with a newline after it.
    #[must_use]
    pub fn text(&self) -> String {
        self.window(1, self.lines.len()).text()
    }
}

/// Decompiles and prints the published function `id` of `program`. `names` gives the names
/// of the intrinsic instructions.
///
/// # Errors
///
/// Returns the [`DecompError`] of [`decompile`].
pub fn render(
    program: &Program,
    id: FuncId,
    opts: &Opts,
    names: &dyn IntrinsicNames,
    fuel: &mut Fuel,
) -> Result<Output, DecompError> {
    let env = cache::RenderEnv::new(program, fuel);
    let decomp = decompile_in(program, id, opts, &env, fuel);
    let out = decomp.map(|d| {
        let name = env.callee_name(id.0.off).unwrap_or_default();
        let body = print::body_units(program, id);
        finish(d, &env, names, &name, &body)
    });
    env.charge(fuel);
    out
}

/// Runs the self-check, the printer and the line map on `decomp`. `name` is the name of the
/// function, and `body` holds the address and the length of each instruction of its body.
#[must_use]
pub fn finish(
    mut decomp: Decomp,
    env: &dyn PrintEnv,
    names: &dyn IntrinsicNames,
    name: &str,
    body: &[(u64, u8)],
) -> Output {
    let validation = selfcheck::check(&mut decomp);
    let printed = print::print(&decomp, env, names, name);
    let mut elided = decomp.elided.clone();
    let flow = print::flow_addrs(&decomp.view);
    let dropped = linemap::cover(
        &printed.lines,
        &decomp.view.insns,
        &flow,
        &decomp.view.effects,
        body,
        &mut elided,
    );
    let elided = linemap::merge(elided);
    let mut all = decomp.warnings.clone();
    all.extend(printed.warnings);
    all.extend(dropped);
    Output {
        entry: decomp.view.entry,
        name: name.to_owned(),
        metrics: metrics::measure(&printed.lines, decomp.mode, validation),
        warnings: warnings::rows(&all, &decomp.view),
        lines: printed.lines,
        elided,
        vars: printed.vars,
    }
}

/// The L1 form of a function as text rows (design Section 6.4, `ir_opts.level: l1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1Rows {
    /// One row for each address in address order: the texts of its live ops in run order.
    /// The phis of a block are at the address of the block.
    pub rows: Vec<(u64, Vec<String>)>,
    /// `true` when an op is an `Intrinsic`.
    pub intrinsic: bool,
    /// The lifter version.
    pub lift_ver: u32,
}

/// Gives the text rows of the L1 form of the published function `id`. Each text is the op ID
/// and the op, with the phi arguments.
///
/// # Errors
///
/// Returns [`DecompError::L1`] when the L1 form does not build.
pub fn l1_rows(
    program: &Program,
    id: FuncId,
    names: &dyn IntrinsicNames,
    fuel: &mut Fuel,
) -> Result<L1Rows, DecompError> {
    let ir = l1::build(program, id, &FirOpts::DEFAULT, &Switches::all(), fuel)?;
    let arena = ir.ssa.arena();
    let mut by_addr: std::collections::BTreeMap<u64, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut intrinsic = false;
    for i in ir.ssa.order() {
        let Some(op) = arena.op(i) else {
            continue;
        };
        if op.opc == ghidorah_ir::Opc::Nop {
            continue;
        }
        intrinsic |= op.opc == ghidorah_ir::Opc::Intrinsic;
        let text = ghidorah_ir::print::op_text(arena, op, names);
        by_addr
            .entry(op.id.addr)
            .or_default()
            .push(format!("{} {text}", op.id));
    }
    Ok(L1Rows {
        rows: by_addr.into_iter().collect(),
        intrinsic,
        lift_ver: ir.l0.lift_ver,
    })
}
