//! The L1 passes in fixed order, with switches (design Section 6.4).
//!
//! | Order | Pass | Effect |
//! |---|---|---|
//! | 1 | `fold` | An op with constant inputs becomes `Copy` of its constant result. |
//! | 2 | `fuse` | `Cond(cc, Flags(op, a, b, c))` becomes one compare through K5. |
//! | 3 | `copyprop` | A use of a `Copy` that keeps the value reads the input of the copy. |
//! | 4 | `sccp` | Wegman-Zadeck constants with two worklists. It removes the CFG edges that never run. |
//! | 5 | `cond_through_phi` | `Cond(cc, phi(f1, f2))` becomes a phi of the compares in the predecessors. |
//! | 6 | `materialize_flags` | Each other `Cond` becomes bit tests on the flags word. |
//! | 7 | `dce` | A worklist removes each pure op whose value no live op reads. |
//!
//! Each pass keeps the result of each L1 run: the stop, the step count, the memory and the
//! location uses of the stop op (AC-256). A pass first plans its changes with fuel. Then it
//! makes them. So a pass that runs out of fuel makes no change.
//!
//! The flags word of `materialize_flags` comes from the semantic module, so an undefined
//! flag has the value that [`x86_flags`](crate::sem::x86_flags) gives.

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::Fuel;

use crate::fuse::fuse;
use crate::interp::eval;
use crate::op::{Arg, Opc, Val};
use crate::ssa::{Ssa, SsaError, out_width};
use crate::{copyprop, dce, sccp};

mod flags;

/// One L1 pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pass {
    /// Constant folding.
    Fold,
    /// Flag fusion through K5.
    Fuse,
    /// Copy propagation.
    Copyprop,
    /// Sparse conditional constant propagation.
    Sccp,
    /// Conditions through flag phis.
    CondThroughPhi,
    /// Bit tests for the left-over flag reads.
    MaterializeFlags,
    /// Dead code removal.
    Dce,
}

impl Pass {
    /// Every pass in run order.
    pub const ALL: [Self; 7] = [
        Self::Fold,
        Self::Fuse,
        Self::Copyprop,
        Self::Sccp,
        Self::CondThroughPhi,
        Self::MaterializeFlags,
        Self::Dce,
    ];

    /// Gives the name of the pass, for example `copyprop`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fold => "fold",
            Self::Fuse => "fuse",
            Self::Copyprop => "copyprop",
            Self::Sccp => "sccp",
            Self::CondThroughPhi => "cond_through_phi",
            Self::MaterializeFlags => "materialize_flags",
            Self::Dce => "dce",
        }
    }

    /// Gives the pass with this name, or `None`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// Gives the position of the pass in run order.
    #[must_use]
    pub const fn position(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Pass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The switches of the passes. Each pass is on or off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Switches {
    on: [bool; 7],
}

impl Default for Switches {
    fn default() -> Self {
        Self::all()
    }
}

impl Switches {
    /// Gives the switches with every pass on.
    #[must_use]
    pub const fn all() -> Self {
        Self { on: [true; 7] }
    }

    /// Gives the switches with every pass off.
    #[must_use]
    pub const fn none() -> Self {
        Self { on: [false; 7] }
    }

    /// Gives the switches with `pass` set to `on`.
    #[must_use]
    pub fn with(mut self, pass: Pass, on: bool) -> Self {
        if let Some(slot) = self.on.get_mut(pass.position()) {
            *slot = on;
        }
        self
    }

    /// Tells if `pass` is on.
    #[must_use]
    pub fn is_on(&self, pass: Pass) -> bool {
        self.on.get(pass.position()).copied().unwrap_or(false)
    }
}

/// The result of one pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassRun {
    /// The pass.
    pub pass: Pass,
    /// The count of changes that the pass made.
    pub changes: u64,
}

/// The result of [`run`]: one row for each pass that ran, in run order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The rows.
    pub runs: Vec<PassRun>,
}

impl Report {
    /// Gives the change count of a pass, or `None` when the pass did not run.
    #[must_use]
    pub fn changes(&self, pass: Pass) -> Option<u64> {
        self.runs.iter().find(|r| r.pass == pass).map(|r| r.changes)
    }
}

/// Runs each pass that is on, in run order.
///
/// # Errors
///
/// Returns the first error of a pass. The passes before it keep their changes.
pub fn run(ssa: &mut Ssa, switches: &Switches, fuel: &mut Fuel) -> Result<Report, SsaError> {
    let mut report = Report::default();
    for pass in Pass::ALL.into_iter().filter(|p| switches.is_on(*p)) {
        let changes = run_pass(ssa, pass, fuel)?;
        report.runs.push(PassRun { pass, changes });
    }
    Ok(report)
}

/// Runs one pass. Gives the count of changes.
///
/// # Errors
///
/// Returns [`SsaError::OutOfFuel`] when the plan of the pass runs out of fuel, and
/// [`SsaError::SeqFull`] or [`SsaError::Full`] when the pass cannot add an op. Then the
/// pass makes no change.
pub fn run_pass(ssa: &mut Ssa, pass: Pass, fuel: &mut Fuel) -> Result<u64, SsaError> {
    match pass {
        Pass::Fold => fold(ssa, fuel),
        Pass::Fuse => fuse_conds(ssa, fuel),
        Pass::Copyprop => copyprop::run(ssa, fuel),
        Pass::Sccp => sccp::run(ssa, fuel),
        Pass::CondThroughPhi => flags::cond_through_phi(ssa, fuel),
        Pass::MaterializeFlags => flags::materialize(ssa, fuel),
        Pass::Dce => dce::run(ssa, fuel),
    }
}

/// Gives the constant of an argument: `Nil` is 0, and a value needs a known constant.
fn known_value(arg: Arg, known: &BTreeMap<Val, u128>) -> Option<u128> {
    match arg {
        Arg::Nil => Some(0),
        Arg::K(imm) => Some(u128::from(imm.get())),
        Arg::V(v) => known.get(&v).copied(),
        Arg::L(_) => None,
    }
}

/// The pass `fold`: each op with constant inputs becomes `Copy` of its result.
///
/// The walk follows the run order, so a def comes before its uses outside phis. A phi with
/// one constant on each argument gives that constant to its users. A result above 64 bits
/// stays an op, but its users can still fold. An input that `eval` rejects stays an op.
fn fold(ssa: &mut Ssa, fuel: &mut Fuel) -> Result<u64, SsaError> {
    let mut known: BTreeMap<Val, u128> = BTreeMap::new();
    let mut plan = Vec::new();
    for index in ssa.order() {
        fuel.tick()?;
        let Some(&op) = ssa.arena().op(index) else {
            continue;
        };
        let Some(out) = op.out else {
            continue;
        };
        if op.opc == Opc::Phi {
            let args = ssa.arena().phi_args(&op).unwrap_or_default();
            let values: Option<Vec<u128>> = args.iter().map(|&a| known_value(a, &known)).collect();
            if let Some(&first) = values.as_deref().and_then(<[u128]>::first)
                && values.iter().flatten().all(|&v| v == first)
            {
                known.insert(out, first);
            }
            continue;
        }
        let [Some(x), Some(y), Some(z)] = op.a.map(|a| known_value(a, &known)) else {
            continue;
        };
        let Ok(result) = eval(op.opc, op.w, op.sub, x, y, z) else {
            continue;
        };
        known.insert(out, result);
        let Ok(value) = u64::try_from(result) else {
            continue;
        };
        let w = out_width(&op);
        let folded = [Arg::k(value), Arg::Nil, Arg::Nil];
        if !(op.opc == Opc::Copy && op.w == w && op.a == folded) {
            plan.push((index, w, folded));
        }
    }
    for &(index, w, a) in &plan {
        ssa.set_op(index, Opc::Copy, w, 0, a);
    }
    Ok(u64::try_from(plan.len()).unwrap_or(u64::MAX))
}

/// The pass `fuse`: `Cond(cc, Flags(op, a, b, c))` becomes the compare of [`fuse`].
///
/// The compare takes the width of the `Flags` op, which must be 8, 16, 32 or 64 bits.
/// The walk looks through `Copy` ops that keep the value.
fn fuse_conds(ssa: &mut Ssa, fuel: &mut Fuel) -> Result<u64, SsaError> {
    let mut plan = Vec::new();
    for index in ssa.order() {
        fuel.tick()?;
        let Some(&op) = ssa.arena().op(index) else {
            continue;
        };
        let (Opc::Cond, Some(cc)) = (op.opc, op.cc()) else {
            continue;
        };
        let Arg::V(f) = ssa.root(op.a[0]) else {
            continue;
        };
        let Some(&thunk) = ssa.live_def(f) else {
            continue;
        };
        let Some(flag_op) = thunk
            .flag_op()
            .filter(|_| matches!(thunk.w, 8 | 16 | 32 | 64))
        else {
            continue;
        };
        let (a, b) = (ssa.root(thunk.a[0]), ssa.root(thunk.a[1]));
        if let Some((opc, x, y)) = fuse(flag_op, cc, a, b) {
            plan.push((index, opc, thunk.w, [x, y, Arg::Nil]));
        }
    }
    for &(index, opc, w, a) in &plan {
        ssa.set_op(index, opc, w, 0, a);
    }
    Ok(u64::try_from(plan.len()).unwrap_or(u64::MAX))
}
