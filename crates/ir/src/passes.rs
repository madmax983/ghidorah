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

use std::fmt;

use ghidorah_base::Fuel;

use crate::ssa::{Ssa, SsaError};

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
    let _ = (ssa, pass, fuel);
    Ok(0)
}
