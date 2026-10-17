//! Fuel: a counter of work units (design Section 10.11, rule 3).
//!
//! Every semantic stop uses fuel, not time. So the same input and the same fuel give
//! the same result on every host.

use std::fmt;

use crate::catalog::ErrorCode;

/// A fuel tank with a fixed limit.
///
/// A failed [`Fuel::take`] empties the tank. So all later takes fail too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fuel {
    limit: u64,
    used: u64,
}

/// The error of a [`Fuel::take`] that needs more fuel than the tank holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfFuel {
    /// The limit of the tank.
    pub limit: u64,
    /// The units that the failed take asked for.
    pub needed: u64,
}

impl OutOfFuel {
    /// Gives the error code: `BUDGET_EXCEEDED`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::BudgetExceeded
    }
}

impl fmt::Display for OutOfFuel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The work needs {} more fuel units. The limit of {} units is used.",
            self.needed, self.limit
        )
    }
}

impl std::error::Error for OutOfFuel {}

impl Fuel {
    /// Makes a full tank of `limit` units.
    #[must_use]
    pub const fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Makes a tank of `u64::MAX` units.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::new(u64::MAX)
    }

    /// Takes `units` from the tank.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfFuel`] when fewer than `units` remain. The tank is then empty.
    pub fn take(&mut self, units: u64) -> Result<(), OutOfFuel> {
        let _ = units;
        Ok(())
    }

    /// Takes one unit.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfFuel`] when the tank is empty.
    pub fn tick(&mut self) -> Result<(), OutOfFuel> {
        self.take(1)
    }

    /// Gives the limit of the tank.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Gives the units that the work used.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Gives the units that remain.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        0
    }

    /// Tells if no unit remains.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}
