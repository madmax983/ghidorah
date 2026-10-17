//! The clock seam (design Section 10.11, rule 4, ADR-0012).
//!
//! Time comes from an injected [`Clock`]. This crate reads no system clock.
//! The `cli` crate gives the system clock. Tests and `RunConfig.fixed_time` use [`FixedClock`].

use std::cell::Cell;

/// A source of time.
pub trait Clock {
    /// Gives the wall-clock time in milliseconds since the Unix epoch.
    fn unix_ms(&self) -> u64;

    /// Gives a monotonic time in milliseconds from a start that the clock selects.
    ///
    /// Only `max_ms` guards use it. Output never holds it.
    fn monotonic_ms(&self) -> u64;
}

/// A clock that always gives the same time. Its monotonic time stays at 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    unix_ms: u64,
}

impl FixedClock {
    /// Makes a clock that always gives `unix_ms`.
    #[must_use]
    pub const fn new(unix_ms: u64) -> Self {
        Self { unix_ms }
    }
}

impl Clock for FixedClock {
    fn unix_ms(&self) -> u64 {
        self.unix_ms
    }

    fn monotonic_ms(&self) -> u64 {
        0
    }
}

/// A test clock that moves only when the test moves it.
#[derive(Debug, Default)]
pub struct ManualClock {
    unix_ms: Cell<u64>,
    monotonic_ms: Cell<u64>,
}

impl ManualClock {
    /// Makes a clock at `unix_ms` with a monotonic time of 0.
    #[must_use]
    pub const fn new(unix_ms: u64) -> Self {
        Self {
            unix_ms: Cell::new(unix_ms),
            monotonic_ms: Cell::new(0),
        }
    }

    /// Moves both times forward by `ms`. A time at `u64::MAX` stays there.
    pub fn advance(&self, ms: u64) {
        self.unix_ms.set(self.unix_ms.get().saturating_add(ms));
        self.monotonic_ms
            .set(self.monotonic_ms.get().saturating_add(ms));
    }
}

impl Clock for ManualClock {
    fn unix_ms(&self) -> u64 {
        self.unix_ms.get()
    }

    fn monotonic_ms(&self) -> u64 {
        self.monotonic_ms.get()
    }
}
