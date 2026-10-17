//! The run configuration and the process environment (design Section 10.11, ADR-0012).
//!
//! The binary reads each `GHIDORAH_*` variable once into [`RunConfig`]. Other code gets
//! [`RunConfig`] and a [`Clock`] as arguments. No code changes the process environment.
//!
//! | Variable | Field | Values |
//! |---|---|---|
//! | `GHIDORAH_FIXED_TIME` | [`RunConfig::fixed_time`] | Milliseconds since the Unix epoch, in decimal |
//! | `GHIDORAH_EVAL` | [`RunConfig::eval_mode`] | `1` (on) or `0` (off) |

use std::fmt;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ghidorah_base::{Clock, FixedClock};
use ghidorah_json::Value;

/// The variable of [`RunConfig::fixed_time`].
pub const FIXED_TIME_VAR: &str = "GHIDORAH_FIXED_TIME";

/// The variable of [`RunConfig::eval_mode`].
pub const EVAL_VAR: &str = "GHIDORAH_EVAL";

/// The settings that make a run deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunConfig {
    /// The fixed wall-clock time in milliseconds since the Unix epoch, or `None`.
    ///
    /// With a fixed time, the clock never moves. So recorded durations are 0.
    pub fixed_time: Option<u64>,
    /// `true` turns the time guards off for the evaluation harness.
    pub eval_mode: bool,
}

impl RunConfig {
    /// Reads the run configuration from the variables that `lookup` gives.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError`] when a variable has a value that does not parse.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, EnvError> {
        let _ = lookup;
        Ok(Self::default())
    }

    /// Gives the clock of the run: a [`FixedClock`] with a fixed time, else a [`SystemClock`].
    #[must_use]
    pub fn clock(&self) -> Box<dyn Clock + Send> {
        match self.fixed_time {
            Some(ms) => Box::new(FixedClock::new(ms)),
            None => Box::new(SystemClock::new()),
        }
    }

    /// Gives the JSON form `{ fixed_time, eval_mode }`. A missing time is `null`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

/// A variable with a value that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvError {
    /// The variable name.
    pub var: &'static str,
    /// The value, cut to 64 characters.
    pub value: String,
    /// The values that the variable accepts.
    pub expected: &'static str,
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The variable {} has the value {:?}, which is not valid. Set it to {}.",
            self.var, self.value, self.expected
        )
    }
}

impl std::error::Error for EnvError {}

/// The system clock: wall-clock time from [`SystemTime`] and monotonic time from [`Instant`].
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// Makes a clock whose monotonic time starts now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// The parts of the process environment that the command line uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    /// The run configuration.
    pub run: RunConfig,
    /// The current directory. Relative paths of the command line start here.
    pub cwd: PathBuf,
    /// The value of `HOME`, or `None`.
    pub home: Option<PathBuf>,
    /// The value of `XDG_DATA_HOME`, or `None`.
    pub xdg_data_home: Option<PathBuf>,
}

impl Env {
    /// Makes an environment with `cwd`, a default [`RunConfig`] and no `HOME`.
    #[must_use]
    pub const fn new(cwd: PathBuf) -> Self {
        Self {
            run: RunConfig {
                fixed_time: None,
                eval_mode: false,
            },
            cwd,
            home: None,
            xdg_data_home: None,
        }
    }

    /// Reads the environment from the variables that `lookup` gives.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError`] when a `GHIDORAH_*` variable does not parse.
    pub fn from_lookup(
        cwd: PathBuf,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, EnvError> {
        let non_empty = |name: &str| lookup(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        Ok(Self {
            run: RunConfig::from_lookup(lookup)?,
            cwd,
            home: non_empty("HOME"),
            xdg_data_home: non_empty("XDG_DATA_HOME"),
        })
    }

    /// Gives the default projects root (design Section 3.10).
    ///
    /// The root is `$XDG_DATA_HOME/ghidorah/projects`, else
    /// `$HOME/.local/share/ghidorah/projects`, else `None`.
    #[must_use]
    pub fn projects_root(&self) -> Option<PathBuf> {
        None
    }
}
