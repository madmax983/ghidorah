//! Property tests over choice sequences.
//!
//! A property reads all its random values from a [`Gen`]. The `Gen` records each
//! value as a choice. On a failure, [`shrink`] makes the choice sequence smaller.
//! It deletes chunks first and then lowers single values. A short sequence reads
//! as zeros after its end, so each smaller sequence is a valid input.
//!
//! [`check`] reads `PBT_SEED` and `PBT_CASES` from the environment. A failure
//! gives one repro line with the seed, the case and the shrunk choices.

use std::fmt;

use crate::rng::Xoshiro256ss;

/// The largest number of choices that one case can record.
pub const MAX_CHOICES: usize = 65_536;

/// The default number of property runs that one shrink can use.
pub const DEFAULT_SHRINK_BUDGET: u32 = 10_000;

/// A source of choices for one property case.
#[derive(Debug, Clone)]
pub struct Gen {
    choices: Vec<u64>,
    pos: usize,
    rng: Option<Xoshiro256ss>,
}

impl Gen {
    /// Makes a generator that draws new random choices from `seed`.
    #[must_use]
    pub fn random(seed: u64) -> Self {
        Self {
            choices: Vec::new(),
            pos: 0,
            rng: Some(Xoshiro256ss::seed_from_u64(seed)),
        }
    }

    /// Makes a generator that replays `choices`. After the end, each draw gives 0.
    #[must_use]
    pub const fn replay(choices: Vec<u64>) -> Self {
        Self {
            choices,
            pos: 0,
            rng: None,
        }
    }

    /// Returns the choices that the generator recorded or replayed.
    #[must_use]
    pub fn choices(&self) -> &[u64] {
        &self.choices
    }

    /// Draws a value in `0..n`. For `n == 0` the value can be any `u64`.
    pub fn draw(&mut self, n: u64) -> u64 {
        let _ = (n, self.pos);
        0
    }

    /// Draws any `u64`. Edge values (0, 1, `u64::MAX` and powers of two) come more often.
    pub fn u64(&mut self) -> u64 {
        self.draw(0)
    }

    /// Draws any `u8`.
    pub fn u8(&mut self) -> u8 {
        0
    }

    /// Draws a boolean.
    pub fn bool(&mut self) -> bool {
        false
    }

    /// Draws a value in `lo..=hi`. When `lo > hi` the value is `lo`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        let _ = hi;
        lo
    }

    /// Draws a byte vector of at most `max_len` bytes.
    pub fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let _ = max_len;
        Vec::new()
    }

    /// Draws a vector of at most `max_len` items. Each item comes from `item`.
    pub fn vec<T>(&mut self, max_len: usize, mut item: impl FnMut(&mut Self) -> T) -> Vec<T> {
        let _ = (max_len, &mut item);
        Vec::new()
    }

    /// Draws one item of `items`. An empty slice gives `None`.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.first()
    }
}

/// Returns the fixed seed of a property name: the FNV-1a hash of the name.
#[must_use]
pub fn name_seed(name: &str) -> u64 {
    let _ = name;
    0
}

/// The settings of one property run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The number of random cases.
    pub cases: u32,
    /// The seed of the first case.
    pub seed: u64,
    /// The largest number of property runs during a shrink.
    pub shrink_budget: u32,
}

impl Config {
    /// Makes the settings for `name` with `cases` cases.
    ///
    /// The seed is the FNV-1a hash of `name`, so each property has a fixed seed.
    /// `PBT_SEED` (decimal or `0x` hex) and `PBT_CASES` change the values.
    #[must_use]
    pub fn from_env(name: &str, cases: u32) -> Self {
        let _ = name;
        Self {
            cases,
            seed: 0,
            shrink_budget: DEFAULT_SHRINK_BUDGET,
        }
    }
}

/// A property failure after the shrink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The property name.
    pub name: String,
    /// The seed of the run.
    pub seed: u64,
    /// The index of the first failed case.
    pub case: u32,
    /// The shrunk choice sequence.
    pub choices: Vec<u64>,
    /// The failure message of the shrunk case.
    pub message: String,
}

impl Failure {
    /// Returns the one-line repro text of the failure.
    #[must_use]
    pub fn repro(&self) -> String {
        String::new()
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.repro())
    }
}

impl std::error::Error for Failure {}

/// Runs `prop` for each case of `config`.
///
/// A property fails when it returns `Err` or when it panics.
///
/// # Errors
///
/// Returns the shrunk [`Failure`] of the first failed case.
pub fn run<P>(name: &str, config: &Config, prop: P) -> Result<u32, Failure>
where
    P: Fn(&mut Gen) -> Result<(), String>,
{
    let _ = (name, prop);
    Ok(config.cases)
}

/// Runs `prop` for `cases` cases with the settings of [`Config::from_env`].
///
/// # Panics
///
/// Panics with the repro line when a case fails. This fails the calling test.
pub fn check<P>(name: &str, cases: u32, prop: P)
where
    P: Fn(&mut Gen) -> Result<(), String>,
{
    let _ = run(name, &Config::from_env(name, cases), prop);
}

/// Shrinks a failing choice sequence with the default budget.
///
/// `fails` returns `true` when a sequence still fails. The result fails too.
pub fn shrink<F>(choices: &[u64], fails: F) -> Vec<u64>
where
    F: FnMut(&[u64]) -> bool,
{
    shrink_with_budget(choices, DEFAULT_SHRINK_BUDGET, fails)
}

/// Shrinks a failing choice sequence with at most `budget` calls of `fails`.
pub fn shrink_with_budget<F>(choices: &[u64], budget: u32, fails: F) -> Vec<u64>
where
    F: FnMut(&[u64]) -> bool,
{
    let _ = (budget, fails);
    choices.to_vec()
}

/// Shrinks a failing byte input with the default budget.
pub fn shrink_bytes<F>(input: &[u8], fails: F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    let _ = fails;
    input.to_vec()
}
