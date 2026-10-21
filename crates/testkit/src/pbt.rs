//! Property tests over choice sequences.
//!
//! A property reads all its random values from a [`Gen`]. The `Gen` records each
//! value as a choice. On a failure, [`shrink`] makes the choice sequence smaller.
//! It deletes chunks first and then lowers single values. A short sequence reads
//! as zeros after its end, so each smaller sequence is a valid input.
//!
//! [`check`] reads `PBT_SEED` and `PBT_CASES` from the environment. A failure
//! gives one repro line with the seed, the case and the shrunk choices.

mod shrink;

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::rng::{Rng, Xoshiro256ss, below, fnv1a64};

/// The largest number of choices that one case can record.
pub const MAX_CHOICES: usize = 65_536;

/// The default number of property runs that one shrink can use.
pub const DEFAULT_SHRINK_BUDGET: u32 = 10_000;

/// The largest number of choices that a repro line shows.
const REPRO_CHOICES: usize = 64;

/// Edge values that [`Gen::u64`] draws more often.
const EDGES: [u64; 12] = [
    0,
    1,
    2,
    0xff,
    0x100,
    0xffff,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    u64::MAX - 1,
    u64::MAX,
];

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

    /// Reads the next choice. `bound == 0` allows any value, else the value is below `bound`.
    ///
    /// A replayed value above the bound reads as the largest allowed value.
    fn choice(&mut self, bound: u64, make: impl FnOnce(&mut Xoshiro256ss) -> u64) -> u64 {
        let clamp = |v: u64| if bound == 0 { v } else { v.min(bound - 1) };
        if let Some(&v) = self.choices.get(self.pos) {
            self.pos += 1;
            return clamp(v);
        }
        let Some(rng) = self.rng.as_mut() else {
            return 0;
        };
        if self.choices.len() >= MAX_CHOICES {
            return 0;
        }
        let v = clamp(make(rng));
        self.choices.push(v);
        self.pos += 1;
        v
    }

    /// Draws a value in `0..n`. For `n == 0` the value can be any `u64`.
    pub fn draw(&mut self, n: u64) -> u64 {
        self.choice(n, |rng| {
            if n == 0 {
                rng.next_u64()
            } else {
                below(rng, n)
            }
        })
    }

    /// Draws any `u64`. Edge values (0, 1, `u64::MAX` and powers of two) come more often.
    pub fn u64(&mut self) -> u64 {
        self.choice(0, |rng| {
            if below(rng, 4) == 0 {
                let i = usize::try_from(below(rng, 12)).unwrap_or(0);
                EDGES.get(i).copied().unwrap_or(0)
            } else {
                rng.next_u64()
            }
        })
    }

    /// Draws any `u8`.
    pub fn u8(&mut self) -> u8 {
        u8::try_from(self.draw(256)).unwrap_or(u8::MAX)
    }

    /// Draws a boolean.
    pub fn bool(&mut self) -> bool {
        self.draw(2) == 1
    }

    /// Draws a continue flag for a sequence. A random flag is `true` 7 times in 8.
    pub fn more(&mut self) -> bool {
        self.choice(2, |rng| u64::from(below(rng, 8) != 0)) == 1
    }

    /// Draws a value in `lo..=hi`. When `lo > hi` the value is `lo`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if lo > hi {
            return lo;
        }
        let span = hi - lo;
        if span == u64::MAX {
            return self.draw(0);
        }
        lo + self.draw(span + 1)
    }

    /// Draws a byte vector of at most `max_len` bytes.
    pub fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        self.vec(max_len, Self::u8)
    }

    /// Draws a vector of at most `max_len` items. Each item comes from `item`.
    pub fn vec<T>(&mut self, max_len: usize, mut item: impl FnMut(&mut Self) -> T) -> Vec<T> {
        let mut out = Vec::new();
        while out.len() < max_len && self.more() {
            out.push(item(self));
        }
        out
    }

    /// Draws one item of `items`. An empty slice gives `None`.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let n = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let i = usize::try_from(self.draw(n)).unwrap_or(0);
        items.get(i)
    }
}

/// Returns the fixed seed of a property name: the FNV-1a hash of the name.
#[must_use]
pub fn name_seed(name: &str) -> u64 {
    fnv1a64(name.as_bytes())
}

/// Parses a decimal or `0x` hex number.
fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim();
    text.strip_prefix("0x").map_or_else(
        || text.parse().ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
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
        let seed = std::env::var("PBT_SEED")
            .ok()
            .and_then(|s| parse_number(&s))
            .unwrap_or_else(|| name_seed(name));
        let cases = std::env::var("PBT_CASES")
            .ok()
            .and_then(|s| parse_number(&s))
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(cases);
        Self {
            cases,
            seed,
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
        let shown: Vec<String> = self
            .choices
            .iter()
            .take(REPRO_CHOICES)
            .map(u64::to_string)
            .collect();
        let more = if self.choices.len() > REPRO_CHOICES {
            ", .."
        } else {
            ""
        };
        let message = self.message.replace(['\n', '\r'], " ");
        format!(
            "pbt property {} failed at case {} (PBT_SEED=0x{:016x}): {}; shrunk choices: [{}{}]",
            self.name,
            self.case,
            self.seed,
            message,
            shown.join(", "),
            more
        )
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.repro())
    }
}

impl std::error::Error for Failure {}

/// Returns the text of a panic payload.
pub(crate) fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(ToString::to_string)
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panic with a payload that is not text".to_string())
}

/// Runs `prop` once and turns a panic into an error.
fn eval<P>(prop: &P, g: &mut Gen) -> Result<(), String>
where
    P: Fn(&mut Gen) -> Result<(), String>,
{
    match catch_unwind(AssertUnwindSafe(|| prop(g))) {
        Ok(result) => result,
        Err(payload) => Err(format!("panic: {}", panic_text(payload.as_ref()))),
    }
}

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
    let mut seeder = Xoshiro256ss::seed_from_u64(config.seed);
    for case in 0..config.cases {
        let mut g = Gen::random(seeder.next_u64());
        if let Err(first) = eval(&prop, &mut g) {
            let shrunk = shrink_with_budget(g.choices(), config.shrink_budget, |c| {
                eval(&prop, &mut Gen::replay(c.to_vec())).is_err()
            });
            let message = eval(&prop, &mut Gen::replay(shrunk.clone()))
                .err()
                .unwrap_or(first);
            return Err(Failure {
                name: name.to_string(),
                seed: config.seed,
                case,
                choices: shrunk,
                message,
            });
        }
    }
    Ok(config.cases)
}

/// Runs `prop` for `cases` cases with the settings of [`Config::from_env`].
///
/// # Panics
///
/// Panics with the repro line when a case fails. This fails the calling test.
#[allow(
    clippy::panic,
    reason = "a property failure must fail the calling test"
)]
pub fn check<P>(name: &str, cases: u32, prop: P)
where
    P: Fn(&mut Gen) -> Result<(), String>,
{
    if let Err(failure) = run(name, &Config::from_env(name, cases), prop) {
        panic!("{}", failure.repro());
    }
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
    shrink::run(choices, budget, fails)
}

/// Shrinks a failing byte input with the default budget.
pub fn shrink_bytes<F>(input: &[u8], mut fails: F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    let wide: Vec<u64> = input.iter().map(|&b| u64::from(b)).collect();
    let to_bytes = |c: &[u64]| -> Vec<u8> {
        c.iter()
            .map(|&v| u8::try_from(v).unwrap_or(u8::MAX))
            .collect()
    };
    let shrunk = shrink::run(&wide, DEFAULT_SHRINK_BUDGET, |c| fails(&to_bytes(c)));
    to_bytes(&shrunk)
}
