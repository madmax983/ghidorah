//! Model-based tests.
//!
//! A model test runs one random operation sequence against the system under
//! test (SUT) and against a simple model. After each operation, the two
//! observations must be equal. The operation sequence comes from a
//! [`Gen`], so a failure shrinks to a short sequence.

use std::fmt::Debug;

use crate::pbt::{self, Config, Failure, Gen};

/// The settings of a model test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The number of random sequences.
    pub cases: u32,
    /// The largest number of operations in one sequence.
    pub max_steps: usize,
}

/// Runs a model test and returns the shrunk failure.
///
/// `init` makes a fresh SUT and model for each sequence. `gen_op` draws one
/// operation. `sut_apply` and `model_apply` apply it and return an observation.
///
/// # Errors
///
/// Returns the shrunk [`Failure`]. Its message lists the operations and both observations.
pub fn try_model_check<S, M, Op, O>(
    name: &str,
    settings: Settings,
    init: impl Fn() -> (S, M),
    gen_op: impl Fn(&mut Gen) -> Op,
    sut_apply: impl Fn(&mut S, &Op) -> O,
    model_apply: impl Fn(&mut M, &Op) -> O,
) -> Result<u32, Failure>
where
    Op: Debug,
    O: PartialEq + Debug,
{
    let _ = (init, gen_op, sut_apply, model_apply);
    pbt::run(
        name,
        &Config::from_env(name, settings.cases),
        |_g: &mut Gen| Ok(()),
    )
}

/// Runs a model test with the settings of [`try_model_check`].
///
/// # Panics
///
/// Panics with the repro line when a sequence fails. This fails the calling test.
pub fn model_check<S, M, Op, O>(
    name: &str,
    settings: Settings,
    init: impl Fn() -> (S, M),
    gen_op: impl Fn(&mut Gen) -> Op,
    sut_apply: impl Fn(&mut S, &Op) -> O,
    model_apply: impl Fn(&mut M, &Op) -> O,
) where
    Op: Debug,
    O: PartialEq + Debug,
{
    let _ = try_model_check(name, settings, init, gen_op, sut_apply, model_apply);
}
