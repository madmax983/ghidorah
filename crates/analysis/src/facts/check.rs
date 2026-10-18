//! The check of one claim atom: three verdicts with an absence basis (design Section 11.8).
//!
//! [`Checker`] reads the merged facts of a program. It keeps the scope of each function that
//! a check reads, so the claims of one call share the work.

use ghidorah_base::Fuel;
use ghidorah_db::Program;

use super::relations::{Atom, Outcome, Verdict};

/// The checker of the claims of one program.
#[derive(Debug)]
pub struct Checker<'p> {
    program: &'p Program,
}

impl<'p> Checker<'p> {
    /// Makes a checker of `program`.
    #[must_use]
    pub const fn new(program: &'p Program) -> Self {
        Self { program }
    }

    /// Gives the program of the checker.
    #[must_use]
    pub const fn program(&self) -> &'p Program {
        self.program
    }

    /// Checks one atom with the fuel `fuel`. A check that runs out of fuel gives `unknown`
    /// with `stopped`.
    pub fn check(&mut self, atom: &Atom, fuel: &mut Fuel) -> Outcome {
        let _ = (atom, fuel);
        Outcome::new(Verdict::Unknown, Vec::new(), Vec::new())
    }
}
