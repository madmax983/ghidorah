//! The facts of a program for the printer: [`PrintEnv`] for [`ProgramEnv`].

use crate::ProgramEnv;
use crate::print::PrintEnv;

impl PrintEnv for ProgramEnv<'_> {}
