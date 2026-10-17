//! The analyzers: one file per analyzer (design Section 7.1, ADR-0024).
//!
//! Each file exports its spec and its `run` function. [`crate::registry`] lists the specs.
//! This module is a plain list of the analyzer files.

pub mod calls;
pub mod disasm;
pub mod endbr;
pub mod entry;
pub mod fde;
pub mod noreturn;
pub mod stubs;
pub mod symbols;
