//! The analyzers: one file per analyzer (design Section 7.1, ADR-0024).
//!
//! Each file exports its spec and its `run` function. [`crate::registry`] lists the specs.
//! The derived views `gaps`, `lang` and `metrics` read the committed facts and have no spec.
//! This module is a plain list of the analyzer files.

pub mod addrtaken;
pub mod calls;
pub mod dataptr;
pub mod disasm;
pub mod endbr;
pub mod entry;
pub mod fde;
pub mod gaps;
pub mod lang;
pub mod metrics;
pub mod noreturn;
pub mod refs;
pub mod strings;
pub mod stubs;
pub mod symbols;
