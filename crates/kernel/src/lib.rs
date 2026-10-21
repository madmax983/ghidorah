#![cfg_attr(verus_only, feature(proc_macro_hygiene))]
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
//! Verus-verified leaf crate of ghidorah (ADR-0011, design Section 13.1).
//!
//! Plain builds take the stub attributes of `ghidorah-spec`. Verus builds take `vstd`.
//! So the verified code is the shipped code. `cargo xtask verify` runs the proofs.
//!
//! | Kernel | Module | Exec items |
//! |---|---|---|
//! | K1 Reader | [`reader`] | [`Reader`]: fixed-width reads, LEB128, C strings, `take`, `skip`, `seek` |
//! | K2 Range math | [`range`] | [`range_last`], [`Range`], [`va_to_file`] |
//! | K3 `RangeSet` | [`rangeset`] | [`RangeSet`]: `contains`, `find`, `insert`, `remove`, set operations |
//! | K5 Flag fusion | [`flags`] | [`fused_pred`], [`eval_pred`], [`fused_rhs`] and the `Sub`, `Add` and `Logic` flags |
//! | K6 Budget fit | [`budget`] | [`fit_prefix`] |
//! | K7 Provenance | [`source`] | [`may_overwrite`] |
//!
//! The crate denies `indexing_slicing` and `arithmetic_side_effects`.
//! Each exception names the reason "bound proved by Verus".

pub mod budget;
pub mod flags;
pub mod range;
pub mod rangeset;
pub mod reader;
pub mod source;

pub use budget::fit_prefix;
pub use flags::{FuseOp, Pred, eval_pred, fused_pred, fused_rhs};
pub use range::{Mapping, Range, range_last, va_to_file};
pub use rangeset::RangeSet;
pub use reader::{Endian, ReadError, Reader};
pub use source::may_overwrite;
