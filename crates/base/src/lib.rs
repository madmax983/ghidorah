//! Base types of ghidorah.
//!
//! The crate is a pure core crate. It does no I/O and reads no clock.
//! It depends only on `ghidorah-kernel`.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`address`] | [`Address`] and [`SpaceId`] | Section 3.1 |
//! | [`interval`] | [`IntervalMap`] over the K2 range math | Section 3.2 |
//! | [`id`] | The ID newtypes, [`Id`] and the one ID parser | Section 3.5, ADR-0008 |
//! | [`addr_expr`] | The syntax of address input | Section 10.5, ADR-0007 |
//! | [`default_name`] | The computed default names `FUN_`, `LAB_`, `DAT_` and `EXT_` | Section 3.4 |
//! | [`catalog`] | The frozen [`ErrorCode`], [`WarningCode`] and [`DiagCode`] catalogs | Section 10.8, ADR-0002 |
//! | [`limits`] | [`Limits`] and [`bounded_vec`] | Section 4.7 |
//! | [`fuel`] | [`Fuel`], the counter of work units | Section 10.11 |
//! | [`sha256`](mod@sha256) | SHA-256 | Section 3.5 |
//! | [`fnv`] | FNV-1a with 64 bits | Section 7.13 |
//! | [`hex`] | Hex text | ADR-0007 |
//! | [`bintext`] | [`BinText`], the one carrier of binary text | Section 10.16, ADR-0022 |
//! | [`dym`] | [`did_you_mean`] | Section 10.5 |
//! | [`glob`] | [`Glob`] with linear work | Section 10.4 |
//! | [`clock`] | The [`Clock`] seam and [`FixedClock`] | Section 10.11, ADR-0012 |

pub mod addr_expr;
pub mod address;
pub mod bintext;
pub mod catalog;
pub mod clock;
pub mod default_name;
pub mod dym;
pub mod fnv;
pub mod fuel;
pub mod glob;
pub mod hex;
pub mod id;
pub mod interval;
pub mod limits;
pub mod sha256;
mod tables;

pub use addr_expr::{AddrExpr, AddrExprError};
pub use address::{Address, SpaceId};
pub use bintext::{BinText, Caps, Rendered};
pub use catalog::{CodeInfo, DiagCode, ErrorCode, RepairClass, Reserved, WarningCode};
pub use clock::{Clock, FixedClock, ManualClock};
pub use default_name::{DefaultKind, DefaultName};
pub use dym::{Suggestion, did_you_mean};
pub use fnv::{Fnv1a64, fnv1a64};
pub use fuel::{Fuel, OutOfFuel};
pub use ghidorah_kernel::Range;
/// The K6 budget fit rule. `ghidorah-tools` reaches the kernel through this crate (Section 2.2).
pub use ghidorah_kernel::fit_prefix;
pub use glob::{Glob, GlobError};
pub use id::{
    BinaryId, BlockId, ExportId, FileOffset, FuncId, Id, IdError, IdKind, ImportId, JumpTableId,
    NoteId, OpId, RefId, RegVar, Rev, SectionId, SegmentId, SetName, Storage, StringId, SymId,
    SyscallId, TxId, TypeRef, VarId,
};
pub use interval::{IntervalError, IntervalMap};
pub use limits::{Bound, Clamp, Limits, bounded_count, bounded_vec};
pub use sha256::{Sha256, sha256};
