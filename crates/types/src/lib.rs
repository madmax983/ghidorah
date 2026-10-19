#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
//! Types, prototypes and calling conventions of ghidorah (design Section 9).
//!
//! The crate is a pure core crate. It does no I/O and reads no clock.
//! It depends only on `ghidorah-base`. The data files are part of the crate source.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`ty`] | [`Type`], [`TypeId`], [`Prim`], [`Record`], [`Sig`] | Section 9.1 |
//! | [`store`] | [`TypeStore`] and [`StoreError`] | Section 9.1 |
//! | [`ctext`] | Canonical C text and [`TypeRef`](ghidorah_base::TypeRef) | Sections 3.5, 9.1 |
//! | [`model`] | [`DataModel`] and its presets [`DataModel::X86_64_SYSV`] and [`DataModel::X86_64_WIN`] | Section 9.1 |
//! | [`layout`] | The natural layout engine [`layout::sysv`] | Section 9.3 |
//! | [`cparse`] | The C parser: [`parse_sig`] and [`parse_type`] | Section 9.2 |
//! | [`prelude`] | The built-in prelude types | Section 9.2 |
//! | [`proto`] | The Tier-0 prototypes [`Tier0`] | Section 9.4 |
//! | [`cc`] | Calling-convention tables, [`cc::SYSV_X86_64`] | Section 7.10 |
//! | [`msx64`] | The MS x64 table [`cc::MS_X64`] of PE binaries | Section 7.10 |
//! | [`noreturn`] | Lists of functions that do not return | Section 7.7 |
//! | [`syscalls`] | The x86-64 syscall table | Section 7.11 |
//! | [`data`] | The embedded data files | Section 2.6 |
//!
//! The crate denies `indexing_slicing` and `arithmetic_side_effects`. Hostile C text never
//! causes a panic.

pub mod cc;
pub mod cparse;
pub mod ctext;
pub mod data;
pub mod layout;
pub mod model;
pub mod msx64;
pub mod noreturn;
pub mod prelude;
pub mod proto;
pub mod store;
pub mod syscalls;
mod tables;
pub mod ty;

pub use cc::CallConv;
pub use cparse::{CDiag, CParseError, ParsedSig, Span, parse_sig, parse_type};
pub use data::DataError;
pub use layout::{FieldLayout, Layout, LayoutError};
pub use model::{DataModel, SizeAlign};
pub use noreturn::NoreturnList;
pub use prelude::PreludeError;
pub use proto::{Attrs, Category, Effect, Fmt, FmtKind, Proto, Tier0, Tier0Error};
pub use store::{StoreError, TypeStore};
pub use syscalls::SyscallTable;
pub use ty::{
    Enum, Enumerator, Field, Param, Prim, Quals, Record, RecordKind, Sig, TagKind, Type, TypeId,
};

/// The calling-convention tables. An agent signature names a table by its name.
pub const CALL_CONVS: &[&CallConv] = &[&cc::SYSV_X86_64, &cc::MS_X64];

/// Gives the calling-convention table with the name `name`.
#[must_use]
pub fn call_conv(name: &str) -> Option<&'static CallConv> {
    CALL_CONVS.iter().copied().find(|c| c.name == name)
}

/// A function that gives an embedded noreturn list.
pub type NoreturnFn = fn() -> Result<&'static NoreturnList, &'static DataError>;

/// The noreturn list of each binary format. The key is the format name of the loader.
pub const NORETURN_BY_FORMAT: &[(&str, NoreturnFn)] =
    &[("elf64-le", noreturn::elf), ("pe32+-x86_64", noreturn::pe)];

/// Gives the noreturn list of the binary format `format`, for example `elf64-le`.
///
/// # Errors
///
/// Returns the [`DataError`] of the embedded list file.
pub fn noreturn_list(format: &str) -> Option<Result<&'static NoreturnList, &'static DataError>> {
    NORETURN_BY_FORMAT
        .iter()
        .find(|(name, _)| *name == format)
        .map(|(_, list)| list())
}
