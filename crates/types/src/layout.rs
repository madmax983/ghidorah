//! The natural layout engine (design Section 9.3).
//!
//! The engine works in bits with checked `u64` math and gives bytes. The rules are the
//! System V rules, and both data model presets use them:
//!
//! - A field starts at the next multiple of its alignment.
//! - A record takes the alignment of its most aligned field, at least 1.
//! - The size of a record is a multiple of its alignment.
//! - All fields of a union start at offset 0.
//! - A flexible array member adds its alignment, but no size.
//!
//! Bit-fields and packing are not in the MVP. The C parser rejects them.

use std::fmt;

use ghidorah_base::ErrorCode;

use crate::model::DataModel;
use crate::store::{StoreError, TypeStore};
use crate::ty::TypeId;

/// The layout of one field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLayout {
    /// The field name.
    pub name: String,
    /// The offset from the start of the record, in bytes.
    pub offset: u64,
    /// The size of the field, in bytes. A flexible array member has size 0.
    pub size: u64,
    /// The field type.
    pub ty: TypeId,
}

/// The layout of a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The size in bytes.
    pub size: u64,
    /// The alignment in bytes.
    pub align: u64,
    /// The fields of a record in declaration order. Other types have no fields.
    pub fields: Vec<FieldLayout>,
}

/// An error of the layout engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// The ID names no type of the store.
    UnknownId(TypeId),
    /// The type has no known size: `void`, a declared record or an array of unknown length.
    Incomplete(TypeId),
    /// The type is a function type. It has no size.
    NotObject(TypeId),
    /// The size of the type does not fit in 64 bits of bits.
    Overflow(TypeId),
    /// The type graph is deeper than [`MAX_DEPTH`](crate::store::MAX_DEPTH).
    Depth,
}

impl LayoutError {
    /// Gives the tool error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::InternalError
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("layout error")
    }
}

impl std::error::Error for LayoutError {}

/// Gives the natural layout of the type `id` in the data model `model`.
///
/// # Errors
///
/// Returns [`LayoutError`] for an unknown, incomplete or function type, an overflow or a
/// type graph that is too deep.
pub fn sysv(store: &TypeStore, id: TypeId, model: &DataModel) -> Result<Layout, LayoutError> {
    let _ = (store, model);
    Err(LayoutError::UnknownId(id))
}

/// Gives the layout text of a type, one line for each field.
///
/// The first line names the type, its size and its alignment, for example
/// `struct s size=8 align=4`. Each field line gives the offset in hex and the declaration,
/// for example `+0x4 int b`. Each line ends with a line end.
///
/// # Errors
///
/// Returns the errors of [`TypeStore::c_decl`].
pub fn render(store: &TypeStore, id: TypeId, layout: &Layout) -> Result<String, StoreError> {
    let _ = (store, layout);
    Err(StoreError::UnknownId(id))
}
