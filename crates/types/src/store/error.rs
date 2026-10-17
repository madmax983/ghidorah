//! The error of a store operation (ADR-0002).

use std::fmt;

use ghidorah_base::{DiagCode, ErrorCode};

use super::{MAX_DEPTH, MAX_MEMBERS, MAX_NAME, MAX_TYPES};
use crate::ty::{TagKind, TypeId};

/// An error of a store operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The ID names no type of the store.
    UnknownId(TypeId),
    /// The store holds [`MAX_TYPES`] types.
    Full,
    /// The name is empty, too long or not a C identifier.
    BadName(String),
    /// A different type with this name exists.
    Duplicate(String),
    /// The tag names a type of another kind.
    KindMismatch {
        /// The tag.
        name: String,
        /// The kind of the existing tag.
        have: TagKind,
    },
    /// Two fields, parameters or enum constants have the same name.
    DuplicateMember(String),
    /// A field has an incomplete type or a function type.
    IncompleteByValue {
        /// The field name.
        field: String,
        /// The field type.
        ty: TypeId,
    },
    /// A flexible array member is not the last field of a struct with other fields.
    FlexibleNotLast(String),
    /// An array element has an incomplete type: `void`, a declared record or an array
    /// without a length.
    IncompleteElement(TypeId),
    /// A derived type has a bad part: an array of functions, a function that returns an
    /// array or a function, or a `void` parameter.
    BadPart(TypeId),
    /// A type has more than [`MAX_MEMBERS`] members.
    TooManyMembers,
    /// A walk over the graph of types is deeper than [`MAX_DEPTH`].
    Depth,
    /// A C text is longer than [`MAX_TEXT`](crate::ctext::MAX_TEXT) bytes.
    TextLimit,
}

impl StoreError {
    /// Gives the diagnostic code of the C parser for the error.
    #[must_use]
    pub const fn diag(&self) -> DiagCode {
        match self {
            Self::UnknownId(_) | Self::KindMismatch { .. } => DiagCode::UnknownType,
            Self::Full | Self::TooManyMembers | Self::Depth | Self::TextLimit => DiagCode::Limit,
            Self::BadName(_) | Self::Duplicate(_) | Self::DuplicateMember(_) | Self::BadPart(_) => {
                DiagCode::Syntax
            }
            Self::IncompleteByValue { .. }
            | Self::FlexibleNotLast(_)
            | Self::IncompleteElement(_) => DiagCode::IncompleteByValue,
        }
    }

    /// Gives the tool error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownId(_) => ErrorCode::NotFound,
            Self::Full | Self::TooManyMembers | Self::Depth | Self::TextLimit => {
                ErrorCode::LimitExceeded
            }
            _ => ErrorCode::InvalidArgument,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownId(id) => write!(f, "The type ID {} is not in the store.", id.index()),
            Self::Full => write!(
                f,
                "The store holds {MAX_TYPES} types. It takes no more types."
            ),
            Self::BadName(name) => write!(
                f,
                "The name `{name}` is not a C identifier of at most {MAX_NAME} bytes."
            ),
            Self::Duplicate(name) => write!(f, "Another type has the name `{name}`."),
            Self::KindMismatch { name, have } => {
                write!(f, "The tag `{name}` names a {} type.", have.keyword())
            }
            Self::DuplicateMember(name) => {
                write!(f, "The name `{name}` comes twice in one type.")
            }
            Self::IncompleteByValue { field, .. } => write!(
                f,
                "The field `{field}` has an incomplete type or a function type."
            ),
            Self::FlexibleNotLast(field) => write!(
                f,
                "The flexible array member `{field}` is not the last field after other fields."
            ),
            Self::IncompleteElement(id) => write!(
                f,
                "The array element type {} has no known size.",
                id.index()
            ),
            Self::BadPart(id) => write!(f, "The type {} is not a valid part here.", id.index()),
            Self::TooManyMembers => write!(f, "The type has more than {MAX_MEMBERS} members."),
            Self::Depth => write!(f, "The type graph is deeper than {MAX_DEPTH} levels."),
            Self::TextLimit => write!(
                f,
                "The C text is longer than {} bytes.",
                crate::ctext::MAX_TEXT
            ),
        }
    }
}

impl std::error::Error for StoreError {}
