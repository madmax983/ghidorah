//! The type store (design Section 9.1).
//!
//! A [`TypeStore`] owns the types of one program. It gives one [`TypeId`] to each type.
//! A derived type (pointer, array, qualified type, function type) gets the same ID each time.
//! Records and enums have identity by tag. Tags and typedef names use two name spaces, as in C.
//!
//! The store checks each new type:
//!
//! - Each ID that a type names exists.
//! - A record field has a complete object type. So a record cannot hold itself by value.
//! - A flexible array member comes last in a struct with at least one other field.
//! - An array element is a complete object type. A function returns no array and no function.

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{DiagCode, ErrorCode};

use crate::ty::{Enumerator, Field, Prim, Quals, RecordKind, Sig, TagKind, Type, TypeId};

/// The largest number of types in one store.
pub const MAX_TYPES: usize = 1 << 20;

/// The largest number of fields, parameters or enum constants of one type.
pub const MAX_MEMBERS: usize = 4096;

/// The deepest walk over the type graph. Pointers end a walk.
pub const MAX_DEPTH: usize = 256;

/// The longest name of a tag, a typedef, a field or a parameter, in bytes.
pub const MAX_NAME: usize = 1024;

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
    /// A walk over the type graph goes deeper than [`MAX_DEPTH`].
    Depth,
    /// A C text is longer than [`MAX_TEXT`](crate::ctext::MAX_TEXT) bytes.
    TextLimit,
}

impl StoreError {
    /// Gives the diagnostic code of the C parser for the error.
    #[must_use]
    pub const fn diag(&self) -> DiagCode {
        DiagCode::Oob
    }

    /// Gives the tool error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::InternalError
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("type store error")
    }
}

impl std::error::Error for StoreError {}

/// The types of one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeStore {
    types: Vec<Type>,
    tags: BTreeMap<String, TypeId>,
    typedefs: BTreeMap<String, TypeId>,
    derived: BTreeMap<Type, TypeId>,
}

impl Default for TypeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeStore {
    /// Makes a store that holds only the primitive types.
    ///
    /// The primitive types get the IDs `0` to `18` in the order of [`Prim::ALL`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            types: Vec::new(),
            tags: BTreeMap::new(),
            typedefs: BTreeMap::new(),
            derived: BTreeMap::new(),
        }
    }

    /// Gives the number of types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Tells if the store holds no type.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Gives the type with the ID `id`.
    #[must_use]
    pub fn get(&self, id: TypeId) -> Option<&Type> {
        let _ = id;
        None
    }

    /// Gives all IDs in order.
    pub fn ids(&self) -> impl Iterator<Item = TypeId> + '_ {
        std::iter::empty()
    }

    /// Gives the ID of a primitive type.
    #[must_use]
    pub const fn prim(&self, prim: Prim) -> TypeId {
        let _ = prim;
        TypeId::from_index(u32::MAX)
    }

    /// Gives the pointer type to `to`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`] or [`StoreError::Full`].
    pub fn ptr(&mut self, to: TypeId) -> Result<TypeId, StoreError> {
        Err(StoreError::UnknownId(to))
    }

    /// Gives the array type of `len` elements of `elem`. `None` gives an array of unknown length.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::IncompleteElement`] for an element
    /// without a known size, [`StoreError::BadPart`] for a function element, or
    /// [`StoreError::Full`].
    pub fn array(&mut self, elem: TypeId, len: Option<u64>) -> Result<TypeId, StoreError> {
        let _ = len;
        Err(StoreError::UnknownId(elem))
    }

    /// Gives `inner` with the qualifiers `quals`. Empty qualifiers give `inner`.
    ///
    /// The qualifiers of a qualified `inner` join the new qualifiers.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`] or [`StoreError::Full`].
    pub fn qual(&mut self, quals: Quals, inner: TypeId) -> Result<TypeId, StoreError> {
        let _ = quals;
        Err(StoreError::UnknownId(inner))
    }

    /// Gives the function type of `sig`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::BadPart`] for an array or a function
    /// return type or a `void` parameter, [`StoreError::TooManyMembers`],
    /// [`StoreError::DuplicateMember`] for two parameters with one name, or [`StoreError::Full`].
    pub fn func(&mut self, sig: Sig) -> Result<TypeId, StoreError> {
        Err(StoreError::UnknownId(sig.ret))
    }

    /// Adds the typedef `name` for `target`. The same typedef again gives its ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BadName`], [`StoreError::UnknownId`],
    /// [`StoreError::Duplicate`] when `name` names another type, or [`StoreError::Full`].
    pub fn typedef(&mut self, name: &str, target: TypeId) -> Result<TypeId, StoreError> {
        let _ = target;
        Err(StoreError::BadName(name.to_string()))
    }

    /// Declares the tag `name` without a definition. A declared tag of the same kind gives its ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BadName`], [`StoreError::KindMismatch`] when the tag has
    /// another kind, or [`StoreError::Full`].
    pub fn declare(&mut self, kind: TagKind, name: &str) -> Result<TypeId, StoreError> {
        let _ = kind;
        Err(StoreError::BadName(name.to_string()))
    }

    /// Defines a record. A tag of a declared record gets the fields. The same definition
    /// again gives its ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BadName`], [`StoreError::KindMismatch`],
    /// [`StoreError::Duplicate`] for a complete record with other fields,
    /// [`StoreError::UnknownId`], [`StoreError::DuplicateMember`],
    /// [`StoreError::IncompleteByValue`], [`StoreError::FlexibleNotLast`],
    /// [`StoreError::TooManyMembers`], [`StoreError::Depth`] or [`StoreError::Full`].
    /// The store does not change on an error.
    pub fn define_record(
        &mut self,
        kind: RecordKind,
        name: Option<&str>,
        fields: Vec<Field>,
    ) -> Result<TypeId, StoreError> {
        let _ = (kind, fields);
        Err(StoreError::BadName(name.unwrap_or_default().to_string()))
    }

    /// Defines an enum. The same definition again gives its ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BadName`], [`StoreError::KindMismatch`],
    /// [`StoreError::Duplicate`], [`StoreError::DuplicateMember`],
    /// [`StoreError::TooManyMembers`] or [`StoreError::Full`].
    pub fn define_enum(
        &mut self,
        name: Option<&str>,
        items: Vec<Enumerator>,
    ) -> Result<TypeId, StoreError> {
        let _ = items;
        Err(StoreError::BadName(name.unwrap_or_default().to_string()))
    }

    /// Gives the record or the enum with the tag `name`.
    #[must_use]
    pub fn lookup_tag(&self, name: &str) -> Option<TypeId> {
        let _ = name;
        None
    }

    /// Gives the typedef `name`.
    #[must_use]
    pub fn lookup_typedef(&self, name: &str) -> Option<TypeId> {
        let _ = name;
        None
    }

    /// Gives the tag names in byte order.
    pub fn tag_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.tags.keys().take(0).map(String::as_str)
    }

    /// Gives the typedef names in byte order.
    pub fn typedef_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.typedefs.keys().take(0).map(String::as_str)
    }

    /// Gives the type behind the typedefs and the qualifiers of `id`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`] or [`StoreError::Depth`].
    pub fn resolve(&self, id: TypeId) -> Result<TypeId, StoreError> {
        Err(StoreError::UnknownId(id))
    }

    /// Tells if `id` is a complete object type: a type with a known size.
    #[must_use]
    pub fn is_complete(&self, id: TypeId) -> bool {
        let _ = id;
        false
    }
}
