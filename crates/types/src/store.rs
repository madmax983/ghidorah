//! The type store (design Section 9.1).
//!
//! A [`TypeStore`] owns the types of one program. It gives one [`TypeId`] to each type.
//! A derived type (pointer, array, qualified type, function type) gets the same ID each time.
//! A record or an enum without a tag gets the same ID for the same members.
//! A record or an enum with a tag has identity by tag. Tags and typedef names use two name
//! spaces, as in C.
//!
//! The store checks each new type:
//!
//! - Each ID that a type names exists.
//! - A record field has a complete object type. So a record cannot hold itself by value.
//! - A flexible array member comes last in a struct with at least one other field.
//! - An array element is a complete object type. A function returns no array and no function.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{DiagCode, ErrorCode};

use crate::ty::{
    Enum, Enumerator, Field, Prim, Quals, Record, RecordKind, Sig, TagKind, Type, TypeId,
};

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

/// Tells if `name` is a C identifier of at most [`MAX_NAME`] bytes.
#[must_use]
pub fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    first_ok && name.len() <= MAX_NAME && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn check_name(name: &str) -> Result<(), StoreError> {
    if is_identifier(name) {
        Ok(())
    } else {
        Err(StoreError::BadName(name.to_string()))
    }
}

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
        let types: Vec<Type> = Prim::ALL.into_iter().map(Type::Prim).collect();
        let derived = (0u32..)
            .zip(Prim::ALL)
            .map(|(i, p)| (Type::Prim(p), TypeId::from_index(i)))
            .collect();
        Self {
            types,
            tags: BTreeMap::new(),
            typedefs: BTreeMap::new(),
            derived,
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
        self.types.get(usize::try_from(id.index()).ok()?)
    }

    /// Gives all IDs in order.
    pub fn ids(&self) -> impl Iterator<Item = TypeId> + '_ {
        (0u32..).take(self.types.len()).map(TypeId::from_index)
    }

    /// Gives the ID of a primitive type.
    #[must_use]
    pub const fn prim(&self, prim: Prim) -> TypeId {
        TypeId::from_index(prim as u32)
    }

    fn check(&self, id: TypeId) -> Result<&Type, StoreError> {
        self.get(id).ok_or(StoreError::UnknownId(id))
    }

    fn push(&mut self, ty: Type) -> Result<TypeId, StoreError> {
        if self.types.len() >= MAX_TYPES {
            return Err(StoreError::Full);
        }
        let index = u32::try_from(self.types.len()).map_err(|_| StoreError::Full)?;
        self.types.push(ty);
        Ok(TypeId::from_index(index))
    }

    fn intern(&mut self, ty: Type) -> Result<TypeId, StoreError> {
        if let Some(id) = self.derived.get(&ty) {
            return Ok(*id);
        }
        let id = self.push(ty.clone())?;
        self.derived.insert(ty, id);
        Ok(id)
    }

    /// Gives the pointer type to `to`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`] or [`StoreError::Full`].
    pub fn ptr(&mut self, to: TypeId) -> Result<TypeId, StoreError> {
        self.check(to)?;
        self.intern(Type::Ptr(to))
    }

    /// Gives the array type of `len` elements of `elem`. `None` gives an array of unknown length.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::IncompleteElement`] for an element
    /// without a known size, [`StoreError::BadPart`] for a function element, or
    /// [`StoreError::Full`].
    pub fn array(&mut self, elem: TypeId, len: Option<u64>) -> Result<TypeId, StoreError> {
        self.check(elem)?;
        if self.is_func(elem) {
            return Err(StoreError::BadPart(elem));
        }
        if !self.is_complete(elem) {
            return Err(StoreError::IncompleteElement(elem));
        }
        self.intern(Type::Array { elem, len })
    }

    /// Gives `inner` with the qualifiers `quals`. Empty qualifiers give `inner`.
    ///
    /// The qualifiers of a qualified `inner` join the new qualifiers.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`] or [`StoreError::Full`].
    pub fn qual(&mut self, quals: Quals, inner: TypeId) -> Result<TypeId, StoreError> {
        let ty = self.check(inner)?;
        if quals.is_empty() {
            return Ok(inner);
        }
        let ty = match ty {
            Type::Qual {
                quals: old,
                inner: base,
            } => Type::Qual {
                quals: old.union(quals),
                inner: *base,
            },
            _ => Type::Qual { quals, inner },
        };
        self.intern(ty)
    }

    /// Gives the function type of `sig`.
    ///
    /// The C parser applies the C adjustment of array and function parameters first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::BadPart`] for an array or a function
    /// return type or a `void` parameter, [`StoreError::TooManyMembers`],
    /// [`StoreError::BadName`], [`StoreError::DuplicateMember`] for two parameters with one
    /// name, or [`StoreError::Full`].
    pub fn func(&mut self, sig: Sig) -> Result<TypeId, StoreError> {
        self.check(sig.ret)?;
        if self.is_func(sig.ret) || self.is_array(sig.ret) {
            return Err(StoreError::BadPart(sig.ret));
        }
        if sig.params.len() > MAX_MEMBERS {
            return Err(StoreError::TooManyMembers);
        }
        let mut names = BTreeSet::new();
        for p in &sig.params {
            self.check(p.ty)?;
            if self.strip(p.ty) == Some(self.prim(Prim::Void)) {
                return Err(StoreError::BadPart(p.ty));
            }
            if let Some(name) = &p.name {
                check_name(name)?;
                if !names.insert(name.as_str()) {
                    return Err(StoreError::DuplicateMember(name.clone()));
                }
            }
        }
        self.intern(Type::Func(sig))
    }

    /// Adds the typedef `name` for `target`. The same typedef again gives its ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BadName`], [`StoreError::UnknownId`],
    /// [`StoreError::Duplicate`] when `name` names another type, or [`StoreError::Full`].
    pub fn typedef(&mut self, name: &str, target: TypeId) -> Result<TypeId, StoreError> {
        check_name(name)?;
        self.check(target)?;
        if let Some(id) = self.typedefs.get(name) {
            return match self.get(*id) {
                Some(Type::Typedef { target: old, .. }) if *old == target => Ok(*id),
                _ => Err(StoreError::Duplicate(name.to_string())),
            };
        }
        let id = self.push(Type::Typedef {
            name: name.to_string(),
            target,
        })?;
        self.typedefs.insert(name.to_string(), id);
        Ok(id)
    }

    /// Gives the kind of the tag type `id`.
    fn tag_kind(&self, id: TypeId) -> Option<TagKind> {
        match self.get(id)? {
            Type::Record(r) => Some(r.kind.into()),
            Type::Enum(_) => Some(TagKind::Enum),
            _ => None,
        }
    }

    /// Gives the existing tag `name` when its kind is `kind`.
    fn existing_tag(&self, kind: TagKind, name: &str) -> Result<Option<TypeId>, StoreError> {
        let Some(id) = self.tags.get(name).copied() else {
            return Ok(None);
        };
        match self.tag_kind(id) {
            Some(have) if have == kind => Ok(Some(id)),
            Some(have) => Err(StoreError::KindMismatch {
                name: name.to_string(),
                have,
            }),
            None => Err(StoreError::Duplicate(name.to_string())),
        }
    }

    /// Declares the tag `name` without a definition. A declared tag of the same kind gives its ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BadName`], [`StoreError::KindMismatch`] when the tag has
    /// another kind, or [`StoreError::Full`].
    pub fn declare(&mut self, kind: TagKind, name: &str) -> Result<TypeId, StoreError> {
        check_name(name)?;
        if let Some(id) = self.existing_tag(kind, name)? {
            return Ok(id);
        }
        let ty = match kind {
            TagKind::Struct | TagKind::Union => Type::Record(Record {
                kind: if kind == TagKind::Struct {
                    RecordKind::Struct
                } else {
                    RecordKind::Union
                },
                name: Some(name.to_string()),
                fields: Vec::new(),
                complete: false,
            }),
            TagKind::Enum => Type::Enum(Enum {
                name: Some(name.to_string()),
                items: Vec::new(),
                complete: false,
            }),
        };
        let id = self.push(ty)?;
        self.tags.insert(name.to_string(), id);
        Ok(id)
    }

    /// Checks the fields of a new record.
    fn check_fields(&self, kind: RecordKind, fields: &[Field]) -> Result<(), StoreError> {
        if fields.len() > MAX_MEMBERS {
            return Err(StoreError::TooManyMembers);
        }
        let mut names = BTreeSet::new();
        let last = fields.len().saturating_sub(1);
        for (i, f) in fields.iter().enumerate() {
            check_name(&f.name)?;
            if !names.insert(f.name.as_str()) {
                return Err(StoreError::DuplicateMember(f.name.clone()));
            }
            self.check(f.ty)?;
            if self.is_flexible(f.ty) {
                if kind != RecordKind::Struct || i != last || fields.len() < 2 {
                    return Err(StoreError::FlexibleNotLast(f.name.clone()));
                }
            } else if !self.is_complete(f.ty) {
                return Err(StoreError::IncompleteByValue {
                    field: f.name.clone(),
                    ty: f.ty,
                });
            }
        }
        Ok(())
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
    /// [`StoreError::TooManyMembers`] or [`StoreError::Full`].
    /// The store does not change on an error.
    pub fn define_record(
        &mut self,
        kind: RecordKind,
        name: Option<&str>,
        fields: Vec<Field>,
    ) -> Result<TypeId, StoreError> {
        let existing = match name {
            Some(n) => {
                check_name(n)?;
                self.existing_tag(kind.into(), n)?
            }
            None => None,
        };
        self.check_fields(kind, &fields)?;
        let Some(n) = name else {
            return self.intern(Type::Record(Record {
                kind,
                name: None,
                fields,
                complete: true,
            }));
        };
        if let Some(id) = existing {
            let index = usize::try_from(id.index()).map_err(|_| StoreError::UnknownId(id))?;
            return match self.types.get_mut(index) {
                Some(Type::Record(r)) if !r.complete => {
                    r.fields = fields;
                    r.complete = true;
                    Ok(id)
                }
                Some(Type::Record(r)) if r.fields == fields => Ok(id),
                _ => Err(StoreError::Duplicate(n.to_string())),
            };
        }
        let id = self.push(Type::Record(Record {
            kind,
            name: Some(n.to_string()),
            fields,
            complete: true,
        }))?;
        self.tags.insert(n.to_string(), id);
        Ok(id)
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
        let existing = match name {
            Some(n) => {
                check_name(n)?;
                self.existing_tag(TagKind::Enum, n)?
            }
            None => None,
        };
        if items.len() > MAX_MEMBERS {
            return Err(StoreError::TooManyMembers);
        }
        let mut names = BTreeSet::new();
        for item in &items {
            check_name(&item.name)?;
            if !names.insert(item.name.as_str()) {
                return Err(StoreError::DuplicateMember(item.name.clone()));
            }
        }
        let Some(n) = name else {
            return self.intern(Type::Enum(Enum {
                name: None,
                items,
                complete: true,
            }));
        };
        if let Some(id) = existing {
            let index = usize::try_from(id.index()).map_err(|_| StoreError::UnknownId(id))?;
            return match self.types.get_mut(index) {
                Some(Type::Enum(e)) if !e.complete => {
                    e.items = items;
                    e.complete = true;
                    Ok(id)
                }
                Some(Type::Enum(e)) if e.items == items => Ok(id),
                _ => Err(StoreError::Duplicate(n.to_string())),
            };
        }
        let id = self.push(Type::Enum(Enum {
            name: Some(n.to_string()),
            items,
            complete: true,
        }))?;
        self.tags.insert(n.to_string(), id);
        Ok(id)
    }

    /// Gives the record or the enum with the tag `name`.
    #[must_use]
    pub fn lookup_tag(&self, name: &str) -> Option<TypeId> {
        self.tags.get(name).copied()
    }

    /// Gives the typedef `name`.
    #[must_use]
    pub fn lookup_typedef(&self, name: &str) -> Option<TypeId> {
        self.typedefs.get(name).copied()
    }

    /// Gives the tag names in byte order.
    pub fn tag_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.tags.keys().map(String::as_str)
    }

    /// Gives the typedef names in byte order.
    pub fn typedef_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.typedefs.keys().map(String::as_str)
    }

    /// Gives the type behind the typedefs and the qualifiers of `id`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`] or [`StoreError::Depth`].
    pub fn resolve(&self, id: TypeId) -> Result<TypeId, StoreError> {
        let mut cur = id;
        for _ in 0..=MAX_DEPTH {
            match self.check(cur)? {
                Type::Typedef { target, .. } => cur = *target,
                Type::Qual { inner, .. } => cur = *inner,
                _ => return Ok(cur),
            }
        }
        Err(StoreError::Depth)
    }

    /// Gives the type behind the typedefs and the qualifiers of `id`, with no depth limit.
    ///
    /// Each typedef and each qualified type names a type with a lower ID. So the walk ends.
    pub(crate) fn strip(&self, id: TypeId) -> Option<TypeId> {
        let mut cur = id;
        for _ in 0..=self.types.len() {
            match self.get(cur)? {
                Type::Typedef { target, .. } => cur = *target,
                Type::Qual { inner, .. } => cur = *inner,
                _ => return Some(cur),
            }
        }
        None
    }

    fn is_func(&self, id: TypeId) -> bool {
        self.strip(id)
            .is_some_and(|t| matches!(self.get(t), Some(Type::Func(_))))
    }

    fn is_array(&self, id: TypeId) -> bool {
        self.strip(id)
            .is_some_and(|t| matches!(self.get(t), Some(Type::Array { .. })))
    }

    /// Tells if `id` is an array of unknown length with a complete element: a flexible member.
    pub(crate) fn is_flexible(&self, id: TypeId) -> bool {
        match self.strip(id).and_then(|t| self.get(t)) {
            Some(Type::Array { elem, len: None }) => self.is_complete(*elem),
            _ => false,
        }
    }

    /// Tells if `id` is a complete object type: a type with a known size.
    #[must_use]
    pub fn is_complete(&self, id: TypeId) -> bool {
        let mut cur = id;
        for _ in 0..=self.types.len() {
            match self.get(cur) {
                None | Some(Type::Func(_)) => return false,
                Some(Type::Prim(p)) => return *p != Prim::Void,
                Some(Type::Ptr(_)) => return true,
                Some(Type::Array { elem, len }) => {
                    if len.is_none() {
                        return false;
                    }
                    cur = *elem;
                }
                Some(Type::Record(r)) => return r.complete,
                Some(Type::Enum(e)) => return e.complete,
                Some(Type::Typedef { target, .. }) => cur = *target,
                Some(Type::Qual { inner, .. }) => cur = *inner,
            }
        }
        false
    }
}
