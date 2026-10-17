//! Codecs for record structs: [`ToJson`], [`FromJson`] and the [`json_record!`] macro.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::value::{Object, Value};
use crate::write::push_segment;

/// A type with a JSON form.
pub trait ToJson {
    /// Gives the JSON value of `self`.
    fn to_json(&self) -> Value;

    /// Tells if a record leaves this field out of its object. `None` of `Option` gives `true`.
    fn is_absent(&self) -> bool {
        false
    }
}

/// A type that reads its JSON form back.
pub trait FromJson: Sized {
    /// Reads a value of the type from `value`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] with the pointer of the first bad part.
    fn from_json(value: &Value) -> Result<Self, DecodeError>;

    /// Gives the value of a record field that the object does not have.
    ///
    /// `Option` gives `Some(None)`. Other types give `None`, so the record needs the field.
    #[must_use]
    fn from_absent() -> Option<Self> {
        None
    }
}

/// The reason of a [`DecodeError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecodeKind {
    /// The value has the wrong JSON type.
    Type {
        /// The expected type, for example `string` or `unsigned integer`.
        expected: &'static str,
        /// The JSON type of the value. See [`Value::kind`].
        found: &'static str,
    },
    /// An integer is outside the range of the field type, or the number is not an integer.
    Range,
    /// A required field is missing.
    Missing,
    /// The object has a member that the record does not declare.
    Unknown,
    /// The object has two members with the same name.
    Duplicate,
}

impl DecodeKind {
    /// Gives the stable text form, for example `E_TYPE`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Type { .. } => "E_TYPE",
            Self::Range => "E_RANGE",
            Self::Missing => "E_MISSING",
            Self::Unknown => "E_UNKNOWN",
            Self::Duplicate => "E_DUPLICATE",
        }
    }
}

/// A value that does not decode, with the RFC 6901 pointer of the bad part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    kind: DecodeKind,
    /// The path segments from the bad part up to the root, so a parent adds its segment last.
    rev_path: Vec<String>,
}

impl DecodeError {
    /// Makes an error at the current value.
    #[must_use]
    pub const fn new(kind: DecodeKind) -> Self {
        Self {
            kind,
            rev_path: Vec::new(),
        }
    }

    /// Makes a type error: the value has the JSON type `found` and not `expected`.
    #[must_use]
    pub const fn type_error(expected: &'static str, found: &Value) -> Self {
        Self::new(DecodeKind::Type {
            expected,
            found: found.kind(),
        })
    }

    /// Gives the reason.
    #[must_use]
    pub const fn kind(&self) -> DecodeKind {
        self.kind
    }

    /// Gives the RFC 6901 pointer of the bad part, for example `/items/2/name`.
    #[must_use]
    pub fn path(&self) -> String {
        let mut path = String::new();
        for segment in self.rev_path.iter().rev() {
            push_segment(&mut path, segment);
        }
        path
    }

    /// Puts the member name `key` in front of the path.
    #[must_use]
    pub fn at_key(mut self, key: &str) -> Self {
        self.rev_path.push(key.to_owned());
        self
    }

    /// Puts the array index `index` in front of the path.
    #[must_use]
    pub fn at_index(mut self, index: usize) -> Self {
        self.rev_path.push(index.to_string());
        self
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path();
        match self.kind {
            DecodeKind::Type { expected, found } => write!(
                f,
                "{} at '{path}': expected {expected}, found {found}",
                self.kind.as_str()
            ),
            DecodeKind::Range => write!(
                f,
                "{} at '{path}': the number is not an integer in range",
                self.kind.as_str()
            ),
            DecodeKind::Missing => write!(
                f,
                "{} at '{path}': the required field is missing",
                self.kind.as_str()
            ),
            DecodeKind::Unknown => write!(
                f,
                "{} at '{path}': the record has no field with this name",
                self.kind.as_str()
            ),
            DecodeKind::Duplicate => write!(
                f,
                "{} at '{path}': the object has two members with this name",
                self.kind.as_str()
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Gives the JSON name of a field identifier: `r#type` gives `type`.
#[must_use]
pub fn field_key(ident: &str) -> &str {
    ident.strip_prefix("r#").unwrap_or(ident)
}

/// A checked view of the members of a record object.
///
/// [`Fields::new`] checks the member names. [`Fields::take`] reads one field.
#[derive(Debug, Clone, Copy)]
pub struct Fields<'a> {
    object: &'a Object,
}

impl<'a> Fields<'a> {
    /// Checks that `value` is an object whose member names are in `names`, each one time only.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeKind::Type`] when `value` is not an object.
    /// Returns [`DecodeKind::Unknown`] for a name outside `names`.
    /// Returns [`DecodeKind::Duplicate`] for a repeated name.
    pub fn new(value: &'a Value, names: &[&str]) -> Result<Self, DecodeError> {
        let object = value
            .as_object()
            .ok_or_else(|| DecodeError::type_error("object", value))?;
        let mut seen = BTreeSet::new();
        for (key, _) in object.iter() {
            if !names.contains(&key) {
                return Err(DecodeError::new(DecodeKind::Unknown).at_key(key));
            }
            if !seen.insert(key) {
                return Err(DecodeError::new(DecodeKind::Duplicate).at_key(key));
            }
        }
        Ok(Self { object })
    }

    /// Reads the field `name`. A missing field uses [`FromJson::from_absent`].
    ///
    /// # Errors
    ///
    /// Returns [`DecodeKind::Missing`] for a missing required field.
    /// Returns the error of [`FromJson::from_json`], with `name` in front of its path.
    pub fn take<T: FromJson>(&self, name: &str) -> Result<T, DecodeError> {
        match self.object.get(name) {
            Some(value) => T::from_json(value).map_err(|e| e.at_key(name)),
            None => {
                T::from_absent().ok_or_else(|| DecodeError::new(DecodeKind::Missing).at_key(name))
            }
        }
    }
}

impl ToJson for Value {
    fn to_json(&self) -> Value {
        self.clone()
    }
}

impl FromJson for Value {
    fn from_json(value: &Value) -> Result<Self, DecodeError> {
        Ok(value.clone())
    }
}

impl ToJson for bool {
    fn to_json(&self) -> Value {
        Value::Bool(*self)
    }
}

impl FromJson for bool {
    fn from_json(value: &Value) -> Result<Self, DecodeError> {
        value
            .as_bool()
            .ok_or_else(|| DecodeError::type_error("bool", value))
    }
}

impl ToJson for String {
    fn to_json(&self) -> Value {
        Value::String(self.clone())
    }
}

impl FromJson for String {
    fn from_json(value: &Value) -> Result<Self, DecodeError> {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| DecodeError::type_error("string", value))
    }
}

impl<T: ToJson> ToJson for Option<T> {
    fn to_json(&self) -> Value {
        self.as_ref().map_or(Value::Null, ToJson::to_json)
    }

    fn is_absent(&self) -> bool {
        self.is_none()
    }
}

impl<T: FromJson> FromJson for Option<T> {
    fn from_json(value: &Value) -> Result<Self, DecodeError> {
        if value.is_null() {
            Ok(None)
        } else {
            T::from_json(value).map(Some)
        }
    }

    fn from_absent() -> Option<Self> {
        Some(None)
    }
}

impl<T: ToJson> ToJson for Box<T> {
    fn to_json(&self) -> Value {
        (**self).to_json()
    }

    fn is_absent(&self) -> bool {
        (**self).is_absent()
    }
}

impl<T: FromJson> FromJson for Box<T> {
    fn from_json(value: &Value) -> Result<Self, DecodeError> {
        T::from_json(value).map(Self::new)
    }

    fn from_absent() -> Option<Self> {
        T::from_absent().map(Self::new)
    }
}

impl<T: ToJson> ToJson for Vec<T> {
    fn to_json(&self) -> Value {
        Value::Array(self.iter().map(ToJson::to_json).collect())
    }
}

impl<T: FromJson> FromJson for Vec<T> {
    fn from_json(value: &Value) -> Result<Self, DecodeError> {
        let items = value
            .as_array()
            .ok_or_else(|| DecodeError::type_error("array", value))?;
        items
            .iter()
            .enumerate()
            .map(|(i, item)| T::from_json(item).map_err(|e| e.at_index(i)))
            .collect()
    }
}

impl<T: ToJson> ToJson for BTreeMap<String, T> {
    fn to_json(&self) -> Value {
        Value::Object(self.iter().map(|(k, v)| (k.clone(), v.to_json())).collect())
    }
}

impl<T: FromJson> FromJson for BTreeMap<String, T> {
    fn from_json(value: &Value) -> Result<Self, DecodeError> {
        let object = value
            .as_object()
            .ok_or_else(|| DecodeError::type_error("object", value))?;
        let mut map = Self::new();
        for (key, item) in object.iter() {
            if map.contains_key(key) {
                return Err(DecodeError::new(DecodeKind::Duplicate).at_key(key));
            }
            let decoded = T::from_json(item).map_err(|e| e.at_key(key))?;
            map.insert(key.to_owned(), decoded);
        }
        Ok(map)
    }
}

/// Makes the codec impls of integer types. `$read` gives the 64-bit value of a number.
macro_rules! int_codec {
    ($read:ident, $name:literal: $($ty:ty),*) => {
        $(
            impl ToJson for $ty {
                fn to_json(&self) -> Value {
                    Value::from(*self)
                }
            }

            impl FromJson for $ty {
                fn from_json(value: &Value) -> Result<Self, DecodeError> {
                    let number = value
                        .as_number()
                        .ok_or_else(|| DecodeError::type_error($name, value))?;
                    number
                        .$read()
                        .and_then(|wide| Self::try_from(wide).ok())
                        .ok_or_else(|| DecodeError::new(DecodeKind::Range))
                }
            }
        )*
    };
}

int_codec!(as_u64, "unsigned integer": u8, u16, u32, u64, usize);
int_codec!(as_i64, "integer": i8, i16, i32, i64, isize);

/// Declares one or more record structs with their [`ToJson`] and [`FromJson`] impls.
///
/// Each field maps to a member with the field name (`r#type` gives `type`).
/// The writer keeps the field order and leaves out a `None` field.
/// The reader rejects an unknown member, a repeated member and a missing required field.
/// An `Option` field can be missing or `null`.
///
/// ```
/// ghidorah_json::json_record! {
///     /// One import of a binary.
///     #[derive(Debug, Clone, PartialEq, Eq)]
///     pub struct Import {
///         /// The symbol name.
///         pub name: String,
///         /// The ordinal, when the format has one.
///         pub ordinal: Option<u16>,
///     }
/// }
///
/// use ghidorah_json::{FromJson, ToJson};
/// let import = Import { name: "puts".to_owned(), ordinal: None };
/// let value = import.to_json();
/// assert_eq!(value.to_string(), r#"{"name":"puts"}"#);
/// assert_eq!(Import::from_json(&value), Ok(import));
/// ```
#[macro_export]
macro_rules! json_record {
    ($(
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident : $ty:ty
            ),* $(,)?
        }
    )+) => {
        $(
            $(#[$meta])*
            $vis struct $name {
                $(
                    $(#[$field_meta])*
                    $field_vis $field: $ty,
                )*
            }

            impl $crate::ToJson for $name {
                fn to_json(&self) -> $crate::Value {
                    #[allow(unused_mut, reason = "a record with no fields does not change the object")]
                    let mut object = $crate::Object::new();
                    $(
                        if !$crate::ToJson::is_absent(&self.$field) {
                            object.push(
                                $crate::field_key(stringify!($field)),
                                $crate::ToJson::to_json(&self.$field),
                            );
                        }
                    )*
                    $crate::Value::Object(object)
                }
            }

            impl $crate::FromJson for $name {
                fn from_json(
                    value: &$crate::Value,
                ) -> ::core::result::Result<Self, $crate::DecodeError> {
                    #[allow(unused_variables, reason = "a record with no fields reads no field")]
                    let fields = $crate::Fields::new(
                        value,
                        &[$($crate::field_key(stringify!($field))),*],
                    )?;
                    ::core::result::Result::Ok(Self {
                        $(
                            $field: fields.take($crate::field_key(stringify!($field)))?,
                        )*
                    })
                }
            }
        )+
    };
}
