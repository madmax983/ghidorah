//! The JSON value and the insertion-ordered object.

use std::collections::BTreeSet;
use std::fmt;

use crate::number::Number;

/// A JSON value.
///
/// `Default` gives [`Value::Null`]. `Display` gives the compact text of [`crate::write`].
/// Equality compares objects member by member in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Value {
    /// The `null` literal.
    #[default]
    Null,
    /// The `true` or `false` literal.
    Bool(bool),
    /// A number with its raw lexeme.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Self>),
    /// An object with its members in insertion order.
    Object(Object),
}

/// A JSON object: a list of members in insertion order.
///
/// The parser keeps a repeated name as a second member, so a write gives the same text again.
/// [`Object::get`] gives the last member with a name, as `JSON.parse` does.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Object {
    members: Vec<(String, Value)>,
}

impl Object {
    /// Makes an empty object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// Gives the number of members, repeated names included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Tells if the object has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Gives the value of the last member with the name `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.members
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Gives the value of the last member with the name `key`, for a change.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.members
            .iter_mut()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Tells if a member has the name `key`.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Adds a member at the end. A repeated name gives a second member.
    pub fn push(&mut self, key: impl Into<String>, value: Value) {
        self.members.push((key.into(), value));
    }

    /// Sets the value of the last member with the name `key`, or adds a member at the end.
    ///
    /// Gives the old value when a member with the name exists.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        let key = key.into();
        if let Some(slot) = self.get_mut(&key) {
            return Some(std::mem::replace(slot, value));
        }
        self.members.push((key, value));
        None
    }

    /// Removes all members with the name `key` and gives the value of the last one.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let mut found = None;
        let mut kept = Vec::with_capacity(self.members.len());
        for (k, v) in std::mem::take(&mut self.members) {
            if k == key {
                found = Some(v);
            } else {
                kept.push((k, v));
            }
        }
        self.members = kept;
        found
    }

    /// Gives the members in insertion order.
    #[must_use]
    pub fn members(&self) -> &[(String, Value)] {
        &self.members
    }

    /// Gives the members in insertion order, with their names as `&str`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.members.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Gives the name of the first member whose name an earlier member has.
    #[must_use]
    pub fn first_duplicate(&self) -> Option<&str> {
        let mut seen = BTreeSet::new();
        self.members
            .iter()
            .map(|(k, _)| k.as_str())
            .find(|k| !seen.insert(*k))
    }

    /// Gives the members and drops the object.
    #[must_use]
    pub fn into_members(self) -> Vec<(String, Value)> {
        self.members
    }
}

impl<K: Into<String>> FromIterator<(K, Value)> for Object {
    fn from_iter<I: IntoIterator<Item = (K, Value)>>(iter: I) -> Self {
        let mut object = Self::new();
        for (key, value) in iter {
            object.push(key, value);
        }
        object
    }
}

impl IntoIterator for Object {
    type Item = (String, Value);
    type IntoIter = std::vec::IntoIter<(String, Value)>;

    fn into_iter(self) -> Self::IntoIter {
        self.members.into_iter()
    }
}

impl Value {
    /// Makes an object value from `(name, value)` pairs, in their order.
    pub fn object<K: Into<String>>(members: impl IntoIterator<Item = (K, Self)>) -> Self {
        Self::Object(members.into_iter().collect())
    }

    /// Makes a number value from a finite `f64`. `NaN` and the infinities give `None`.
    #[must_use]
    pub fn from_f64(value: f64) -> Option<Self> {
        Number::from_f64(value).map(Self::Number)
    }

    /// Gives the name of the JSON type: `null`, `bool`, `number`, `string`, `array` or `object`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }

    /// Tells if the value is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Gives the boolean of a `true` or `false` value.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Gives the number of a number value.
    #[must_use]
    pub const fn as_number(&self) -> Option<&Number> {
        match self {
            Self::Number(n) => Some(n),
            _ => None,
        }
    }

    /// Gives a number value as `u64`. See [`Number::as_u64`].
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(Number::as_u64)
    }

    /// Gives a number value as `i64`. See [`Number::as_i64`].
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(Number::as_i64)
    }

    /// Gives a number value as `f64`. See [`Number::as_f64`].
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().and_then(Number::as_f64)
    }

    /// Gives the text of a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Gives the items of an array value.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Gives the items of an array value, for a change.
    pub const fn as_array_mut(&mut self) -> Option<&mut Vec<Self>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Gives the object of an object value.
    #[must_use]
    pub const fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Gives the object of an object value, for a change.
    pub const fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Gives the value of the last member named `key` of an object value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_object().and_then(|o| o.get(key))
    }

    /// Gives the value at an RFC 6901 pointer, or `None` when the text or the path is not valid.
    ///
    /// See [`crate::pointer::get`]. A `*` segment here is a plain name, not a map.
    #[must_use]
    pub fn pointer(&self, text: &str) -> Option<&Self> {
        let pointer = crate::pointer::parse(text).ok()?;
        crate::pointer::get(self, &pointer)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::write::write(self))
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<Number> for Value {
    fn from(value: Number) -> Self {
        Self::Number(value)
    }
}

impl From<Vec<Self>> for Value {
    fn from(value: Vec<Self>) -> Self {
        Self::Array(value)
    }
}

impl From<Object> for Value {
    fn from(value: Object) -> Self {
        Self::Object(value)
    }
}

impl<T: Into<Self>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

/// Makes `From` impls for integer types.
macro_rules! from_int {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Value {
                fn from(value: $ty) -> Self {
                    Self::Number(Number::from(value))
                }
            }
        )*
    };
}

from_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);
