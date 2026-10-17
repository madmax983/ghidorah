//! `OutputShape`: the typed tree of a tool result (design Section 10.1).
//!
//! No tool declares `outputSchema` (Section 10.10). The shape documents the `data` member
//! of the envelope, and test `ac_132a` checks each example result against it.
//! `batch_run` uses it to type references before a step runs (Section 11.3).

use std::fmt;

use ghidorah_base::{Id, IdKind};
use ghidorah_json::Value;

/// The shape of one output value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputShape {
    /// Any value.
    Any,
    /// A string.
    Str,
    /// An integer below 2^53.
    Int,
    /// `true` or `false`.
    Bool,
    /// An address: a string `^0x[0-9a-f]+$`.
    Addr,
    /// An ID of this kind, for example `fn:0x401000`.
    Id(IdKind),
    /// Binary text in its one JSON shape `{ text, hex, len, truncated?, src }` (ADR-0022).
    Text,
    /// `null` or a value of the inner shape.
    Nullable(&'static Self),
    /// An array of values of the inner shape.
    List(&'static Self),
    /// An object with these members and no others.
    Obj(&'static [Field]),
}

/// One member of an object shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// The member name.
    pub name: &'static str,
    /// The shape of the member value.
    pub shape: OutputShape,
    /// `true` when the member can be absent.
    pub optional: bool,
}

impl Field {
    /// Makes a required member.
    #[must_use]
    pub const fn req(name: &'static str, shape: OutputShape) -> Self {
        Self {
            name,
            shape,
            optional: false,
        }
    }

    /// Makes an optional member.
    #[must_use]
    pub const fn opt(name: &'static str, shape: OutputShape) -> Self {
        Self {
            name,
            shape,
            optional: true,
        }
    }
}

/// The first place where a value does not fit its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeError {
    /// The JSON pointer of the value, for example `/items/3/addr`.
    pub path: String,
    /// What the shape expects there, for example `an address text`.
    pub expected: String,
}

impl fmt::Display for ShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The value at {} does not fit. The shape expects {}.",
            self.path, self.expected
        )
    }
}

impl std::error::Error for ShapeError {}

/// How strict a fit check is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// Every required member must be present.
    Exact,
    /// Members can be absent. Use it for results with `fields` (a projection).
    Partial,
}

/// The smallest integer that an `Int` value must stay below: 2^53.
const INT_LIMIT: u64 = 1 << 53;

/// The members of the one JSON shape of binary text.
const TEXT_FIELDS: &[Field] = &[
    Field::req("text", OutputShape::Str),
    Field::req("hex", OutputShape::Str),
    Field::req("len", OutputShape::Int),
    Field::opt("truncated", OutputShape::Bool),
    Field::req("src", OutputShape::Str),
];

impl OutputShape {
    /// Checks `value` against the shape.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError`] for the first value in document order that does not fit.
    /// An object member that the shape does not name does not fit.
    pub fn check(&self, value: &Value, fit: Fit) -> Result<(), ShapeError> {
        self.check_at(value, fit, &mut String::new())
    }

    fn check_at(&self, value: &Value, fit: Fit, path: &mut String) -> Result<(), ShapeError> {
        let ok = match (self, value) {
            (Self::Any, _)
            | (Self::Nullable(_), Value::Null)
            | (Self::Str, Value::String(_))
            | (Self::Bool, Value::Bool(_)) => true,
            (Self::Int, Value::Number(n)) => {
                n.as_u64().is_some_and(|v| v < INT_LIMIT)
                    || n.as_i64().is_some_and(|v| v.unsigned_abs() < INT_LIMIT)
            }
            (Self::Addr, Value::String(t)) => is_addr_text(t),
            (Self::Id(kind), Value::String(t)) => is_id_text(t, *kind),
            (Self::Text, Value::Object(object)) => {
                check_object(TEXT_FIELDS, object, Fit::Exact, path)?;
                object.get("src").and_then(Value::as_str) == Some(ghidorah_base::bintext::SRC)
            }
            (Self::Nullable(inner), _) => return inner.check_at(value, fit, path),
            (Self::List(inner), Value::Array(items)) => {
                for (i, item) in items.iter().enumerate() {
                    let len = path.len();
                    path.push('/');
                    path.push_str(&i.to_string());
                    inner.check_at(item, fit, path)?;
                    path.truncate(len);
                }
                true
            }
            (Self::Obj(fields), Value::Object(object)) => {
                check_object(fields, object, fit, path)?;
                true
            }
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(ShapeError {
                path: path.clone(),
                expected: self.name().to_owned(),
            })
        }
    }

    /// Gives a short name of the shape for errors.
    const fn name(&self) -> &'static str {
        match self {
            Self::Any => "any value",
            Self::Str => "a string",
            Self::Int => "an integer below 2^53",
            Self::Bool => "a boolean",
            Self::Addr => "an address text",
            Self::Id(_) => "an ID of the shape kind",
            Self::Text => "binary text",
            Self::Nullable(_) => "null or the inner shape",
            Self::List(_) => "an array",
            Self::Obj(_) => "an object",
        }
    }
}

/// Checks the members of `object` against `fields`.
fn check_object(
    fields: &[Field],
    object: &ghidorah_json::Object,
    fit: Fit,
    path: &mut String,
) -> Result<(), ShapeError> {
    for (key, member) in object.iter() {
        let len = path.len();
        path.push('/');
        path.push_str(key);
        let Some(field) = fields.iter().find(|f| f.name == key) else {
            return Err(ShapeError {
                path: path.clone(),
                expected: "no such member".to_owned(),
            });
        };
        field.shape.check_at(member, fit, path)?;
        path.truncate(len);
    }
    if fit == Fit::Exact
        && let Some(f) = fields
            .iter()
            .find(|f| !f.optional && !object.contains_key(f.name))
    {
        return Err(ShapeError {
            path: path.clone(),
            expected: format!("the member {}", f.name),
        });
    }
    Ok(())
}

/// Tells if `text` is an address text: `0x` and lower case hex digits.
#[must_use]
pub fn is_addr_text(text: &str) -> bool {
    text.strip_prefix("0x").is_some_and(|digits| {
        !digits.is_empty()
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Tells if `text` parses as an ID of `kind`.
#[must_use]
pub fn is_id_text(text: &str, kind: IdKind) -> bool {
    Id::parse(text).is_ok_and(|id| id.kind() == kind)
}
