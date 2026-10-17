//! Typed reads of `mem_read { as: "type" }`: the C type, its layout and its field values.

use ghidorah_base::{Caps, ErrorCode};
use ghidorah_db::Program;
use ghidorah_json::{Object, Value};
use ghidorah_types::{CParseError, DataModel, Prim, Type, TypeId, TypeStore, layout, parse_type};

use super::{MAX_ELEMENTS, MAX_FIELD_DEPTH};
use crate::errors::ToolError;
use crate::handlers::func_sections as fs;

/// The C type of a typed read: its store, its ID and its size.
pub struct Typed {
    /// A copy of the store of the program with the parsed type.
    pub store: TypeStore,
    /// The type.
    pub id: TypeId,
    /// The size in bytes.
    pub size: u64,
    /// The alignment in bytes.
    pub align: u64,
}

/// Gives the `C_PARSE_ERROR` of a C text that does not parse (design Section 9.2).
fn parse_error(error: &CParseError) -> ToolError {
    let list = error
        .errors
        .iter()
        .map(|d| {
            let expected = d.expected.iter().map(|e| Value::from(e.as_str())).collect();
            Value::object([
                ("code", Value::from(d.code.name())),
                ("line", Value::from(d.at.line)),
                ("col", Value::from(d.at.col)),
                ("expected", Value::Array(expected)),
                ("hint", Value::from(d.hint.as_str())),
            ])
        })
        .collect();
    ToolError::new(ErrorCode::CParseError)
        .path("/c")
        .detail("errors", Value::Array(list))
}

/// Parses the C type text `c` in a copy of the store of `program` and lays it out.
///
/// # Errors
///
/// Returns `C_PARSE_ERROR` for text that does not parse and `INVALID_ARGUMENT` for a type
/// with no size.
pub fn parse(program: &Program, c: &str) -> Result<Typed, ToolError> {
    let mut store = program.types().store().clone();
    let id = parse_type(&mut store, c).map_err(|e| parse_error(&e))?;
    let shape = layout::sysv(&store, id, program.types().model()).map_err(|_| {
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", "c")
            .path("/c")
            .detail("expected", Value::from("a C type with a known size"))
    })?;
    Ok(Typed {
        store,
        id,
        size: shape.size,
        align: shape.align,
    })
}

/// The bytes of a typed read and the rules to show them.
struct Reader<'a> {
    store: &'a TypeStore,
    model: &'a DataModel,
    bytes: &'a [u8],
    caps: Caps,
}

impl Reader<'_> {
    /// Gives the value of `size` bytes at `offset` of the type `ty`.
    fn value(&self, ty: TypeId, offset: u64, size: u64) -> Value {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let end = usize::try_from(offset.saturating_add(size)).unwrap_or(usize::MAX);
        let Some(raw) = self.bytes.get(start..end) else {
            return Value::Null;
        };
        let base = self.store.resolve(ty).ok().and_then(|t| self.store.get(t));
        let char_array = match base {
            Some(Type::Array { elem, .. }) => {
                let e = self
                    .store
                    .resolve(*elem)
                    .ok()
                    .and_then(|t| self.store.get(t));
                matches!(e, Some(Type::Prim(Prim::Char | Prim::SChar | Prim::UChar)))
            }
            _ => false,
        };
        if char_array {
            let text = raw.split(|b| *b == 0).next().unwrap_or_default();
            return fs::bin_text(text, self.caps);
        }
        if raw.len() <= 8 {
            let mut word = [0u8; 8];
            for (dst, src) in word.iter_mut().zip(raw) {
                *dst = *src;
            }
            return fs::hex(u64::from_le_bytes(word));
        }
        Value::from(ghidorah_base::hex::encode(raw))
    }

    /// Adds the fields of the record `ty` at `offset` to `out`, with the path prefix `path`.
    fn fields(&self, ty: TypeId, offset: u64, path: &str, depth: usize, out: &mut Vec<Value>) {
        let Ok(shape) = layout::sysv(self.store, ty, self.model) else {
            return;
        };
        for f in &shape.fields {
            let at = offset.saturating_add(f.offset);
            let name = if path.is_empty() {
                f.name.clone()
            } else {
                format!("{path}.{}", f.name)
            };
            let inner = self.store.resolve(f.ty).ok();
            let kind = inner.and_then(|t| self.store.get(t));
            match kind {
                Some(Type::Record(_)) if depth < MAX_FIELD_DEPTH => {
                    self.fields(f.ty, at, &name, depth.saturating_add(1), out);
                }
                Some(Type::Array {
                    elem,
                    len: Some(len),
                }) if !self.is_char(*elem) && depth < MAX_FIELD_DEPTH => {
                    let size = layout::sysv(self.store, *elem, self.model).map_or(0, |l| l.size);
                    for i in 0..(*len).min(MAX_ELEMENTS) {
                        let off = at.saturating_add(size.saturating_mul(i));
                        self.push(out, &format!("{name}[{i}]"), *elem, off, size);
                    }
                }
                _ => self.push(out, &name, f.ty, at, f.size),
            }
        }
    }

    /// Tells if `ty` is a `char` type.
    fn is_char(&self, ty: TypeId) -> bool {
        let base = self.store.resolve(ty).ok().and_then(|t| self.store.get(t));
        matches!(
            base,
            Some(Type::Prim(Prim::Char | Prim::SChar | Prim::UChar))
        )
    }

    /// Adds one field row `{ path, offset, size, type, value }`.
    fn push(&self, out: &mut Vec<Value>, path: &str, ty: TypeId, offset: u64, size: u64) {
        let mut row = Object::new();
        row.push("path", Value::from(path));
        row.push("offset", Value::from(offset));
        row.push("size", Value::from(size));
        row.push(
            "type",
            Value::from(self.store.c_text(ty).unwrap_or_default()),
        );
        row.push("value", self.value(ty, offset, size));
        out.push(Value::Object(row));
    }
}

/// Gives the field rows of `typed` over `bytes`. A type that is not a record gives one row
/// with the path `.`.
#[must_use]
pub fn fields(program: &Program, typed: &Typed, bytes: &[u8], caps: Caps) -> Vec<Value> {
    let reader = Reader {
        store: &typed.store,
        model: program.types().model(),
        bytes,
        caps,
    };
    let mut out = Vec::new();
    let base = typed.store.resolve(typed.id).ok();
    if base
        .and_then(|t| typed.store.get(t))
        .is_some_and(|t| matches!(t, Type::Record(_)))
    {
        reader.fields(typed.id, 0, "", 0, &mut out);
    } else {
        reader.push(&mut out, ".", typed.id, 0, typed.size);
    }
    out
}
