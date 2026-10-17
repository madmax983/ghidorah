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
//! - An enum has the size of `int` when its values fit in 32 bits, else the size of `long long`.
//!
//! Bit-fields and packing are not in the MVP. The C parser rejects them.

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::ErrorCode;

use crate::model::{DataModel, SizeAlign};
use crate::store::{MAX_DEPTH, StoreError, TypeStore};
use crate::ty::{Enum, Record, RecordKind, Type, TypeId};

/// The bits in a byte.
const BYTE: u64 = 8;

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
    /// The size of the type in bits does not fit in 64 bits. The ID is the first type
    /// whose size does not fit.
    Overflow(TypeId),
    /// The type graph is deeper than [`MAX_DEPTH`].
    Depth,
}

impl LayoutError {
    /// Gives the tool error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownId(_) => ErrorCode::NotFound,
            Self::Depth => ErrorCode::LimitExceeded,
            _ => ErrorCode::InvalidArgument,
        }
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownId(id) => write!(f, "The type ID {} is not in the store.", id.index()),
            Self::Incomplete(id) => write!(
                f,
                "The type {} is incomplete. It has no known size.",
                id.index()
            ),
            Self::NotObject(id) => write!(
                f,
                "The type {} is a function type. It has no size.",
                id.index()
            ),
            Self::Overflow(id) => write!(
                f,
                "The size of the type {} does not fit in 64 bits of bits.",
                id.index()
            ),
            Self::Depth => write!(f, "The type graph is deeper than {MAX_DEPTH} levels."),
        }
    }
}

impl std::error::Error for LayoutError {}

/// The size and the alignment of a type, in bits.
#[derive(Debug, Clone, Copy)]
struct Bits {
    size: u64,
    align: u64,
}

impl Bits {
    fn of(id: TypeId, sa: SizeAlign) -> Result<Self, LayoutError> {
        let size = sa.size.checked_mul(BYTE).ok_or(LayoutError::Overflow(id))?;
        let align = sa
            .align
            .max(1)
            .checked_mul(BYTE)
            .ok_or(LayoutError::Overflow(id))?;
        Ok(Self { size, align })
    }
}

/// One layout computation with a memo of the sizes.
struct Ctx<'a> {
    store: &'a TypeStore,
    model: &'a DataModel,
    memo: BTreeMap<TypeId, Bits>,
}

impl Ctx<'_> {
    fn bits(&mut self, id: TypeId, depth: usize) -> Result<Bits, LayoutError> {
        if depth > MAX_DEPTH {
            return Err(LayoutError::Depth);
        }
        if let Some(b) = self.memo.get(&id) {
            return Ok(*b);
        }
        let next = depth.saturating_add(1);
        let b = match self.store.get(id).ok_or(LayoutError::UnknownId(id))? {
            Type::Prim(p) => Bits::of(id, self.model.prim(*p).ok_or(LayoutError::Incomplete(id))?)?,
            Type::Ptr(_) => Bits::of(id, self.model.pointer)?,
            Type::Array { elem, len } => {
                let n = len.ok_or(LayoutError::Incomplete(id))?;
                let e = self.bits(*elem, next)?;
                Bits {
                    size: e.size.checked_mul(n).ok_or(LayoutError::Overflow(id))?,
                    align: e.align,
                }
            }
            Type::Record(r) => {
                if !r.complete {
                    return Err(LayoutError::Incomplete(id));
                }
                self.record(id, r, next)?.0
            }
            Type::Enum(e) => {
                if !e.complete {
                    return Err(LayoutError::Incomplete(id));
                }
                Bits::of(id, self.enum_size(id, e)?)?
            }
            Type::Typedef { target, .. } => self.bits(*target, next)?,
            Type::Qual { inner, .. } => self.bits(*inner, next)?,
            Type::Func(_) => return Err(LayoutError::NotObject(id)),
        };
        self.memo.insert(id, b);
        Ok(b)
    }

    /// Gives the size of an enum: `int` when the values fit in 32 bits, else `long long`.
    fn enum_size(&self, id: TypeId, e: &Enum) -> Result<SizeAlign, LayoutError> {
        let fits = |lo: i128, hi: i128| e.items.iter().all(|i| lo <= i.value && i.value <= hi);
        let signed32 = fits(i128::from(i32::MIN), i128::from(i32::MAX));
        let unsigned32 = fits(0, i128::from(u32::MAX));
        let signed64 = fits(i128::from(i64::MIN), i128::from(i64::MAX));
        let unsigned64 = fits(0, i128::from(u64::MAX));
        if signed32 || unsigned32 {
            Ok(self.model.int)
        } else if signed64 || unsigned64 {
            Ok(self.model.long_long)
        } else {
            Err(LayoutError::Overflow(id))
        }
    }

    /// Gives the size of a record and the offset and the size of each field, in bits.
    fn record(
        &mut self,
        id: TypeId,
        r: &Record,
        depth: usize,
    ) -> Result<(Bits, Vec<(u64, u64)>), LayoutError> {
        let mut end = 0u64;
        let mut align = BYTE;
        let mut fields = Vec::with_capacity(r.fields.len());
        let flexible_elem = |t: TypeId| match self.store.strip(t).and_then(|s| self.store.get(s)) {
            Some(Type::Array { elem, len: None }) => Some(*elem),
            _ => None,
        };
        let elems: Vec<Option<TypeId>> = r.fields.iter().map(|f| flexible_elem(f.ty)).collect();
        for (f, flex) in r.fields.iter().zip(elems) {
            let (b, size) = if let Some(elem) = flex {
                (self.bits(elem, depth)?, 0)
            } else {
                let b = self.bits(f.ty, depth)?;
                (b, b.size)
            };
            align = align.max(b.align);
            let offset = match r.kind {
                RecordKind::Struct => end
                    .checked_next_multiple_of(b.align)
                    .ok_or(LayoutError::Overflow(id))?,
                RecordKind::Union => 0,
            };
            let field_end = offset.checked_add(size).ok_or(LayoutError::Overflow(id))?;
            end = end.max(field_end);
            fields.push((offset, size));
        }
        let size = end
            .checked_next_multiple_of(align)
            .ok_or(LayoutError::Overflow(id))?;
        Ok((Bits { size, align }, fields))
    }
}

/// Gives the natural layout of the type `id` in the data model `model`.
///
/// A record, or a typedef of a record, gives the layout of each field.
///
/// # Errors
///
/// Returns [`LayoutError`] for an unknown, incomplete or function type, an overflow or a
/// type graph that is too deep.
pub fn sysv(store: &TypeStore, id: TypeId, model: &DataModel) -> Result<Layout, LayoutError> {
    let mut ctx = Ctx {
        store,
        model,
        memo: BTreeMap::new(),
    };
    let b = ctx.bits(id, 0)?;
    let mut fields = Vec::new();
    let target = store.strip(id).ok_or(LayoutError::UnknownId(id))?;
    if let Some(Type::Record(r)) = store.get(target) {
        let (_, places) = ctx.record(target, r, 1)?;
        for (f, (offset, size)) in r.fields.iter().zip(places) {
            fields.push(FieldLayout {
                name: f.name.clone(),
                offset: offset / BYTE,
                size: size / BYTE,
                ty: f.ty,
            });
        }
    }
    Ok(Layout {
        size: b.size / BYTE,
        align: b.align / BYTE,
        fields,
    })
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
    let mut lines = vec![format!(
        "{} size={} align={}\n",
        store.c_text(id)?,
        layout.size,
        layout.align
    )];
    for f in &layout.fields {
        lines.push(format!(
            "+{:#x} {}\n",
            f.offset,
            store.c_decl(f.ty, &f.name)?
        ));
    }
    Ok(lines.concat())
}
