//! The [`Json`] forms of the values of the tables: addresses, facts, names and IDs.

use ghidorah_base::{
    Address, ExportId, FuncId, Id, ImportId, JumpTableId, NoteId, Range, Rev, SetName, StringId,
    TxId, VarId, WarningCode,
};
use ghidorah_json::{DecodeKind, Value};
use ghidorah_kernel::RangeSet;
use ghidorah_types::TypeId;

use super::{CodecError, Obj, Reason};
use crate::comments::CommentKind;
use crate::fact::{Fact, SessionLabel};
use crate::funcs::{PartKind, StartReason};
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::{DataDef, FlowKind};
use crate::notes::{NoteKind, NoteStatus};
use crate::overrides::FlowOverride;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::strings::{Encoding, StrInfo};
use crate::symbols::{SymKey, SymKind};
use crate::why::RuleCode;

/// A value with a JSON form.
pub(crate) trait Json: Sized {
    /// Gives the JSON form.
    fn enc(&self) -> Value;

    /// Reads the JSON form.
    fn dec(v: &Value) -> Result<Self, CodecError>;
}

/// A RAM offset. Its form is the text of its RAM address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Off(pub u64);

/// Makes an object from members in their order.
pub(crate) fn obj<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::object(members)
}

pub(super) fn text(v: &Value) -> Result<&str, CodecError> {
    v.as_str().ok_or_else(|| CodecError::kind("string", v))
}

/// Reads a name of `names` and gives its item.
fn named<T: Copy>(
    v: &Value,
    form: &'static str,
    items: &[T],
    name: fn(T) -> &'static str,
) -> Result<T, CodecError> {
    let t = text(v)?;
    items
        .iter()
        .copied()
        .find(|i| name(*i) == t)
        .ok_or_else(|| CodecError::text(form))
}

macro_rules! int_json {
    ($read:ident, $($ty:ty),*) => {$(
        impl Json for $ty {
            fn enc(&self) -> Value {
                Value::from(*self)
            }

            fn dec(v: &Value) -> Result<Self, CodecError> {
                let n = v.as_number().ok_or_else(|| CodecError::kind("integer", v))?;
                n.$read()
                    .and_then(|w| Self::try_from(w).ok())
                    .ok_or_else(|| CodecError::new(Reason::Json(DecodeKind::Range)))
            }
        }
    )*};
}

int_json!(as_u64, u8, u16, u32, u64);
int_json!(as_i64, i8);

impl Json for bool {
    fn enc(&self) -> Value {
        Value::Bool(*self)
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        v.as_bool().ok_or_else(|| CodecError::kind("bool", v))
    }
}

impl Json for String {
    fn enc(&self) -> Value {
        Value::from(self.as_str())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        text(v).map(ToString::to_string)
    }
}

impl<T: Json> Json for Option<T> {
    fn enc(&self) -> Value {
        self.as_ref().map_or(Value::Null, Json::enc)
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        if v.is_null() {
            Ok(None)
        } else {
            T::dec(v).map(Some)
        }
    }
}

impl<T: Json> Json for Vec<T> {
    fn enc(&self) -> Value {
        Value::Array(self.iter().map(Json::enc).collect())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let items = v.as_array().ok_or_else(|| CodecError::kind("array", v))?;
        items
            .iter()
            .enumerate()
            .map(|(i, x)| T::dec(x).map_err(|e| e.at_index(i)))
            .collect()
    }
}

impl<T: Json> Json for Box<T> {
    fn enc(&self) -> Value {
        (**self).enc()
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        T::dec(v).map(Self::new)
    }
}

impl Json for Address {
    fn enc(&self) -> Value {
        Value::from(self.to_string())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        Self::parse(text(v)?).map_err(|_| CodecError::text("address"))
    }
}

impl Json for Off {
    fn enc(&self) -> Value {
        Address::ram(self.0).enc()
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let a = Address::dec(v)?;
        if a.is_ram() {
            Ok(Self(a.off))
        } else {
            Err(CodecError::text("RAM address"))
        }
    }
}

impl Json for Range {
    fn enc(&self) -> Value {
        obj([
            ("first", Off(self.first).enc()),
            ("last", Off(self.last).enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["first", "last"])?;
        let (first, last) = (o.get::<Off>("first")?.0, o.get::<Off>("last")?.0);
        Self::new(first, last).ok_or_else(|| CodecError::text("range"))
    }
}

impl Json for RangeSet {
    fn enc(&self) -> Value {
        self.ranges().to_vec().enc()
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        Vec::<Range>::dec(v).map(|r| Self::from_ranges(&r))
    }
}

impl Json for Source {
    fn enc(&self) -> Value {
        Value::from(self.name())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        named(v, "source", &Self::ALL, Self::name)
    }
}

impl Json for SessionLabel {
    fn enc(&self) -> Value {
        Value::from(self.as_str())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        Self::new(text(v)?).map_err(|_| CodecError::text("session label"))
    }
}

macro_rules! newtype_json {
    ($($ty:ident($inner:ty)),*) => {$(
        impl Json for $ty {
            fn enc(&self) -> Value {
                self.0.enc()
            }

            fn dec(v: &Value) -> Result<Self, CodecError> {
                <$inner>::dec(v).map($ty)
            }
        }
    )*};
}

newtype_json!(
    TxId(u64),
    Rev(u64),
    NoteId(u64),
    SymKey(u16),
    FuncId(Address)
);
newtype_json!(JumpTableId(Address), StringId(Address));

impl Json for TypeId {
    fn enc(&self) -> Value {
        self.index().enc()
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        u32::dec(v).map(Self::from_index)
    }
}

impl<T: Json> Json for Fact<T> {
    fn enc(&self) -> Value {
        obj([
            ("value", self.value.enc()),
            ("source", self.source.enc()),
            ("tx", self.tx.enc()),
            ("session", self.session.enc()),
            ("force", self.force.enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["value", "source", "tx", "session", "force"])?;
        Ok(Self {
            value: o.get("value")?,
            source: o.get("source")?,
            tx: o.get("tx")?,
            session: o.get("session")?,
            force: o.get("force")?,
        })
    }
}

/// The flow kinds of code units.
const FLOW_KINDS: [FlowKind; 8] = [
    FlowKind::Seq,
    FlowKind::Jmp,
    FlowKind::Jcc,
    FlowKind::Call,
    FlowKind::ICall,
    FlowKind::IJmp,
    FlowKind::Ret,
    FlowKind::Trap,
];

/// The methods of jump tables.
const JT_METHODS: [JtMethod; 2] = [JtMethod::A, JtMethod::Agent];

/// The string encodings.
const ENCODINGS: [Encoding; 3] = [Encoding::Ascii, Encoding::Utf8, Encoding::Utf16Le];

/// The kinds of function parts.
const PART_KINDS: [PartKind; 3] = [PartKind::Main, PartKind::Cold, PartKind::Thunk];

/// Gives the output name of a part kind.
const fn part_name(kind: PartKind) -> &'static str {
    match kind {
        PartKind::Main => "main",
        PartKind::Cold => "cold",
        PartKind::Thunk => "thunk",
    }
}

macro_rules! name_json {
    ($($ty:ident: $form:literal, $items:expr, $name:expr;)*) => {$(
        impl Json for $ty {
            fn enc(&self) -> Value {
                Value::from($name(*self))
            }

            fn dec(v: &Value) -> Result<Self, CodecError> {
                named(v, $form, &$items, $name)
            }
        }
    )*};
}

name_json! {
    SymKind: "symbol kind", SymKind::ALL, SymKind::name;
    CommentKind: "comment kind", CommentKind::ALL, CommentKind::name;
    RefType: "reference type", RefType::ALL, RefType::name;
    StartReason: "start reason", StartReason::ALL, StartReason::name;
    NoteKind: "note kind", NoteKind::ALL, NoteKind::name;
    NoteStatus: "note status", NoteStatus::ALL, NoteStatus::name;
    FlowKind: "flow kind", FLOW_KINDS, FlowKind::name;
    JtMethod: "jump-table method", JT_METHODS, JtMethod::name;
    Encoding: "encoding", ENCODINGS, Encoding::name;
    PartKind: "part kind", PART_KINDS, part_name;
    WarningCode: "warning code", WarningCode::ALL, WarningCode::name;
}

impl Json for RefKey {
    fn enc(&self) -> Value {
        obj([
            ("from", self.from.enc()),
            ("op_index", self.op_index.enc()),
            ("to", self.to.enc()),
            ("kind", self.kind.enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["from", "op_index", "to", "kind"])?;
        Ok(Self {
            from: o.get("from")?,
            op_index: o.get("op_index")?,
            to: o.get("to")?,
            kind: o.get("kind")?,
        })
    }
}

impl Json for Ref {
    fn enc(&self) -> Value {
        obj([("key", self.key.enc()), ("primary", self.primary.enc())])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["key", "primary"])?;
        Ok(Self {
            key: o.get("key")?,
            primary: o.get("primary")?,
        })
    }
}

impl Json for DataDef {
    fn enc(&self) -> Value {
        obj([("type", self.ty.enc()), ("len", self.len.enc())])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["type", "len"])?;
        Ok(Self {
            ty: o.get("type")?,
            len: o.get("len")?,
        })
    }
}

impl Json for JumpTable {
    fn enc(&self) -> Value {
        obj([
            ("base", self.base.enc()),
            ("entry_size", self.entry_size.enc()),
            ("count", self.count.enc()),
            ("targets", self.targets.enc()),
            ("method", self.method.enc()),
            ("resolved", self.resolved.enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let names = [
            "base",
            "entry_size",
            "count",
            "targets",
            "method",
            "resolved",
        ];
        let o = Obj::new(v, &names)?;
        Ok(Self {
            base: o.get("base")?,
            entry_size: o.get("entry_size")?,
            count: o.get("count")?,
            targets: o.get("targets")?,
            method: o.get("method")?,
            resolved: o.get("resolved")?,
        })
    }
}

impl Json for FlowOverride {
    fn enc(&self) -> Value {
        let kind = ("kind", Value::from(self.name()));
        match self {
            Self::Fallthrough(to) => obj([kind, ("to", to.enc())]),
            Self::CallAsJump | Self::JumpAsCall => obj([kind]),
            Self::IndirectTargets(t) => obj([kind, ("targets", t.enc())]),
        }
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let kind = v.get("kind").ok_or_else(|| CodecError::kind("object", v))?;
        match text(kind).map_err(|e| e.at("kind"))? {
            "fallthrough" => Ok(Self::Fallthrough(Obj::new(v, &["kind", "to"])?.get("to")?)),
            "call_as_jump" => Obj::new(v, &["kind"]).map(|_| Self::CallAsJump),
            "jump_as_call" => Obj::new(v, &["kind"]).map(|_| Self::JumpAsCall),
            "indirect_targets" => Ok(Self::IndirectTargets(
                Obj::new(v, &["kind", "targets"])?.get("targets")?,
            )),
            _ => Err(CodecError::text("flow override").at("kind")),
        }
    }
}

impl Json for StrInfo {
    fn enc(&self) -> Value {
        obj([
            ("encoding", self.encoding.enc()),
            ("len", self.len.enc()),
            ("referenced", self.referenced.enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["encoding", "len", "referenced"])?;
        Ok(Self {
            encoding: o.get("encoding")?,
            len: o.get("len")?,
            referenced: o.get("referenced")?,
        })
    }
}

/// Reads an ID text of one kind with `pick`.
fn id<T>(v: &Value, form: &'static str, pick: fn(Id) -> Option<T>) -> Result<T, CodecError> {
    Id::parse(text(v)?)
        .ok()
        .and_then(pick)
        .ok_or_else(|| CodecError::text(form))
}

impl Json for VarId {
    fn enc(&self) -> Value {
        Value::from(self.to_string())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        id(v, "variable ID", |i| match i {
            Id::Var(var) => Some(var),
            _ => None,
        })
    }
}

impl Json for ImportId {
    fn enc(&self) -> Value {
        Value::from(self.to_string())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        id(v, "import ID", |i| match i {
            Id::Import(x) => Some(x),
            _ => None,
        })
    }
}

impl Json for ExportId {
    fn enc(&self) -> Value {
        Value::from(self.to_string())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        id(v, "export ID", |i| match i {
            Id::Export(x) => Some(x),
            _ => None,
        })
    }
}

impl Json for SetName {
    fn enc(&self) -> Value {
        Value::from(self.as_str())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        Self::new(text(v)?).map_err(|_| CodecError::text("set name"))
    }
}

impl Json for RuleCode {
    fn enc(&self) -> Value {
        Value::from(self.as_str())
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        Self::new(text(v)?).map_err(|_| CodecError::text("rule code"))
    }
}
