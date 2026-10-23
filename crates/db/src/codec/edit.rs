//! The JSON form of an [`Edit`]: `op` names the variant, and the other members hold its fields.
//!
//! | `op` | Members |
//! |---|---|
//! | `SetName` | `addr`, `key`, `kind`, `primary`, `name`, `evidence` |
//! | `SetComment` | `addr`, `kind`, `text` |
//! | `SetVarFact` | `var`, `field`: `{"name":..}` or `{"type":..}` |
//! | `AddRef` | `ref` |
//! | `RemoveRef` | `key` |
//! | `CreateFunction` | `func`, `vars`: `[{"var","name","ty"}]`, `plate` |
//! | `DeleteFunction` | `func`, `cascade` |
//! | `SetSignature` | `func`, `sig` |
//! | `SetNoreturn` | `func`, `noreturn` |
//! | `SetJumpTable` | `at`, `table` |
//! | `SetFlowOverride` | `at`, `flow` |
//! | `SetDataDef` | `at`, `def` |
//! | `WriteNote` | `note` |
//! | `DeleteNote` | `id` |
//! | `ReplaceAnalysis` | `set`: the tables of the analysis layer |

use std::sync::Arc;

use ghidorah_base::VarId;
use ghidorah_json::Value;

use super::values::{Json, obj};
use super::{CodecError, Obj, tables};
use crate::edit::{Edit, EditKind, FuncRecord, VarField};
use crate::vars::VarFact;

/// Gives the JSON form of an edit.
pub(super) fn encode(edit: &Edit) -> Value {
    let op = ("op", Value::from(edit.kind().name()));
    match edit {
        Edit::SetName {
            addr,
            key,
            kind,
            primary,
            name,
            evidence,
        } => obj([
            op,
            ("addr", addr.enc()),
            ("key", key.enc()),
            ("kind", kind.enc()),
            ("primary", primary.enc()),
            ("name", name.enc()),
            ("evidence", evidence.enc()),
        ]),
        Edit::SetComment { addr, kind, text } => obj([
            op,
            ("addr", addr.enc()),
            ("kind", kind.enc()),
            ("text", text.enc()),
        ]),
        Edit::SetVarFact { var, field } => {
            let field = match field {
                VarField::Name(n) => obj([("name", n.enc())]),
                VarField::Type(t) => obj([("type", t.enc())]),
            };
            obj([op, ("var", var.enc()), ("field", field)])
        }
        Edit::AddRef { fact } => obj([op, ("ref", fact.enc())]),
        Edit::RemoveRef { key } => obj([op, ("key", key.enc())]),
        Edit::CreateFunction(r) => obj([
            op,
            ("func", r.func.enc()),
            (
                "vars",
                Value::Array(r.vars.iter().map(|(v, f)| var_row(v, f)).collect()),
            ),
            ("plate", r.plate.enc()),
        ]),
        Edit::DeleteFunction { id, cascade } => {
            obj([op, ("func", id.enc()), ("cascade", cascade.enc())])
        }
        Edit::SetSignature { id, sig } => obj([op, ("func", id.enc()), ("sig", sig.enc())]),
        Edit::SetNoreturn { id, noreturn } => {
            obj([op, ("func", id.enc()), ("noreturn", noreturn.enc())])
        }
        Edit::SetJumpTable { id, table } => obj([op, ("at", id.enc()), ("table", table.enc())]),
        Edit::SetFlowOverride { at, flow } => obj([op, ("at", at.enc()), ("flow", flow.enc())]),
        Edit::SetDataDef { at, def } => obj([op, ("at", at.enc()), ("def", def.enc())]),
        Edit::WriteNote(note) => obj([op, ("note", note.enc())]),
        Edit::DeleteNote { id } => obj([op, ("id", id.enc())]),
        Edit::ReplaceAnalysis(set) => obj([op, ("set", tables::encode(set))]),
    }
}

/// Gives the row of one variable of a function record.
pub(super) fn var_row(var: &VarId, facts: &VarFact) -> Value {
    obj([
        ("var", var.enc()),
        ("name", facts.name.enc()),
        ("ty", facts.ty.enc()),
    ])
}

/// Reads the row of one variable.
pub(super) fn var_from_row(v: &Value) -> Result<(VarId, VarFact), CodecError> {
    let o = Obj::new(v, &["var", "name", "ty"])?;
    Ok((
        o.get("var")?,
        VarFact {
            name: o.get("name")?,
            ty: o.get("ty")?,
        },
    ))
}

/// Gives the member names of the JSON form of `kind`, `op` first.
const fn names(kind: EditKind) -> &'static [&'static str] {
    match kind {
        EditKind::SetName => &["op", "addr", "key", "kind", "primary", "name", "evidence"],
        EditKind::SetComment => &["op", "addr", "kind", "text"],
        EditKind::SetVarFact => &["op", "var", "field"],
        EditKind::AddRef => &["op", "ref"],
        EditKind::RemoveRef => &["op", "key"],
        EditKind::CreateFunction => &["op", "func", "vars", "plate"],
        EditKind::DeleteFunction => &["op", "func", "cascade"],
        EditKind::SetSignature => &["op", "func", "sig"],
        EditKind::SetNoreturn => &["op", "func", "noreturn"],
        EditKind::SetJumpTable => &["op", "at", "table"],
        EditKind::SetFlowOverride => &["op", "at", "flow"],
        EditKind::SetDataDef => &["op", "at", "def"],
        EditKind::WriteNote => &["op", "note"],
        EditKind::DeleteNote => &["op", "id"],
        EditKind::ReplaceAnalysis => &["op", "set"],
    }
}

/// Reads the `field` member of a `SetVarFact` edit.
fn field(v: &Value) -> Result<VarField, CodecError> {
    if v.get("type").is_some() {
        return Ok(VarField::Type(Obj::new(v, &["type"])?.get("type")?));
    }
    Ok(VarField::Name(Obj::new(v, &["name"])?.get("name")?))
}

/// Reads an edit.
pub(super) fn decode(v: &Value) -> Result<Edit, CodecError> {
    if v.as_object().is_none() {
        return Err(CodecError::kind("object", v));
    }
    let op = v.get("op").map_or(Ok(""), |op| {
        op.as_str()
            .ok_or_else(|| CodecError::kind("string", op).at("op"))
    })?;
    let kind = EditKind::parse(op).ok_or_else(|| CodecError::text("edit kind").at("op"))?;
    let o = Obj::new(v, names(kind))?;
    Ok(match kind {
        EditKind::SetName => Edit::SetName {
            addr: o.get("addr")?,
            key: o.get("key")?,
            kind: o.get("kind")?,
            primary: o.get("primary")?,
            name: o.get("name")?,
            evidence: o.get("evidence")?,
        },
        EditKind::SetComment => Edit::SetComment {
            addr: o.get("addr")?,
            kind: o.get("kind")?,
            text: o.get("text")?,
        },
        EditKind::SetVarFact => Edit::SetVarFact {
            var: o.get("var")?,
            field: o.with("field", field)?,
        },
        EditKind::AddRef => Edit::AddRef {
            fact: o.get("ref")?,
        },
        EditKind::RemoveRef => Edit::RemoveRef { key: o.get("key")? },
        EditKind::CreateFunction => Edit::CreateFunction(Box::new(FuncRecord {
            func: o.get("func")?,
            vars: o.each("vars", var_from_row)?,
            plate: o.get("plate")?,
        })),
        EditKind::DeleteFunction => Edit::DeleteFunction {
            id: o.get("func")?,
            cascade: o.get("cascade")?,
        },
        EditKind::SetSignature => Edit::SetSignature {
            id: o.get("func")?,
            sig: o.get("sig")?,
        },
        EditKind::SetNoreturn => Edit::SetNoreturn {
            id: o.get("func")?,
            noreturn: o.get("noreturn")?,
        },
        EditKind::SetJumpTable => Edit::SetJumpTable {
            id: o.get("at")?,
            table: o.get("table")?,
        },
        EditKind::SetFlowOverride => Edit::SetFlowOverride {
            at: o.get("at")?,
            flow: o.get("flow")?,
        },
        EditKind::SetDataDef => Edit::SetDataDef {
            at: o.get("at")?,
            def: o.get("def")?,
        },
        EditKind::WriteNote => Edit::WriteNote(o.get("note")?),
        EditKind::DeleteNote => Edit::DeleteNote { id: o.get("id")? },
        EditKind::ReplaceAnalysis => {
            Edit::ReplaceAnalysis(Arc::new(o.with("set", tables::decode)?))
        }
    })
}
