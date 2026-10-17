//! The rows of `history_list`: one change per applied edit.
//!
//! | Edit | Kind | ID | `fields` |
//! |---|---|---|---|
//! | `SetName` | `name` | the address | `{ name, old, evidence }` |
//! | `SetComment` | `comment` | the address | `{ kind, text, old }` |
//! | `SetVarFact` | `var` | the `var:` ID | `{ field, value }` |
//! | `AddRef`, `RemoveRef` | `ref` | the `ref:` ID | `{ present, primary? }` |
//! | `CreateFunction`, `DeleteFunction` | `function` | the `fn:` ID | `{ present }` |
//! | `SetSignature` | `signature` | the `fn:` ID | `{ sig }` |
//! | `SetNoreturn` | `noreturn` | the `fn:` ID | `{ noreturn }` |
//! | `SetJumpTable` | `jumptable` | the `jt:` ID | `{ targets }` |
//! | `SetFlowOverride` | `flow` | the address | `{ flow, targets? }` |
//! | `SetDataDef` | `data` | the address | `{ type, len }` |
//! | `WriteNote`, `DeleteNote` | `note` | the `note:` ID | `{ present, kind?, status? }` |
//! | `ReplaceAnalysis`, a run marker | `analysis` | `analysis` or the `tx:` ID | `{}` or the run facts |
//!
//! A name of the source `imported` comes from the binary, so it has the `BinText` form.

use ghidorah_base::{Address, BinText, Caps, hex};
use ghidorah_json::{Limits, Value};
use ghidorah_types::TypeId;

use super::ChangeKind;
use crate::edit::{Edit, VarField};
use crate::fact::Fact;
use crate::journal::RunLine;
use crate::overrides::FlowOverride;
use crate::program::Program;
use crate::refs::RefKey;
use crate::source::Source;
use crate::tx::Applied;

/// One change of a fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Change {
    /// The kind of the fact.
    pub kind: ChangeKind,
    /// The ID of the fact.
    pub id: String,
    /// The address of the fact.
    pub addr: Option<Address>,
    /// The new state.
    pub fields: Value,
    /// The key of the fact: changes with one key coalesce.
    pub key: String,
}

/// Gives the JSON form of a text of the binary.
fn bin_text(text: &str) -> Value {
    let json = BinText::new(text.as_bytes()).to_json(Caps::DEFAULT);
    ghidorah_json::parse(&json, &Limits::DEFAULT).unwrap_or(Value::Null)
}

/// Gives the JSON form of a name fact: `null`, a text or a `BinText` for an imported name.
fn name_value(slot: Option<&Fact<String>>) -> Value {
    match slot {
        None => Value::Null,
        Some(f) if f.source == Source::Imported => bin_text(&f.value),
        Some(f) => Value::from(f.value.as_str()),
    }
}

/// Gives the `t:` reference of a type, or its index for a type without a reference.
fn type_value(program: &Program, ty: TypeId) -> Value {
    program
        .types()
        .type_ref(ty)
        .map_or_else(|_| Value::from(ty.index()), |r| Value::from(r.to_string()))
}

/// Gives the `ref:` ID of a reference key.
fn ref_id(key: &RefKey) -> String {
    format!("ref:{}>{}:{}", key.from, key.to, key.kind.name())
}

/// Gives the address list of jump-table or indirect targets.
fn targets(list: &[Address]) -> Value {
    Value::Array(list.iter().map(|a| Value::from(a.to_string())).collect())
}

/// Makes a change. Its key joins the kind, the ID and `sub`.
fn made(kind: ChangeKind, id: String, addr: Option<Address>, fields: Value, sub: &str) -> Change {
    let key = format!("{}|{id}|{sub}", kind.name());
    Change {
        kind,
        id,
        addr,
        fields,
        key,
    }
}

/// Gives `{ present }`.
fn present(yes: bool) -> Value {
    Value::object([("present", Value::Bool(yes))])
}

/// Gives the text of a comment fact, or `null`.
fn text_of(t: Option<&Fact<String>>) -> Value {
    t.map_or(Value::Null, |f| Value::from(f.value.as_str()))
}

/// Gives the change of a name, a comment or a variable edit.
fn text_change(program: &Program, a: &Applied) -> Option<Change> {
    Some(match &a.edit {
        Edit::SetName {
            addr,
            key,
            name,
            evidence,
            ..
        } => {
            let (old, old_key) = match &a.inverse {
                Edit::SetName { name, key, .. } => (name.as_ref(), *key),
                _ => (None, None),
            };
            let sym = key.or(old_key).map_or(0, |k| k.0);
            let evidence = evidence.iter().map(|e| Value::from(e.as_str())).collect();
            let fields = Value::object([
                ("name", name_value(name.as_ref())),
                ("old", name_value(old)),
                ("evidence", Value::Array(evidence)),
            ]);
            let sub = sym.to_string();
            made(
                ChangeKind::Name,
                addr.to_string(),
                Some(*addr),
                fields,
                &sub,
            )
        }
        Edit::SetComment { addr, kind, text } => {
            let old = match &a.inverse {
                Edit::SetComment { text, .. } => text.as_ref(),
                _ => None,
            };
            let fields = Value::object([
                ("kind", Value::from(kind.name())),
                ("text", text_of(text.as_ref())),
                ("old", text_of(old)),
            ]);
            let id = addr.to_string();
            made(ChangeKind::Comment, id, Some(*addr), fields, kind.name())
        }
        Edit::SetVarFact { var, field } => {
            let (name, value) = match field {
                VarField::Name(n) => ("name", name_value(n.as_ref())),
                VarField::Type(t) => (
                    "type",
                    t.as_ref()
                        .map_or(Value::Null, |f| type_value(program, f.value)),
                ),
            };
            let fields = Value::object([("field", Value::from(name)), ("value", value)]);
            made(
                ChangeKind::Var,
                var.to_string(),
                Some(var.func.0),
                fields,
                name,
            )
        }
        _ => return None,
    })
}

/// Gives the change of a function, signature or noreturn edit.
fn func_change(program: &Program, a: &Applied) -> Option<Change> {
    let (kind, id, fields) = match &a.edit {
        Edit::CreateFunction(r) => (ChangeKind::Function, r.func.id(), present(true)),
        Edit::DeleteFunction { id, .. } => (ChangeKind::Function, *id, present(false)),
        Edit::SetSignature { id, sig } => {
            let value = sig
                .as_ref()
                .map_or(Value::Null, |f| type_value(program, f.value));
            (ChangeKind::Signature, *id, Value::object([("sig", value)]))
        }
        Edit::SetNoreturn { id, noreturn } => {
            let value = noreturn
                .as_ref()
                .map_or(Value::Null, |f| Value::Bool(f.value));
            (
                ChangeKind::Noreturn,
                *id,
                Value::object([("noreturn", value)]),
            )
        }
        _ => return None,
    };
    Some(made(kind, id.to_string(), Some(id.0), fields, ""))
}

/// Gives the `fields` of a flow override slot.
fn flow_fields(flow: Option<&FlowOverride>) -> Value {
    match flow {
        None => Value::object([("flow", Value::Null)]),
        Some(FlowOverride::IndirectTargets(list)) => Value::object([
            ("flow", Value::from("indirect_targets")),
            ("targets", targets(list)),
        ]),
        Some(FlowOverride::Fallthrough(to)) => Value::object([
            ("flow", Value::from("fallthrough")),
            ("targets", targets(&[*to])),
        ]),
        Some(FlowOverride::CallAsJump) => Value::object([("flow", Value::from("call_as_jump"))]),
        Some(FlowOverride::JumpAsCall) => Value::object([("flow", Value::from("jump_as_call"))]),
    }
}

/// Gives the change of a reference, table, flow, data, note or analysis edit.
fn other_change(program: &Program, a: &Applied) -> Change {
    match &a.edit {
        Edit::AddRef { fact } => {
            let key = fact.value.key;
            let fields = Value::object([
                ("present", Value::Bool(true)),
                ("primary", Value::Bool(fact.value.primary)),
            ]);
            made(ChangeKind::Ref, ref_id(&key), Some(key.from), fields, "")
        }
        Edit::RemoveRef { key } => made(
            ChangeKind::Ref,
            ref_id(key),
            Some(key.from),
            present(false),
            "",
        ),
        Edit::SetJumpTable { id, table } => {
            let value = table
                .as_ref()
                .map_or(Value::Null, |f| targets(&f.value.targets));
            let fields = Value::object([("targets", value)]);
            made(
                ChangeKind::JumpTable,
                id.to_string(),
                Some(id.0),
                fields,
                "",
            )
        }
        Edit::SetFlowOverride { at, flow } => {
            let fields = flow_fields(flow.as_ref().map(|f| &f.value));
            made(ChangeKind::Flow, at.to_string(), Some(*at), fields, "")
        }
        Edit::SetDataDef { at, def } => {
            let fields = def.as_ref().map_or_else(
                || Value::object([("type", Value::Null)]),
                |f| {
                    Value::object([
                        ("type", type_value(program, f.value.ty)),
                        ("len", Value::from(f.value.len)),
                    ])
                },
            );
            made(ChangeKind::Data, at.to_string(), Some(*at), fields, "")
        }
        Edit::WriteNote(n) => {
            let fields = Value::object([
                ("present", Value::Bool(true)),
                ("kind", Value::from(n.kind.name())),
                ("status", Value::from(n.status.name())),
            ]);
            made(ChangeKind::Note, n.id.to_string(), n.at, fields, "")
        }
        Edit::DeleteNote { id } => made(ChangeKind::Note, id.to_string(), None, present(false), ""),
        _ => made(
            ChangeKind::Analysis,
            "analysis".to_owned(),
            None,
            Value::Object(ghidorah_json::Object::new()),
            "",
        ),
    }
}

/// Gives the change of one applied edit.
pub(super) fn change(program: &Program, a: &Applied) -> Change {
    text_change(program, a)
        .or_else(|| func_change(program, a))
        .unwrap_or_else(|| other_change(program, a))
}

/// Gives the change of an analysis run marker. Each run is its own fact.
pub(super) fn run_change(line: &RunLine) -> Change {
    let id = line.tx.to_string();
    Change {
        kind: ChangeKind::Analysis,
        key: format!("analysis|{id}|run"),
        id,
        addr: None,
        fields: Value::object([
            ("state", Value::from(line.state.name())),
            ("inputs_hash", Value::from(hex::encode(&line.inputs_hash))),
            ("fuel_used", Value::from(line.fuel_used)),
            ("result_hash", Value::from(hex::encode(&line.result_hash))),
        ]),
    }
}
