//! The input rules of edits: the fact keys, the normal form, the origin check, the no-op
//! test and the write rule.

use ghidorah_base::{Address, Id};
use ghidorah_json::Value;
use ghidorah_types::TypeId;

use super::apply::{Ctx, Mode};
use super::{BlockedEdit, Edit, EditError, Layer, MAX_EVIDENCE, MAX_EVIDENCE_LEN, VarField};
use crate::codec::Json;
use crate::comments::CommentKind;
use crate::fact::{Fact, Invalid, Origin};
use crate::notes::{NoteSet, SetMembers};
use crate::overrides::FlowOverride;
use crate::program::Program;
use crate::source::write_rule;
use crate::why::FactKey;

/// Gives the keys of the facts that `edit` names, in key order.
pub(super) fn keys(edit: &Edit) -> Vec<FactKey> {
    let mut out = match edit {
        Edit::SetName { addr, key, .. } => {
            key.map(|k| FactKey::Symbol(*addr, k)).into_iter().collect()
        }
        Edit::SetComment { addr, kind, .. } => vec![FactKey::Comment(*addr, *kind)],
        Edit::SetVarFact { var, .. } => vec![FactKey::Var(var.clone())],
        Edit::AddRef { fact } => vec![FactKey::Ref(fact.value.key)],
        Edit::RemoveRef { key } => vec![FactKey::Ref(*key)],
        Edit::CreateFunction(r) => {
            let id = r.func.id();
            let mut v = vec![FactKey::Func(id)];
            if r.func.sig.is_some() {
                v.push(FactKey::Signature(id));
            }
            if r.func.flags.noreturn.is_some() {
                v.push(FactKey::Noreturn(id));
            }
            if r.plate.is_some() {
                v.push(FactKey::Comment(r.func.entry, CommentKind::Plate));
            }
            v.extend(r.vars.iter().map(|(var, _)| FactKey::Var(var.clone())));
            v
        }
        Edit::DeleteFunction { id, .. } => vec![FactKey::Func(*id)],
        Edit::SetSignature { id, .. } => vec![FactKey::Signature(*id)],
        Edit::SetNoreturn { id, .. } => vec![FactKey::Noreturn(*id)],
        Edit::SetJumpTable { id, .. } => vec![FactKey::JumpTable(*id)],
        Edit::SetFlowOverride { at, .. } => vec![FactKey::FlowOverride(*at)],
        Edit::SetDataDef { at, .. } => vec![FactKey::Data(at.off)],
        Edit::WriteNote(n) => vec![FactKey::Note(n.id)],
        Edit::DeleteNote { id } => vec![FactKey::Note(*id)],
        Edit::ReplaceAnalysis(_) => Vec::new(),
    };
    out.sort();
    out.dedup();
    out
}

/// Puts a forward edit in its normal form: an empty comment removes the comment, and the
/// indirect targets and the ID members of a set are sorted without duplicates.
pub(crate) fn normalize(edit: &mut Edit) {
    match edit {
        Edit::SetComment { text, .. } => {
            if text.as_ref().is_some_and(|t| t.value.is_empty()) {
                *text = None;
            }
        }
        Edit::SetFlowOverride {
            flow:
                Some(Fact {
                    value: FlowOverride::IndirectTargets(targets),
                    ..
                }),
            ..
        } => {
            targets.sort_unstable();
            targets.dedup();
        }
        Edit::WriteNote(note) => {
            if let Some(NoteSet {
                members: SetMembers::Ids(ids),
                ..
            }) = &mut note.set
            {
                ids.sort_unstable();
                ids.dedup();
            }
        }
        _ => {}
    }
}

/// Checks that a fact of an edit belongs to the layer of the Tx. A forward fact also needs
/// the origin of the Tx.
pub(super) fn own<T>(ctx: &Ctx<'_>, key: &FactKey, fact: &Fact<T>) -> Result<(), EditError> {
    if Layer::of(fact.source) != Some(ctx.layer()) {
        return Err(EditError::WrongLayer(fact.source));
    }
    let o = ctx.origin;
    let same = fact.source == o.source
        && fact.tx == o.tx
        && fact.session == o.session
        && fact.force == o.force;
    if ctx.mode == Mode::Forward && !same {
        return Err(EditError::Origin(key.clone()));
    }
    Ok(())
}

/// Tells if two slots hold the same fact. A forward edit compares the value and the source.
/// An exact edit compares the whole fact.
pub(super) fn same<T: PartialEq>(mode: Mode, a: Option<&Fact<T>>, b: Option<&Fact<T>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => match mode {
            Mode::Exact => x == y,
            Mode::Forward => x.value == y.value && x.source == y.source,
        },
        _ => false,
    }
}

/// Applies the write rule to a write over a fact with the origin `current`.
///
/// `value` gives the JSON form of the current value for the error.
pub(super) fn rule(
    ctx: &Ctx<'_>,
    key: &FactKey,
    current: Origin,
    value: impl FnOnce() -> Value,
) -> Result<(), EditError> {
    let o = ctx.origin;
    if ctx.mode == Mode::Exact || write_rule(current.source, o.source, o.force).is_allowed() {
        return Ok(());
    }
    Err(EditError::Blocked(Box::new(BlockedEdit {
        key: key.clone(),
        value: value(),
        current,
        attempted: o.source,
        force: o.force,
    })))
}

/// Tells if the write of `new` over `current` is a no-op. Else applies the write rule.
pub(super) fn gate<T: PartialEq + Json>(
    ctx: &Ctx<'_>,
    key: &FactKey,
    current: Option<&Fact<T>>,
    new: Option<&Fact<T>>,
) -> Result<bool, EditError> {
    if same(ctx.mode, current, new) {
        return Ok(true);
    }
    if let Some(c) = current {
        rule(ctx, key, c.origin(), || c.value.enc())?;
    }
    Ok(false)
}

/// Checks the evidence of a forward `SetName` edit.
pub(super) fn evidence(items: &[String]) -> Result<(), EditError> {
    if items.len() > MAX_EVIDENCE {
        return Err(Invalid::TooMany {
            count: items.len(),
            max: MAX_EVIDENCE,
        }
        .into());
    }
    match items
        .iter()
        .map(|t| t.chars().count())
        .find(|n| *n > MAX_EVIDENCE_LEN)
    {
        Some(len) => Err(Invalid::TooLong {
            len,
            max: MAX_EVIDENCE_LEN,
        }
        .into()),
        None => Ok(()),
    }
}

/// Checks that the type store has the type `ty`.
pub(super) fn known(p: &Program, ty: TypeId) -> Result<(), EditError> {
    match p.types().store().get(ty) {
        Some(_) => Ok(()),
        None => Err(EditError::UnknownType(ty)),
    }
}

/// Checks that `ty` is a function type.
pub(super) fn signature(p: &Program, ty: TypeId) -> Result<(), EditError> {
    known(p, ty)?;
    match p.types().sig(ty) {
        Some(_) => Ok(()),
        None => Err(EditError::NotFuncType(ty)),
    }
}

/// Checks the type of a forward variable fact.
pub(super) fn var_type(p: &Program, field: &VarField) -> Result<(), EditError> {
    match field {
        VarField::Type(Some(t)) => known(p, t.value),
        _ => Ok(()),
    }
}

/// Checks the targets of a forward jump table or indirect target list (invariant 8).
pub(super) fn targets(p: &Program, targets: &[Address]) -> Result<(), EditError> {
    match targets.iter().find(|t| !p.is_code_target(**t)) {
        Some(t) => Err(EditError::BadTarget(*t)),
        None => Ok(()),
    }
}

/// Tells if a code unit or a data definition starts at `at` (invariant 2).
pub(crate) fn starts_unit(p: &Program, at: Address) -> bool {
    at.is_ram() && (p.code_unit(at.off).is_some() || p.data_def(at.off).is_some())
}

/// Tells if `text` parses as an ID.
pub(crate) fn is_id(text: &str) -> bool {
    Id::parse(text).is_ok()
}
