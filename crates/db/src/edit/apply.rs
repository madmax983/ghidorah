//! The apply step of an edit: the mode checks, the write rule and the exact write.
//!
//! An exact write of a slot first removes the current fact with the rank `User`, so no rule
//! blocks it. Then it puts the new fact with its own origin. A failed put puts the old fact
//! back, so a failed edit changes nothing.

use ghidorah_base::{Address, JumpTableId, NoteId, Rev, TxId, VarId};

use super::rules::{evidence, gate, known, own, rule, same, starts_unit, targets, var_type};
use super::{Edit, EditError, Layer, VarField, funcs};
use crate::codec::Json;
use crate::comments::CommentKind;
use crate::fact::{Fact, Invalid, Origin, WriteError};
use crate::jumptables::JumpTable;
use crate::listing::DataDef;
use crate::notes::Note;
use crate::overrides::FlowOverride;
use crate::program::{Program, Tables};
use crate::refs::{Ref, RefKey};
use crate::source::Source;
use crate::symbols::{SymKey, SymKind, Symbol};
use crate::why::FactKey;

/// How an edit applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// A new edit of a transaction: origin, write rule and input rules apply.
    Forward,
    /// A rollback, undo or replay edit: it puts its exact state.
    Exact,
}

/// The context of one apply step.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ctx<'a> {
    /// The origin of the transaction. Its source selects the layer.
    pub origin: &'a Origin,
    /// The mode.
    pub mode: Mode,
    /// The revision that the commit of the transaction gives.
    pub rev: Rev,
}

impl Ctx<'_> {
    /// Gives the layer of the transaction.
    pub(crate) fn layer(&self) -> Layer {
        Layer::of(self.origin.source).unwrap_or(Layer::Base)
    }

    /// Tells if the edit is a forward edit.
    pub(crate) fn forward(&self) -> bool {
        self.mode == Mode::Forward
    }
}

/// Gives the origin that removes any fact: the rank `User` with no force.
pub(super) fn top() -> Origin {
    let mut o = Origin::load();
    o.source = Source::User;
    o
}

/// Gives the edit error of a manager write.
pub(super) fn werr<T>(e: WriteError<T>) -> EditError {
    match e {
        WriteError::Invalid(i) => i.into(),
        WriteError::Blocked(b) => Invalid::BadSource(b.attempted).into(),
    }
}

/// Gives the tables of a layer for a change.
pub(super) fn tables(p: &mut Program, layer: Layer) -> Result<&mut Tables, EditError> {
    let source = match layer {
        Layer::Base => Source::Agent,
        Layer::Analysis => Source::Analysis,
    };
    Ok(p.layer_mut(source)?)
}

/// Puts the exact slot `new` with `write`. Gives the old fact.
pub(super) fn exact<M, T: Clone>(
    m: &mut M,
    new: Option<&Fact<T>>,
    mut write: impl FnMut(&mut M, Option<T>, &Origin) -> Result<Option<Fact<T>>, WriteError<T>>,
) -> Result<Option<Fact<T>>, EditError> {
    let old = write(m, None, &top()).map_err(werr)?;
    if let Some(f) = new
        && let Err(e) = write(m, Some(f.value.clone()), &f.origin())
    {
        if let Some(o) = &old {
            // The old fact was valid in this slot, so the put succeeds.
            let _ = write(m, Some(o.value.clone()), &o.origin());
        }
        return Err(werr(e));
    }
    Ok(old)
}

/// Applies `edit` to `program`. Gives the exact inverse, or `None` for a no-op.
///
/// # Errors
///
/// Returns the [`EditError`] of the first broken rule. Then the program does not change.
pub(crate) fn apply(
    program: &mut Program,
    edit: &Edit,
    ctx: &Ctx<'_>,
) -> Result<Option<Edit>, EditError> {
    match edit {
        Edit::SetName {
            addr,
            key,
            kind,
            primary,
            name,
            evidence: items,
        } => {
            if ctx.forward() {
                evidence(items)?;
            }
            set_name(program, ctx, *addr, *key, (*kind, *primary), name.as_ref())
        }
        Edit::SetComment { addr, kind, text } => {
            set_comment(program, ctx, *addr, *kind, text.as_ref())
        }
        Edit::SetVarFact { var, field } => set_var_fact(program, ctx, var, field),
        Edit::AddRef { fact } => add_ref(program, ctx, fact),
        Edit::RemoveRef { key } => remove_ref(program, ctx, *key),
        Edit::CreateFunction(r) => funcs::create(program, ctx, r),
        Edit::DeleteFunction { id, cascade } => funcs::delete(program, ctx, *id, *cascade),
        Edit::SetSignature { id, sig } => funcs::signature(program, ctx, *id, sig.as_ref()),
        Edit::SetNoreturn { id, noreturn } => funcs::noreturn(program, ctx, *id, noreturn.as_ref()),
        Edit::SetJumpTable { id, table } => set_jump_table(program, ctx, *id, table.as_ref()),
        Edit::SetFlowOverride { at, flow } => set_flow(program, ctx, *at, flow.as_ref()),
        Edit::SetDataDef { at, def } => set_data(program, ctx, *at, def.as_ref()),
        Edit::WriteNote(note) => write_note(program, ctx, note),
        Edit::DeleteNote { id } => delete_note(program, ctx, *id),
        Edit::ReplaceAnalysis(set) => {
            if ctx.layer() != Layer::Analysis {
                return Err(EditError::WrongLayer(ctx.origin.source));
            }
            if **set == *program.analysis() {
                return Ok(None);
            }
            let old = program.swap_analysis(set.clone());
            Ok(Some(Edit::ReplaceAnalysis(old)))
        }
    }
}

/// Applies a `SetVarFact` edit.
fn set_var_fact(
    p: &mut Program,
    ctx: &Ctx<'_>,
    var: &VarId,
    field: &VarField,
) -> Result<Option<Edit>, EditError> {
    if ctx.forward() {
        var_type(p, field)?;
    }
    let key = FactKey::Var(var.clone());
    let t = tables(p, ctx.layer())?;
    let current = t.vars.get(var).cloned().unwrap_or_default();
    let field = match field {
        VarField::Name(n) => {
            let new = slot(ctx, &key, n.as_ref())?;
            if gate(ctx, &key, current.name.as_ref(), new)? {
                return Ok(None);
            }
            VarField::Name(exact(&mut t.vars, new, |m, v, o| m.set_name(var, v, o))?)
        }
        VarField::Type(ty) => {
            let new = slot(ctx, &key, ty.as_ref())?;
            if gate(ctx, &key, current.ty.as_ref(), new)? {
                return Ok(None);
            }
            VarField::Type(exact(&mut t.vars, new, |m, v, o| m.set_type(var, v, o))?)
        }
    };
    Ok(Some(Edit::SetVarFact {
        var: var.clone(),
        field,
    }))
}

/// Applies a `SetJumpTable` edit.
fn set_jump_table(
    p: &mut Program,
    ctx: &Ctx<'_>,
    id: JumpTableId,
    table: Option<&Fact<JumpTable>>,
) -> Result<Option<Edit>, EditError> {
    let key = FactKey::JumpTable(id);
    let new = slot(ctx, &key, table)?;
    if let Some(t) = new
        && ctx.forward()
    {
        targets(p, &t.value.targets)?;
    }
    let t = tables(p, ctx.layer())?;
    if gate(ctx, &key, t.jumptables.get(id), new)? {
        return Ok(None);
    }
    let old = exact(&mut t.jumptables, new, |m, v, o| m.set(id, v, o))?;
    Ok(Some(Edit::SetJumpTable { id, table: old }))
}

/// Applies a `SetFlowOverride` edit.
fn set_flow(
    p: &mut Program,
    ctx: &Ctx<'_>,
    at: Address,
    flow: Option<&Fact<FlowOverride>>,
) -> Result<Option<Edit>, EditError> {
    let key = FactKey::FlowOverride(at);
    let new = slot(ctx, &key, flow)?;
    if let Some(Fact {
        value: FlowOverride::IndirectTargets(list),
        ..
    }) = new
        && ctx.forward()
    {
        targets(p, list)?;
    }
    let t = tables(p, ctx.layer())?;
    if gate(ctx, &key, t.overrides.get(at), new)? {
        return Ok(None);
    }
    let old = exact(&mut t.overrides, new, |m, v, o| m.set(at, v, o))?;
    Ok(Some(Edit::SetFlowOverride { at, flow: old }))
}

/// Applies a `SetDataDef` edit.
fn set_data(
    p: &mut Program,
    ctx: &Ctx<'_>,
    at: Address,
    def: Option<&Fact<DataDef>>,
) -> Result<Option<Edit>, EditError> {
    if !at.is_ram() {
        return Err(Invalid::NotRam(at).into());
    }
    let key = FactKey::Data(at.off);
    let new = slot(ctx, &key, def)?;
    if let Some(d) = new
        && ctx.forward()
    {
        known(p, d.value.ty)?;
    }
    let t = tables(p, ctx.layer())?;
    if gate(ctx, &key, t.listing.data(at.off), new)? {
        return Ok(None);
    }
    let old = exact(&mut t.listing, new, |m, v, o| m.set_data(at.off, v, o))?;
    Ok(Some(Edit::SetDataDef { at, def: old }))
}

/// Checks the fact of a slot with [`own`] and gives the slot.
fn slot<'a, T>(
    ctx: &Ctx<'_>,
    key: &FactKey,
    new: Option<&'a Fact<T>>,
) -> Result<Option<&'a Fact<T>>, EditError> {
    if let Some(f) = new {
        own(ctx, key, f)?;
    }
    Ok(new)
}

/// Applies a `SetName` edit. `new_sym` gives the kind and the primary flag of a new symbol.
fn set_name(
    p: &mut Program,
    ctx: &Ctx<'_>,
    addr: Address,
    key: Option<SymKey>,
    (kind, primary): (SymKind, bool),
    name: Option<&Fact<String>>,
) -> Result<Option<Edit>, EditError> {
    let t = tables(p, ctx.layer())?;
    let target = match key {
        Some(k) => t.symbols.get(addr, k),
        None => t.symbols.primary(addr),
    }
    .cloned();
    let slot_key = match (&target, key) {
        (Some(s), _) => s.key,
        (None, Some(k)) => k,
        (None, None) => t.symbols.next_key(addr)?,
    };
    let fkey = FactKey::Symbol(addr, slot_key);
    let name = slot(ctx, &fkey, name)?;
    if gate(ctx, &fkey, target.as_ref().map(|s| &s.name), name)? {
        return Ok(None);
    }
    let restore = |s: &Symbol| Edit::SetName {
        addr,
        key: Some(s.key),
        kind: s.kind,
        primary: s.primary,
        name: Some(s.name.clone()),
        evidence: Vec::new(),
    };
    Ok(match (target, name) {
        (None, None) => None,
        (Some(s), None) => {
            t.symbols.remove(addr, s.key);
            Some(restore(&s))
        }
        (None, Some(f)) => {
            let symbol = Symbol {
                addr,
                key: slot_key,
                name: f.clone(),
                kind,
                primary,
            };
            t.symbols.put_exact(symbol)?;
            Some(Edit::SetName {
                addr,
                key: Some(slot_key),
                kind,
                primary,
                name: None,
                evidence: Vec::new(),
            })
        }
        (Some(s), Some(f)) => {
            t.symbols.rename_exact(addr, s.key, f.clone())?;
            Some(restore(&s))
        }
    })
}

/// Applies a `SetComment` edit.
fn set_comment(
    p: &mut Program,
    ctx: &Ctx<'_>,
    addr: Address,
    kind: CommentKind,
    text: Option<&Fact<String>>,
) -> Result<Option<Edit>, EditError> {
    let key = FactKey::Comment(addr, kind);
    let new = slot(ctx, &key, text)?;
    let t = tables(p, ctx.layer())?;
    if gate(ctx, &key, t.comments.get(addr, kind), new)? {
        return Ok(None);
    }
    let old = exact(&mut t.comments, new, |m, v, o| m.set(addr, kind, v, o))?;
    Ok(Some(Edit::SetComment {
        addr,
        kind,
        text: old,
    }))
}

/// Applies an `AddRef` edit.
fn add_ref(p: &mut Program, ctx: &Ctx<'_>, fact: &Fact<Ref>) -> Result<Option<Edit>, EditError> {
    let key = fact.value.key;
    let fkey = FactKey::Ref(key);
    own(ctx, &fkey, fact)?;
    if ctx.forward() && !starts_unit(p, key.from) {
        return Err(EditError::NotCode(key.from));
    }
    let t = tables(p, ctx.layer())?;
    if gate(ctx, &fkey, t.refs.get(&key), Some(fact))? {
        return Ok(None);
    }
    let old = t.refs.remove(&key, &top()).map_err(werr)?;
    t.refs.add(fact.value, &fact.origin()).map_err(werr)?;
    Ok(Some(old.map_or(Edit::RemoveRef { key }, |o| {
        Edit::AddRef { fact: o }
    })))
}

/// Applies a `RemoveRef` edit.
fn remove_ref(p: &mut Program, ctx: &Ctx<'_>, key: RefKey) -> Result<Option<Edit>, EditError> {
    let t = tables(p, ctx.layer())?;
    if gate(ctx, &FactKey::Ref(key), t.refs.get(&key), None)? {
        return Ok(None);
    }
    let old = t.refs.remove(&key, &top()).map_err(werr)?;
    Ok(old.map(|o| Edit::AddRef { fact: o }))
}

/// Gives the origin of a note for the write rule.
fn note_origin(n: &Note) -> Origin {
    Origin::new(n.src, TxId(0), n.session.clone(), false)
}

/// Tells if two notes are the same for a forward edit: equal but for `rev` and `session`.
fn same_note(a: &Note, b: &Note) -> bool {
    let mut b = b.clone();
    b.rev = a.rev;
    b.session = a.session.clone();
    *a == b
}

/// Applies a `WriteNote` edit.
fn write_note(p: &mut Program, ctx: &Ctx<'_>, note: &Note) -> Result<Option<Edit>, EditError> {
    let key = FactKey::Note(note.id);
    if ctx.layer() != Layer::Base {
        return Err(EditError::WrongLayer(ctx.origin.source));
    }
    if Layer::of(note.src) != Some(Layer::Base) {
        return Err(EditError::WrongLayer(note.src));
    }
    let o = ctx.origin;
    if ctx.forward() && (note.src, &note.session, note.rev) != (o.source, &o.session, ctx.rev) {
        return Err(EditError::Origin(key));
    }
    let current = p.notes().get(note.id).cloned();
    if let Some(c) = &current {
        let noop = match ctx.mode {
            Mode::Exact => c == note,
            Mode::Forward => same_note(c, note),
        };
        if noop {
            return Ok(None);
        }
        rule(ctx, &key, note_origin(c), || c.enc())?;
    }
    let old = p.notes_mut().write(note.clone())?;
    Ok(Some(old.map_or(Edit::DeleteNote { id: note.id }, |n| {
        Edit::WriteNote(Box::new(n))
    })))
}

/// Applies a `DeleteNote` edit.
fn delete_note(p: &mut Program, ctx: &Ctx<'_>, id: NoteId) -> Result<Option<Edit>, EditError> {
    if ctx.layer() != Layer::Base {
        return Err(EditError::WrongLayer(ctx.origin.source));
    }
    let Some(current) = p.notes().get(id).cloned() else {
        return Ok(None);
    };
    rule(ctx, &FactKey::Note(id), note_origin(&current), || {
        current.enc()
    })?;
    Ok(p.notes_mut()
        .delete(id)
        .map(|n| Edit::WriteNote(Box::new(n))))
}

/// Tells if a slot of a record holds the same fact as `new`, for the no-op test.
pub(super) fn same_slot<T: PartialEq>(
    ctx: &Ctx<'_>,
    current: Option<&Fact<T>>,
    new: Option<&Fact<T>>,
) -> bool {
    same(ctx.mode, current, new)
}
