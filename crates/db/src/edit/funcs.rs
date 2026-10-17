//! The function edits: create, delete, signature and noreturn.
//!
//! - A create with listed variables or a plate comment needs empty variable and plate
//!   slots for the function. Its inverse is a cascading delete. A create without them has
//!   a delete without cascade as its inverse. So each inverse is exact.
//! - A forward signature or noreturn edit on a discovered function makes a base holder record.
//!   The body of the record is the one byte at the entry. Its inverse is a delete without
//!   cascade.

use ghidorah_base::{FuncId, VarId};

use super::apply::{Ctx, exact, same_slot, tables, top};
use super::rules::{gate, own, rule, signature as check_sig};
use super::{Edit, EditError, FuncRecord, Layer};
use crate::codec::Json;
use crate::comments::CommentKind;
use crate::fact::{Fact, Invalid, Origin};
use crate::funcs::Function;
use crate::program::{Program, Tables};
use crate::vars::VarFact;
use crate::why::FactKey;

/// Tells if two function records are the same for the no-op test.
fn same_func(ctx: &Ctx<'_>, a: &Function, b: &Function) -> bool {
    let plain = |f: &Function| {
        let mut f = f.clone();
        f.sig = None;
        f.flags.noreturn = None;
        f
    };
    plain(a) == plain(b)
        && same_slot(ctx, a.sig.as_ref(), b.sig.as_ref())
        && same_slot(ctx, a.flags.noreturn.as_ref(), b.flags.noreturn.as_ref())
}

/// Checks the facts of a function record with [`own`].
fn own_record(ctx: &Ctx<'_>, p: &Program, r: &FuncRecord) -> Result<(), EditError> {
    let func = &r.func;
    let id = func.id();
    if Layer::of(func.source) != Some(ctx.layer()) {
        return Err(EditError::WrongLayer(func.source));
    }
    if ctx.forward() && func.source != ctx.origin.source {
        return Err(EditError::Origin(FactKey::Func(id)));
    }
    if let Some(s) = &func.sig {
        own(ctx, &FactKey::Signature(id), s)?;
        if ctx.forward() {
            check_sig(p, s.value)?;
        }
    }
    if let Some(n) = &func.flags.noreturn {
        own(ctx, &FactKey::Noreturn(id), n)?;
    }
    for (var, facts) in &r.vars {
        let key = FactKey::Var(var.clone());
        if var.func != id {
            return Err(Invalid::NoFunc(var.func).into());
        }
        if let Some(n) = &facts.name {
            own(ctx, &key, n)?;
        }
        if let Some(t) = &facts.ty {
            own(ctx, &key, t)?;
            if ctx.forward() {
                super::rules::known(p, t.value)?;
            }
        }
    }
    if let Some(plate) = &r.plate {
        own(
            ctx,
            &FactKey::Comment(func.entry, CommentKind::Plate),
            plate,
        )?;
    }
    Ok(())
}

/// Puts the variable facts and the plate comment of a record into empty slots.
fn fill(t: &mut Tables, r: &FuncRecord) -> Result<(), EditError> {
    for (var, facts) in &r.vars {
        exact(&mut t.vars, facts.name.as_ref(), |m, v, o| {
            m.set_name(var, v, o)
        })?;
        exact(&mut t.vars, facts.ty.as_ref(), |m, v, o| {
            m.set_type(var, v, o)
        })?;
    }
    let entry = r.func.entry;
    exact(&mut t.comments, r.plate.as_ref(), |m, v, o| {
        m.set(entry, CommentKind::Plate, v, o)
    })?;
    Ok(())
}

/// Removes a function. With `cascade`, also removes its variable facts and its plate
/// comment. Gives the record of the removed facts.
fn remove(t: &mut Tables, id: FuncId, cascade: bool) -> Option<FuncRecord> {
    let func = t.funcs.remove(id)?;
    let mut record = FuncRecord {
        vars: Vec::new(),
        plate: None,
        func,
    };
    if cascade {
        let vars: Vec<VarId> = t.vars.of_func(id).map(|(v, _)| v.clone()).collect();
        for var in vars {
            let name = t.vars.set_name(&var, None, &top()).ok().flatten();
            let ty = t.vars.set_type(&var, None, &top()).ok().flatten();
            record.vars.push((var, VarFact { name, ty }));
        }
        let entry = record.func.entry;
        record.plate = t
            .comments
            .set(entry, CommentKind::Plate, None, &top())
            .ok()
            .flatten();
    }
    Some(record)
}

/// Applies a `CreateFunction` edit.
pub(super) fn create(
    p: &mut Program,
    ctx: &Ctx<'_>,
    r: &FuncRecord,
) -> Result<Option<Edit>, EditError> {
    own_record(ctx, p, r)?;
    let id = r.func.id();
    let t = tables(p, ctx.layer())?;
    if let Some(existing) = t.funcs.get(id) {
        let vars_same = r.vars.iter().all(|(var, f)| {
            let cur = t.vars.get(var).cloned().unwrap_or_default();
            same_slot(ctx, cur.name.as_ref(), f.name.as_ref())
                && same_slot(ctx, cur.ty.as_ref(), f.ty.as_ref())
        });
        let plate = t.comments.get(r.func.entry, CommentKind::Plate);
        let plate_same = r.plate.is_none() || same_slot(ctx, plate, r.plate.as_ref());
        if same_func(ctx, existing, &r.func) && vars_same && plate_same {
            return Ok(None);
        }
    }
    let listed = !r.vars.is_empty() || r.plate.is_some();
    if listed {
        if let Some((var, _)) = t.vars.of_func(id).next() {
            return Err(EditError::Occupied(FactKey::Var(var.clone())));
        }
        if t.comments.get(r.func.entry, CommentKind::Plate).is_some() {
            return Err(EditError::Occupied(FactKey::Comment(
                r.func.entry,
                CommentKind::Plate,
            )));
        }
    }
    t.funcs.insert(r.func.clone())?;
    if let Err(e) = fill(t, r) {
        // The slots were empty, so a cascading remove puts the layer back.
        remove(t, id, true);
        return Err(e);
    }
    Ok(Some(Edit::DeleteFunction {
        id,
        cascade: listed,
    }))
}

/// Applies a `DeleteFunction` edit.
pub(super) fn delete(
    p: &mut Program,
    ctx: &Ctx<'_>,
    id: FuncId,
    cascade: bool,
) -> Result<Option<Edit>, EditError> {
    let t = tables(p, ctx.layer())?;
    let Some(func) = t.funcs.get(id) else {
        return Ok(None);
    };
    let mut origin = Origin::load();
    origin.source = func.source;
    rule(ctx, &FactKey::Func(id), origin, || func.enc())?;
    if cascade {
        let entry = func.entry;
        for (var, facts) in t.vars.of_func(id) {
            let key = FactKey::Var(var.clone());
            let name = facts.name.as_ref().map(Fact::origin);
            for o in [name, facts.ty.as_ref().map(Fact::origin)]
                .into_iter()
                .flatten()
            {
                rule(ctx, &key, o, || var.enc())?;
            }
        }
        if let Some(c) = t.comments.get(entry, CommentKind::Plate) {
            rule(
                ctx,
                &FactKey::Comment(entry, CommentKind::Plate),
                c.origin(),
                || c.value.enc(),
            )?;
        }
    }
    Ok(remove(t, id, cascade).map(|r| Edit::CreateFunction(Box::new(r))))
}

/// Makes a holder record for a forward edit on a discovered function of the base layer.
/// `set` puts the fact into the record.
fn holder(
    p: &mut Program,
    ctx: &Ctx<'_>,
    id: FuncId,
    set: impl FnOnce(&mut Function),
) -> Result<Option<Edit>, EditError> {
    let Some(view) = p.func(id) else {
        return Err(Invalid::NoFunc(id).into());
    };
    let found = view.func;
    let mut f = Function::new(
        id.0,
        found.start_reason,
        found.confidence,
        ctx.origin.source,
    );
    set(&mut f);
    tables(p, Layer::Base)?.funcs.insert(f)?;
    Ok(Some(Edit::DeleteFunction { id, cascade: false }))
}

/// Applies a `SetSignature` edit.
pub(super) fn signature(
    p: &mut Program,
    ctx: &Ctx<'_>,
    id: FuncId,
    sig: Option<&Fact<ghidorah_types::TypeId>>,
) -> Result<Option<Edit>, EditError> {
    let key = FactKey::Signature(id);
    if let Some(s) = sig {
        own(ctx, &key, s)?;
        if ctx.forward() {
            check_sig(p, s.value)?;
        }
    }
    let t = tables(p, ctx.layer())?;
    let Some(func) = t.funcs.get(id) else {
        return match sig {
            None => Ok(None),
            Some(s) if ctx.forward() && ctx.layer() == Layer::Base => {
                holder(p, ctx, id, |f| f.sig = Some(s.clone()))
            }
            Some(_) => Err(Invalid::NoFunc(id).into()),
        };
    };
    if gate(ctx, &key, func.sig.as_ref(), sig)? {
        return Ok(None);
    }
    let old = exact(&mut t.funcs, sig, |m, v, o| m.set_sig(id, v, o))?;
    Ok(Some(Edit::SetSignature { id, sig: old }))
}

/// Applies a `SetNoreturn` edit.
pub(super) fn noreturn(
    p: &mut Program,
    ctx: &Ctx<'_>,
    id: FuncId,
    flag: Option<&Fact<bool>>,
) -> Result<Option<Edit>, EditError> {
    let key = FactKey::Noreturn(id);
    if let Some(n) = flag {
        own(ctx, &key, n)?;
    }
    let t = tables(p, ctx.layer())?;
    let Some(func) = t.funcs.get(id) else {
        return match flag {
            None => Ok(None),
            Some(n) if ctx.forward() && ctx.layer() == Layer::Base => {
                holder(p, ctx, id, |f| f.flags.noreturn = Some(n.clone()))
            }
            Some(_) => Err(Invalid::NoFunc(id).into()),
        };
    };
    if gate(ctx, &key, func.flags.noreturn.as_ref(), flag)? {
        return Ok(None);
    }
    let old = exact(&mut t.funcs, flag, |m, v, o| m.set_noreturn(id, v, o))?;
    Ok(Some(Edit::SetNoreturn { id, noreturn: old }))
}
