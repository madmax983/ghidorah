//! The return value of a function: no value, an integer value or a floating value (design
//! Section 7.10).
//!
//! | Source | Rule |
//! |---|---|
//! | the signature fact of the function | a `void` return type gives no value, a floating type gives a floating value, another type an integer value |
//! | the Tier-0 prototype of its name, or of an import | the same rule |
//! | [`recover_value`] | the floating return of [`super::recover`]. Else a `ret` that returns the entry value of `rax` gives no value. Else the value is an integer value. |
//!
//! A C function returns a value on each path or on none. So one `ret` with the entry value of
//! `rax` is enough. The walk takes the last write of `rax` on each path back from a `ret`. A
//! read of `rax` is no write.

use ghidorah_base::{Address, Fuel, FuncId};
use ghidorah_db::{Program, Types};
use ghidorah_ir::Loc;
use ghidorah_types::{DataModel, Prim, Type, TypeId, TypeStore};

use super::{Event, FloatRet, declared_ret, ends_in_ret, events, kind_of, recover};
use crate::fir::FuncIr;
use crate::fir::callsite::{self, Memo};

/// The return value of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetValue {
    /// No value: a `void` return type, or a `ret` that returns the entry value of `rax`.
    Void,
    /// A value in `rax`, or a value whose kind the facts do not tell.
    Int,
    /// A `float` or a `double` in `xmm0`.
    Float(FloatRet),
}

/// Gives the return value that the return type `ty` of `store` gives.
fn value_of(store: &TypeStore, model: &DataModel, ty: TypeId) -> RetValue {
    let void = store
        .resolve(ty)
        .ok()
        .and_then(|t| store.get(t))
        .is_some_and(|t| *t == Type::Prim(Prim::Void));
    if void {
        return RetValue::Void;
    }
    kind_of(store, model, ty).map_or(RetValue::Int, RetValue::Float)
}

/// Gives the return value of the published function `id` with the L0 IR `l0`. The signature
/// fact comes first, then the Tier-0 prototype of the name, then [`recover_value`].
#[must_use]
pub fn ret_value(program: &Program, id: FuncId, l0: &FuncIr) -> RetValue {
    match declared_ret(program, id) {
        Some((store, ty)) => value_of(store, program.types().model(), ty),
        None => recover_value(l0),
    }
}

/// Recovers the return value of `l0` by the rules of the module doc.
#[must_use]
pub fn recover_value(l0: &FuncIr) -> RetValue {
    if let Some(k) = recover(l0) {
        return RetValue::Float(k);
    }
    let preds = l0.body.cfg.preds();
    let rets: Vec<usize> = (0..l0.body.blocks.len())
        .filter(|&n| ends_in_ret(l0, n))
        .collect();
    if events(l0, &preds, &rets, Loc::RAX, false).contains(&Event::Entry) {
        RetValue::Void
    } else {
        RetValue::Int
    }
}

/// Gives the return value of the function or the import at `addr`, with the solve memo
/// `memo` of the caller.
///
/// An import, through its stub or its slot, gives the return type of its Tier-0 prototype. A
/// function gives [`ret_value`]. The recovery reads the L0 IR of the solve of the function,
/// with fuel from `fuel`. An import with no prototype, a function whose IR does not build and
/// another address give `None`.
pub fn ret_value_in(
    program: &Program,
    addr: u64,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Option<RetValue> {
    let at = Address::ram(addr);
    let model = program.types().model();
    if let Some(row) = program
        .imports()
        .values()
        .find(|r| r.stub == Some(at) || r.slot == Some(at))
        && program.func(FuncId(at)).is_none()
    {
        let proto = row.id.name().and_then(Types::prototype)?;
        let tier0 = ghidorah_types::proto::builtin().ok()?;
        return Some(value_of(tier0.store(), model, proto.sig.ret));
    }
    let id = FuncId(at);
    if let Some((store, ty)) = declared_ret(program, id) {
        return Some(value_of(store, model, ty));
    }
    callsite::param_facts(program, id, memo, fuel).ok()?;
    memo.ir(addr).map(recover_value)
}
