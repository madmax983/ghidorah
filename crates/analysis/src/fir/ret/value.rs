//! The return value of a function: no value, an integer value or a floating value (design
//! Section 7.10).
//!
//! | Source | Rule |
//! |---|---|
//! | the signature fact of the function | a `void` return type gives no value, a floating type gives a floating value, another type an integer value |
//! | the Tier-0 prototype of its name, or of an import | the same rule |
//! | [`recover_value`] | the floating return of [`super::recover`]. Else a `ret` that returns the entry value of `rax` gives no value. Else the value is an integer value. |
//! | [`ret_value`], with no fact | [`recover_value`], then the callers when the value only passes on from calls |
//!
//! A C function returns a value on each path or on none. So one `ret` with the entry value of
//! `rax` is enough. The walk takes the last write of `rax` on each path back from a `ret`. A
//! read of `rax` is no write.
//!
//! The value of a function passes on from calls in two cases. The last event of `rax` before
//! each `ret` is a call, or the function has no `ret`. An example is a function that only
//! tail calls.
//! Then a floating return of a callee ([`super::float_ret_in`]) gives a floating value. Else
//! the callers decide ([`callers_ignore_rax`]). The function has no value when these are true:
//!
//! - It has at least one reference, and each reference to its entry is a direct call.
//! - No export names it.
//! - After each call site, instructions write `rax` and `xmm0` before any read of them, branch
//!   or return. A call writes both. The scan reads at most [`CALLER_SCAN`] instructions.

use ghidorah_base::{Address, Fuel, FuncId};
use ghidorah_db::{Program, RefType, Types};
use ghidorah_ir::Loc;
use ghidorah_types::{DataModel, Prim, Type, TypeId, TypeStore};
use ghidorah_x86::{Flow, Reg};

use super::{
    Event, Exits, FloatRet, RET_DEPTH, declared_ret, events, float_ret_in, kind_of, recover,
};
use crate::code::decode_at;
use crate::fir::FuncIr;
use crate::fir::callsite::{self, Memo};

/// The largest number of instructions after a call site that [`callers_ignore_rax`] reads.
pub const CALLER_SCAN: usize = 8;

/// The return value that the body of a function gives.
enum Body {
    /// The body tells the value.
    Value(RetValue),
    /// The value passes on from calls.
    Passed,
}

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

/// Gives the return value of the published function `id` with the L0 IR `l0`.
///
/// The signature fact comes first, then the Tier-0 prototype of the name, then the recovery
/// with the callers (see the module doc).
#[must_use]
pub fn ret_value(program: &Program, id: FuncId, l0: &FuncIr) -> RetValue {
    if let Some((store, ty)) = declared_ret(program, id) {
        return value_of(store, program.types().model(), ty);
    }
    let mut fuel = Fuel::new(callsite::CALLEE_FUEL);
    recover_with_callers(program, id.0.off, l0, &mut Memo::default(), &mut fuel)
}

/// Recovers the return value of `l0` by the rules of the module doc, with no caller evidence.
/// A value that passes on from calls is an integer value.
#[must_use]
pub fn recover_value(l0: &FuncIr) -> RetValue {
    match recover_body(l0) {
        Body::Value(v) => v,
        Body::Passed => RetValue::Int,
    }
}

/// Recovers the return value of the function `entry` with the L0 IR `l0`. A value that passes
/// on from calls is the floating return of a callee. Else it is no value when the callers
/// ignore it ([`callers_ignore_rax`]). The callees take fuel from `fuel`.
fn recover_with_callers(
    program: &Program,
    entry: u64,
    l0: &FuncIr,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> RetValue {
    match recover_body(l0) {
        Body::Value(v) => v,
        Body::Passed => passed_value(program, entry, l0, memo, fuel),
    }
}

/// Gives the value of the function `entry` with the L0 IR `l0`. Its value passes on from
/// calls. A floating return of a callee gives a floating value. Else the callers decide.
fn passed_value(
    program: &Program,
    entry: u64,
    l0: &FuncIr,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> RetValue {
    let id = FuncId(Address::ram(entry));
    if let Some(k) = float_ret_in(program, id, l0, memo, fuel) {
        RetValue::Float(k)
    } else if callers_ignore_rax(program, entry) {
        RetValue::Void
    } else {
        RetValue::Int
    }
}

/// Gives the return value that the body `l0` tells (see the module doc).
fn recover_body(l0: &FuncIr) -> Body {
    if let Some(k) = recover(l0) {
        return Body::Value(RetValue::Float(k));
    }
    let last = events(l0, &Exits::of(l0), Loc::RAX, false);
    if last.contains(&Event::Entry) {
        Body::Value(RetValue::Void)
    } else if last.iter().all(|e| matches!(e, Event::Call(_))) {
        Body::Passed
    } else {
        Body::Value(RetValue::Int)
    }
}

/// Tells if each caller of the function `entry` ignores the `rax` value of its call (see the
/// module doc). A function with no reference, a reference that is not a direct call, or an
/// export gives `false`.
#[must_use]
pub fn callers_ignore_rax(program: &Program, entry: u64) -> bool {
    let at = Address::ram(entry);
    if program.exports().values().any(|e| e.addr == Some(at)) {
        return false;
    }
    let refs = program.refs_to(at);
    !refs.is_empty()
        && refs.iter().all(|r| {
            let k = r.value.key;
            k.kind == RefType::UnconditionalCall
                && k.from.is_ram()
                && rax_dead_after(program, k.from.off)
        })
}

/// Tells if instructions after the direct call at `site` write `rax` and `xmm0` before any
/// read of them, branch or return. A call writes both.
fn rax_dead_after(program: &Program, site: u64) -> bool {
    let Some(call) = decode_at(program, site).filter(|i| i.flow() == Flow::Call) else {
        return false;
    };
    let xmm0 = Reg::xmm(0);
    let mut live = [Reg::RAX, xmm0].to_vec();
    let mut at = site.checked_add(u64::from(call.len()));
    for _ in 0..CALLER_SCAN {
        let Some(insn) = at.and_then(|a| decode_at(program, a)) else {
            return false;
        };
        if live.iter().any(|r| insn.regs_read().contains(*r)) {
            return false;
        }
        match insn.flow() {
            Flow::Call | Flow::ICall => return true,
            Flow::Seq => live.retain(|r| !insn.regs_written().contains(*r)),
            _ => return false,
        }
        if live.is_empty() {
            return true;
        }
        at = at.and_then(|a| a.checked_add(u64::from(insn.len())));
    }
    false
}

/// Gives the return value of the function or the import at `addr`, with the solve memo
/// `memo` of the caller.
///
/// An import, through its stub or its slot, gives the return type of its Tier-0 prototype. A
/// function gives [`ret_value`]. The recovery reads the L0 IR of the solve of the function,
/// with fuel from `fuel`. An import with no prototype, a function whose IR does not build and
/// another address give `None`. So does a function on the walk of `memo`, or a walk of
/// [`RET_DEPTH`] functions (see the module doc of [`super`]).
pub fn ret_value_in(
    program: &Program,
    addr: u64,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Option<RetValue> {
    if !memo.enter(addr, RET_DEPTH) {
        return None;
    }
    let out = value_in(program, addr, memo, fuel);
    memo.leave();
    out
}

/// Gives the return value of [`ret_value_in`] with `addr` on the walk of `memo`.
fn value_in(program: &Program, addr: u64, memo: &mut Memo, fuel: &mut Fuel) -> Option<RetValue> {
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
    match recover_body(memo.ir(addr)?) {
        Body::Value(v) => Some(v),
        Body::Passed => {
            let l0 = memo.ir(addr)?.clone();
            Some(passed_value(program, addr, &l0, memo, fuel))
        }
    }
}
