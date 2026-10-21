//! The parameters and the parameter slots of a signature or a Tier-0 prototype (design
//! Section 7.10).
//!
//! A slot is the location of one parameter: an argument register, or a stack slot `Stack(k)`
//! with its offset `k` at entry. [`sig_slots`] gives the slots of a signature from the class
//! of each parameter:
//!
//! | Convention | Rule |
//! |---|---|
//! | positional (MS x64) | parameter n uses floating register n for a floating type, else integer register n. The parameters after the register slots are on the stack. |
//! | another convention (`SysV`) | a parameter uses the next free register of its class: the integer list or the floating list. A parameter whose list is full is on the stack. |
//!
//! A parameter has the floating class when its type is a `float`, a `double` or a `long
//! double` of 8 bytes. The stack slots go up by 8 bytes from the first stack parameter
//! offset of the convention, in parameter order.

use ghidorah_base::FuncId;
use ghidorah_db::{Program, Types};
use ghidorah_ir::Loc;
use ghidorah_types::{CallConv, DataModel, Sig, TypeStore};

use crate::cc::{ParamSource, Params, conv_of, loc_of};
use crate::fir::ret;

/// Gives the location of each parameter in parameter order. `floats[i]` tells if parameter
/// `i` has the floating class (see the module doc).
#[must_use]
pub fn sig_slots(conv: &CallConv, floats: &[bool]) -> Vec<Loc> {
    let ints: Vec<Loc> = conv.int_args.iter().filter_map(|n| loc_of(n)).collect();
    let fls: Vec<Loc> = conv.float_args.iter().filter_map(|n| loc_of(n)).collect();
    let first = i64::from(conv.stack_arg_offset);
    let (mut next_int, mut next_float, mut stack) = (0usize, 0usize, 0i64);
    let mut out = Vec::with_capacity(floats.len());
    for (n, &float) in floats.iter().enumerate() {
        let reg = if conv.positional {
            if float { fls.get(n) } else { ints.get(n) }
        } else if float {
            next_float = next_float.saturating_add(1);
            fls.get(next_float.saturating_sub(1))
        } else {
            next_int = next_int.saturating_add(1);
            ints.get(next_int.saturating_sub(1))
        };
        if let Some(r) = reg {
            out.push(*r);
            continue;
        }
        let off = first.saturating_add(stack.saturating_mul(8));
        stack = stack.saturating_add(1);
        if let Ok(k) = i32::try_from(off) {
            out.push(Loc::Stack(k));
        }
    }
    out
}

/// Gives the floating class of each parameter of `sig`, whose types are in `store`.
fn sig_floats(store: &TypeStore, model: &DataModel, sig: &Sig) -> Vec<bool> {
    sig.params
        .iter()
        .map(|p| ret::kind_of(store, model, p.ty).is_some())
        .collect()
}

/// Gives the parameters of a signature with the floating classes `floats`. A positional
/// convention counts each slot as an integer slot. Another convention counts the integer and
/// the floating parameters apart.
fn from_sig(conv: &CallConv, floats: &[bool], variadic: bool) -> Params {
    let count = |want: bool| {
        let n = floats.iter().filter(|f| **f == want).count();
        u8::try_from(n).unwrap_or(u8::MAX)
    };
    let (int, float) = if conv.positional {
        (u8::try_from(floats.len()).unwrap_or(u8::MAX), 0)
    } else {
        (count(false), count(true))
    };
    Params {
        int,
        float,
        stack: 0,
        varargs: variadic,
    }
}

/// Gives the parameters of the Tier-0 prototype signature `sig` in the convention `conv`.
pub(crate) fn proto_params(program: &Program, conv: &CallConv, sig: &Sig) -> Params {
    let floats = ghidorah_types::proto::builtin().map_or_else(
        |_| vec![false; sig.params.len()],
        |t| sig_floats(t.store(), program.types().model(), sig),
    );
    from_sig(conv, &floats, sig.variadic)
}

/// Gives the signature that a fact gives the published function `id`. The signature fact
/// comes first, then the Tier-0 prototype of its name. The result holds the type store and
/// the source too.
pub(crate) fn declared(program: &Program, id: FuncId) -> Option<(&Sig, &TypeStore, ParamSource)> {
    let view = program.func(id)?;
    let types = program.types();
    if let Some(sig) = view.sig.and_then(|s| types.sig(s.value)) {
        return Some((sig, types.store(), ParamSource::Signature));
    }
    let proto = program
        .name(id.0)
        .filter(|n| !n.is_default())
        .and_then(|n| Types::prototype(&n.text))?;
    let tier0 = ghidorah_types::proto::builtin().ok()?;
    Some((&proto.sig, tier0.store(), ParamSource::Prototype))
}

/// Gives the parameters that a fact gives the published function `id`: its signature, then
/// the Tier-0 prototype of its name. A function with no such fact gives `None`.
pub(crate) fn fixed(program: &Program, id: FuncId) -> Option<(Params, ParamSource)> {
    let (sig, store, source) = declared(program, id)?;
    let floats = sig_floats(store, program.types().model(), sig);
    Some((from_sig(conv_of(program), &floats, sig.variadic), source))
}

/// Gives the slot of each parameter of the signature or the Tier-0 prototype of the published
/// function `id` ([`sig_slots`]). A function with no such fact gives `None`.
#[must_use]
pub fn fixed_slots(program: &Program, id: FuncId) -> Option<Vec<Loc>> {
    let (sig, store, _) = declared(program, id)?;
    let floats = sig_floats(store, program.types().model(), sig);
    Some(sig_slots(conv_of(program), &floats))
}
