//! The floating return of a function (design Section 7.10).
//!
//! A function returns a `float` or a `double` in the first floating return register of its
//! convention: `xmm0` in `SysV` and in MS x64. [`float_ret`] gives the kind of that value:
//!
//! | Source | Rule |
//! |---|---|
//! | the signature fact of the function | a `float`, a `double` or an 8-byte `long double` return type |
//! | the Tier-0 prototype of its name | the same rule |
//! | [`recover`] | the L0 body, by the rules below |
//!
//! A signature or a prototype with another return type gives no floating return.
//!
//! [`recover`] walks back from each `ret` over the L0 ops to the last event of `xmm0` and of
//! `rax` on each path. An event is a read, a write, a call or the function entry.
//!
//! - A write of `xmm0` that no op reads before the `ret` is a floating return value. Such a
//!   write is a move, a zero idiom or a floating op such as `addsd`.
//! - A scalar op on `float` values (`addss`, `cvtsi2ss`) or a 32-bit move gives `float`.
//!   Another floating write gives `double`.
//! - A write of `rax` that no op reads before the `ret` is an integer return value.
//! - The function returns a floating value when a `ret` has a floating return value and no
//!   `ret` has an integer return value.
//!
//! A call writes both registers, so the value after a call is no evidence. A write of
//! `xmm0` by another op, for example an integer vector op, is no evidence too.

use std::collections::BTreeSet;

use ghidorah_base::FuncId;
use ghidorah_db::{Program, Types};
use ghidorah_ir::{Arena, Arg, IntrinsicId, Loc, Node, Op, Opc};
use ghidorah_types::{DataModel, Prim, Type, TypeId, TypeStore};
use ghidorah_x86::Mnem;

use super::FuncIr;

/// The kind of a floating return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FloatRet {
    /// A `float` of 32 bits.
    Float,
    /// A `double` of 64 bits.
    Double,
}

impl FloatRet {
    /// Gives the C name of the type: `float` or `double`.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::Float => "float",
            Self::Double => "double",
        }
    }

    /// Gives the primitive type of the kind.
    #[must_use]
    pub const fn prim(self) -> Prim {
        match self {
            Self::Float => Prim::Float,
            Self::Double => Prim::Double,
        }
    }
}

/// The scalar ops that give a `float` value.
const FLOAT_OPS: [Mnem; 11] = [
    Mnem::Addss,
    Mnem::Subss,
    Mnem::Mulss,
    Mnem::Divss,
    Mnem::Sqrtss,
    Mnem::Minss,
    Mnem::Maxss,
    Mnem::Rcpss,
    Mnem::Rsqrtss,
    Mnem::Cvtsi2ss,
    Mnem::Cvtsd2ss,
];

/// The ops that give a `double` value: the scalar ops on `double` values and the sign and
/// absolute-value masks of compilers.
const DOUBLE_OPS: [Mnem; 17] = [
    Mnem::Addsd,
    Mnem::Subsd,
    Mnem::Mulsd,
    Mnem::Divsd,
    Mnem::Sqrtsd,
    Mnem::Minsd,
    Mnem::Maxsd,
    Mnem::Cvtsi2sd,
    Mnem::Cvtss2sd,
    Mnem::Andpd,
    Mnem::Andnpd,
    Mnem::Orpd,
    Mnem::Xorpd,
    Mnem::Andps,
    Mnem::Andnps,
    Mnem::Orps,
    Mnem::Xorps,
];

/// The last event of a register before a `ret` on one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// An op reads the register.
    Read,
    /// An op writes the register. A floating write has its kind.
    Write(Option<FloatRet>),
    /// A call writes the register.
    Call,
    /// The path reaches the function entry.
    Entry,
}

/// Gives the floating return of the published function `id` with the L0 IR `l0`.
///
/// The signature fact comes first, then the Tier-0 prototype of the name, then [`recover`].
#[must_use]
pub fn float_ret(program: &Program, id: FuncId, l0: &FuncIr) -> Option<FloatRet> {
    match declared_ret(program, id) {
        Some((store, ty)) => kind_of(store, program.types().model(), ty),
        None => recover(l0),
    }
}

/// Gives the return type that a fact gives the function `id`, with its store: the signature,
/// then the Tier-0 prototype of its name. A function with no such fact gives `None`.
fn declared_ret(program: &Program, id: FuncId) -> Option<(&TypeStore, TypeId)> {
    let view = program.func(id)?;
    let types = program.types();
    if let Some(sig) = view.sig.and_then(|s| types.sig(s.value)) {
        return Some((types.store(), sig.ret));
    }
    let name = program.name(id.0).filter(|n| !n.is_default())?;
    let proto = Types::prototype(&name.text)?;
    let tier0 = ghidorah_types::proto::builtin().ok()?;
    Some((tier0.store(), proto.sig.ret))
}

/// Gives the floating kind of the type `ty` of `store`, or `None` for another type.
fn kind_of(store: &TypeStore, model: &DataModel, ty: TypeId) -> Option<FloatRet> {
    let id = store.resolve(ty).ok()?;
    match store.get(id)? {
        Type::Prim(Prim::Float) => Some(FloatRet::Float),
        Type::Prim(Prim::Double) => Some(FloatRet::Double),
        Type::Prim(Prim::LongDouble) => model
            .prim(Prim::LongDouble)
            .filter(|p| p.size == 8)
            .map(|_| FloatRet::Double),
        _ => None,
    }
}

/// Recovers the floating return of `l0` by the rules of the module doc.
#[must_use]
pub fn recover(l0: &FuncIr) -> Option<FloatRet> {
    let xmm0 = Loc::xmm(0)?;
    let preds = l0.body.cfg.preds();
    let rets: Vec<usize> = (0..l0.body.blocks.len())
        .filter(|&n| ends_in_ret(l0, n))
        .collect();
    let int = events(l0, &preds, &rets, Loc::RAX)
        .iter()
        .any(|e| matches!(e, Event::Write(_)));
    if int {
        return None;
    }
    events(l0, &preds, &rets, xmm0)
        .into_iter()
        .filter_map(|e| match e {
            Event::Write(k) => k,
            Event::Read | Event::Call | Event::Entry => None,
        })
        .max()
}

/// Gives the ops of block `n` of `l0` in run order.
fn block_ops(l0: &FuncIr, n: usize) -> Vec<&Op> {
    let Some(b) = l0.body.blocks.get(n) else {
        return Vec::new();
    };
    let first = usize::try_from(b.first).unwrap_or(usize::MAX);
    let count = usize::try_from(b.count).unwrap_or(0);
    l0.arena
        .insns()
        .iter()
        .skip(first)
        .take(count)
        .flat_map(|span| l0.arena.span_ops(span).unwrap_or_default())
        .collect()
}

/// Tells if block `n` of `l0` ends in a `ret`.
fn ends_in_ret(l0: &FuncIr, n: usize) -> bool {
    block_ops(l0, n).last().is_some_and(|op| op.opc == Opc::Ret)
}

/// Gives the last event of `loc` on each path from the end of a block of `starts` back to the
/// entry. `preds` holds the predecessors of each block. The paths share one walk, so the walk
/// reads each block once, also for a function with many `ret` blocks.
fn events(l0: &FuncIr, preds: &[Vec<Node>], starts: &[usize], loc: Loc) -> Vec<Event> {
    let entry = l0.body.cfg.entry().index();
    let mut out = Vec::new();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut work = starts.to_vec();
    while let Some(n) = work.pop() {
        if !seen.insert(n) {
            continue;
        }
        let ops = block_ops(l0, n);
        if let Some(e) = ops.iter().rev().find_map(|op| event(&l0.arena, op, loc)) {
            out.push(e);
            continue;
        }
        if n == entry {
            out.push(Event::Entry);
        }
        work.extend(
            preds
                .get(n)
                .into_iter()
                .flatten()
                .map(|p| p.index())
                .filter(|p| !seen.contains(p)),
        );
    }
    out
}

/// Gives the event of the op `op` for `loc`, or `None` when the op does not touch it.
fn event(arena: &Arena, op: &Op, loc: Loc) -> Option<Event> {
    match op.opc {
        Opc::Call | Opc::CallInd => Some(Event::Call),
        Opc::Get if op.a[0].as_loc() == Some(loc) => Some(Event::Read),
        Opc::Put if op.a[0].as_loc() == Some(loc) => {
            Some(Event::Write(Some(move_kind(arena, op.a[1]))))
        }
        Opc::Intrinsic | Opc::Syscall => match arena.effect(op) {
            Some(e) if e.defs.contains(loc) => Some(Event::Write(op_kind(e.name))),
            Some(e) if e.uses.contains(loc) => Some(Event::Read),
            Some(_) => None,
            None => (op.opc == Opc::Syscall && loc == Loc::RAX).then_some(Event::Write(None)),
        },
        _ => None,
    }
}

/// Gives the kind of the intrinsic `name`, or `None` for an op with no floating value.
fn op_kind(name: IntrinsicId) -> Option<FloatRet> {
    let is = |list: &[Mnem]| list.iter().any(|m| name.0 == *m as u16);
    if is(&FLOAT_OPS) {
        Some(FloatRet::Float)
    } else if is(&DOUBLE_OPS) {
        Some(FloatRet::Double)
    } else {
        None
    }
}

/// Gives the kind of the value `a` of a move into an XMM register. A move of 32 bits, such as
/// `movss` or `movd`, gives `float`. Another move gives `double`.
fn move_kind(arena: &Arena, a: Arg) -> FloatRet {
    let narrow = a
        .as_v()
        .and_then(|v| arena.def_of(v))
        .and_then(|i| arena.op(i))
        .is_some_and(|d| matches!(d.opc, Opc::ZExt | Opc::SExt | Opc::Insert) && d.sub == 32);
    if narrow {
        FloatRet::Float
    } else {
        FloatRet::Double
    }
}
