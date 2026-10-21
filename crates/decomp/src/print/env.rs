//! The facts of a program for the printer: [`PrintEnv`] for [`ProgramEnv`].
//!
//! | Method | Facts |
//! |---|---|
//! | `var_name`, `var_type` | the variable facts of the `var:` ID |
//! | `comments` | the PLATE, PRE, POST and EOL comments at the instructions of the body |
//! | `signature` | the signature fact of the function, then the Tier-0 prototype of its name |
//! | `string_bytes` | the bytes of the string fact |
//! | `call_targets` | the targets of the call references from the site |
//! | `syscall_name` | the x86-64 syscall table |
//! | `ret_value` | the return value of a callee: its Tier-0 prototype, else the recovery ([`ret_value_in`]) |
//!
//! The register of the result of a call comes from these facts too:
//!
//! | Callee | Result |
//! |---|---|
//! | a signature with a `float`, a `double` or an 8-byte `long double` return type | the floating return register, `xmm0` |
//! | a signature with another return type | `rax` |
//! | a signature with no return value | none |
//! | no signature, and the recovery gives no return value | none |
//! | no signature: the caller reads the `xmm0` def, and reads the `rax` def only as a return value | `xmm0` |
//! | no signature, another caller | `rax` |
//!
//! The `rax` def of a call with no `rax` result is a value that the call leaves behind. A
//! return of it gives no value, so the path prints `return;`.
//!
//! Each return of L1 with no floating return reads `rax`. So a return of the `rax` def of a
//! call tells nothing about the callee.

use std::collections::BTreeSet;

use ghidorah_analysis::cc::{conv_of, loc_of};
use ghidorah_analysis::fir::callsite::Memo;
use ghidorah_analysis::fir::ret::{RetValue, ret_value_in};
use ghidorah_base::{Address, Fuel, FuncId, VarId};
use ghidorah_db::{CommentKind, Types};
use ghidorah_ir::Loc;
use ghidorah_types::{CallConv, DataModel, Prim, Sig, Type, TypeId, TypeStore};

use super::{PrintEnv, Signature, body_units};
use crate::expr::{Call, Callee, Expr, Stmt, VarIdx};
use crate::lattice::{Store, Stores, Ty};
use crate::view::View;
use crate::{Env, ProgramEnv};

/// The comment kinds that the text shows, in kind order.
const KINDS: [CommentKind; 4] = [
    CommentKind::Eol,
    CommentKind::Pre,
    CommentKind::Post,
    CommentKind::Plate,
];

/// Gives the signature of `sig` in the store `which`.
fn signature(sig: &Sig, store: &TypeStore, which: Store) -> Signature {
    let ty = |id: TypeId| Ty { store: which, id };
    let void = store
        .resolve(sig.ret)
        .ok()
        .and_then(|t| store.get(t))
        .is_some_and(|t| *t == Type::Prim(Prim::Void));
    Signature {
        params: sig.params.iter().map(|p| ty(p.ty)).collect(),
        names: sig.params.iter().map(|p| p.name.clone()).collect(),
        ret: (!void).then(|| ty(sig.ret)),
        variadic: sig.variadic,
    }
}

/// Gives the first floating return register of `conv`: `xmm0` in each convention.
pub(super) fn float_ret(conv: &CallConv) -> Option<Loc> {
    conv.float_ret.first().and_then(|n| loc_of(n))
}

/// Gives the register of the result of a callee with the signature `sig` (see the module
/// doc). A signature with no return value gives `None`.
#[must_use]
pub(crate) fn ret_loc(sig: &Signature, stores: &Stores<'_>, conv: &CallConv) -> Option<Loc> {
    let ret = sig.ret?;
    let float = float_ret(conv).filter(|_| stores.is_float(ret));
    Some(float.unwrap_or(Loc::RAX))
}

/// Gives the register of the result of the call `c` with no signature (see the module doc).
/// `reads` holds the variables that a statement reads other than as a return value.
#[must_use]
pub(crate) fn caller_ret_loc(c: &Call, reads: &BTreeSet<VarIdx>, conv: &CallConv) -> Loc {
    let def = |loc: Loc| c.rets.iter().find(|(l, _)| *l == loc).map(|(_, v)| *v);
    match float_ret(conv) {
        Some(f) if def(f).is_some() && !def(Loc::RAX).is_some_and(|v| reads.contains(&v)) => f,
        _ => Loc::RAX,
    }
}

/// Gives the inputs of the call `c` that the text can show. The `rax` value of a direct or an
/// indirect call is its varargs count, and the text never shows it.
fn shown_inputs(c: &Call) -> Vec<&Expr> {
    if !matches!(c.callee, Callee::Direct(_) | Callee::Indirect(_)) {
        return c.inputs();
    }
    let mut out = Vec::new();
    if let Callee::Indirect(t) = &c.callee {
        out.push(t);
    }
    out.extend(
        c.args
            .iter()
            .filter(|(l, _)| *l != Loc::RAX)
            .map(|(_, e)| e),
    );
    out.extend(c.mem.iter());
    out
}

/// Gives the variables that the statements, conditions and switch values of `view` read. A
/// variable that is the full value of a return is not a read of that return. The varargs
/// count of a call is no read ([`shown_inputs`]).
#[must_use]
pub(crate) fn reads(view: &View) -> BTreeSet<VarIdx> {
    let mut stack: Vec<&Expr> = Vec::new();
    for n in &view.nodes {
        stack.extend([&n.cond, &n.target, &n.index].into_iter().flatten());
        for s in &n.stmts {
            match s {
                Stmt::Return { uses, .. } => stack.extend(
                    uses.iter()
                        .map(|(_, e)| e)
                        .filter(|e| !matches!(e, Expr::Var { .. })),
                ),
                Stmt::Call(c) => stack.extend(shown_inputs(c)),
                _ => stack.extend(s.exprs()),
            }
        }
    }
    let mut out = BTreeSet::new();
    while let Some(e) = stack.pop() {
        match e {
            Expr::Var { var, .. } => {
                out.insert(*var);
            }
            Expr::Call(c) => stack.extend(shown_inputs(c)),
            _ => stack.extend(e.inputs()),
        }
    }
    out
}

impl PrintEnv for ProgramEnv<'_> {
    fn var_name(&self, id: &VarId) -> Option<(String, &'static str)> {
        self.0
            .var(id)
            .name
            .map(|f| (f.value.clone(), f.source.name()))
    }

    fn var_type(&self, id: &VarId) -> Option<TypeId> {
        self.0.var(id).ty.map(|f| f.value)
    }

    fn comments(&self, entry: u64) -> Vec<(u64, CommentKind, String)> {
        let mut out = Vec::new();
        for (addr, _) in body_units(self.0, FuncId(Address::ram(entry))) {
            for kind in KINDS {
                if let Some(f) = self.0.comment(Address::ram(addr), kind) {
                    out.push((addr, kind, f.value.clone()));
                }
            }
        }
        out
    }

    fn signature(&self, addr: u64) -> Option<Signature> {
        let p = self.0;
        let types = p.types();
        if let Some(sig) = p
            .func(FuncId(Address::ram(addr)))
            .and_then(|f| f.sig)
            .and_then(|s| types.sig(s.value))
        {
            return Some(signature(sig, types.store(), Store::Program));
        }
        let name = self.callee_name(addr)?;
        let proto = Types::prototype(&name)?;
        let tier0 = ghidorah_types::proto::builtin().ok()?;
        Some(signature(&proto.sig, tier0.store(), Store::Tier0))
    }

    fn string_bytes(&self, addr: u64) -> Option<Vec<u8>> {
        let info = self.0.string(addr)?;
        ghidorah_analysis::analyzers::strings::bytes(self.0, addr, info)
    }

    fn types(&self) -> Option<(&TypeStore, &DataModel)> {
        let t = self.0.types();
        Some((t.store(), t.model()))
    }

    fn call_targets(&self, site: u64) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .0
            .refs_from(Address::ram(site))
            .iter()
            .filter(|r| r.value.key.kind.is_call())
            .map(|r| r.value.key.to.off)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    fn syscall_name(&self, nr: u64) -> Option<&'static str> {
        ghidorah_types::syscalls::x86_64().ok()?.name(nr)
    }

    fn conv(&self) -> &'static CallConv {
        conv_of(self.0)
    }

    fn ret_value(&self, addr: u64) -> Option<RetValue> {
        let mut fuel = Fuel::new(crate::PARAM_FUEL);
        ret_value_in(self.0, addr, &mut Memo::default(), &mut fuel)
    }
}
