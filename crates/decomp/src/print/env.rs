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

use ghidorah_analysis::cc::conv_of;
use ghidorah_base::{Address, FuncId, VarId};
use ghidorah_db::{CommentKind, Types};
use ghidorah_types::{CallConv, DataModel, Prim, Sig, Type, TypeId, TypeStore};

use super::{PrintEnv, Signature, body_units};
use crate::lattice::{Store, Ty};
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
}
