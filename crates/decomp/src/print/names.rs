//! The names and types of the variables, the function line and the variable rows.
//!
//! | Storage | Default name |
//! |---|---|
//! | `param:<n>` | `param_<n + 1>` |
//! | `stack:-<k>` | `local_<k>` in hex |
//! | `stack:<k>` | `local_p<k>` in hex |
//! | a register value | `v<N>`, numbered in view order |
//!
//! A name fact of the variable wins over its default name.

use std::collections::BTreeSet;

use ghidorah_base::Storage;
use ghidorah_ir::Loc;

use super::expr::safe;
use super::{PrintEnv, Printer, VarRow, width_type};
use crate::expr::{Callee, Expr, Stmt, VarIdx};
use crate::lattice::Ty;
use crate::view::View;

/// Gives the default name of a storage. `temps` counts the register values so far.
fn default_name(storage: &Storage, temps: &mut u32) -> String {
    match storage {
        Storage::Param(n) => format!("param_{}", u32::from(*n).saturating_add(1)),
        Storage::Stack(k) if *k < 0 => format!("local_{:x}", k.unsigned_abs()),
        Storage::Stack(k) => format!("local_p{k:x}"),
        Storage::Reg(_) | Storage::Ret => {
            *temps = temps.saturating_add(1);
            format!("v{temps}")
        }
    }
}

/// Gives the name and the name source of each variable of `view`.
pub(super) fn var_names(view: &View, env: &dyn PrintEnv) -> Vec<(String, &'static str)> {
    let mut temps = 0u32;
    view.vars
        .iter()
        .map(|v| {
            let default = default_name(&v.id.storage, &mut temps);
            match env.var_name(&v.id) {
                Some((name, source)) => (safe(&name), source),
                None => (default, "default"),
            }
        })
        .collect()
}

/// Gives the variables that hold a register value that a call leaves behind: a call result
/// in a location other than `rax`.
pub(super) fn clobbers(view: &View) -> BTreeSet<VarIdx> {
    let mut out = BTreeSet::new();
    for s in view.nodes.iter().flat_map(|n| &n.stmts) {
        let mut calls = Vec::new();
        if let Stmt::Call(c) = s {
            calls.push(c);
        }
        for e in s.exprs() {
            for x in e.preorder() {
                if let Expr::Call(c) = x {
                    calls.push(c);
                }
            }
        }
        for c in calls {
            if matches!(c.callee, Callee::Intrinsic(_)) {
                continue;
            }
            out.extend(
                c.rets
                    .iter()
                    .filter(|(l, _)| *l != Loc::RAX)
                    .map(|(_, v)| *v),
            );
        }
    }
    out
}

impl Printer<'_> {
    /// Gives the C type text of a variable: its lattice type, else the type of its width.
    fn var_type(&self, v: VarIdx, sig: Option<Ty>) -> String {
        let ty = self.types.get(v.index()).copied().flatten().or(sig);
        ty.and_then(|t| self.stores.text(t))
            .unwrap_or_else(|| width_type(self.view().var(v).map_or(64, |x| x.w)))
    }

    /// Gives the function line: the return type, the name and the parameters. It marks each
    /// parameter variable as used.
    pub(super) fn head(&mut self, name: &str) -> String {
        let view = self.view();
        let sig = self.env.signature(view.entry);
        let params: Vec<(u16, VarIdx)> = view
            .vars
            .iter()
            .enumerate()
            .filter_map(|(i, v)| match v.id.storage {
                Storage::Param(n) => Some((n, VarIdx(u32::try_from(i).unwrap_or(u32::MAX)))),
                _ => None,
            })
            .collect();
        let used_max = params
            .iter()
            .filter(|(_, v)| self.used.contains(v))
            .map(|(n, _)| usize::from(*n).saturating_add(1))
            .max()
            .unwrap_or(0);
        // The signature, the prototype or the parameter recovery gives the count. A parameter
        // that the text reads adds its slot only to a count that can grow (`ParamInfo::grows`).
        let (facts, grows, variadic) = match (&sig, self.env.param_info(view.entry)) {
            (Some(s), _) => (s.params.len(), false, s.variadic),
            (None, Some(i)) => (usize::from(i.count), i.grows(), i.varargs),
            (None, None) => (0, true, false),
        };
        let count = if grows { facts.max(used_max) } else { facts };
        let mut texts = Vec::new();
        for n in 0..count {
            let sig_ty = sig.as_ref().and_then(|s| s.params.get(n)).copied();
            let var = params
                .iter()
                .find(|(p, _)| usize::from(*p) == n)
                .map(|(_, v)| *v);
            let (pname, ty) = match var {
                Some(v) => {
                    let pname = self.var(v);
                    let lattice = self.types.get(v.index()).copied().flatten().or(sig_ty);
                    (pname, lattice)
                }
                None => (format!("param_{}", n.saturating_add(1)), sig_ty),
            };
            let decl = ty
                .and_then(|t| self.stores.decl(t, &pname))
                .unwrap_or_else(|| {
                    let w = var.and_then(|v| self.view().var(v)).map_or(64, |x| x.w);
                    format!("{} {pname}", width_type(w))
                });
            texts.push(decl);
        }
        if variadic {
            texts.push("...".to_owned());
        }
        let ret = match &sig {
            Some(s) => s
                .ret
                .and_then(|t| self.stores.text(t))
                .unwrap_or_else(|| "void".to_owned()),
            None => self
                .rets
                .iter()
                .max()
                .map_or_else(|| "void".to_owned(), |w| width_type(*w)),
        };
        let list = if texts.is_empty() {
            "void".to_owned()
        } else {
            texts.join(", ")
        };
        format!("{ret} {name}({list})")
    }

    /// Gives the rows of the variables that the text names, in view order.
    pub(super) fn var_rows(&self) -> Vec<VarRow> {
        let sig = self.env.signature(self.view().entry);
        self.view()
            .vars
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                let idx = VarIdx(u32::try_from(i).ok()?);
                if !self.used.contains(&idx) {
                    return None;
                }
                let sig_ty = match (&sig, &v.id.storage) {
                    (Some(s), Storage::Param(n)) => s.params.get(usize::from(*n)).copied(),
                    _ => None,
                };
                let (name, source) = self.vnames.get(i).cloned()?;
                Some(VarRow {
                    id: v.id.clone(),
                    name,
                    ty: self.var_type(idx, sig_ty),
                    source,
                })
            })
            .collect()
    }
}
