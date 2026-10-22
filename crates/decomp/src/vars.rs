//! Out-of-SSA variables (design Section 8.2).
//!
//! Each L1 value that does not fold becomes a member of one variable:
//!
//! 1. Liveness over the reachable blocks gives the interference of the values. A phi argument
//!    is live at the end of its predecessor, and the def of a phi is at the start of its
//!    block. The defs of the entry values are at the function start.
//! 2. A phi and each of its arguments share a variable when no two members interfere. Then the
//!    values of one stack slot share a variable on the same rule.
//! 3. Each phi argument in another variable gets a copy on its edge. The copies of one edge
//!    run as one parallel copy. A cycle of copies takes a temporary variable.
//!
//! Variable identity is storage-based ([`VarId`]): a parameter, a stack slot, or a register
//! name with the address of the first def. So agent names and types survive a new decompile.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, RegVar, Storage, VarId};
use ghidorah_ir::{Arena, Arg, Loc, Node, OpId, Opc, Val};
use ghidorah_types::CallConv;

use crate::expr::{Expr, Stmt, VarIdx};
use crate::view::facts::{Facts, Kind};
use crate::view::stmts::{self, Raw, Term};
use crate::view::{Env, Var, VarKind};

/// The source of an edge with copies: a block, or the function entry.
pub(crate) type From = Option<Node>;

/// The result of the out-of-SSA step.
#[derive(Debug, Clone, Default)]
pub(crate) struct Assigned {
    /// The variable of each value.
    pub(crate) of: BTreeMap<Val, VarIdx>,
    /// The variables.
    pub(crate) vars: Vec<Var>,
    /// The copies of each edge `(from, to)` in run order.
    pub(crate) copies: BTreeMap<(From, Node), Vec<Stmt>>,
}

/// The inputs of the out-of-SSA step beyond the facts.
pub(crate) struct Ctx<'a> {
    pub(crate) f: &'a Facts<'a>,
    pub(crate) raws: &'a [Raw],
    pub(crate) l0: &'a Arena,
    pub(crate) conv: Option<&'a CallConv>,
    pub(crate) entry: u64,
    /// The facts of the program: an edge copy of a string address is that string.
    pub(crate) env: &'a dyn Env,
    /// The count of the parameter slots of the function, when the facts know it. It is at
    /// least the count of the slots that the L1 body reads. An entry value of a later slot is
    /// not a parameter.
    pub(crate) params: Option<u16>,
    /// The location of each parameter slot ([`crate::Env::param_slots`]). In a convention
    /// that numbers its integer and floating slots apart, it is the slot list of the view
    /// ([`crate::vars_names::layout`]).
    pub(crate) slots: Option<Vec<Loc>>,
}

/// Gives the values that a statement reads.
fn stmt_uses(s: &Stmt) -> Vec<Val> {
    s.exprs()
        .into_iter()
        .flat_map(Expr::vars)
        .map(|v| Val(v.0))
        .collect()
}

/// Gives the values that a statement defines.
fn stmt_defs(s: &Stmt) -> Vec<Val> {
    match s {
        Stmt::Assign { var, .. } => vec![Val(var.0)],
        Stmt::Call(c) => c.rets.iter().map(|(_, v)| Val(v.0)).collect(),
        Stmt::Store { .. } | Stmt::Return { .. } | Stmt::Goto { .. } => Vec::new(),
    }
}

/// One event of a block, in run order.
#[derive(Debug, Clone, Copy)]
enum Ev {
    Def(Val),
    Use(Val),
}

/// Gives the events of a raw block: the statements, then the terminator.
fn events(raw: &Raw) -> Vec<Ev> {
    let mut out = Vec::new();
    for s in &raw.stmts {
        out.extend(stmt_uses(s).into_iter().map(Ev::Use));
        out.extend(stmt_defs(s).into_iter().map(Ev::Def));
    }
    let tail: Vec<Val> = match &raw.term {
        Term::Plain => Vec::new(),
        Term::Branch { cond, .. } => cond.vars().into_iter().map(|v| Val(v.0)).collect(),
        Term::BranchStop { cond, tail, .. } => cond
            .vars()
            .into_iter()
            .map(|v| Val(v.0))
            .chain(stmt_uses(tail))
            .collect(),
        Term::Switch { target, selector } => target
            .vars()
            .into_iter()
            .chain(selector.iter().flat_map(|s| s.expr.vars()))
            .map(|v| Val(v.0))
            .collect(),
    };
    out.extend(tail.into_iter().map(Ev::Use));
    out
}

/// The phis of a block: each phi value with its op and its arguments.
fn phis_of(f: &Facts<'_>, b: Node) -> Vec<(Val, OpId, Vec<Arg>)> {
    phi_ops(f, b)
        .into_iter()
        .map(|(_, v, at, args)| (v, at, args))
        .collect()
}

/// The phis of a block: each phi with its op index, its value, its op and its arguments.
fn phi_ops(f: &Facts<'_>, b: Node) -> Vec<(u32, Val, OpId, Vec<Arg>)> {
    f.ssa
        .phis(b)
        .iter()
        .filter_map(|&i| {
            let op = f.op(i)?;
            let v = op.out?;
            let args = f.ssa.arena().phi_args(op).unwrap_or_default().to_vec();
            Some((i, v, op.id, args))
        })
        .collect()
}

/// Gives the op of the last L0 `Put` of `loc` in the block `b`. It is the move that gives a
/// phi of `loc` its argument on an edge from `b`.
fn last_put(cx: &Ctx<'_>, b: Node, loc: Loc) -> Option<OpId> {
    let f = cx.f;
    f.ops
        .get(&b)?
        .iter()
        .rev()
        .filter(|&&i| f.ssa.is_insn_op(i))
        .filter_map(|&i| cx.l0.op(i))
        .find(|op| op.opc == Opc::Put && op.a[0].as_loc() == Some(loc))
        .map(|op| op.id)
}

/// The interference graph of the values.
#[derive(Debug, Default)]
struct Interference(BTreeMap<Val, BTreeSet<Val>>);

impl Interference {
    fn add(&mut self, a: Val, b: Val) {
        if a != b {
            self.0.entry(a).or_default().insert(b);
            self.0.entry(b).or_default().insert(a);
        }
    }

    fn has(&self, a: Val, b: Val) -> bool {
        self.0.get(&a).is_some_and(|s| s.contains(&b))
    }

    /// Adds an edge from `d` to each value of `live`.
    fn def(&mut self, d: Val, live: &BTreeSet<Val>) {
        for &x in live {
            self.add(d, x);
        }
    }
}

/// Gives the phi arguments of the edge `from -> to`.
fn edge_args(f: &Facts<'_>, from: From, to: Node) -> Vec<Arg> {
    let preds = f.ssa.preds(to);
    let slots: Vec<usize> = match from {
        Some(b) => preds
            .iter()
            .enumerate()
            .filter(|(_, p)| **p == b)
            .map(|(j, _)| j)
            .collect(),
        None => vec![preds.len()],
    };
    let mut out = Vec::new();
    for (_, _, args) in phis_of(f, to) {
        for &j in &slots {
            if let Some(&a) = args.get(j) {
                out.push(a);
            }
        }
    }
    out
}

/// Gives the values of a list of arguments.
fn vals(args: &[Arg]) -> impl Iterator<Item = Val> + '_ {
    args.iter().filter_map(|a| a.as_v())
}

/// Computes the liveness and the interference of the values of `cx`.
fn interference(cx: &Ctx<'_>) -> Interference {
    let f = cx.f;
    let reach: BTreeSet<Node> = f.reach.iter().copied().collect();
    let evs: BTreeMap<Node, Vec<Ev>> = cx.raws.iter().map(|r| (r.block, events(r))).collect();
    let mut gen_: BTreeMap<Node, BTreeSet<Val>> = BTreeMap::new();
    let mut kill: BTreeMap<Node, BTreeSet<Val>> = BTreeMap::new();
    for &b in &f.reach {
        let mut g = BTreeSet::new();
        let mut k: BTreeSet<Val> = phis_of(f, b).iter().map(|p| p.0).collect();
        for ev in evs.get(&b).into_iter().flatten() {
            match *ev {
                Ev::Use(v) if !k.contains(&v) => {
                    g.insert(v);
                }
                Ev::Def(v) => {
                    k.insert(v);
                }
                Ev::Use(_) => {}
            }
        }
        gen_.insert(b, g);
        kill.insert(b, k);
    }
    let mut live_in: BTreeMap<Node, BTreeSet<Val>> = BTreeMap::new();
    let live_out_of = |b: Node, live_in: &BTreeMap<Node, BTreeSet<Val>>| {
        let mut out = BTreeSet::new();
        for s in f.ssa.cfg().succs(b) {
            if !reach.contains(s) {
                continue;
            }
            out.extend(live_in.get(s).into_iter().flatten().copied());
            out.extend(vals(&edge_args(f, Some(b), *s)));
        }
        out
    };
    let rounds = f.reach.len().saturating_mul(2).saturating_add(8);
    for _ in 0..rounds {
        let mut changed = false;
        for &b in f.reach.iter().rev() {
            let out = live_out_of(b, &live_in);
            let k = kill.get(&b).cloned().unwrap_or_default();
            let mut inn: BTreeSet<Val> = out.difference(&k).copied().collect();
            inn.extend(gen_.get(&b).into_iter().flatten().copied());
            if live_in.get(&b) != Some(&inn) {
                live_in.insert(b, inn);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut graph = Interference::default();
    for &b in &f.reach {
        let mut live = live_out_of(b, &live_in);
        for ev in evs.get(&b).into_iter().flatten().rev() {
            match *ev {
                Ev::Def(v) => {
                    live.remove(&v);
                    graph.def(v, &live);
                }
                Ev::Use(v) => {
                    live.insert(v);
                }
            }
        }
        let phis: Vec<Val> = phis_of(f, b).iter().map(|p| p.0).collect();
        for &p in &phis {
            live.remove(&p);
        }
        for &p in &phis {
            graph.def(p, &live);
            for &q in &phis {
                graph.add(p, q);
            }
        }
    }
    if let Some(&entry) = f.reach.first() {
        let mut live = live_in.get(&entry).cloned().unwrap_or_default();
        live.extend(vals(&edge_args(f, None, entry)));
        let inputs: Vec<Val> = inputs_of(f);
        for &i in &inputs {
            live.remove(&i);
        }
        for &i in &inputs {
            graph.def(i, &live);
            for &j in &inputs {
                graph.add(i, j);
            }
        }
    }
    graph
}

/// Gives the entry values in start order.
fn inputs_of(f: &Facts<'_>) -> Vec<Val> {
    f.start
        .iter()
        .filter_map(|&i| f.op(i).and_then(|o| o.out))
        .filter(|v| matches!(f.kind_of(*v), Kind::Input(_)) && f.use_count(*v) > 0)
        .collect()
}

/// A union-find over values with member lists.
#[derive(Debug, Default)]
struct Classes {
    parent: BTreeMap<Val, Val>,
    members: BTreeMap<Val, Vec<Val>>,
}

impl Classes {
    fn add(&mut self, v: Val) {
        if let std::collections::btree_map::Entry::Vacant(slot) = self.parent.entry(v) {
            slot.insert(v);
            self.members.insert(v, vec![v]);
        }
    }

    fn find(&self, v: Val) -> Val {
        let mut cur = v;
        for _ in 0..=self.parent.len() {
            match self.parent.get(&cur) {
                Some(&p) if p != cur => cur = p,
                _ => return cur,
            }
        }
        cur
    }

    /// Joins the classes of `a` and `b` when no members interfere. Gives `true` on a join.
    fn join(&mut self, a: Val, b: Val, g: &Interference) -> bool {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb || !self.parent.contains_key(&ra) || !self.parent.contains_key(&rb) {
            return false;
        }
        let ma = self.members.get(&ra).cloned().unwrap_or_default();
        let mb = self.members.get(&rb).cloned().unwrap_or_default();
        if ma.iter().any(|x| mb.iter().any(|y| g.has(*x, *y))) {
            return false;
        }
        let (keep, gone) = if ra < rb { (ra, rb) } else { (rb, ra) };
        self.parent.insert(gone, keep);
        let moved = self.members.remove(&gone).unwrap_or_default();
        self.members.entry(keep).or_default().extend(moved);
        true
    }
}

/// Gives the values that need a variable, in def order. The used entry values come first.
/// Then each reachable block gives its phis and the values of its statements.
fn members_in_order(cx: &Ctx<'_>) -> Vec<Val> {
    let mut out = inputs_of(cx.f);
    for raw in cx.raws {
        out.extend(phis_of(cx.f, raw.block).iter().map(|p| p.0));
        for s in &raw.stmts {
            out.extend(stmt_defs(s));
            out.extend(stmt_uses(s));
        }
        for ev in events(raw) {
            if let Ev::Use(v) = ev {
                out.push(v);
            }
        }
    }
    for raw in cx.raws {
        for (_, _, args) in phis_of(cx.f, raw.block) {
            out.extend(vals(&args));
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|v| seen.insert(*v));
    out
}

/// Gives the home location of each value: the first location that an L0 `Put` writes it to.
fn homes(l0: &Arena) -> BTreeMap<Val, Loc> {
    let mut out = BTreeMap::new();
    for op in l0.ops() {
        if op.opc == Opc::Put
            && let (Some(loc), Arg::V(x)) = (op.a[0].as_loc(), op.a[1])
        {
            out.entry(x).or_insert(loc);
        }
    }
    out
}

/// Assigns the variables of a view (see the module doc).
pub(crate) fn assign(cx: &Ctx<'_>) -> Assigned {
    let f = cx.f;
    let graph = interference(cx);
    let order = members_in_order(cx);
    let mut classes = Classes::default();
    for &v in &order {
        classes.add(v);
    }
    for raw in cx.raws {
        for (p, _, args) in phis_of(f, raw.block) {
            for x in vals(&args) {
                let _ = classes.join(p, x, &graph);
            }
        }
    }
    let home = homes(cx.l0);
    let mut by_slot: BTreeMap<i32, Vec<Val>> = BTreeMap::new();
    for &v in &order {
        if let Some(Loc::Stack(k)) = home.get(&v) {
            by_slot.entry(*k).or_default().push(v);
        }
    }
    for list in by_slot.values() {
        for pair in list.windows(2) {
            if let [a, b] = pair {
                let _ = classes.join(*a, *b, &graph);
            }
        }
    }
    let mut namer = crate::vars_names::Namer::new(cx, &home);
    let mut of: BTreeMap<Val, VarIdx> = BTreeMap::new();
    let mut root_var: BTreeMap<Val, VarIdx> = BTreeMap::new();
    for &v in &order {
        let root = classes.find(v);
        let idx = if let Some(&i) = root_var.get(&root) {
            i
        } else {
            let members = classes.members.get(&root).cloned().unwrap_or_default();
            let i = namer.class(&members);
            root_var.insert(root, i);
            i
        };
        of.insert(v, idx);
    }
    let copies = edge_copies(cx, &of, &mut namer);
    Assigned {
        of,
        vars: namer.into_vars(),
        copies,
    }
}

/// Gives the parallel copies of each edge, in run order.
fn edge_copies(
    cx: &Ctx<'_>,
    of: &BTreeMap<Val, VarIdx>,
    namer: &mut crate::vars_names::Namer<'_>,
) -> BTreeMap<(From, Node), Vec<Stmt>> {
    let f = cx.f;
    let reach: BTreeSet<Node> = f.reach.iter().copied().collect();
    let mut out = BTreeMap::new();
    for &to in &f.reach {
        let phis = phi_ops(f, to);
        if phis.is_empty() {
            continue;
        }
        let preds = f.ssa.preds(to);
        let mut froms: Vec<From> = preds
            .iter()
            .filter(|p| reach.contains(p))
            .map(|p| Some(*p))
            .collect();
        if Some(&to) == f.reach.first() {
            froms.push(None);
        }
        froms.dedup();
        for from in froms {
            let slot = match from {
                Some(b) => preds.iter().position(|p| *p == b),
                None => Some(preds.len()),
            };
            let Some(slot) = slot else {
                continue;
            };
            let mut list: Vec<(VarIdx, Expr, OpId)> = Vec::new();
            for (i, p, phi_at, args) in &phis {
                // The copy shows the move that sets the argument on this edge, else the phi.
                let at = from
                    .zip(f.ssa.phi_loc(*i))
                    .and_then(|(b, loc)| last_put(cx, b, loc))
                    .unwrap_or(*phi_at);
                let Some(&dst) = of.get(p) else {
                    continue;
                };
                let w = f.ssa.value_width(*p).unwrap_or(64);
                let src = match args.get(slot) {
                    Some(Arg::V(x)) => match of.get(x) {
                        Some(&s) if s == dst => continue,
                        Some(&s) => Expr::Var {
                            var: s,
                            w: f.ssa.value_width(*x).unwrap_or(w),
                        },
                        None => continue,
                    },
                    Some(Arg::K(k)) => stmts::konst(cx.env, k.get(), w),
                    _ => continue,
                };
                list.push((dst, src, at));
            }
            if !list.is_empty() {
                let addr = f.ssa.block_addr(to).unwrap_or(cx.entry);
                out.insert((from, to), sequence(list, namer, addr));
            }
        }
    }
    out
}

/// Orders one parallel copy. A cycle takes a temporary variable.
fn sequence(
    mut list: Vec<(VarIdx, Expr, OpId)>,
    namer: &mut crate::vars_names::Namer<'_>,
    addr: u64,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    let reads = |list: &[(VarIdx, Expr, OpId)], v: VarIdx, skip: usize| {
        list.iter()
            .enumerate()
            .any(|(k, (_, e, _))| k != skip && e.vars().contains(&v))
    };
    let cap = list.len().saturating_mul(3).saturating_add(4);
    for _ in 0..cap {
        if list.is_empty() {
            break;
        }
        if let Some(k) = (0..list.len()).find(|&k| !reads(&list, list[k].0, k)) {
            let (var, value, at) = list.remove(k);
            out.push(Stmt::Assign { var, value, at });
            continue;
        }
        let (d, _, at) = list[0].clone();
        let w = namer.width(d);
        let t = namer.temp(w, addr);
        out.push(Stmt::Assign {
            var: t,
            value: Expr::Var { var: d, w },
            at,
        });
        for (_, e, _) in &mut list {
            if let Expr::Var { var, .. } = e
                && *var == d
            {
                *var = t;
            }
        }
    }
    out
}

/// Gives the variable identity of a function and a storage.
pub(crate) fn var_id(entry: u64, storage: Storage) -> VarId {
    VarId {
        func: FuncId(Address::ram(entry)),
        storage,
    }
}

/// Gives a register variable storage, or `None` for a name outside the grammar.
pub(crate) fn reg_storage(name: &str, def: u64) -> Option<Storage> {
    RegVar::new(name, def).ok().map(Storage::Reg)
}

/// Gives the kind of a storage.
pub(crate) const fn kind_of(s: &Storage) -> VarKind {
    match s {
        Storage::Param(_) => VarKind::Param,
        Storage::Stack(_) => VarKind::Local,
        Storage::Reg(_) | Storage::Ret => VarKind::Temp,
    }
}
