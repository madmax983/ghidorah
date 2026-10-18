//! The check of one claim atom: three verdicts with an absence basis (design Section 11.8).
//!
//! [`Checker`] reads the merged facts of a program. It keeps the scope of each function that
//! a check reads, so the claims of one call share the work. Each scope build, each node of a
//! `reaches` walk and each call-site evaluation takes fuel. A check that runs out of fuel gives
//! `unknown` with `stopped`.
//!
//! A `supported` verdict has no gaps: nothing blocks it. A `refuted` verdict has no gaps by
//! construction. An `unknown` verdict lists the gaps that block a sound negative.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId, Glob};
use ghidorah_db::{Encoding, Program, RefType};

use super::callers;
use super::outcome::{Evidence, Gap, Outcome, Verdict};
use super::relations::{Atom, Endpoint, RefClass};
use super::scope::{self, Imports, Scope};
use crate::callgraph::Callee;

/// The check ran out of fuel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stop;

/// The result of a step of a check.
pub(crate) type Step<T> = Result<T, Stop>;

/// The checker of the claims of one program.
#[derive(Debug)]
pub struct Checker<'p> {
    program: &'p Program,
    pub(crate) imports: Imports,
    scopes: BTreeMap<FuncId, Option<Scope>>,
    all_gaps: Option<BTreeSet<Address>>,
}

impl<'p> Checker<'p> {
    /// Makes a checker of `program`.
    #[must_use]
    pub fn new(program: &'p Program) -> Self {
        Self {
            program,
            imports: Imports::of(program),
            scopes: BTreeMap::new(),
            all_gaps: None,
        }
    }

    /// Gives the program of the checker.
    #[must_use]
    pub const fn program(&self) -> &'p Program {
        self.program
    }

    /// Checks one atom with the fuel `fuel`. A check that runs out of fuel gives `unknown`
    /// with `stopped`.
    pub fn check(&mut self, atom: &Atom, fuel: &mut Fuel) -> Outcome {
        self.eval(atom, fuel)
            .unwrap_or_else(|Stop| Outcome::out_of_fuel())
    }

    /// Gives the endpoint of `ep` with a PLT stub function as its import.
    #[must_use]
    pub fn normal(&self, ep: &Endpoint) -> Endpoint {
        match ep {
            Endpoint::Func(f) => self
                .imports
                .at(f.0)
                .map_or_else(|| ep.clone(), |i| Endpoint::Import(i.clone())),
            _ => ep.clone(),
        }
    }

    fn eval(&mut self, atom: &Atom, fuel: &mut Fuel) -> Step<Outcome> {
        match atom {
            Atom::Calls { f, g } => match self.normal(g) {
                Endpoint::Func(g) => self.calls(*f, &Callee::Func(g), fuel),
                Endpoint::Import(i) => self.calls(*f, &Callee::Import(i), fuel),
                Endpoint::Syscall(n) => self.has_syscall(*f, n, fuel),
            },
            Atom::Reaches { f, g, depth } => {
                let goal = self.normal(g);
                self.reaches(*f, &goal, *depth, fuel)
            }
            Atom::UsesImport { f, import } => self.uses_import(*f, import, fuel),
            Atom::RefsString { f, glob } => self.refs_string(*f, glob, fuel),
            Atom::RefsAddr { f, addr } => self.refs_addr(*f, *addr, fuel),
            Atom::Xref { from, to, kind } => Ok(self.xref(*from, *to, *kind)),
            Atom::ConstArg {
                callee,
                index,
                value,
            } => {
                let callee = self.normal(callee);
                callers::const_arg(self, &callee, *index, *value, fuel)
            }
            Atom::HasSyscall { f, number } => self.has_syscall(*f, *number, fuel),
            Atom::Noreturn { f } => self.noreturn(*f, fuel),
            Atom::InFunc { addr, f } => Ok(self.in_func(*addr, *f)),
        }
    }

    /// Builds the scope of `func` when the checker has none yet. The build takes fuel.
    pub(crate) fn ensure(&mut self, func: FuncId, fuel: &mut Fuel) -> Step<()> {
        if self.scopes.contains_key(&func) {
            return Ok(());
        }
        let built = scope::build(self.program, &self.imports, func);
        let cost = built.as_ref().map_or(1, |s| s.cost.max(1));
        self.scopes.insert(func, built);
        fuel.take(cost).map_err(|_| Stop)
    }

    /// Gives the scope of `func` after [`Self::ensure`].
    pub(crate) fn scope(&self, func: FuncId) -> Option<&Scope> {
        self.scopes.get(&func).and_then(Option::as_ref)
    }

    /// Gives the gaps of every function of the program.
    pub(crate) fn all_gaps(&mut self, fuel: &mut Fuel) -> Step<BTreeSet<Address>> {
        if let Some(all) = &self.all_gaps {
            return Ok(all.clone());
        }
        let mut all = BTreeSet::new();
        for view in self.program.funcs() {
            self.ensure(view.id(), fuel)?;
            if let Some(s) = self.scope(view.id()) {
                all.extend(s.gaps.iter().copied());
            }
        }
        self.all_gaps = Some(all.clone());
        Ok(all)
    }

    fn calls(&mut self, f: FuncId, g: &Callee, fuel: &mut Fuel) -> Step<Outcome> {
        self.ensure(f, fuel)?;
        let Some(s) = self.scope(f) else {
            return Ok(missing(f));
        };
        Ok(match s.calls.get(g) {
            Some(ev) => supported(ev.iter().cloned().collect()),
            None => negative(site_gaps(&s.gaps)),
        })
    }

    fn reaches(&mut self, f: FuncId, goal: &Endpoint, depth: u8, fuel: &mut Fuel) -> Step<Outcome> {
        let node = match goal {
            Endpoint::Func(g) => Some(Callee::Func(*g)),
            Endpoint::Import(i) => Some(Callee::Import(i.clone())),
            Endpoint::Syscall(_) => None,
        };
        let mut seen: BTreeSet<FuncId> = BTreeSet::from([f]);
        let mut parent: BTreeMap<FuncId, (FuncId, Evidence)> = BTreeMap::new();
        let mut level = vec![f];
        let mut gaps = Vec::new();
        for _ in 0..depth {
            let mut next = Vec::new();
            for x in level {
                fuel.take(1).map_err(|_| Stop)?;
                self.ensure(x, fuel)?;
                let Some(s) = self.scope(x) else { continue };
                gaps.extend(site_gaps(&s.gaps));
                if let Endpoint::Syscall(n) = goal {
                    for (site, nr) in &s.syscalls {
                        match nr {
                            Some(k) if k == n => {
                                return Ok(supported(path(&parent, x, Evidence::Site(*site))));
                            }
                            Some(_) => {}
                            None => gaps.push(Gap::Site(*site)),
                        }
                    }
                }
                for (c, ev) in &s.calls {
                    let Some(first) = ev.first().cloned() else {
                        continue;
                    };
                    if node.as_ref() == Some(c) {
                        return Ok(supported(path(&parent, x, first)));
                    }
                    if let Callee::Func(y) = c
                        && seen.insert(*y)
                    {
                        parent.insert(*y, (x, first));
                        next.push(*y);
                    }
                }
            }
            level = next;
        }
        Ok(negative(gaps))
    }

    fn uses_import(
        &mut self,
        f: FuncId,
        import: &ghidorah_base::ImportId,
        fuel: &mut Fuel,
    ) -> Step<Outcome> {
        self.ensure(f, fuel)?;
        let Some(s) = self.scope(f) else {
            return Ok(missing(f));
        };
        let mut evidence: Vec<Evidence> = s
            .calls
            .get(&Callee::Import(import.clone()))
            .map(|ev| ev.iter().cloned().collect())
            .unwrap_or_default();
        if let Some(row) = self.program.imports().get(import) {
            let names = [row.stub, row.slot, Some(row.ext)];
            for key in &s.refs {
                if names.contains(&Some(key.to)) {
                    evidence.push(Evidence::Ref(*key));
                }
            }
        }
        Ok(if evidence.is_empty() {
            negative(site_gaps(&s.gaps))
        } else {
            supported(evidence)
        })
    }

    fn refs_string(&mut self, f: FuncId, glob: &Glob, fuel: &mut Fuel) -> Step<Outcome> {
        self.ensure(f, fuel)?;
        let Some(s) = self.scope(f) else {
            return Ok(missing(f));
        };
        let mut evidence = Vec::new();
        for key in &s.refs {
            if key.kind.is_flow() || !key.to.is_ram() {
                continue;
            }
            let Some(text) = string_text(self.program, key.to.off) else {
                continue;
            };
            let (hit, work) = glob.matches_counted(&text);
            fuel.take(work.max(1)).map_err(|_| Stop)?;
            if hit {
                evidence.push(Evidence::Ref(*key));
            }
        }
        Ok(if evidence.is_empty() {
            negative(data_gaps(self.program, s))
        } else {
            supported(evidence)
        })
    }

    fn refs_addr(&mut self, f: FuncId, addr: Address, fuel: &mut Fuel) -> Step<Outcome> {
        self.ensure(f, fuel)?;
        let Some(s) = self.scope(f) else {
            return Ok(missing(f));
        };
        let evidence: Vec<Evidence> = s
            .refs
            .iter()
            .filter(|k| k.to == addr)
            .map(|k| Evidence::Ref(*k))
            .collect();
        Ok(if evidence.is_empty() {
            negative(data_gaps(self.program, s))
        } else {
            supported(evidence)
        })
    }

    fn xref(&self, from: Address, to: Address, kind: Option<RefClass>) -> Outcome {
        let p = self.program;
        let evidence: Vec<Evidence> = p
            .refs_from(from)
            .iter()
            .map(|r| r.value.key)
            .filter(|k| k.to == to && kind.is_none_or(|c| c.matches(k.kind)))
            .map(Evidence::Ref)
            .collect();
        if !evidence.is_empty() {
            return supported(evidence);
        }
        let analyzed = from.is_ram()
            && p.code_unit(from.off).is_some_and(|u| {
                let ghidorah_db::CodeUnit::Insn { flow, .. } = *u;
                !scope::is_gap(p, from, flow)
            });
        if analyzed {
            negative(Vec::new())
        } else {
            negative(vec![Gap::Site(from)])
        }
    }

    fn has_syscall(&mut self, f: FuncId, number: u16, fuel: &mut Fuel) -> Step<Outcome> {
        self.ensure(f, fuel)?;
        let Some(s) = self.scope(f) else {
            return Ok(missing(f));
        };
        let mut evidence = Vec::new();
        let mut gaps = site_gaps(&s.jump_gaps);
        for (site, nr) in &s.syscalls {
            match nr {
                Some(n) if *n == number => evidence.push(Evidence::Site(*site)),
                Some(_) => {}
                None => gaps.push(Gap::Site(*site)),
            }
        }
        Ok(if evidence.is_empty() {
            negative(gaps)
        } else {
            supported(evidence)
        })
    }

    fn noreturn(&mut self, f: FuncId, fuel: &mut Fuel) -> Step<Outcome> {
        let Some(view) = self.program.func(f) else {
            return Ok(missing(f));
        };
        if view.noreturn.is_some_and(|n| n.value) {
            return Ok(supported(vec![Evidence::Func(f)]));
        }
        self.ensure(f, fuel)?;
        let Some(s) = self.scope(f) else {
            return Ok(missing(f));
        };
        if !s.rets.is_empty() {
            let rets = s.rets.iter().map(|a| Evidence::Site(*a)).collect();
            return Ok(Outcome::new(Verdict::Refuted, rets, Vec::new()));
        }
        let mut gaps: Vec<Gap> = s.tails.iter().map(|a| Gap::Site(*a)).collect();
        gaps.extend(site_gaps(&s.jump_gaps));
        if gaps.is_empty() {
            gaps.push(Gap::Func(f));
        }
        Ok(Outcome::new(Verdict::Unknown, Vec::new(), gaps))
    }

    fn in_func(&self, addr: Address, f: FuncId) -> Outcome {
        let p = self.program;
        let Some(view) = p.func(f) else {
            return missing(f);
        };
        if addr.is_ram() && view.func.body.contains(addr.off) {
            return supported(vec![Evidence::Func(f)]);
        }
        match p.owner_of(addr) {
            Some(g) if g != f => {
                Outcome::new(Verdict::Refuted, vec![Evidence::Func(g)], Vec::new())
            }
            _ => Outcome::new(Verdict::Unknown, Vec::new(), vec![Gap::Site(addr)]),
        }
    }
}

/// Gives the evidence of a path: the edges from `f` to `x`, then the edge `last`.
fn path(parent: &BTreeMap<FuncId, (FuncId, Evidence)>, x: FuncId, last: Evidence) -> Vec<Evidence> {
    let mut out = vec![last];
    let mut at = x;
    while let Some((up, ev)) = parent.get(&at) {
        out.push(ev.clone());
        at = *up;
    }
    out
}

/// Gives a `supported` outcome: nothing blocks it, so it has no gaps.
pub(crate) fn supported(evidence: Vec<Evidence>) -> Outcome {
    Outcome::new(Verdict::Supported, evidence, Vec::new())
}

/// Gives the negative outcome of `gaps`: `refuted` with no gap, else `unknown`.
pub(crate) fn negative(gaps: Vec<Gap>) -> Outcome {
    let verdict = if gaps.is_empty() {
        Verdict::Refuted
    } else {
        Verdict::Unknown
    };
    Outcome::new(verdict, Vec::new(), gaps)
}

/// Gives the outcome of a claim about a function that does not exist.
fn missing(f: FuncId) -> Outcome {
    Outcome::new(Verdict::Unknown, Vec::new(), vec![Gap::Func(f)])
}

/// Gives a site gap for each address of `sites`.
pub(crate) fn site_gaps(sites: &BTreeSet<Address>) -> Vec<Gap> {
    sites.iter().map(|a| Gap::Site(*a)).collect()
}

/// Gives the gaps of a data claim: the indirect sites, and each reference to a pointer slot.
/// A pointer slot can lead to more data, so the reference blocks a negative verdict.
fn data_gaps(p: &Program, s: &Scope) -> Vec<Gap> {
    let mut gaps = site_gaps(&s.gaps);
    for key in &s.refs {
        if !key.kind.is_flow() && is_pointer_slot(p, key.to) {
            gaps.push(Gap::Ref(*key));
        }
    }
    gaps
}

/// Tells if `addr` is a pointer slot: data with a `data` reference out of it.
fn is_pointer_slot(p: &Program, addr: Address) -> bool {
    addr.is_ram()
        && p.code_unit(addr.off).is_none()
        && p.refs_from(addr)
            .iter()
            .any(|r| r.value.key.kind == RefType::Data)
}

/// Gives the text of the string at the RAM offset `off`, or `None` when no string starts there.
fn string_text(p: &Program, off: u64) -> Option<String> {
    let info = p.string(off)?;
    let raw = crate::analyzers::strings::bytes(p, off, info)?;
    Some(match info.encoding {
        Encoding::Utf16Le => {
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| {
                    u16::from_le_bytes([
                        c.first().copied().unwrap_or(0),
                        c.get(1).copied().unwrap_or(0),
                    ])
                })
                .collect();
            String::from_utf16_lossy(&units)
        }
        Encoding::Ascii | Encoding::Utf8 => String::from_utf8_lossy(&raw).into_owned(),
    })
}
