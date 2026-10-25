//! The call sites of a callee and their argument values: the `const_arg` check.
//!
//! | Callee | Call sites | Unresolved callers |
//! |---|---|---|
//! | a function | call references to the entry, jumps from outside the body, override targets | a reference that takes the entry address, an export or an entry point at the entry |
//! | an import | call and jump references to the stub or the EXTERNAL address from outside the stub, override targets | a reference that takes the stub or the EXTERNAL address |
//! | a syscall | the syscall sites with the number | a syscall site with no number |
//!
//! Each gap of the program is also an unresolved caller: an indirect call or jump with no
//! target can go to any callee. Block-local evaluation gives the value of each argument
//! ([`crate::callargs`]). A site with no value for the argument blocks a negative verdict.

use std::collections::BTreeSet;

use ghidorah_base::{Address, Fuel, FuncId, ImportId};
use ghidorah_db::{Program, RefType};

use super::check::{Checker, Step, Stop, negative, site_gaps, supported};
use super::outcome::{Evidence, Gap, Outcome};
use super::relations::Endpoint;
use super::scope::override_targets;
use crate::callargs::{self, ArgValue};

/// Tells if the reference type is a jump.
const fn is_jump(kind: RefType) -> bool {
    matches!(
        kind,
        RefType::UnconditionalJump | RefType::ConditionalJump | RefType::ComputedJump
    )
}

/// Gives the value of an argument as a number: an integer, or the address of a pointer.
fn number(v: &ArgValue) -> Option<u64> {
    match v {
        ArgValue::Int(c) => Some(*c),
        ArgValue::Str { addr, .. } | ArgValue::Addr(addr) => Some(*addr),
        ArgValue::Func(f) => f.0.is_ram().then_some(f.0.off),
        ArgValue::Unknown => None,
    }
}

/// Adds the result of the argument `arg` at the site `at`: evidence for a match, a gap for an
/// unknown value.
fn judge(
    arg: Option<&ArgValue>,
    value: u64,
    at: Address,
    evidence: &mut Vec<Evidence>,
    gaps: &mut Vec<Gap>,
) {
    match arg.and_then(number) {
        Some(v) if v == value => evidence.push(Evidence::Site(at)),
        Some(_) => {}
        None => gaps.push(Gap::Site(at)),
    }
}

/// Gives the sites of the `IndirectTargets` overrides that list one of `targets`.
fn override_sites(p: &Program, targets: &[Address]) -> BTreeSet<Address> {
    let mut out = BTreeSet::new();
    for layer in p.layers() {
        for (at, _) in layer.overrides().iter() {
            if override_targets(p, at).is_some_and(|t| t.iter().any(|a| targets.contains(a))) {
                out.insert(at);
            }
        }
    }
    out
}

/// Gives the call sites of the function `g` and the gaps of the code that can call it another
/// way.
fn func_callers(p: &Program, g: FuncId) -> (BTreeSet<Address>, Vec<Gap>) {
    let mut sites = BTreeSet::new();
    let mut taken = Vec::new();
    let inside = |a: Address| a.is_ram() && p.func(g).is_some_and(|v| v.func.body.contains(a.off));
    for r in p.refs_to(g.0) {
        let key = r.value.key;
        if key.kind.is_call() || (is_jump(key.kind) && !inside(key.from)) {
            sites.insert(key.from);
        } else if !key.kind.is_flow() {
            taken.push(Gap::Ref(key));
        }
    }
    sites.extend(override_sites(p, &[g.0]));
    for row in p.exports().values() {
        if row.addr == Some(g.0) {
            taken.push(Gap::Export(row.id.clone()));
        }
    }
    let entry = g.0.is_ram() && p.binary().entry_points.iter().any(|e| e.addr == g.0.off);
    if entry {
        taken.push(Gap::Func(g));
    }
    (sites, taken)
}

/// Gives the call sites of the import `id` and the gaps of the code that can call it another
/// way. The references of the stub and of the import slot are not sites.
fn import_callers(p: &Program, id: &ImportId) -> (BTreeSet<Address>, Vec<Gap>) {
    let mut sites = BTreeSet::new();
    let mut taken = Vec::new();
    let Some(row) = p.imports().get(id) else {
        return (sites, taken);
    };
    let stub_func = row.stub.and_then(|s| p.owner_of(s));
    let addrs: Vec<Address> = row.stub.into_iter().chain([row.ext]).collect();
    for a in &addrs {
        for r in p.refs_to(*a) {
            let key = r.value.key;
            let own = stub_func.is_some() && p.owner_of(key.from) == stub_func;
            if own || Some(key.from) == row.slot {
                continue;
            }
            if key.kind.is_call() || is_jump(key.kind) {
                sites.insert(key.from);
            } else if !key.kind.is_flow() {
                taken.push(Gap::Ref(key));
            }
        }
    }
    sites.extend(override_sites(p, &addrs));
    (sites, taken)
}

/// Checks `const_arg(callee, index, value)`.
pub(crate) fn const_arg(
    c: &mut Checker<'_>,
    callee: &Endpoint,
    index: u8,
    value: u64,
    fuel: &mut Fuel,
) -> Step<Outcome> {
    let mut gaps = site_gaps(&c.all_gaps(fuel)?);
    let p = c.program();
    let idx = usize::from(index);
    let mut evidence = Vec::new();
    let sites = match callee {
        Endpoint::Syscall(n) => {
            let found = crate::syscalls::sites(p, fuel);
            if fuel.is_empty() {
                return Err(Stop);
            }
            for site in found {
                let at = Address::ram(site.site);
                match site.nr {
                    None => gaps.push(Gap::Site(at)),
                    Some(nr) if nr == u64::from(*n) => {
                        judge(site.args.get(idx), value, at, &mut evidence, &mut gaps);
                    }
                    Some(_) => {}
                }
            }
            BTreeSet::new()
        }
        Endpoint::Func(g) => {
            let (sites, taken) = func_callers(p, *g);
            gaps.extend(taken);
            sites
        }
        Endpoint::Import(id) => {
            let (sites, taken) = import_callers(p, id);
            gaps.extend(taken);
            sites
        }
    };
    for at in sites {
        let values = if at.is_ram() {
            callargs::at(p, at.off, fuel).ok()
        } else {
            None
        };
        if fuel.is_empty() {
            return Err(Stop);
        }
        judge(
            values.as_ref().and_then(|v| v.get(idx)),
            value,
            at,
            &mut evidence,
            &mut gaps,
        );
    }
    Ok(if evidence.is_empty() {
        negative(gaps)
    } else {
        supported(evidence)
    })
}
