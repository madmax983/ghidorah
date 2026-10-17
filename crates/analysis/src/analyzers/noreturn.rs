//! `NoReturnKnown` (band 301) and `NoReturnDiscovered` (band 302) (design Section 7.7).
//!
//! `NoReturnKnown` reads the noreturn list of the binary format. The match uses the name part
//! of each import without leading underscores. The PLT stub of a listed import gets the
//! noreturn flag with `R_NORETURN_KNOWN`. The import slot of a listed import becomes a
//! noreturn slot, so a `call [rip+slot]` site does not fall through.
//!
//! `NoReturnDiscovered` gives a function the flag when one of these rules holds:
//!
//! | Rule | Condition |
//! |---|---|
//! | `R_NORETURN_BODY` | No path returns: no `ret`, no unknown end, and each exit goes to a noreturn function or slot |
//! | `R_NORETURN_FALLTHROUGH` | 3 or more call sites fall through into another function, bad code or memory that is not executable |
//!
//! The flags of the flow are the least fixpoint from the known flags. Each run computes them
//! again for all functions, so a lost reason also removes a flag. A body that a flag of the
//! fixpoint does not cut waits for the next `Disasm` run. A flag of the fall-through rule
//! stays while its function exists: its cuts can remove the call sites that gave it.

use std::collections::BTreeMap;

use ghidorah_base::{Address, FuncId};
use ghidorah_db::FactKey;
use ghidorah_kernel::RangeSet;

use crate::code::{decode_at, is_exec};
use crate::ctx::{AnalysisCtx, Summary, UNIT_NORETURN_CALL};
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::{Rule, Why};

/// The smallest number of unsafe call sites of `R_NORETURN_FALLTHROUGH`.
pub const UNSAFE_SITES: u64 = 3;

/// The largest number of call-site premises of one `R_NORETURN_FALLTHROUGH` record.
const SITE_PREMISES: usize = 8;

/// The spec of `NoReturnKnown`.
pub const KNOWN: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::NoReturnKnown,
    name: "NoReturnKnown",
    priority: 301,
    triggers: &[Trigger::Bytes, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Flags the stubs and the slots of the imports on the noreturn list.",
};

/// The spec of `NoReturnDiscovered`.
pub const DISCOVERED: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::NoReturnDiscovered,
    name: "NoReturnDiscovered",
    priority: 302,
    triggers: &[Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[Opt {
        name: "unsafe_sites",
        value: UNSAFE_SITES,
        doc: "The smallest number of call sites with an unsafe fall-through.",
    }],
    doc: "Flags the functions whose flow never returns.",
};

/// Gives the function key of an entry.
const fn func_key(entry: u64) -> FactKey {
    FactKey::Func(FuncId(Address::ram(entry)))
}

/// Gives the noreturn key of an entry.
const fn flag_key(entry: u64) -> FactKey {
    FactKey::Noreturn(FuncId(Address::ram(entry)))
}

/// Runs one step of `NoReturnKnown` over `ranges`.
pub fn run_known(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    let Some(Ok(list)) = ghidorah_types::noreturn_list(program.meta().format.name()) else {
        return Step { work: 1 };
    };
    let mut work = 1u64;
    for row in program.imports().values() {
        work = work.saturating_add(1);
        let listed = row.id.name().is_some_and(|n| list.contains(n));
        let Some(stub) = row.stub.filter(|a| a.is_ram() && ranges.contains(a.off)) else {
            continue;
        };
        if listed && ctx.is_entry(stub.off) {
            let premises = vec![func_key(stub.off), FactKey::Import(row.id.clone())];
            let _ = ctx.set_known(stub.off, Some(Why::new(Rule::NoreturnKnown, premises)));
        }
    }
    for (slot, id) in ctx.import_slots() {
        work = work.saturating_add(1);
        if ranges.contains(slot) && id.name().is_some_and(|n| list.contains(n)) {
            let _ = ctx.set_slot(slot, id);
        }
    }
    Step { work }
}

/// The state of one fixpoint round: the known flags, the base-layer flags and the new flags.
struct Fix<'c, 'a> {
    ctx: &'c AnalysisCtx<'a>,
    found: BTreeMap<u64, Why>,
}

impl Fix<'_, '_> {
    /// Tells if the function `entry` is noreturn in the fixpoint so far.
    fn noreturn(&self, entry: u64) -> bool {
        let base = self
            .ctx
            .program()
            .base()
            .funcs()
            .get(FuncId(Address::ram(entry)))
            .and_then(|f| f.flags.noreturn.as_ref())
            .map(|f| f.value);
        base.unwrap_or_else(|| {
            self.ctx.work.known.contains_key(&entry) || self.found.contains_key(&entry)
        })
    }

    /// Gives the function that an exit to `to` goes into.
    fn exit_func(&self, to: u64) -> Option<u64> {
        if self.ctx.is_entry(to) {
            return Some(to);
        }
        self.ctx.owner(to).or_else(|| self.ctx.extent_owner(to))
    }

    /// Gives the why-record of `R_NORETURN_BODY` for the function `entry` with `summary`.
    fn body_rule(&self, entry: u64, summary: &Summary) -> Option<Why> {
        if summary.ret || summary.unknown {
            return None;
        }
        let mut premises = vec![func_key(entry)];
        for to in &summary.exits {
            let target = self.exit_func(*to)?;
            if !self.noreturn(target) {
                return None;
            }
            premises.push(flag_key(target));
        }
        for slot in &summary.slot_exits {
            premises.push(FactKey::Import(self.ctx.work.slots.get(slot)?.clone()));
        }
        for (site, target) in &summary.calls {
            let cut = self
                .ctx
                .work
                .units
                .get(site)
                .is_some_and(|u| u.flags & UNIT_NORETURN_CALL != 0);
            if cut {
                if !self.noreturn(*target) {
                    return None;
                }
                premises.push(flag_key(*target));
            }
        }
        Some(Why::new(Rule::NoreturnBody, premises))
    }

    /// Gives the why-record of `R_NORETURN_FALLTHROUGH` for the function `entry`.
    fn fallthrough_rule(&self, entry: u64) -> Option<Why> {
        let program = self.ctx.program();
        let mut unsafe_sites = Vec::new();
        for site in self.ctx.call_sites(entry) {
            let Some(unit) = self.ctx.work.units.get(&site) else {
                continue;
            };
            let Some(next) = site.checked_add(u64::from(unit.len)) else {
                continue;
            };
            let bad = self.ctx.is_entry(next)
                || !is_exec(program, next)
                || decode_at(program, next).is_none();
            if bad {
                unsafe_sites.push(site);
            }
        }
        let count = u64::try_from(unsafe_sites.len()).unwrap_or(u64::MAX);
        if count < UNSAFE_SITES {
            return None;
        }
        let mut premises = vec![func_key(entry)];
        premises.extend(
            unsafe_sites
                .into_iter()
                .take(SITE_PREMISES)
                .map(FactKey::CodeUnit),
        );
        Some(Why::new(Rule::NoreturnFallthrough, premises))
    }
}

/// Runs one step of `NoReturnDiscovered`: the least fixpoint of the flow flags of every
/// function. The ranges only queue the step.
pub fn run_discovered(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = ranges;
    let entries: Vec<(u64, Summary)> = ctx
        .funcs()
        .filter_map(|(e, f)| f.summary.clone().map(|s| (e, s)))
        .collect();
    let kept: BTreeMap<u64, Why> = ctx
        .work
        .found
        .iter()
        .filter(|(e, w)| w.rule == Rule::NoreturnFallthrough && ctx.is_entry(**e))
        .map(|(e, w)| (*e, w.clone()))
        .collect();
    let mut fix = Fix { ctx, found: kept };
    let sites: BTreeMap<u64, Why> = ctx
        .entries()
        .into_iter()
        .filter_map(|e| fix.fallthrough_rule(e).map(|w| (e, w)))
        .collect();
    let mut work = 1u64.saturating_add(u64::try_from(sites.len()).unwrap_or(u64::MAX));
    for _ in 0..=entries.len() {
        let mut grew = false;
        for (entry, summary) in &entries {
            work = work.saturating_add(1);
            if fix.found.contains_key(entry) {
                continue;
            }
            let why = fix
                .body_rule(*entry, summary)
                .or_else(|| sites.get(entry).cloned());
            if let Some(why) = why {
                fix.found.insert(*entry, why);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    let found = fix.found;
    let all: Vec<u64> = ctx.entries();
    for entry in all {
        let _ = ctx.set_found(entry, found.get(&entry).cloned());
    }
    Step { work }
}
