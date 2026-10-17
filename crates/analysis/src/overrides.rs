//! `Overrides` (band 160): the seeds of the higher-rank facts (design Sections 3.6 and 7.1).
//!
//! The analyzer reads the base layer once:
//!
//! | Base fact | Seed |
//! |---|---|
//! | an agent or user function | a function with the start reason `Agent` and `R_AGENT_FUNCTION` |
//! | an `indirect_targets` override at a call | a function at each RAM target with `R_AGENT_CALL_TARGET` |
//! | an agent call reference to executable memory | a function at the target with `R_AGENT_REF` |
//!
//! `Disasm` reads the flow of each site with [`site_flow`]. An agent jump table or an
//! `indirect_targets` override at an indirect jump gives its cases. A method A table of the
//! work state gives the cases of a jump with no agent fact. The other flow overrides change
//! the flow of the site. Analysis never writes over an agent fact (ADR-0013). When it
//! disagrees, the function gets `W_AGENT_OVERRIDE_CONFLICT` with the analysis value.

use std::collections::BTreeMap;

use ghidorah_base::{Address, JumpTableId};
use ghidorah_db::{FactKey, FlowOverride, RefType, StartReason};
use ghidorah_kernel::RangeSet;
use ghidorah_x86::Flow;

use crate::code::{decode_at, is_exec};
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The confidence of a function that an agent call target or reference seeds.
pub const TARGET_CONFIDENCE: u8 = 95;

/// Gives the spec of `Overrides` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "Overrides",
        priority: 160,
        triggers: &[Trigger::Bytes],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Seeds the agent functions, the agent call targets and the agent call references.",
    }
}

/// The flow of one site that a fact sets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SiteFlow {
    /// The cases of an indirect jump: an agent table, an agent override or a method A table.
    Cases(Vec<u64>),
    /// The targets of an indirect call from an agent override.
    Calls(Vec<u64>),
    /// The flow after the instruction goes to this address.
    Fallthrough(u64),
    /// The call is a jump.
    CallAsJump,
    /// The jump is a call.
    JumpAsCall,
}

/// Gives the flow that a fact sets for the instruction at `at` with the decoder flow `flow`.
#[must_use]
pub fn site_flow(ctx: &AnalysisCtx<'_>, at: u64, flow: Flow) -> Option<SiteFlow> {
    let over = ctx
        .program()
        .base()
        .overrides()
        .get(Address::ram(at))
        .map(|f| f.value.clone());
    match (flow, over) {
        (Flow::IJmp, _) => cases(ctx, at).map(SiteFlow::Cases),
        (Flow::ICall, Some(FlowOverride::IndirectTargets(t))) => Some(SiteFlow::Calls(ram(&t))),
        (_, Some(FlowOverride::Fallthrough(t))) if t.is_ram() => Some(SiteFlow::Fallthrough(t.off)),
        (Flow::Call, Some(FlowOverride::CallAsJump)) => Some(SiteFlow::CallAsJump),
        (Flow::Jmp, Some(FlowOverride::JumpAsCall)) => Some(SiteFlow::JumpAsCall),
        _ => None,
    }
}

/// Gives the case targets of the indirect jump at `site`. The order is an agent
/// `indirect_targets` override, an agent table, then a resolved method A table.
#[must_use]
pub(crate) fn cases(ctx: &AnalysisCtx<'_>, site: u64) -> Option<Vec<u64>> {
    let base = ctx.program().base();
    let addr = Address::ram(site);
    if let Some(FlowOverride::IndirectTargets(t)) = base.overrides().get(addr).map(|f| &f.value) {
        return Some(ram(t));
    }
    if let Some(t) = base.jumptables().get(JumpTableId(addr)) {
        return Some(ram(&t.value.targets));
    }
    ctx.ir()
        .tables
        .get(&site)
        .filter(|r| r.table.resolved)
        .map(|r| ram(&r.table.targets))
}

/// Gives the RAM offsets of `addrs` in order.
fn ram(addrs: &[Address]) -> Vec<u64> {
    addrs.iter().filter(|a| a.is_ram()).map(|a| a.off).collect()
}

/// Tells if a reference kind is a call.
const fn is_call(kind: RefType) -> bool {
    matches!(
        kind,
        RefType::UnconditionalCall | RefType::ConditionalCall | RefType::ComputedCall
    )
}

/// Runs one step: the seeds of the base layer.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = ranges;
    let program = ctx.program();
    let base = program.base();
    let mut seeds: Vec<(u64, u8, Why)> = Vec::new();
    for (at, fact) in base.overrides().iter() {
        if let FlowOverride::IndirectTargets(targets) = &fact.value
            && decode_at(program, at.off).is_some_and(|i| i.flow() == Flow::ICall)
        {
            for t in ram(targets).into_iter().filter(|t| is_exec(program, *t)) {
                let why = Why::new(Rule::AgentCallTarget, vec![FactKey::FlowOverride(at)]);
                seeds.push((t, TARGET_CONFIDENCE, why));
            }
        }
    }
    for r in base.refs().iter() {
        let key = r.value.key;
        if is_call(key.kind) && key.to.is_ram() && is_exec(program, key.to.off) {
            let why = Why::new(Rule::AgentRef, vec![FactKey::Ref(key)]);
            seeds.push((key.to.off, TARGET_CONFIDENCE, why));
        }
    }
    for f in base.funcs().iter().filter(|f| f.entry.is_ram()) {
        let why = Why::new(Rule::AgentFunction, vec![FactKey::Func(f.id())]);
        seeds.push((f.entry.off, 100, why));
    }
    let mut work = 1u64;
    let mut best: BTreeMap<u64, (u8, Why)> = BTreeMap::new();
    for (entry, confidence, why) in seeds {
        work = work.saturating_add(1);
        let slot = best
            .entry(entry)
            .or_insert_with(|| (confidence, why.clone()));
        if confidence > slot.0 || (confidence == slot.0 && why < slot.1) {
            *slot = (confidence, why);
        }
    }
    for (entry, (confidence, why)) in best {
        let _ = ctx.add_reason(entry, StartReason::Agent, confidence, why);
    }
    Step { work }
}
