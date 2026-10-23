//! `CallTargets` (band 400): a function at each direct call target (design Section 7.3).
//!
//! The roots are the functions with a start reason other than `Call`. A walk in address order
//! goes from the roots over the direct call sites of the bodies. Each target that the walk
//! reaches in executable memory gets the start reason `Call` with confidence 95 and
//! `R_CALL_TARGET`. The premise is the reference of the first call site of the walk. A `Call`
//! reason that the walk does not reach goes. So dead code after a new noreturn call does not
//! keep its callees.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ghidorah_base::Address;
use ghidorah_db::{FactKey, RefKey, RefType, StartReason};
use ghidorah_kernel::RangeSet;

use crate::code::is_exec;
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::CallTargets,
    name: "CallTargets",
    priority: 400,
    triggers: &[Trigger::Instructions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each direct call target that the roots reach.",
};

/// Runs one step: the walk over every body. The ranges only queue the step.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = ranges;
    let program = ctx.program();
    let roots: Vec<u64> = ctx
        .funcs()
        .filter(|(_, f)| f.reasons.keys().any(|r| *r != StartReason::Call))
        .map(|(e, _)| e)
        .collect();
    let mut walked: BTreeSet<u64> = roots.iter().copied().collect();
    let mut queue: VecDeque<u64> = roots.into_iter().collect();
    let mut reached: BTreeMap<u64, RefKey> = BTreeMap::new();
    let mut work = 1u64;
    while let Some(f) = queue.pop_front() {
        work = work.saturating_add(1);
        let Some(summary) = ctx.summary(f) else {
            continue;
        };
        for (site, target) in &summary.calls {
            work = work.saturating_add(1);
            if ctx.owner(*site) != Some(f) || !is_exec(program, *target) {
                continue;
            }
            let key = RefKey {
                from: Address::ram(*site),
                op_index: 0,
                to: Address::ram(*target),
                kind: RefType::UnconditionalCall,
            };
            if !ctx.work.refs.contains(&key) {
                continue;
            }
            reached.entry(*target).or_insert(key);
            if walked.insert(*target) {
                queue.push_back(*target);
            }
        }
    }
    let lost: Vec<u64> = ctx
        .funcs()
        .filter(|(e, f)| f.reasons.contains_key(&StartReason::Call) && !reached.contains_key(e))
        .map(|(e, _)| e)
        .collect();
    for entry in lost {
        let _ = ctx.remove_reason(entry, StartReason::Call);
    }
    for (target, key) in reached {
        let why = Why::new(Rule::CallTarget, vec![FactKey::Ref(key)]);
        let _ = ctx.add_reason(target, StartReason::Call, 95, why);
    }
    Step { work }
}
