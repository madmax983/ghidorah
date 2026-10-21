//! `TailCallsAndParts` (band 420): FETCH tail calls and cold parts (design Section 7.3).
//!
//! A jump from a function `F` to an address `T` outside the body of `F` is a candidate. The
//! analyzer decides each candidate with [`decide`]. A tail jump is an unconditional jump with
//! a stack height of 0. Code at `T` obeys the calling convention when [`crate::cc::obeys`] is
//! true for it. Then it reads only argument registers and the stack pointer before it writes
//! them.
//!
//! | Candidate | Decision |
//! |---|---|
//! | `T` has another reason than its FDE, a call site, or jumps from two functions | [`Decision::Keep`] |
//! | an FDE-only `T`, only tail jumps from `F`, code that obeys, no flow back into `F` | [`Decision::TailCall`] |
//! | another FDE-only `T` with jumps from `F` only | [`Decision::Cold`]: `T` becomes a `Cold` part of `F` |
//! | a `T` in the body of `F` with no function, one tail jump from `F`, code that obeys, and a shape of the list below | [`Decision::TailCall`] |
//!
//! The shapes of a `T` with no function:
//!
//! - `T` is outside the declared extent of `F`.
//! - `F` has no extent, and the jump is above the entry of `F`. `T` is an `endbr64` head, or
//!   `T` is below the entry of `F`, or only that jump reaches `T`.
//!
//! A tail call gives `T` the start reason `TailCall` with `R_TAILCALL`. A cold part loses its
//! FDE start reason, so the descent of `F` takes its code as a part.
//!
//! [`import_jumps`] gives the tail calls of an import: an indirect jump at stack height 0
//! through the slot of the import, as `jmp [rip+x]` of a `-fno-plt` build. A thunk has none,
//! because its decompile passes its parameters on.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId};
use ghidorah_db::{FactKey, FlowKind, Program, StartReason};
use ghidorah_ir::Opc;
use ghidorah_kernel::RangeSet;
use ghidorah_x86::Mnem;

use crate::cc::{conv_of, obeys};
use crate::code::decode_at;
use crate::ctx::{AnalysisCtx, UNIT_NORETURN_CALL};
use crate::fir::callsite::slot_load;
use crate::fir::{FuncIr, Unit};
use crate::irfacts::{func_key, work_ir, work_ir_at};
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// Gives the spec of `TailCallsAndParts` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "TailCallsAndParts",
        priority: 420,
        triggers: &[Trigger::Instructions, Trigger::Functions],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Finds tail calls by the FETCH rule and merges cold parts into their parents.",
    }
}

/// One jump of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Jump {
    /// The jump site.
    pub site: u64,
    /// The entry of the function of the jump.
    pub from: u64,
    /// The jump is conditional.
    pub conditional: bool,
    /// The stack height at the jump, or `None` for an unknown height.
    pub height: Option<i64>,
}

/// One candidate target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one condition of the decision table of the module"
)]
pub struct Candidate {
    /// The target.
    pub target: u64,
    /// A function starts at the target.
    pub is_func: bool,
    /// The only start reason of the function is its FDE.
    pub fde_only: bool,
    /// A direct call goes to the target.
    pub called: bool,
    /// The jumps to the target.
    pub jumps: Vec<Jump>,
    /// The flow of the target comes back into the body of the jump source.
    pub returns_into_source: bool,
    /// The source function has a declared extent, and the target is outside it.
    pub outside_extent: bool,
    /// The source function has no declared extent.
    pub no_extent: bool,
    /// The target is an `endbr64` instruction.
    pub endbr: bool,
    /// The target is below the entry of the source function.
    pub before_entry: bool,
    /// Only this jump of the source reaches the target: no other branch and no fall-through.
    pub jump_only: bool,
    /// The code at the target obeys the calling convention.
    pub conv: bool,
}

/// The decision about a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    /// The candidate stays as it is.
    Keep,
    /// The target is a function that a tail call reaches.
    TailCall,
    /// The target is a cold part of the function at `parent`.
    Cold {
        /// The entry of the parent.
        parent: u64,
    },
}

/// Decides one candidate by the rules of the module table.
#[must_use]
pub fn decide(c: &Candidate) -> Decision {
    let Some(first) = c.jumps.first() else {
        return Decision::Keep;
    };
    let sources: BTreeSet<u64> = c.jumps.iter().map(|j| j.from).collect();
    let tail = c
        .jumps
        .iter()
        .all(|j| !j.conditional && j.height == Some(0));
    if c.is_func {
        if !c.fde_only || c.called || sources.len() != 1 {
            return Decision::Keep;
        }
        return if tail && c.conv && !c.returns_into_source {
            Decision::TailCall
        } else {
            Decision::Cold { parent: first.from }
        };
    }
    let head = c.endbr || c.before_entry || c.jump_only;
    let shape = c.outside_extent || (c.no_extent && head);
    if tail && c.conv && sources.len() == 1 && shape {
        Decision::TailCall
    } else {
        Decision::Keep
    }
}

/// The suffix of the symbol name of a cold part.
const COLD_SUFFIX: &str = ".cold";

/// The fuel of one function IR of the analyzer.
const IR_FUEL: u64 = 1_000_000;

/// The jumps of one function: the site, the target and the conditional flag.
type Jumps = Vec<(u64, u64, bool)>;

/// Gives the direct jumps of the function `entry` in the work state.
fn jumps_of(ctx: &AnalysisCtx<'_>, entry: u64) -> Jumps {
    let program = ctx.program();
    ctx.units_of(entry)
        .into_iter()
        .filter(|(_, u)| matches!(u.flow, FlowKind::Jmp | FlowKind::Jcc))
        .filter_map(|(at, u)| {
            let t = decode_at(program, at)?.target()?;
            Some((at, t, u.flow == FlowKind::Jcc))
        })
        .collect()
}

/// Tells if the function `entry` has only an FDE start, or only an FDE and a symbol with the
/// `.cold` suffix.
fn cold_shape(ctx: &AnalysisCtx<'_>, entry: u64) -> bool {
    let Some(f) = ctx.work.funcs.get(&entry) else {
        return false;
    };
    let cold_name = || {
        ctx.program()
            .base()
            .symbols()
            .primary(Address::ram(entry))
            .is_some_and(|s| s.name.value.ends_with(COLD_SUFFIX))
    };
    f.reasons.keys().all(|r| match r {
        StartReason::Fde => true,
        StartReason::Symbol => cold_name(),
        _ => false,
    })
}

/// The stack heights of the jumps of the functions of one step, cached by function.
struct Heights {
    by_func: BTreeMap<u64, BTreeMap<u64, Option<i64>>>,
}

impl Heights {
    /// Gives the stack height before the instruction at `site` of the function `entry`.
    fn at(&mut self, ctx: &AnalysisCtx<'_>, entry: u64, site: u64) -> Option<i64> {
        let map = self.by_func.entry(entry).or_insert_with(|| {
            let mut out = BTreeMap::new();
            if let Ok(ir) = work_ir(ctx, entry, &mut Fuel::new(IR_FUEL))
                && let Some(frame) = &ir.frame
            {
                for (at, sp) in &frame.sp {
                    out.insert(*at, sp.offset());
                }
            }
            out
        });
        map.get(&site).copied().flatten()
    }
}

/// Gives the candidate of the function `target` with the jumps from the work state.
fn func_candidate(ctx: &AnalysisCtx<'_>, target: u64, heights: &mut Heights) -> Candidate {
    let sources: Vec<u64> = ctx
        .work
        .exits
        .get(&target)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();
    let mut jumps = Vec::new();
    let mut returns_into_source = false;
    for from in sources {
        if from == target {
            continue;
        }
        for (site, t, conditional) in jumps_of(ctx, from) {
            if t == target {
                jumps.push(Jump {
                    site,
                    from,
                    conditional,
                    height: heights.at(ctx, from, site),
                });
            }
        }
        let shares = |a: u64, b: u64| {
            ctx.summary(a)
                .is_some_and(|s| s.exits.iter().any(|x| *x != b && ctx.owner(*x) == Some(b)))
        };
        returns_into_source |= shares(target, from) || shares(from, target);
    }
    Candidate {
        target,
        is_func: true,
        fde_only: cold_shape(ctx, target),
        called: !ctx.call_sites(target).is_empty(),
        jumps,
        returns_into_source,
        conv: conv_at(ctx, target, target),
        ..Candidate::default()
    }
}

/// Tells if the code at `root` in the body of `owner` obeys the calling convention.
fn conv_at(ctx: &AnalysisCtx<'_>, owner: u64, root: u64) -> bool {
    let conv = conv_of(ctx.program());
    work_ir_at(ctx, owner, root, &mut Fuel::new(IR_FUEL)).is_ok_and(|ir| obeys(&ir, conv))
}

/// Tells if a unit of `units` falls through into `at`: a plain unit, a conditional branch or
/// a call that returns ends at `at`.
fn falls_into(units: &BTreeMap<u64, Unit>, at: u64) -> bool {
    units.range(..at).next_back().is_some_and(|(start, u)| {
        start.checked_add(u64::from(u.len)) == Some(at)
            && match u.flow {
                FlowKind::Seq | FlowKind::Jcc | FlowKind::ICall => true,
                FlowKind::Call => u.flags & UNIT_NORETURN_CALL == 0,
                _ => false,
            }
    })
}

/// Gives the candidates of the jumps `jumps` of `entry` to code of its own body.
fn body_candidates(
    ctx: &AnalysisCtx<'_>,
    entry: u64,
    jumps: &Jumps,
    heights: &mut Heights,
) -> Vec<Candidate> {
    let program = ctx.program();
    let mut out = Vec::new();
    let no_extent = ctx
        .work
        .funcs
        .get(&entry)
        .is_none_or(|f| f.extents.is_empty());
    let units = ctx.units_of(entry);
    for (site, t, conditional) in jumps.iter().copied() {
        if conditional || t == entry || ctx.owner(t) != Some(entry) {
            continue;
        }
        let outside = !no_extent && !ctx.in_own_extent(entry, t);
        let endbr = decode_at(program, t).is_some_and(|i| i.mnem() == Mnem::Endbr64);
        let before_entry = t < entry;
        let other = jumps.iter().any(|(s, x, _)| *x == t && *s != site);
        let jump_only = !other && !falls_into(&units, t);
        // A site below the entry is code of another function that the descent reached first.
        let head = site > entry && (endbr || before_entry || jump_only);
        if !(outside || no_extent && head) {
            continue;
        }
        out.push(Candidate {
            target: t,
            jumps: vec![Jump {
                site,
                from: entry,
                conditional,
                height: heights.at(ctx, entry, site),
            }],
            outside_extent: outside,
            no_extent,
            endbr,
            before_entry,
            jump_only,
            conv: conv_at(ctx, entry, t),
            ..Candidate::default()
        });
    }
    out
}

/// Runs one step over `ranges`: each function that the ranges touch gets its candidates
/// again, as a source of jumps and as a target.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    if !ctx.program().meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    let mut heights = Heights {
        by_func: BTreeMap::new(),
    };
    let mut cands: BTreeMap<u64, Candidate> = BTreeMap::new();
    for entry in ctx.touching(ranges) {
        work = work.saturating_add(1);
        let jumps = jumps_of(ctx, entry);
        let mut targets: BTreeSet<u64> = jumps
            .iter()
            .map(|(_, t, _)| *t)
            .filter(|t| *t != entry && ctx.is_entry(*t))
            .collect();
        targets.insert(entry);
        for t in targets {
            if cold_shape(ctx, t) && !cands.contains_key(&t) {
                cands.insert(t, func_candidate(ctx, t, &mut heights));
            }
        }
        for c in body_candidates(ctx, entry, &jumps, &mut heights) {
            cands.entry(c.target).or_insert(c);
        }
    }
    for (target, c) in cands {
        work = work.saturating_add(1);
        match decide(&c) {
            Decision::Keep => {}
            Decision::TailCall => {
                let Some(j) = c.jumps.first() else {
                    continue;
                };
                let why = Why::new(
                    Rule::Tailcall,
                    vec![FactKey::CodeUnit(j.site), func_key(j.from)],
                );
                let _ = ctx.add_reason(target, StartReason::TailCall, CONFIDENCE, why);
            }
            Decision::Cold { parent } => {
                ctx.ir_mut().parts.insert(target, parent);
                let _ = ctx.remove_reason(target, StartReason::Symbol);
                let _ = ctx.remove_reason(target, StartReason::Fde);
            }
        }
    }
    Step { work }
}

/// The confidence of a `TailCall` start (design Section 7.3).
pub const CONFIDENCE: u8 = 80;

/// Gives the addresses of the tail calls of an import in `fir`, the IR of the function `id`
/// (see the module doc).
#[must_use]
pub fn import_jumps(program: &Program, id: FuncId, fir: &FuncIr) -> BTreeSet<u64> {
    if program.func(id).is_none_or(|f| f.func.flags.thunk) {
        return BTreeSet::new();
    }
    let slots = crate::work::import_slots(program);
    fir.arena
        .ops()
        .iter()
        .filter(|op| op.opc == Opc::JumpInd)
        .filter(|op| fir.frame.as_ref().and_then(|f| f.sp_at(op.id.addr)) == Some(0))
        .filter(|op| {
            slot_load(&fir.arena, op.a[0], op.id.addr).is_some_and(|s| slots.contains_key(&s))
        })
        .map(|op| op.id.addr)
        .collect()
}
