//! `GapComponents` (band 470): seed 13 of design Section 7.3, code components in gaps.
//!
//! A gap is executable code that no solid function owns. [`super::gaps`] gives the scope and
//! the fixed area of the binary. A function is solid when it has a start reason outside
//! [`DERIVED`], or when the flow of a solid function reaches its entry. The reasons of
//! [`DERIVED`] come from the code of other functions. So the gaps do not depend on the seeds
//! of this module.
//!
//! The analyzer decodes each gap linearly. After an instruction that does not fall through,
//! it skips padding. The CFG of the gap instructions has these edges:
//!
//! | Flow | Edge |
//! |---|---|
//! | the fall-through of an instruction | strong |
//! | a conditional branch to a gap instruction | strong |
//! | a case of a resolved jump table or of an agent table | strong |
//! | an unconditional jump to a gap instruction | a join when only one strong part jumps there |
//! | a call | none |
//!
//! An unconditional jump to a call target, or to code that two strong parts jump to, is a
//! tail call. It leaves the component. Each weakly connected component becomes a function
//! when it passes 3 tests:
//!
//! - Every instruction decodes, and no branch goes into an instruction or into padding. A
//!   direct call goes to executable memory.
//! - Every path ends in `ret`, an indirect jump, a noreturn call or a jump out of the
//!   component. A jump out goes to a function entry or to another component.
//! - It has at least [`MIN_INSNS`] instructions.
//!
//! The entry is the lowest address of the component that has no predecessor in it. It gets
//! the reason `GapComponent`, confidence [`CONFIDENCE`] and `R_GAP_COMPONENT`. Each step tests
//! every gap again, and a `GapComponent` reason that fails a test goes. An entry gets the
//! reason at most [`MAX_ADDS`] times, so the steps reach a fixpoint. One step decodes at
//! most [`MAX_SCAN`] gap bytes.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Limits, Range};
use ghidorah_db::{FlowOverride, StartReason};
use ghidorah_kernel::RangeSet;
use ghidorah_x86::{Flow, Insn, Opts, decode};

use crate::analyzers::dataptr::{case_targets, seed, skip_padding};
use crate::analyzers::gaps;
use crate::code::{is_exec, slot_of};
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::{Rule, Why};

/// The confidence of a `GapComponent` start.
pub const CONFIDENCE: u8 = 40;

/// The smallest number of instructions of a component.
pub const MIN_INSNS: u64 = 4;

/// The largest number of gap bytes that one step decodes.
pub const MAX_SCAN: u64 = 4 << 20;

/// The largest number of times that one entry gets the reason.
pub const MAX_ADDS: u8 = 8;

/// The reasons that come from the code of another function. Alone they do not make a
/// function solid.
pub const DERIVED: [StartReason; 4] = [
    StartReason::GapComponent,
    StartReason::Call,
    StartReason::TailCall,
    StartReason::AddrTaken,
];

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::GapComponents,
    name: "GapComponents",
    priority: 470,
    triggers: &[Trigger::Bytes, Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[Opt {
        name: "min_insns",
        value: MIN_INSNS,
        doc: "The smallest number of instructions of a gap component.",
    }],
    doc: "Starts a function at the entry of each closed code component in a gap.",
};

/// The gap state of a work state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GapState {
    /// The number of times that each entry got the reason.
    pub adds: BTreeMap<u64, u8>,
}

/// The flow after one gap node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Exit {
    /// The flow continues at the next address.
    Falls,
    /// The path ends in a way that the tests accept: `ret`, an indirect jump or a noreturn
    /// call.
    Ends,
    /// The path ends in a way that the tests reject: a trap or bytes that do not decode.
    #[default]
    Stops,
    /// An unconditional jump to the target.
    Jump(u64),
    /// A conditional branch to the target. The flow also continues at the next address.
    Branch(u64),
}

impl Exit {
    /// Tells if the flow continues at the next address.
    const fn falls(self) -> bool {
        matches!(self, Self::Falls | Self::Branch(_))
    }
}

/// One decoded item of a gap: an instruction, or one byte that does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Node {
    /// The address.
    at: u64,
    /// The length in bytes.
    len: u64,
    /// The item breaks the decode test.
    bad: bool,
    /// The flow after the item.
    exit: Exit,
    /// The target of a direct call.
    call: Option<u64>,
}

/// Gives the solid functions: the functions with a reason outside [`DERIVED`], and each
/// function that the flow of a solid function reaches.
fn solid(ctx: &AnalysisCtx<'_>) -> BTreeSet<u64> {
    let work = &ctx.work;
    let program = ctx.program();
    let mut taken: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (site, target) in &work.codeptrs.sites {
        if let Some(owner) = work.owner(*site) {
            let t = skip_padding(program, *target).unwrap_or(*target);
            taken.entry(owner).or_default().push(t);
        }
    }
    let mut out: BTreeSet<u64> = work
        .funcs
        .iter()
        .filter(|(_, f)| f.reasons.keys().any(|r| !DERIVED.contains(r)))
        .map(|(e, _)| *e)
        .collect();
    let mut todo: Vec<u64> = out.iter().copied().collect();
    while let Some(entry) = todo.pop() {
        let mut next = taken.remove(&entry).unwrap_or_default();
        if let Some(s) = work.funcs.get(&entry).and_then(|f| f.summary.as_ref()) {
            next.extend(s.calls.values().copied());
            next.extend(s.exits.iter().copied());
        }
        for t in next {
            if work.funcs.contains_key(&t) && out.insert(t) {
                todo.push(t);
            }
        }
    }
    out
}

/// Gives the gaps: the scope without the fixed area and without the bodies of `solid`.
fn free(ctx: &AnalysisCtx<'_>, solid: &BTreeSet<u64>) -> RangeSet {
    let program = ctx.program();
    let mut owned: Vec<Range> = gaps::fixed(program).ranges().to_vec();
    let mut run: Option<Range> = None;
    let units = ctx
        .work
        .units
        .iter()
        .filter(|(_, u)| solid.contains(&u.owner));
    for r in units.filter_map(|(at, u)| u.range(*at)) {
        run = match run {
            Some(cur) if cur.last.checked_add(1) == Some(r.first) => Some(Range {
                first: cur.first,
                last: r.last,
            }),
            Some(cur) => {
                owned.push(cur);
                Some(r)
            }
            None => Some(r),
        };
    }
    owned.extend(run);
    owned.extend(solid.iter().map(|e| Range::single(*e)));
    gaps::scope(program).subtract(&gaps::set_of(owned))
}

/// Makes the node of the instruction `insn` at `at`.
fn node(ctx: &AnalysisCtx<'_>, at: u64, insn: &Insn) -> Node {
    let mut n = Node {
        at,
        len: u64::from(insn.len()).max(1),
        ..Node::default()
    };
    let call_end = |noreturn: bool| if noreturn { Exit::Ends } else { Exit::Falls };
    n.exit = match (insn.flow(), insn.target()) {
        (Flow::Seq, _) => Exit::Falls,
        (Flow::Jmp, Some(t)) => Exit::Jump(t),
        (Flow::Jcc, Some(t)) => Exit::Branch(t),
        (Flow::Call, target) => {
            n.call = target;
            n.bad = !target.is_some_and(|t| is_exec(ctx.program(), t));
            call_end(target.is_some_and(|t| ctx.noreturn(t)))
        }
        (Flow::ICall, _) => call_end(slot_of(insn).is_some_and(|s| ctx.noreturn_slot(s))),
        (Flow::IJmp | Flow::Ret, _) => Exit::Ends,
        (Flow::Jmp | Flow::Jcc | Flow::Trap | Flow::Invalid, _) => Exit::Stops,
    };
    n
}

/// Decodes the gap `r` linearly, at most `left` bytes, and adds its nodes to `out`. Gives the
/// number of bytes that it reads.
fn decode_gap(ctx: &AnalysisCtx<'_>, r: Range, left: u64, out: &mut Vec<Node>) -> u64 {
    let len = u64::try_from(r.len()).unwrap_or(u64::MAX).min(left);
    let Ok(bytes) = ctx.program().mem().read(r.first, len, &Limits::DEFAULT) else {
        return len;
    };
    let mut i = 0usize;
    let mut falls = false;
    while let Some(rest) = bytes.get(i..).filter(|b| !b.is_empty()) {
        let Some(at) = u64::try_from(i).ok().and_then(|o| r.first.checked_add(o)) else {
            break;
        };
        if !falls && let Some(k) = gaps::padding(rest, at) {
            i = i.saturating_add(k.max(1));
            continue;
        }
        let n = match decode(rest, at, &Opts::DEFAULT) {
            Ok(insn) if insn.flow() != Flow::Invalid => node(ctx, at, &insn),
            _ => Node {
                at,
                len: 1,
                bad: true,
                ..Node::default()
            },
        };
        falls = n.exit.falls();
        i = i.saturating_add(usize::try_from(n.len).unwrap_or(1));
        out.push(n);
    }
    len
}

/// Gives the RAM offsets of `addrs`.
fn ram(addrs: &[Address]) -> impl Iterator<Item = u64> + '_ {
    addrs.iter().filter(|a| a.is_ram()).map(|a| a.off)
}

/// Gives the case targets of the resolved jump tables and of the agent tables, by jump site.
fn cases(ctx: &AnalysisCtx<'_>) -> BTreeMap<u64, Vec<u64>> {
    let mut out: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (site, r) in ctx.ir().tables.iter().filter(|(_, r)| r.table.resolved) {
        out.entry(*site).or_default().extend(ram(&r.table.targets));
    }
    let base = ctx.program().base();
    for (id, t) in base.jumptables().iter().filter(|(id, _)| id.0.is_ram()) {
        out.entry(id.0.off)
            .or_default()
            .extend(ram(&t.value.targets));
    }
    for (at, f) in base.overrides().iter().filter(|(at, _)| at.is_ram()) {
        if let FlowOverride::IndirectTargets(targets) = &f.value {
            out.entry(at.off).or_default().extend(ram(targets));
        }
    }
    out
}

/// Union-find sets over the gap nodes.
struct Sets(Vec<usize>);

impl Sets {
    /// Gives the set of `i`, with path halving.
    fn find(&mut self, mut i: usize) -> usize {
        while let Some(&p) = self.0.get(i) {
            if p == i {
                break;
            }
            let up = self.0.get(p).copied().unwrap_or(p);
            if let Some(slot) = self.0.get_mut(i) {
                *slot = up;
            }
            i = up;
        }
        i
    }

    /// Joins the sets of `a` and `b`. The lower index stays the set.
    fn join(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if let Some(slot) = self.0.get_mut(ra.max(rb)) {
            *slot = ra.min(rb);
        }
    }
}

/// The test state of one component.
#[derive(Debug, Clone, Copy, Default)]
struct Part {
    /// The number of decoded instructions.
    insns: u64,
    /// A node breaks a test.
    bad: bool,
    /// The lowest address without a predecessor in the component.
    entry: Option<u64>,
}

/// The CFG of the gap nodes with the sets of its components.
struct Graph {
    /// The components.
    sets: Sets,
    /// The strong edges.
    strong: Vec<(usize, usize)>,
    /// The unconditional jumps to gap nodes that are not call targets.
    jumps: Vec<(usize, usize)>,
    /// The nodes that break a test.
    bad: Vec<bool>,
}

impl Graph {
    /// Builds the edges of `nodes`. A flow to an address outside `free` must go to a function
    /// entry.
    fn new(ctx: &AnalysisCtx<'_>, free: &RangeSet, nodes: &[Node]) -> Self {
        let index: BTreeMap<u64, usize> =
            nodes.iter().enumerate().map(|(i, n)| (n.at, i)).collect();
        let called: BTreeSet<u64> = nodes.iter().filter_map(|n| n.call).collect();
        let mut g = Self {
            sets: Sets((0..nodes.len()).collect()),
            strong: Vec::new(),
            jumps: Vec::new(),
            bad: Vec::with_capacity(nodes.len()),
        };
        for (i, n) in nodes.iter().enumerate() {
            let mut bad = n.bad || n.exit == Exit::Stops;
            if n.exit.falls() {
                match n.at.checked_add(n.len).and_then(|x| index.get(&x)) {
                    Some(&j) => g.strong.push((i, j)),
                    None => bad = true,
                }
            }
            let (target, jump) = match n.exit {
                Exit::Jump(t) => (t, true),
                Exit::Branch(t) => (t, false),
                Exit::Falls | Exit::Ends | Exit::Stops => {
                    g.bad.push(bad);
                    continue;
                }
            };
            match index.get(&target) {
                Some(_) if jump && called.contains(&target) => {}
                Some(&j) if jump => g.jumps.push((i, j)),
                Some(&j) => g.strong.push((i, j)),
                None => bad |= free.contains(target) || !ctx.is_entry(target),
            }
            g.bad.push(bad);
        }
        for (site, targets) in cases(ctx) {
            if let Some(&i) = index.get(&site) {
                let to = targets.iter().filter_map(|t| index.get(t));
                g.strong.extend(to.map(|&j| (i, j)));
            }
        }
        g
    }

    /// Joins the strong edges. Then it joins each jump whose target only one strong part
    /// jumps to. The other jumps are tail calls.
    fn close(&mut self) {
        for &(i, j) in &self.strong {
            self.sets.join(i, j);
        }
        let mut parts: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for &(i, j) in &self.jumps {
            parts.entry(j).or_default().insert(self.sets.find(i));
        }
        for &(i, j) in &self.jumps {
            if parts.get(&j).is_some_and(|p| p.len() == 1) {
                self.sets.join(i, j);
            }
        }
    }

    /// Gives the entries of the components that pass the tests.
    fn entries(mut self, nodes: &[Node]) -> Vec<u64> {
        self.close();
        let mut inner = vec![false; nodes.len()];
        for &(i, j) in self.strong.iter().chain(&self.jumps) {
            if self.sets.find(i) == self.sets.find(j)
                && let Some(p) = inner.get_mut(j)
            {
                *p = true;
            }
        }
        let mut parts: BTreeMap<usize, Part> = BTreeMap::new();
        for (i, n) in nodes.iter().enumerate() {
            let part = parts.entry(self.sets.find(i)).or_default();
            part.insns = part.insns.saturating_add(u64::from(!n.bad));
            part.bad |= self.bad.get(i).copied().unwrap_or(true);
            if part.entry.is_none() && !inner.get(i).copied().unwrap_or(true) {
                part.entry = Some(n.at);
            }
        }
        parts
            .into_values()
            .filter(|p| !p.bad && p.insns >= MIN_INSNS)
            .filter_map(|p| p.entry)
            .collect()
    }
}

/// Gives the entries of the gap components of the work state that pass the tests, and the
/// number of decoded nodes.
fn components(ctx: &AnalysisCtx<'_>) -> (Vec<u64>, u64) {
    let solid = solid(ctx);
    let free = free(ctx, &solid);
    let mut nodes = Vec::new();
    let mut left = MAX_SCAN;
    for r in free.ranges() {
        if left == 0 {
            break;
        }
        left = left.saturating_sub(decode_gap(ctx, *r, left, &mut nodes));
    }
    let count = u64::try_from(nodes.len()).unwrap_or(u64::MAX);
    (Graph::new(ctx, &free, &nodes).entries(&nodes), count)
}

/// Runs one step: every gap gets the tests again. The ranges only queue the step.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = ranges;
    if !ctx.program().meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let (found, count) = components(ctx);
    let skip = case_targets(ctx);
    let mut want = BTreeMap::new();
    for at in found.into_iter().filter(|at| !skip.contains(at)) {
        let has = ctx
            .work
            .funcs
            .get(&at)
            .is_some_and(|f| f.reasons.contains_key(&StartReason::GapComponent));
        let adds = ctx.work.gapcomp.adds.entry(at).or_default();
        if !has {
            if *adds >= MAX_ADDS {
                continue;
            }
            *adds = adds.saturating_add(1);
        }
        want.insert(at, Why::bare(Rule::GapComponent));
    }
    seed(ctx, StartReason::GapComponent, CONFIDENCE, want);
    Step {
        work: count.saturating_add(1),
    }
}
