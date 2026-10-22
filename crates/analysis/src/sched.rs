//! The scheduler: pending sets, the queue, fuel slices, and the committed and shadow runs
//! (design Sections 3.9 and 7.2, ADR-0016).
//!
//! Each analyzer of the scheduler has a pending [`RangeSet`]. One step picks the analyzer with
//! the lowest `(priority, name)` that has pending work. It takes the whole pending set or the
//! first range, by the grain of the spec. Then it runs the analyzer and queues the event
//! ranges for the analyzers that listen to their triggers. A run stops at a fixpoint, or at
//! the first fuel checkpoint when no fuel remains. One step is atomic, so the steps and
//! their order do not depend on the fuel slices (AC-092).
//!
//! | Mode | Publish |
//! |---|---|
//! | [`Mode::First`] | after each run with a change: reads see a partial set |
//! | [`Mode::Shadow`] | once, at completion: reads see the committed set until then |
//!
//! A fresh scheduler gives every address to each analyzer that listens to `Bytes`.
//! [`Scheduler::new`] runs the shipped list [`ANALYZERS`]. [`Scheduler::with_analyzers`] runs
//! another list, for example a list with an analyzer before its register step.

use ghidorah_base::{Fuel, Range};
use ghidorah_db::{AnalysisSet, Commit, Program};
use ghidorah_kernel::RangeSet;

use crate::AnalysisError;
use crate::ctx::AnalysisCtx;
use crate::registry::{self, ANALYZERS, AnalyzerId};
use crate::spec::{AnalyzerSpec, BAND_TRIAGE, Grain, Trigger};
use crate::work::Work;

/// All RAM offsets.
pub const ALL: Range = Range {
    first: 0,
    last: u64::MAX,
};

/// How far a run goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Until {
    /// The bands up to [`BAND_TRIAGE`].
    Triage,
    /// Every band.
    Full,
}

impl Until {
    /// Gives the last band of the run.
    #[must_use]
    pub const fn last_band(self) -> u16 {
        match self {
            Self::Triage => BAND_TRIAGE,
            Self::Full => u16::MAX,
        }
    }
}

/// Where a scheduler publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// The first analysis after a load: publish after each run.
    First,
    /// A re-analysis: publish once at completion with one `ReplaceAnalysis` commit.
    Shadow,
}

/// The state after a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RunState {
    /// No analyzer has pending work.
    Complete,
    /// The fuel stopped the first analysis. Reads see a partial set.
    BudgetStopped,
    /// The fuel stopped a re-analysis. Reads see the old committed set.
    Stale,
}

impl RunState {
    /// Gives the state name: `complete`, `budget_stopped` or `stale`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::BudgetStopped => "budget_stopped",
            Self::Stale => "stale",
        }
    }
}

/// The result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// The state after the run.
    pub state: RunState,
    /// The work units of the run.
    pub steps_used: u64,
    /// `true` when a later run has work to do.
    pub resume: bool,
    /// The commit of the publish step, or `None` when the run published nothing.
    pub commit: Option<Commit>,
}

/// One row of the analyzer table of `analysis_run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnalyzerRow {
    /// The analyzer name.
    pub name: &'static str,
    /// The priority band.
    pub priority: u16,
    /// The number of pending ranges.
    pub pending: u64,
    /// The number of steps of the analyzer.
    pub runs: u64,
}

/// One step of a scheduler: the analyzer, the ranges it took and its work units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// The analyzer.
    pub analyzer: AnalyzerId,
    /// The ranges of the step.
    pub ranges: RangeSet,
    /// The work units.
    pub work: u64,
}

/// The analysis scheduler of one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scheduler {
    specs: Vec<&'static AnalyzerSpec>,
    work: Work,
    pending: Vec<RangeSet>,
    /// The event ranges of each analyzer that are not in its pending set yet. A step adds
    /// them when it picks the analyzer, and a run adds all of them at its end. So one event
    /// does not copy a large pending set.
    inbox: Vec<Vec<Range>>,
    runs: Vec<u64>,
    steps: u64,
    mode: Mode,
    dirty: bool,
    /// `true` while a caller holds the publish of a first analysis: a run publishes only at
    /// completion, and [`Scheduler::flush`] publishes the rest.
    hold: bool,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Gives the index of the next step among `specs`: the lowest `(priority, name)` with pending
/// work up to the band `last`.
#[must_use]
pub fn pick(specs: &[&AnalyzerSpec], pending: &[RangeSet], last: u16) -> Option<usize> {
    pick_by(specs, last, |i| {
        pending.get(i).is_some_and(|set| !set.is_empty())
    })
}

/// Gives the index of the next step among `specs` up to the band `last`, with `busy` as the
/// test for pending work.
fn pick_by(specs: &[&AnalyzerSpec], last: u16, busy: impl Fn(usize) -> bool) -> Option<usize> {
    specs
        .iter()
        .enumerate()
        .filter(|(i, spec)| spec.priority <= last && busy(*i))
        .min_by_key(|(_, spec)| (spec.priority, spec.name))
        .map(|(i, _)| i)
}

/// Gives the ranges of one step of `spec` from its pending set.
#[must_use]
pub fn unit(spec: &AnalyzerSpec, pending: &RangeSet) -> RangeSet {
    match spec.grain {
        Grain::Whole => pending.clone(),
        Grain::Range => {
            let mut out = RangeSet::new();
            if let Some(first) = pending.first() {
                out.insert(first);
            }
            out
        }
    }
}

/// Gives the mirror of `r`: each value `x` becomes `u64::MAX - x`.
///
/// The scheduler keeps the pending set of a [`Grain::Range`] analyzer as the mirror of the
/// set. The mirror reverses the order and keeps overlaps and neighbors. So the first range
/// of the set is the mirror of the last stored range. A step removes that last entry of the
/// stored list with no copy of the other entries.
const fn mirror(r: Range) -> Range {
    Range {
        first: u64::MAX - r.last,
        last: u64::MAX - r.first,
    }
}

/// Gives the ranges of one step of `spec` from its stored pending set: the ranges that
/// [`unit`] gives for the set.
fn unit_of(spec: &AnalyzerSpec, stored: &RangeSet) -> RangeSet {
    match spec.grain {
        Grain::Whole => stored.clone(),
        Grain::Range => {
            let mut out = RangeSet::new();
            if let Some(last) = stored.ranges().last() {
                out.insert(mirror(*last));
            }
            out
        }
    }
}

/// Removes the ranges of one step of `spec` from its stored pending set: the same ranges as
/// [`unit_of`], with no copy of the set.
fn take(spec: &AnalyzerSpec, stored: &mut RangeSet) {
    match spec.grain {
        Grain::Whole => *stored = RangeSet::new(),
        Grain::Range => {
            if let Some(last) = stored.ranges().last().copied() {
                stored.remove(last);
            }
        }
    }
}

/// The largest inbox that [`absorb`] adds range by range.
const SPLICE_MAX: usize = 16;

/// The inbox size that always stays below a drain, for a small pending set.
const INBOX_MAX: usize = 4_096;

/// Adds the inbox ranges `inbox` to `pending`. A small inbox goes in range by range, in
/// place. A larger inbox goes in with one merge of the two sorted lists. Then each insert of
/// [`RangeSet::from_ranges`] lands at the end, so the cost stays near linear.
fn absorb(pending: &mut RangeSet, mut inbox: Vec<Range>) {
    if inbox.len() <= SPLICE_MAX {
        for range in inbox {
            pending.insert(range);
        }
        return;
    }
    inbox.sort_unstable_by_key(|r| r.first);
    let (a, b) = (pending.ranges(), inbox.as_slice());
    let mut merged = Vec::with_capacity(a.len().saturating_add(b.len()));
    let (mut left, mut right) = (a.iter().peekable(), b.iter().peekable());
    loop {
        let next = match (left.peek(), right.peek()) {
            (Some(x), Some(y)) if y.first < x.first => right.next(),
            (Some(_), _) => left.next(),
            (None, _) => right.next(),
        };
        let Some(range) = next else {
            break;
        };
        merged.push(*range);
    }
    *pending = RangeSet::from_ranges(&merged);
}

/// Gives the set of every RAM offset.
fn all() -> RangeSet {
    let mut set = RangeSet::new();
    set.insert(ALL);
    set
}

impl Scheduler {
    /// Makes the scheduler of the first analysis after a load over [`ANALYZERS`]. Each
    /// analyzer that listens to `Bytes` gets every address.
    #[must_use]
    pub fn new() -> Self {
        Self::with_analyzers(ANALYZERS.to_vec())
    }

    /// Makes the scheduler of the first analysis after a load over the analyzers `specs`.
    /// The list order gives the row order. Each analyzer that listens to `Bytes` gets every
    /// address.
    #[must_use]
    pub fn with_analyzers(specs: Vec<&'static AnalyzerSpec>) -> Self {
        let pending = Self::fresh(&specs);
        let inbox = vec![Vec::new(); specs.len()];
        let runs = vec![0; specs.len()];
        Self {
            specs,
            work: Work::default(),
            pending,
            inbox,
            runs,
            steps: 0,
            mode: Mode::First,
            dirty: false,
            hold: false,
        }
    }

    /// Gives the fresh pending sets of `specs`: every address for each listener of `Bytes`.
    fn fresh(specs: &[&AnalyzerSpec]) -> Vec<RangeSet> {
        specs
            .iter()
            .map(|s| {
                if s.listens(Trigger::Bytes) {
                    all()
                } else {
                    RangeSet::new()
                }
            })
            .collect()
    }

    /// Gives the analyzers of the scheduler in row order.
    #[must_use]
    pub fn analyzers(&self) -> &[&'static AnalyzerSpec] {
        &self.specs
    }

    /// Makes a shadow scheduler of a re-analysis with no earlier work state. A shadow with no
    /// work state knows no lower band, so it runs every band. It publishes once at completion.
    #[must_use]
    pub fn shadow() -> Self {
        let mut s = Self::new();
        s.mode = Mode::Shadow;
        s
    }

    /// Starts a re-analysis at the start band `band` in shadow mode. The work of the bands
    /// below `band` stays. Each analyzer at `band` or above gets every address again. A band
    /// at or below the first band starts with an empty work state.
    pub fn restart(&mut self, band: u16) {
        let first = self.specs.iter().map(|s| s.priority).min().unwrap_or(0);
        self.drain_all();
        if band <= first {
            self.work = Work::default();
            self.pending = Self::fresh(&self.specs);
        } else {
            for (spec, set) in self.specs.iter().zip(self.pending.iter_mut()) {
                if spec.priority >= band {
                    *set = all();
                }
            }
        }
        self.mode = Mode::Shadow;
        self.dirty = true;
    }

    /// Gives the mode.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Sets the cap of the code units of the program. The default is
    /// [`crate::analyzers::disasm::MAX_UNITS`].
    pub const fn set_unit_cap(&mut self, cap: u64) {
        self.work.unit_cap = Some(cap);
    }

    /// Tells if a body stopped at the cap of the code units. Then the analysis set holds only
    /// a part of the code of the program.
    #[must_use]
    pub const fn capped(&self) -> bool {
        self.work.capped
    }

    /// Gives the work units of all runs.
    #[must_use]
    pub const fn steps_used(&self) -> u64 {
        self.steps
    }

    /// Tells if no analyzer up to the last band of `until` has pending work.
    #[must_use]
    pub fn is_done(&self, until: Until) -> bool {
        self.next(until.last_band()).is_none()
    }

    /// Tells if the analyzer at `i` has pending work in its set or in its inbox.
    fn busy(&self, i: usize) -> bool {
        self.pending.get(i).is_some_and(|set| !set.is_empty())
            || self.inbox.get(i).is_some_and(|ranges| !ranges.is_empty())
    }

    /// Gives the index of the next step up to the band `last`.
    fn next(&self, last: u16) -> Option<usize> {
        pick_by(&self.specs, last, |i| self.busy(i))
    }

    /// Adds the inbox of the analyzer at `i` to its pending set.
    fn drain(&mut self, i: usize) {
        let mirrored = self.specs.get(i).is_some_and(|s| s.grain == Grain::Range);
        if let (Some(set), Some(ranges)) = (self.pending.get_mut(i), self.inbox.get_mut(i)) {
            let mut ranges = std::mem::take(ranges);
            if mirrored {
                for r in &mut ranges {
                    *r = mirror(*r);
                }
            }
            absorb(set, ranges);
        }
    }

    /// Puts the ranges of `set` in the inbox of the analyzer at `i`. An inbox larger than its
    /// pending set and [`INBOX_MAX`] goes into the set at once. So the inbox stays small and
    /// each merge copies at most twice the ranges that it adds.
    fn post(&mut self, i: usize, set: &RangeSet) {
        let full = match (self.inbox.get_mut(i), self.pending.get(i)) {
            (Some(ranges), Some(pending)) => {
                ranges.extend_from_slice(set.ranges());
                ranges.len() > INBOX_MAX.max(pending.len())
            }
            _ => false,
        };
        if full {
            self.drain(i);
        }
    }

    /// Adds every inbox to its pending set.
    fn drain_all(&mut self) {
        for i in 0..self.pending.len() {
            self.drain(i);
        }
    }

    /// Gives one row for each analyzer in list order.
    #[must_use]
    pub fn rows(&self) -> Vec<AnalyzerRow> {
        self.specs
            .iter()
            .zip(&self.pending)
            .zip(&self.inbox)
            .zip(&self.runs)
            .map(|(((spec, set), ranges), runs)| {
                let len = if ranges.is_empty() {
                    set.len()
                } else {
                    let mut set = set.clone();
                    let mirrored = spec.grain == Grain::Range;
                    let ranges = ranges
                        .iter()
                        .map(|r| if mirrored { mirror(*r) } else { *r })
                        .collect();
                    absorb(&mut set, ranges);
                    set.len()
                };
                AnalyzerRow {
                    name: spec.name,
                    priority: spec.priority,
                    pending: u64::try_from(len).unwrap_or(u64::MAX),
                    runs: *runs,
                }
            })
            .collect()
    }

    /// Runs one step. Gives `None` at a fixpoint of the bands of `until`.
    pub fn step(&mut self, program: &Program, until: Until) -> Option<Ran> {
        let i = self.next(until.last_band())?;
        self.drain(i);
        let spec = *self.specs.get(i)?;
        let current = self.pending.get_mut(i)?;
        let ranges = unit_of(spec, current);
        take(spec, current);
        let mut ctx = AnalysisCtx::new(program, &mut self.work);
        let step = registry::run(spec.id, &mut ctx, &ranges);
        let (events, requeue, changed) = ctx.finish();
        for (trigger, set) in events {
            for j in 0..self.specs.len() {
                if self.specs.get(j).is_some_and(|s| s.listens(trigger)) {
                    self.post(j, &set);
                }
            }
        }
        for (id, set) in requeue {
            if let Some(j) = self.specs.iter().position(|s| s.id == id) {
                self.post(j, &set);
            }
        }
        let work = step.work.max(1);
        if let Some(runs) = self.runs.get_mut(i) {
            *runs = runs.saturating_add(1);
        }
        self.steps = self.steps.saturating_add(work);
        self.dirty |= changed;
        Some(Ran {
            analyzer: spec.id,
            ranges,
            work,
        })
    }

    /// Runs steps until a fixpoint of the bands of `until` or until `fuel` is empty, then
    /// publishes by the mode. A step that starts always ends, so the last step can use more
    /// work units than the fuel holds. The fuel takes at most what it holds.
    ///
    /// # Errors
    ///
    /// Returns an [`AnalysisError`] when the publish step fails. The work state stays.
    pub fn run(
        &mut self,
        program: &mut Program,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<RunOutcome, AnalysisError> {
        let start = self.steps;
        while !fuel.is_empty() {
            let Some(ran) = self.step(program, until) else {
                break;
            };
            let _ = fuel.take(ran.work.min(fuel.remaining()));
        }
        self.drain_all();
        let done = self.is_done(Until::Full);
        let publish = self.dirty && (done || (self.mode == Mode::First && !self.hold));
        let commit = if publish {
            let commit = crate::publish::publish(program, &self.work)?;
            self.dirty = false;
            Some(commit)
        } else {
            None
        };
        let state = match (done, self.mode) {
            (true, _) => RunState::Complete,
            (false, Mode::First) => RunState::BudgetStopped,
            (false, Mode::Shadow) => RunState::Stale,
        };
        Ok(RunOutcome {
            state,
            steps_used: self.steps.saturating_sub(start),
            resume: !done,
            commit,
        })
    }

    /// Holds or releases the publish of a first analysis. While the hold is on, a run of a
    /// first analysis publishes only at completion. A caller that runs many slices in one
    /// call holds the publish and calls [`Scheduler::flush`] once at the end.
    pub const fn set_hold(&mut self, hold: bool) {
        self.hold = hold;
    }

    /// Publishes the work of a first analysis that a hold kept back. A shadow publishes only
    /// at completion, so a flush of a shadow does nothing.
    ///
    /// # Errors
    ///
    /// Returns an [`AnalysisError`] when the publish step fails. The work state stays.
    pub fn flush(&mut self, program: &mut Program) -> Result<Option<Commit>, AnalysisError> {
        if !(self.dirty && self.mode == Mode::First) {
            return Ok(None);
        }
        let commit = crate::publish::publish(program, &self.work)?;
        self.dirty = false;
        Ok(Some(commit))
    }

    /// Gives the analysis set of the work state without a commit.
    ///
    /// # Errors
    ///
    /// Returns an [`AnalysisError`] when the set does not decode.
    pub fn analysis_set(&self, program: &Program) -> Result<AnalysisSet, AnalysisError> {
        crate::publish::analysis_set(program, &self.work)
    }
}
