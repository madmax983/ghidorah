//! `analysis_run`: run or resume the analysis with a fuel budget (design Section 10.4, tool 3).
//!
//! The handler runs the analysis engine of the session in fuel slices through
//! [`Session::analyze_sliced`]. A slice has [`SLICE_STEPS`] work units or a quarter of the
//! units so far, whichever is more. So the publish steps of one call cost at most a log factor
//! over one publish. `binary_load` and the re-analysis of an edit use the same slices.
//!
//! After each slice the session sends one progress report with the work units so far, so the
//! progress value increases strictly (AC-173). It checks the cancel flag at the end of each
//! slice. So `notifications/cancelled` stops the run at the next fuel checkpoint (AC-172).
//!
//! The state is relative to the full analysis. When the last slice of a call with
//! `until: "triage"` does no work, the triage bands have no more work. Then the call gives
//! `resume: false` and `next[0]` `analysis_run { until: "full" }`. Another stop before
//! completion gives `resume: true`, and `next[0]` is the same call with the same `until`.
//!
//! [`Engine`] is the analysis engine of the shipped tools: one [`Scheduler`] per open binary.
//! A session with no engine gets one at the first call. A binary with no scheduler gets one
//! by its analysis state:
//!
//! | Analysis state | Scheduler |
//! |---|---|
//! | none: the first analysis after a load | [`Scheduler::new`]: a publish after each run |
//! | `complete`, from a project | none: the analysis is current, so the run does no work |
//! | `budget_stopped` or `stale`, from a project | [`Scheduler::shadow`]: one publish at completion |

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::{ANALYZERS, AnalyzerRow, Changed, RunState, Scheduler, Until as Band};
use ghidorah_base::{BinaryId, ErrorCode, Fuel, Limits};
use ghidorah_db::Program;
use ghidorah_json::{Object, Value};
use ghidorah_loader::{Binary, Sym};

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::envelope::{AnalysisState, Mutation};
use crate::errors::ToolError;
use crate::hints::Call;
use crate::outshape::{Field, OutputShape};
use crate::session::{AnalysisEngine, OpenBinary, RunReport, Session, Until};
use crate::spec::{Annotations, ArgKind, ArgSpec, Example, FuelSpec, Profile, Role, ToolSpec};

/// The default fuel of one call (Section 7.2).
pub const DEFAULT_STEPS: u64 = 100_000_000;

/// The largest `max_steps` of one call.
pub const MAX_STEPS: u64 = 1_000_000_000_000;

/// The smallest fuel of one slice. The handler sends one progress report per slice.
pub const SLICE_STEPS: u64 = 4_096;

/// Why a run in fuel slices stopped before its end (design Section 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceStop {
    /// The client cancelled the request.
    Cancel,
    /// The `max_ms` guard of the call fired.
    Time,
}

/// The report of a run in fuel slices: [`Session::analyze_sliced`] gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sliced {
    /// The state after the last slice.
    pub state: AnalysisState,
    /// The work units of all slices.
    pub steps_used: u64,
    /// The checkpoint that stopped the run before its end, or `None`.
    pub stop: Option<SliceStop>,
    /// `true` when the last slice did no work: no analyzer up to the bound of the run has
    /// work.
    pub idle: bool,
    /// `true` when the analysis stopped at the cap of the code units.
    pub capped: bool,
}

impl Sliced {
    /// Gives the run report: the last state and the work units of all slices.
    #[must_use]
    pub const fn report(&self) -> RunReport {
        RunReport {
            state: self.state,
            steps_used: self.steps_used,
            capped: self.capped,
        }
    }
}

/// The `why` of the `analysis_run` hint after a stop on the fuel budget.
pub const WHY_RESUME: &str = "The analysis has more work. Call analysis_run again to resume it.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_RESUME, WHY_TRIAGE_DONE];

/// The `why` of the `analysis_run` hint when the triage bands have no more work.
pub const WHY_TRIAGE_DONE: &str =
    "The triage bands have no more work. Call analysis_run with until full to run the other bands.";

/// The analysis engine of the shipped tools: one scheduler per open binary.
#[derive(Debug, Default)]
pub struct Engine {
    schedulers: BTreeMap<BinaryId, Scheduler>,
    /// The seed of the analyzer order of a first analysis, or `None` for the shipped order.
    order: Option<u64>,
    /// The change of the binary model before a first analysis, or `None`.
    edit: Option<fn(&mut Binary)>,
    /// The cap of the code units of each program, or `None` for the shipped cap.
    unit_cap: Option<u64>,
    /// The binaries whose first analysis holds its publish until a flush.
    held: BTreeSet<BinaryId>,
}

impl Engine {
    /// Makes an engine for the seed-order relation of design Section 13.4 (AC-189a). It
    /// shuffles the seed insertion order of the first analysis of each binary with `seed`.
    ///
    /// Before that analysis, the engine makes the program again from a copy of its binary
    /// model. The copy has the symbols, FDEs, entry points, exports, `.pdata` entries and
    /// imports in shuffled order. The symbols at one address keep their order. The rebuild
    /// uses the default limits. The analyzer order of the scheduler also changes.
    #[must_use]
    pub fn with_seed_order(seed: u64) -> Self {
        Self {
            order: Some(seed),
            ..Self::default()
        }
    }

    /// Makes an engine for a relation of the binary model (design Section 13.4).
    ///
    /// Before the first analysis of each binary, the engine makes the program again from a
    /// copy of its binary model. `edit` changes the copy. The rebuild uses the default limits.
    /// The analyzer order of the scheduler stays.
    #[must_use]
    pub fn with_model_edit(edit: fn(&mut Binary)) -> Self {
        Self {
            edit: Some(edit),
            ..Self::default()
        }
    }

    /// Makes an engine with the cap `cap` of the code units of each program, in place of
    /// the shipped cap. A test uses a small cap to make the analysis stop at the cap.
    #[must_use]
    pub fn with_unit_cap(cap: u64) -> Self {
        Self {
            unit_cap: Some(cap),
            ..Self::default()
        }
    }
}

/// Gives the scheduler of the first analysis of a binary: the shipped analyzer order, or the
/// order that `seed` shuffles.
fn first_scheduler(order: Option<u64>) -> Scheduler {
    order.map_or_else(Scheduler::new, |seed| {
        Scheduler::with_analyzers(shuffled(ANALYZERS, seed))
    })
}

/// Makes `program` again from a copy of its binary model. The copy has the seed lists in the
/// order that `order` shuffles, and then the change `edit`. A program with commits stays the
/// same, because the rebuild loses them.
fn rebuild(
    program: &mut Program,
    order: Option<u64>,
    edit: Option<fn(&mut Binary)>,
) -> Result<(), ToolError> {
    if program.rev().0 != 0 {
        return Ok(());
    }
    let mut binary = order.map_or_else(
        || program.binary().clone(),
        |seed| seeds_shuffled(program.binary(), seed),
    );
    if let Some(edit) = edit {
        edit(&mut binary);
    }
    *program =
        Program::from_binary(binary, program.mem().clone(), &Limits::DEFAULT).map_err(|e| {
            ToolError::new(ErrorCode::InternalError).detail("reason", Value::from(e.to_string()))
        })?;
    Ok(())
}

/// Gives a copy of `binary` with its seed lists in the order that `seed` shuffles.
fn seeds_shuffled(binary: &Binary, seed: u64) -> Binary {
    let mut out = binary.clone();
    out.symbols = by_address(&binary.symbols, seed);
    out.fdes = shuffled(&binary.fdes, seed.rotate_left(8));
    out.entry_points = shuffled(&binary.entry_points, seed.rotate_left(16));
    out.exports = shuffled(&binary.exports, seed.rotate_left(24));
    out.pdata = shuffled(&binary.pdata, seed.rotate_left(32));
    out.imports = shuffled(&binary.imports, seed.rotate_left(40));
    out
}

/// Gives `symbols` with their address groups in the order that `seed` shuffles. The symbols
/// at one address keep their table order. The `Symbols` analyzer takes the premise of the first
/// function symbol at an address in the alias order. That order puts a global symbol first,
/// then a weak, another and a local symbol. Inside one binding, it uses the byte order of the
/// name.
fn by_address(symbols: &[Sym], seed: u64) -> Vec<Sym> {
    let mut groups: Vec<Vec<Sym>> = Vec::new();
    let mut slots: BTreeMap<u64, usize> = BTreeMap::new();
    for sym in symbols {
        let slot = *slots.entry(sym.addr).or_insert(groups.len());
        match groups.get_mut(slot) {
            Some(group) => group.push(sym.clone()),
            None => groups.push(vec![sym.clone()]),
        }
    }
    shuffled(&groups, seed).into_iter().flatten().collect()
}

/// Gives `items` in the order of a Fisher-Yates shuffle with a `SplitMix64` stream from `seed`.
/// A list of two or more items always moves: a shuffle that keeps the order turns into a
/// rotation by one.
fn shuffled<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    let mut order: Vec<usize> = (0..items.len()).collect();
    let mut state = seed;
    for i in (1..order.len()).rev() {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let bound = u64::try_from(i).map_or(u64::MAX, |n| n.saturating_add(1));
        let j = usize::try_from(z % bound).unwrap_or(0);
        order.swap(i, j);
    }
    if order.len() >= 2 && order.iter().enumerate().all(|(i, k)| i == *k) {
        order.rotate_left(1);
    }
    order
        .iter()
        .filter_map(|i| items.get(*i).cloned())
        .collect()
}

/// Gives the envelope state of a run state.
const fn state_of(state: RunState) -> AnalysisState {
    match state {
        RunState::Complete => AnalysisState::Complete,
        RunState::BudgetStopped => AnalysisState::BudgetStopped,
        RunState::Stale => AnalysisState::Stale,
    }
}

/// Runs `scheduler` on `binary` up to `band` within `fuel`.
fn drive(
    scheduler: &mut Scheduler,
    binary: &mut OpenBinary,
    band: Band,
    fuel: &mut Fuel,
) -> Result<RunReport, ToolError> {
    let out = scheduler
        .run(&mut binary.program, band, fuel)
        .map_err(|e| {
            ToolError::new(ErrorCode::InternalError).detail("reason", Value::from(e.to_string()))
        })?;
    Ok(RunReport {
        state: state_of(out.state),
        steps_used: out.steps_used,
        capped: scheduler.capped(),
    })
}

impl AnalysisEngine for Engine {
    fn run(
        &mut self,
        binary: &mut OpenBinary,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        let band = match until {
            Until::Triage => Band::Triage,
            Until::Full => Band::Full,
        };
        let (order, edit, cap) = (self.order, self.edit, self.unit_cap);
        let held = self.held.contains(&binary.id);
        let scheduler = match self.schedulers.entry(binary.id) {
            Entry::Occupied(found) => found.into_mut(),
            Entry::Vacant(slot) => match binary.analysis.map(|a| a.state) {
                // The first analysis after a load publishes after each run.
                None => {
                    if order.is_some() || edit.is_some() {
                        rebuild(&mut binary.program, order, edit)?;
                    }
                    slot.insert(first_scheduler(order))
                }
                // A project with a current analysis needs no new run.
                Some(AnalysisState::Complete) => {
                    return Ok(RunReport {
                        state: AnalysisState::Complete,
                        steps_used: 0,
                        capped: false,
                    });
                }
                // A project with a partial or stale set keeps it until a shadow completes.
                Some(AnalysisState::BudgetStopped | AnalysisState::Stale) => {
                    slot.insert(Scheduler::shadow())
                }
            },
        };
        if let Some(cap) = cap {
            scheduler.set_unit_cap(cap);
        }
        scheduler.set_hold(held);
        drive(scheduler, binary, band, fuel)
    }

    fn hold(&mut self, id: BinaryId, on: bool) {
        if on {
            self.held.insert(id);
        } else {
            self.held.remove(&id);
        }
        if let Some(scheduler) = self.schedulers.get_mut(&id) {
            scheduler.set_hold(on);
        }
    }

    fn flush(&mut self, binary: &mut OpenBinary) -> Result<(), ToolError> {
        let Some(scheduler) = self.schedulers.get_mut(&binary.id) else {
            return Ok(());
        };
        scheduler.flush(&mut binary.program).map(drop).map_err(|e| {
            ToolError::new(ErrorCode::InternalError).detail("reason", Value::from(e.to_string()))
        })
    }

    /// Gives `{ analyzers: [[name, version], ..] }` in registry order.
    fn inputs_tag(&self) -> Value {
        Value::object([("analyzers", ghidorah_analysis::inputs::versions())])
    }

    /// Restarts the scheduler of `binary` at the start band `band` in shadow mode. A binary
    /// with no scheduler gets a shadow scheduler. Then the run continues over every band.
    fn reanalyze(
        &mut self,
        binary: &mut OpenBinary,
        band: u16,
        fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        let cap = self.unit_cap;
        let held = self.held.contains(&binary.id);
        let scheduler = self
            .schedulers
            .entry(binary.id)
            .or_insert_with(Scheduler::shadow);
        scheduler.restart(band);
        if let Some(cap) = cap {
            scheduler.set_unit_cap(cap);
        }
        scheduler.set_hold(held);
        drive(scheduler, binary, Band::Full, fuel)
    }

    fn analyzers(&self, id: BinaryId) -> Vec<AnalyzerRow> {
        self.schedulers
            .get(&id)
            .map(Scheduler::rows)
            .unwrap_or_default()
    }
}

/// Installs a new [`Engine`] in `session`.
pub fn install(session: &mut Session) {
    session.set_engine(Box::<Engine>::default());
}

const ARGS: &[ArgSpec] = &[ArgSpec::new(
    "until",
    Role::Param,
    ArgKind::Enum(&["triage", "full"]),
    "How far the analysis runs. The value triage stops after band 700.",
)
.default_json("\"full\"")];

const ROW: &[Field] = &[
    Field::req("name", OutputShape::Str),
    Field::req("priority", OutputShape::Int),
    Field::req("pending", OutputShape::Int),
    Field::req("runs", OutputShape::Int),
];
const ROW_ITEM: OutputShape = OutputShape::Obj(ROW);
const CHANGED: &[Field] = &[
    Field::req("functions", OutputShape::Int),
    Field::req("refs", OutputShape::Int),
    Field::req("strings", OutputShape::Int),
    Field::req("jumptables", OutputShape::Int),
];
const FIELDS: &[Field] = &[
    Field::req("state", OutputShape::Str),
    Field::req("steps_used", OutputShape::Int),
    Field::req("resume", OutputShape::Bool),
    Field::req("analyzers", OutputShape::List(&ROW_ITEM)),
    Field::req("changed", OutputShape::Obj(CHANGED)),
];

/// `analysis_run`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Run the analysis",
    summary: "Run or resume the analysis of a binary within a fuel budget.",
    description: "Run or resume the analysis of a binary within a fuel budget. \
                  The state complete means that no analyzer has work. \
                  With budget_stopped or stale, reads see a partial set, so call analysis_run again while resume is true. \
                  The result lists the analyzers and the changed facts.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations::EDIT,
    mutating: true,
    profiles: &[Profile::Full],
    examples: &[
        Example {
            args: "{}",
            golden: "tests/golden/tools/analysis_run.1.json",
        },
        Example {
            args: r#"{"until":"triage","max_steps":1000}"#,
            golden: "tests/golden/tools/analysis_run.2.json",
        },
    ],
    fuel: Some(FuelSpec {
        default: DEFAULT_STEPS,
        cap: MAX_STEPS,
    }),
    ..ToolSpec::base("analysis_run", run)
};

/// Gives an integer value.
fn int(n: u64) -> Value {
    Value::from(n)
}

/// Runs one engine slice with `steps` fuel units.
fn slice(
    session: &mut Session,
    id: BinaryId,
    until: Until,
    steps: u64,
) -> Result<RunReport, ToolError> {
    let mut fuel = Fuel::new(steps);
    session
        .analyze(id, until, &mut fuel)?
        .ok_or_else(|| ToolError::new(ErrorCode::InternalError))
}

/// Gives the result object of a call.
fn report(
    report: RunReport,
    used: u64,
    resume: bool,
    rows: &[AnalyzerRow],
    changed: Changed,
) -> Object {
    let rows = rows
        .iter()
        .map(|r| {
            Value::object([
                ("name", Value::from(r.name)),
                ("priority", int(u64::from(r.priority))),
                ("pending", int(r.pending)),
                ("runs", int(r.runs)),
            ])
        })
        .collect();
    let mut out = Object::new();
    out.push("state", Value::from(report.state.as_str()));
    out.push("steps_used", int(used));
    out.push("resume", Value::Bool(resume));
    out.push("analyzers", Value::Array(rows));
    out.push(
        "changed",
        Value::object([
            ("functions", int(changed.functions)),
            ("refs", int(changed.refs)),
            ("strings", int(changed.strings)),
            ("jumptables", int(changed.jumptables)),
        ]),
    );
    out
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let binary = session.bound(&ctx.frame)?;
    let id = binary.id;
    let before = binary.program.analysis().clone();
    let rev = binary.program.rev();
    let until = match args.str("until") {
        Some("triage") => Until::Triage,
        _ => Until::Full,
    };
    if !session.has_engine() {
        install(session);
    }
    // A slice with no fuel gives the state. A dry run and a complete analysis stop there.
    let probe = slice(session, id, until, 0)?;
    let dry = args.globals().dry_run;
    let (last, used, idle) = if dry || probe.state == AnalysisState::Complete {
        (probe, 0, false)
    } else {
        let run = session
            .analyze_sliced(id, until, ctx)?
            .ok_or_else(|| ToolError::new(ErrorCode::InternalError))?;
        (run.report(), run.steps_used, run.idle)
    };
    // The state is relative to the full analysis. A triage run whose last slice did no work
    // has no more work, although the bands after triage wait.
    let triage_done = until == Until::Triage && idle && last.state != AnalysisState::Complete;
    let resume = last.state != AnalysisState::Complete && !triage_done;
    let binary = session
        .binary(id)
        .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
    let changed = Changed::between(&before, binary.program.analysis());
    ctx.frame.rev = binary.program.rev().0;
    ctx.frame.analysis = binary.analysis;
    ctx.mutation = Some(Mutation {
        tx: None,
        noop: binary.program.rev() == rev,
        diff: dry.then(|| Value::Array(Vec::new())),
    });
    let mut hint = Object::new();
    hint.push("binary_id", Value::from(id.to_string()));
    if triage_done {
        hint.push("until", Value::from("full"));
        ctx.hint(Call::new(
            "analysis_run",
            Value::Object(hint),
            WHY_TRIAGE_DONE,
        ));
    } else if resume {
        // The resume hint keeps the bound of the call.
        if until == Until::Triage {
            hint.push("until", Value::from("triage"));
        }
        ctx.hint(Call::new("analysis_run", Value::Object(hint), WHY_RESUME));
    }
    let rows = session.analyzer_rows(id);
    Ok(Payload::Object(report(last, used, resume, &rows, changed)))
}
