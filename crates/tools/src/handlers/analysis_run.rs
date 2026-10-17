//! `analysis_run`: run or resume the analysis with a fuel budget (design Section 10.4, tool 3).
//!
//! The handler runs the analysis engine of the session in fuel slices. A slice has
//! [`SLICE_STEPS`] work units or a quarter of the units so far, whichever is more. So the
//! publish steps of one call cost at most a log factor over one publish. After each slice the
//! handler sends one progress report with the work units so far, so the progress value
//! increases strictly (AC-173). It checks the cancel flag at the end of each slice. So
//! `notifications/cancelled` stops the run at the next fuel checkpoint (AC-172).
//!
//! [`Engine`] is the analysis engine of the shipped tools: one [`Scheduler`] per open binary.
//! A session with no engine gets one at the first call.

use std::collections::BTreeMap;

use ghidorah_analysis::{AnalyzerRow, Changed, RunState, Scheduler, Until as Band};
use ghidorah_base::{BinaryId, ErrorCode, Fuel};
use ghidorah_json::{Object, Value};

use crate::api::Progress;
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

/// The `why` of the `analysis_run` hint after a stop on the fuel budget.
pub const WHY_RESUME: &str = "The analysis has more work. Call analysis_run again to resume it.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_RESUME];

/// The analysis engine of the shipped tools: one scheduler per open binary.
#[derive(Debug, Default)]
pub struct Engine {
    schedulers: BTreeMap<BinaryId, Scheduler>,
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
        let scheduler = self.schedulers.entry(binary.id).or_default();
        drive(scheduler, binary, band, fuel)
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
        let scheduler = self
            .schedulers
            .entry(binary.id)
            .or_insert_with(Scheduler::shadow);
        scheduler.restart(band);
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
                  The run stops at a fixpoint or after max_steps work units. \
                  The state complete means that no analyzer has work. \
                  The state budget_stopped means that reads see a partial set, so call analysis_run again while resume is true. \
                  The state stale means that a re-analysis runs, and reads see the old set. \
                  The result lists each analyzer with its priority band, its pending ranges and its runs, and the changed facts of the call.",
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
fn report(report: RunReport, used: u64, rows: &[AnalyzerRow], changed: Changed) -> Object {
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
    out.push(
        "resume",
        Value::Bool(report.state != AnalysisState::Complete),
    );
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
    let mut last = slice(session, id, until, 0)?;
    let mut used = 0u64;
    let dry = args.globals().dry_run;
    while !dry && last.state != AnalysisState::Complete && !ctx.cancelled() {
        let steps = SLICE_STEPS.max(used / 4).min(ctx.fuel.remaining());
        if steps == 0 {
            break;
        }
        last = slice(session, id, until, steps)?;
        let _ = ctx.fuel.take(last.steps_used.min(ctx.fuel.remaining()));
        if last.steps_used == 0 {
            break;
        }
        used = used.saturating_add(last.steps_used);
        ctx.progress(Progress {
            progress: used,
            total: None,
            message: format!("The analysis used {used} work units."),
        });
    }
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
    if last.state != AnalysisState::Complete {
        ctx.hint(Call::new(
            "analysis_run",
            Value::object([("binary_id", Value::from(id.to_string()))]),
            WHY_RESUME,
        ));
    }
    let rows = session.analyzer_rows(id);
    Ok(Payload::Object(report(last, used, &rows, changed)))
}
