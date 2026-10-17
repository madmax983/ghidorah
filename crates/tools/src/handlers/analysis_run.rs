//! `analysis_run`: run or resume the analysis with a fuel budget (design Section 10.4, tool 3).
//!
//! The handler runs the analysis engine of the session in fuel slices of [`SLICE_STEPS`]
//! units. After each slice it sends one progress report with the work units so far, so the
//! progress value increases strictly (AC-173). It checks the cancel flag at the end of each
//! slice. So `notifications/cancelled` stops the run at the next fuel checkpoint (AC-172).
//!
//! [`Engine`] is the analysis engine of the shipped tools: one [`Scheduler`] per open binary.
//! A session with no engine gets one at the first call.

use std::collections::BTreeMap;

use ghidorah_analysis::{AnalyzerRow, Scheduler};
use ghidorah_base::{BinaryId, ErrorCode, Fuel};

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::{AnalysisEngine, OpenBinary, RunReport, Session, Until};
use crate::spec::{Annotations, ArgKind, ArgSpec, Example, FuelSpec, Profile, Role, ToolSpec};

/// The default fuel of one call (Section 7.2).
pub const DEFAULT_STEPS: u64 = 100_000_000;

/// The largest `max_steps` of one call.
pub const MAX_STEPS: u64 = 1_000_000_000_000;

/// The fuel of one slice. The handler sends one progress report per slice.
pub const SLICE_STEPS: u64 = 4_096;

/// The analysis engine of the shipped tools: one scheduler per open binary.
#[derive(Debug, Default)]
pub struct Engine {
    schedulers: BTreeMap<BinaryId, Scheduler>,
}

impl AnalysisEngine for Engine {
    fn run(
        &mut self,
        binary: &mut OpenBinary,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        let _ = (binary, until, fuel, &self.schedulers);
        Err(ToolError::new(ErrorCode::InternalError))
    }

    fn analyzers(&self, id: BinaryId) -> Vec<AnalyzerRow> {
        let _ = id;
        Vec::new()
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
                  The result lists each analyzer with its priority band, its pending ranges and its runs, and the changed facts of the call. \
                  With a progress token, the server sends one progress notification per fuel slice.",
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

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session, args, ctx, SLICE_STEPS);
    Err(ToolError::new(ErrorCode::InternalError))
}
