//! One eval run: every metric of design Section 12.4 over one pool of worker threads.
//!
//! [`evaluate`] reads the frozen inputs, runs each job once and gives a [`Report`]. The jobs
//! are the scenario runs, their second runs, the A/B batch forms and the ablation runs. Other
//! jobs run the robots, the recall runs, the survey recall and the light checks.
//! Every job opens its own sessions, so the jobs can run in any order on any thread. The
//! report keeps the job results in input order, so two runs give the same report.

use std::path::Path;

use crate::checks::{self, Catalog, Fuzz, Metamorphic};
use crate::discover::{self, Discover};
use crate::error::EvalError;
use crate::follower::{self, Follower, HintGraph, Walk};
use crate::inputs::{self, Question, Thresholds};
use crate::lint;
use crate::recall::{self, Recall};
use crate::repair::{self, Attempt, Repair};
use crate::runner::{self, Outcome};
use crate::scenario::{self, Scenario};
use crate::survey::{self, FixtureRecall, SurveyRecall};

/// The result of one eval run.
#[derive(Debug, Clone)]
pub struct Report {
    /// The thresholds as read.
    pub thresholds: Thresholds,
    /// The frozen questions.
    pub questions: Vec<Question>,
    /// The scenarios of `eval/scenarios/`.
    pub scenarios: Vec<Scenario>,
    /// Their outcomes, in the same order.
    pub outcomes: Vec<Outcome>,
    /// The second runs of the determinism compare, in the same order. A scenario that opens
    /// more than one binary (the T2 twins) runs once. AC-200 compares two whole runs instead.
    pub reruns: Vec<Option<Outcome>>,
    /// The ablation runs with `shape: "table"`, for the scenarios with a list call.
    pub tables: Vec<Option<Outcome>>,
    /// The batch forms of `eval/ab/`.
    pub ab_scenarios: Vec<Scenario>,
    /// Their outcomes.
    pub ab_outcomes: Vec<Outcome>,
    /// The lint result of each scenario and batch form, in that order.
    pub lint: Vec<lint::Report>,
    /// The repair robot.
    pub repair: Repair,
    /// The hint-follower robot.
    pub follower: Follower,
    /// The discoverability metric.
    pub discover: Discover,
    /// The recall after a reset.
    pub recall_reset: Recall,
    /// The recall after a reset and 50 noise edits.
    pub recall_edits: Recall,
    /// The survey recall.
    pub survey: SurveyRecall,
    /// The metamorphic relations.
    pub metamorphic: Metamorphic,
    /// The schema fuzz.
    pub fuzz: Fuzz,
    /// The catalog sizes.
    pub catalog: Catalog,
    /// The hint graph.
    pub hint_graph: HintGraph,
}

/// One job of the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Job {
    Scenario(usize),
    Rerun(usize),
    Table(usize),
    Ab(usize),
    Walk(usize),
    Survey(usize),
    Mistake(usize),
    Recall(bool),
    Discover,
    Metamorphic,
    Fuzz,
    Catalog,
    HintGraph,
}

/// The result of one job.
#[derive(Debug)]
enum Done {
    Run(Job, Box<Outcome>),
    Walk(usize, Walk),
    Survey(usize, FixtureRecall),
    Mistake(usize, Attempt),
    Recall(bool, Result<Recall, EvalError>),
    Discover(Result<Discover, EvalError>),
    Metamorphic(Result<Metamorphic, EvalError>),
    Fuzz(Result<Fuzz, EvalError>),
    Catalog(Result<Catalog, EvalError>),
    HintGraph(HintGraph),
}

/// The inputs that the jobs read.
struct Inputs {
    thresholds: Thresholds,
    questions: Vec<Question>,
    scenarios: Vec<Scenario>,
    ab: Vec<Scenario>,
    mistakes: Vec<repair::Mistake>,
    walks: Vec<usize>,
    survey: Vec<survey::FixtureFacts>,
    recall: recall::Spec,
    intents: Vec<inputs::Intent>,
}

impl Inputs {
    fn question(&self, s: &Scenario) -> Option<&Question> {
        self.questions.iter().find(|q| q.id == s.question)
    }

    fn outcome(&self, root: &Path, s: &Scenario, table: bool) -> Outcome {
        let per_token = self.thresholds.chars_per_token;
        self.question(s).map_or_else(
            || Outcome::failed(&s.id, &s.question, "", runner::NO_QUESTION),
            |q| runner::run_shaped(root, s, q, per_token, table),
        )
    }
}

fn missing() -> Outcome {
    Outcome::failed("", "", "", "the job gives no result")
}

fn run_job(root: &Path, inputs: &Inputs, job: Job) -> Done {
    let scenario = |i: usize| inputs.scenarios.get(i);
    match job {
        Job::Scenario(i) | Job::Rerun(i) => Done::Run(
            job,
            Box::new(scenario(i).map_or_else(missing, |s| inputs.outcome(root, s, false))),
        ),
        Job::Table(i) => Done::Run(
            job,
            Box::new(scenario(i).map_or_else(missing, |s| inputs.outcome(root, s, true))),
        ),
        Job::Ab(i) => Done::Run(
            job,
            Box::new(
                inputs
                    .ab
                    .get(i)
                    .map_or_else(missing, |s| inputs.outcome(root, s, false)),
            ),
        ),
        Job::Walk(i) => {
            let walk = scenario(i)
                .and_then(|s| inputs.question(s).map(|q| follower::walk(root, s, q)))
                .unwrap_or_else(|| Walk {
                    scenario: String::new(),
                    reached: false,
                    calls: 0,
                    missing: Vec::new(),
                });
            Done::Walk(i, walk)
        }
        Job::Survey(i) => {
            let fixture = inputs
                .survey
                .get(i)
                .map(|(name, path, facts)| survey::one(root, name, path, facts));
            Done::Survey(
                i,
                fixture.unwrap_or_else(|| FixtureRecall {
                    fixture: String::new(),
                    found: 0,
                    total: 0,
                    missed: Vec::new(),
                }),
            )
        }
        Job::Mistake(i) => Done::Mistake(
            i,
            inputs.mistakes.get(i).map_or_else(
                || Attempt {
                    id: String::new(),
                    class: String::new(),
                    code: String::new(),
                    triggered: false,
                    ok: false,
                    rank: 0,
                },
                |m| repair::attempt(root, m),
            ),
        ),
        Job::Recall(noise) => Done::Recall(noise, recall::run(root, &inputs.recall, noise)),
        Job::Discover => Done::Discover(discover::run(root, &inputs.intents)),
        Job::Metamorphic => Done::Metamorphic(checks::metamorphic(root)),
        Job::Fuzz => Done::Fuzz(checks::fuzz(root)),
        Job::Catalog => Done::Catalog(checks::catalog(root)),
        Job::HintGraph => Done::HintGraph(follower::hint_graph(root)),
    }
}

fn read_inputs(root: &Path) -> Result<Inputs, EvalError> {
    let questions = inputs::read_questions(root)?;
    let scenarios = scenario::read_dir(root, scenario::DIR)?;
    let walks = scenarios
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            questions
                .iter()
                .any(|q| q.id == s.question && follower::CATEGORIES.contains(&q.category.as_str()))
        })
        .map(|(i, _)| i)
        .collect();
    Ok(Inputs {
        thresholds: inputs::read_thresholds(root)?,
        ab: scenario::read_dir(root, scenario::AB_DIR)?,
        mistakes: repair::read(root)?,
        survey: survey::fixtures(root)?,
        recall: recall::read_spec(root)?,
        intents: inputs::read_intents(root, inputs::INTENTS_HELDOUT)?,
        questions,
        scenarios,
        walks,
    })
}

/// Gives the jobs, the slow ones first so the pool ends early.
fn jobs(inputs: &Inputs) -> Vec<Job> {
    let slow = |i: &usize| {
        inputs
            .scenarios
            .get(*i)
            .and_then(|s| inputs.question(s))
            .is_some_and(|q| q.binaries.len() > 1)
    };
    let n = inputs.scenarios.len();
    let (heavy, light): (Vec<usize>, Vec<usize>) = (0..n).partition(slow);
    let mut out: Vec<Job> = Vec::new();
    out.extend(heavy.iter().map(|i| Job::Scenario(*i)));
    out.extend([
        Job::Fuzz,
        Job::Recall(true),
        Job::Recall(false),
        Job::Metamorphic,
        Job::HintGraph,
    ]);
    out.extend(inputs.walks.iter().map(|i| Job::Walk(*i)));
    for i in &light {
        out.push(Job::Scenario(*i));
        out.push(Job::Rerun(*i));
        let lists = inputs.scenarios.get(*i).is_some_and(|s| {
            s.turns
                .iter()
                .any(|t| crate::ab::LIST_TOOLS.contains(&t.tool.as_str()))
        });
        if lists {
            out.push(Job::Table(*i));
        }
    }
    out.extend((0..inputs.ab.len()).map(Job::Ab));
    out.extend((0..inputs.survey.len()).map(Job::Survey));
    out.extend((0..inputs.mistakes.len()).map(Job::Mistake));
    out.extend([Job::Discover, Job::Catalog]);
    out
}

/// Runs every metric once.
///
/// # Errors
///
/// Returns an [`EvalError`] when an input file does not read, or a recall, discoverability or
/// check job cannot open its session.
pub fn evaluate(root: &Path) -> Result<Report, EvalError> {
    let inputs = read_inputs(root)?;
    let all_jobs = jobs(&inputs);
    let done = runner::parallel(&all_jobs, runner::threads(), |job| {
        run_job(root, &inputs, *job)
    });
    let n = inputs.scenarios.len();
    let mut outcomes = vec![None; n];
    let mut reruns = vec![None; n];
    let mut tables = vec![None; n];
    let mut ab_outcomes = vec![None; inputs.ab.len()];
    let mut walks = vec![None; inputs.walks.len()];
    let mut fixtures = vec![None; inputs.survey.len()];
    let mut attempts = vec![None; inputs.mistakes.len()];
    let (mut reset, mut edits, mut disc, mut meta, mut fuzz, mut cat, mut graph) =
        (None, None, None, None, None, None, None);
    for d in done {
        match d {
            Done::Run(Job::Scenario(i), o) => put(&mut outcomes, i, *o),
            Done::Run(Job::Rerun(i), o) => put(&mut reruns, i, *o),
            Done::Run(Job::Table(i), o) => put(&mut tables, i, *o),
            Done::Run(Job::Ab(i), o) => put(&mut ab_outcomes, i, *o),
            Done::Run(_, _) => {}
            Done::Walk(i, w) => {
                if let Some(k) = inputs.walks.iter().position(|x| *x == i) {
                    put(&mut walks, k, w);
                }
            }
            Done::Survey(i, f) => put(&mut fixtures, i, f),
            Done::Mistake(i, a) => put(&mut attempts, i, a),
            Done::Recall(true, r) => edits = Some(r?),
            Done::Recall(false, r) => reset = Some(r?),
            Done::Discover(r) => disc = Some(r?),
            Done::Metamorphic(r) => meta = Some(r?),
            Done::Fuzz(r) => fuzz = Some(r?),
            Done::Catalog(r) => cat = Some(r?),
            Done::HintGraph(g) => graph = Some(g),
        }
    }
    let outcomes: Vec<Outcome> = outcomes
        .into_iter()
        .map(|o| o.unwrap_or_else(missing))
        .collect();
    let ab_outcomes: Vec<Outcome> = ab_outcomes
        .into_iter()
        .map(|o| o.unwrap_or_else(missing))
        .collect();
    let instructions =
        crate::host::session(root, None, ghidorah_tools::Profile::Full)?.instructions();
    let lint = inputs
        .scenarios
        .iter()
        .zip(&outcomes)
        .chain(inputs.ab.iter().zip(&ab_outcomes))
        .map(|(s, o)| match inputs.question(s) {
            Some(q) => lint::lint(s, q, o, &instructions),
            None => lint::Report::default(),
        })
        .collect();
    let incomplete = || EvalError::data("eval", "a job of the run gives no result");
    Ok(Report {
        outcomes,
        reruns,
        tables,
        ab_outcomes,
        lint,
        repair: Repair {
            attempts: attempts.into_iter().flatten().collect(),
        },
        follower: Follower {
            walks: walks.into_iter().flatten().collect(),
        },
        discover: disc.ok_or_else(incomplete)?,
        recall_reset: reset.ok_or_else(incomplete)?,
        recall_edits: edits.ok_or_else(incomplete)?,
        survey: SurveyRecall {
            fixtures: fixtures.into_iter().flatten().collect(),
        },
        metamorphic: meta.ok_or_else(incomplete)?,
        fuzz: fuzz.ok_or_else(incomplete)?,
        catalog: cat.ok_or_else(incomplete)?,
        hint_graph: graph.ok_or_else(incomplete)?,
        thresholds: inputs.thresholds,
        questions: inputs.questions,
        scenarios: inputs.scenarios,
        ab_scenarios: inputs.ab,
    })
}

fn put<T>(slots: &mut [Option<T>], i: usize, value: T) {
    if let Some(slot) = slots.get_mut(i) {
        *slot = Some(value);
    }
}
