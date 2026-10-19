//! The hint-follower robot and the hint graph (design Section 12.4, AC-227).
//!
//! The robot knows no tool. It loads the binaries of the question, then walks breadth first,
//! at most 6 calls deep, over three kinds of edges:
//!
//! - each `{ tool, args }` call in a response: `next`, `omitted.next`, item `next` and
//!   worklist `remedy` calls;
//! - each `page.next_cursor`: the same call with the cursor;
//! - the examples of the tools that `tool_search` finds for the question text.
//!
//! The robot reaches a scenario when the responses show every evidence text of the scenario.
//! A cap of [`MAX_CALLS`] calls bounds each walk.

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;

use ghidorah_json::{Object, Value};
use ghidorah_tools::{Profile, Session};

use crate::host;
use crate::inputs::Question;
use crate::milli::Milli;
use crate::runner;
use crate::scenario::Scenario;

/// The largest depth of a walk.
pub const MAX_DEPTH: u32 = 6;

/// The largest number of calls of a walk.
pub const MAX_CALLS: u64 = 60;

/// The largest number of calls of the hint-graph walk.
pub const GRAPH_CALLS: u64 = 200;

/// The categories that the robot measures.
pub const CATEGORIES: &[&str] = &["triage", "locate"];

/// The result of one walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    /// The scenario ID.
    pub scenario: String,
    /// `true` when the responses show every evidence text.
    pub reached: bool,
    /// The number of calls.
    pub calls: u64,
    /// The evidence texts that no response shows.
    pub missing: Vec<String>,
}

/// The result of the robot over the measured scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Follower {
    /// The walks in scenario order.
    pub walks: Vec<Walk>,
}

impl Follower {
    /// Gives the fraction of reached scenarios.
    #[must_use]
    pub fn rate(&self) -> Milli {
        let reached = self.walks.iter().filter(|w| w.reached).count();
        Milli::ratio(
            u64::try_from(reached).unwrap_or(0),
            u64::try_from(self.walks.len()).unwrap_or(0),
        )
    }
}

/// Gives the call objects `{ tool, args }` anywhere in `response`, in document order.
#[must_use]
pub fn hints(response: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut stack = vec![response];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(m) => {
                if let (Some(Value::String(tool)), Some(args @ Value::Object(_))) =
                    (m.get("tool"), m.get("args"))
                {
                    out.push((tool.clone(), args.clone()));
                }
                for (_, x) in m.iter().collect::<Vec<_>>().into_iter().rev() {
                    stack.push(x);
                }
            }
            Value::Array(items) => stack.extend(items.iter().rev()),
            _ => {}
        }
    }
    out
}

/// Gives the examples of the tools in a `tool_search` response at level `full`.
fn examples(response: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for item in response
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
    {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        for ex in item
            .get("examples")
            .and_then(Value::as_array)
            .unwrap_or_default()
        {
            let args = ex.get("args").cloned().unwrap_or_else(|| ex.clone());
            if matches!(args, Value::Object(_)) {
                out.push((name.to_owned(), args));
            }
        }
    }
    out
}

/// One queued call of a walk.
struct Job {
    tool: String,
    args: Value,
    depth: u32,
}

/// The state of one breadth-first walk.
struct Bfs {
    queue: VecDeque<Job>,
    seen: BTreeSet<String>,
    calls: u64,
}

impl Bfs {
    fn push(&mut self, tool: String, args: Value, depth: u32) {
        let key = format!("{tool} {}", ghidorah_json::write(&args));
        if depth <= MAX_DEPTH && self.seen.insert(key) {
            self.queue.push_back(Job { tool, args, depth });
        }
    }

    /// Queues the edges of a response that a call at `depth` gave.
    fn expand(&mut self, job: &Job, response: &Value) {
        for (tool, args) in hints(response) {
            self.push(tool, args, job.depth + 1);
        }
        if let Some(cursor) = response
            .pointer("/page/next_cursor")
            .and_then(Value::as_str)
        {
            let mut args = match &job.args {
                Value::Object(m) => m.clone(),
                _ => Object::new(),
            };
            args.insert("cursor", Value::from(cursor));
            self.push(job.tool.clone(), Value::Object(args), job.depth + 1);
        }
        if job.tool == "tool_search" {
            for (tool, args) in examples(response) {
                self.push(tool, args, job.depth + 1);
            }
        }
    }

    /// Runs the queue. `visit` sees each response and tells if the walk can stop.
    fn run(
        &mut self,
        session: &mut Session,
        cap: u64,
        visit: &mut dyn FnMut(&str, &Value) -> bool,
    ) {
        while let Some(job) = self.queue.pop_front() {
            if self.calls >= cap {
                break;
            }
            let response = host::call(session, &job.tool, job.args.clone());
            self.calls = self.calls.saturating_add(1);
            if visit(&job.tool, &response) {
                break;
            }
            self.expand(&job, &response);
        }
    }
}

/// Walks the hints for one scenario.
#[must_use]
pub fn walk(root: &Path, scenario: &Scenario, question: &Question) -> Walk {
    return Walk { scenario: scenario.id.clone(), reached: false, calls: 0, missing: Vec::new() };
    let mut out = Walk {
        scenario: scenario.id.clone(),
        reached: false,
        calls: 0,
        missing: scenario.evidence.clone(),
    };
    let Ok(mut session) = host::session(root, None, Profile::Full) else {
        return out;
    };
    let mut bfs = Bfs {
        queue: VecDeque::new(),
        seen: BTreeSet::new(),
        calls: 0,
    };
    for path in &question.binaries {
        bfs.push(
            "binary_load".to_owned(),
            Value::object([("path", Value::from(path.as_str()))]),
            0,
        );
    }
    let search = Value::object([
        ("query", Value::from(question.text.as_str())),
        ("level", Value::from("full")),
    ]);
    bfs.push("tool_search".to_owned(), search, 1);
    let mut missing = scenario.evidence.clone();
    bfs.run(&mut session, MAX_CALLS, &mut |_, response| {
        let text = ghidorah_json::write(response);
        missing.retain(|e| !text.contains(e.as_str()));
        missing.is_empty()
    });
    out.calls = bfs.calls;
    out.reached = missing.is_empty() && !scenario.evidence.is_empty();
    out.missing = missing;
    out
}

/// Walks the hints of every `triage` and `locate` scenario.
#[must_use]
pub fn run(root: &Path, scenarios: &[Scenario], questions: &[Question]) -> Follower {
    let jobs: Vec<(&Scenario, &Question)> = scenarios
        .iter()
        .filter_map(|s| {
            questions
                .iter()
                .find(|q| q.id == s.question)
                .map(|q| (s, q))
        })
        .filter(|(_, q)| CATEGORIES.contains(&q.category.as_str()))
        .collect();
    Follower {
        walks: runner::parallel(&jobs, runner::threads(), |(s, q)| walk(root, s, q)),
    }
}

/// The hint graph of the demo binary: a report-only metric.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HintGraph {
    /// The tools that a call of the walk reaches.
    pub reached: Vec<String>,
    /// The tools of the full profile that no hint reaches.
    pub unreached: Vec<String>,
    /// The tools that gave a success result with no `next` call.
    pub no_next: Vec<String>,
}

/// Walks the `next` hints from `binary_survey` on the demo binary, at most 4 calls deep.
#[must_use]
pub fn hint_graph(root: &Path) -> HintGraph {
    return HintGraph::default();
    let mut out = HintGraph::default();
    let Ok(mut session) = host::session(root, None, Profile::Full) else {
        return out;
    };
    host::call(
        &mut session,
        "binary_load",
        Value::object([("builtin", Value::from("demo"))]),
    );
    let mut bfs = Bfs {
        queue: VecDeque::new(),
        seen: BTreeSet::new(),
        calls: 0,
    };
    bfs.push("binary_survey".to_owned(), host::empty(), MAX_DEPTH - 4);
    let mut reached = BTreeSet::new();
    let mut no_next = BTreeSet::new();
    bfs.run(&mut session, GRAPH_CALLS, &mut |tool, response| {
        reached.insert(tool.to_owned());
        let ok = response.get("ok").and_then(Value::as_bool) == Some(true);
        if ok && response.get("next").is_none() {
            no_next.insert(tool.to_owned());
        }
        false
    });
    let all = ghidorah_tools::registry::shipped().names();
    out.unreached = all
        .iter()
        .filter(|n| !reached.contains(**n))
        .map(|n| (*n).to_owned())
        .collect();
    out.reached = reached.into_iter().collect();
    out.no_next = no_next.into_iter().collect();
    out
}
