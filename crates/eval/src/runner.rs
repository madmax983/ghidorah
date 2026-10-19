//! The scenario runner (design Sections 12.1 and 12.2).
//!
//! The runner opens one session per scenario and sends the turns in order. Before a call it
//! replaces each `$turn` reference with the value of the earlier response. A `restart` turn
//! drops the session and opens a new one over the same projects directory. A new server
//! process opens the projects on disk the same way. After the last turn the runner extracts the
//! answer and checks it against the frozen answer and the budgets.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use ghidorah_json::Value;
use ghidorah_tools::{Profile, Session};

use crate::derive::{self, Source};
use crate::host::{self, Scratch};
use crate::inputs::Question;
use crate::scenario::Scenario;

/// The result of one scenario run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The scenario ID.
    pub id: String,
    /// The question ID.
    pub question: String,
    /// The question category.
    pub category: String,
    /// `true` when the answer and the budgets pass.
    pub pass: bool,
    /// `true` when the answer check passes.
    pub answer_ok: bool,
    /// `true` when the calls and characters stay in the budgets.
    pub budget_ok: bool,
    /// The extracted answer, or `None` when the extraction fails.
    pub answer: Option<Value>,
    /// Why the scenario fails, or `None` for a pass.
    pub error: Option<String>,
    /// The number of calls.
    pub calls: u64,
    /// The sum of the response characters.
    pub chars: u64,
    /// The largest response in characters.
    pub peak: u64,
    /// The token estimate of `chars`.
    pub est_tokens: u64,
    /// The response of each turn.
    pub responses: Vec<Value>,
    /// The arguments of each turn after the references resolve.
    pub sent: Vec<Value>,
}

impl Outcome {
    /// Makes the outcome of a run that fails before its first call, with the reason `error`.
    #[must_use]
    pub fn failed(id: &str, question: &str, category: &str, error: &str) -> Self {
        Self {
            id: id.to_owned(),
            question: question.to_owned(),
            category: category.to_owned(),
            pass: false,
            answer_ok: false,
            budget_ok: false,
            answer: None,
            error: Some(error.to_owned()),
            calls: 0,
            chars: 0,
            peak: 0,
            est_tokens: 0,
            responses: Vec::new(),
            sent: Vec::new(),
        }
    }
}

/// Replaces each `$turn` object in `args` with its value.
///
/// # Errors
///
/// Returns a message when a reference points at the current turn or later, or does not
/// resolve.
pub fn resolve(args: &Value, responses: &[Value]) -> Result<Value, String> {
    match args {
        Value::Object(members) if members.contains_key("$turn") => {
            let src: Source = derive::parse_source(args)?;
            if src.turn >= responses.len() {
                return Err(format!(
                    "the reference to turn {} is not to an earlier turn",
                    src.turn
                ));
            }
            derive::extract(responses, &src)
        }
        Value::Object(members) => {
            let mut out = ghidorah_json::Object::new();
            for (k, v) in members.iter() {
                out.push(k, resolve(v, responses)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => items
            .iter()
            .map(|v| resolve(v, responses))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => Ok(other.clone()),
    }
}

/// Tells if a response holds a `refuted` verdict or an empty list with `complete: true`.
///
/// An `abstain` scenario fails on either (design Section 12.2, AC-228).
#[must_use]
pub fn overclaims(response: &Value) -> bool {
    let mut stack = vec![response];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(members) => {
                if members.get("verdict").and_then(Value::as_str) == Some("refuted") {
                    return true;
                }
                let empty = members
                    .get("items")
                    .and_then(Value::as_array)
                    .is_some_and(<[Value]>::is_empty);
                let complete = members
                    .get("basis")
                    .and_then(|b| b.get("complete"))
                    .and_then(Value::as_bool)
                    == Some(true);
                if empty && complete {
                    return true;
                }
                stack.extend(members.iter().map(|(_, x)| x));
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    false
}

fn open(root: &Path, projects: Option<&Scratch>) -> Result<Session, String> {
    host::session(root, projects.map(Scratch::path), Profile::Full).map_err(|e| e.to_string())
}

/// Runs one scenario against its question. `per_token` is the characters per token.
#[must_use]
pub fn run(root: &Path, scenario: &Scenario, question: &Question, per_token: u64) -> Outcome {
    run_shaped(root, scenario, question, per_token, false)
}

/// Runs one scenario. With `table`, each list call also sends `shape: "table"` (the
/// ablation of design Section 12.4).
#[must_use]
pub fn run_shaped(
    root: &Path,
    scenario: &Scenario,
    question: &Question,
    per_token: u64,
    table: bool,
) -> Outcome {
    let mut out = Outcome::failed(&scenario.id, &question.id, &question.category, "");
    out.error = None;
    let needs_disk = scenario.turns.iter().any(|t| t.restart);
    let projects = if needs_disk {
        match Scratch::new(&scenario.id) {
            Ok(s) => Some(s),
            Err(e) => {
                out.error = Some(format!("the projects directory cannot be made: {e}"));
                return out;
            }
        }
    } else {
        None
    };
    let mut session = match open(root, projects.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    for (i, turn) in scenario.turns.iter().enumerate() {
        if turn.restart {
            drop(session);
            session = match open(root, projects.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    out.error = Some(e);
                    return out;
                }
            };
        }
        let args = match resolve(&turn.args, &out.responses) {
            Ok(Value::Object(mut a))
                if table && crate::ab::LIST_TOOLS.contains(&turn.tool.as_str()) =>
            {
                a.insert("shape", Value::from("table"));
                Value::Object(a)
            }
            Ok(a) => a,
            Err(e) => {
                out.error = Some(format!("turn {i}: {e}"));
                return out;
            }
        };
        let response = host::call(&mut session, &turn.tool, args.clone());
        let size = host::chars(&response);
        out.calls = out.calls.saturating_add(1);
        out.chars = out.chars.saturating_add(size);
        out.peak = out.peak.max(size);
        out.sent.push(args);
        out.responses.push(response);
    }
    out.est_tokens = host::est_tokens(out.chars, per_token);
    let b = scenario.budgets;
    out.budget_ok =
        out.calls <= b.max_calls && out.chars <= b.max_chars && out.peak <= b.max_peak_chars;
    match derive::extract(&out.responses, &scenario.answer) {
        Ok(answer) => {
            out.answer_ok = derive::check(&question.check, &question.value, &answer);
            if question.check == "abstain" && out.responses.iter().any(overclaims) {
                out.answer_ok = false;
                out.error = Some("a step gives refuted or an empty complete result".to_owned());
            }
            out.answer = Some(answer);
        }
        Err(e) => out.error = Some(format!("the answer does not extract: {e}")),
    }
    if !out.answer_ok && out.error.is_none() {
        out.error = Some("the answer is not the frozen answer".to_owned());
    }
    if out.answer_ok && !out.budget_ok {
        out.error = Some("the scenario is over its budgets".to_owned());
    }
    out.pass = out.answer_ok && out.budget_ok;
    out
}

/// Runs `jobs` on at most `threads` worker threads and gives the results in job order.
pub fn parallel<T, R, F>(jobs: &[T], threads: usize, f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let next = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<R>>> = Mutex::new((0..jobs.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..threads.clamp(1, jobs.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(job) = jobs.get(i) else { break };
                    let r = f(job);
                    if let Ok(mut s) = slots.lock()
                        && let Some(slot) = s.get_mut(i)
                    {
                        *slot = Some(r);
                    }
                }
            });
        }
    });
    slots
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect()
}

/// Gives the number of worker threads: the parallelism of the host, at most 4.
#[must_use]
pub fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
}

/// The reason of a run whose scenario names no frozen question.
pub const NO_QUESTION: &str = "the scenario names no frozen question";

/// Runs each scenario against its question in parallel and gives the outcomes in order.
///
/// A scenario whose question does not exist fails with an error.
#[must_use]
pub fn run_all(
    root: &Path,
    scenarios: &[Scenario],
    questions: &[Question],
    per_token: u64,
) -> Vec<Outcome> {
    parallel(scenarios, threads(), |s| {
        questions.iter().find(|q| q.id == s.question).map_or_else(
            || Outcome::failed(&s.id, &s.question, "", NO_QUESTION),
            |q| run(root, s, q, per_token),
        )
    })
}
