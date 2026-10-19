//! Scenario call scripts (design Section 12.2).
//!
//! A scenario file `eval/scenarios/<id>.json` answers one frozen question with a fixed list of
//! turns. A script can only add calls. It cannot change its question or its answer.
//!
//! ```json
//! {
//!   "id": "triage-03",
//!   "question": "q-triage-03",
//!   "turns": [
//!     { "call": { "tool": "binary_load", "args": { "path": "fixtures/bin/canary.gcc-O2.stripped" } } },
//!     { "call": { "tool": "binary_survey", "args": { "include": ["protections"] } } }
//!   ],
//!   "answer": { "turn": 1, "ptr": "/data/protections/canary" },
//!   "provenance": {
//!     "/turns/0/call/args/path": "question:binaries/0",
//!     "/turns/1/call/args/include/0": "schema:binary_survey.include"
//!   },
//!   "budgets": { "max_calls": 2, "max_chars": 2000, "max_peak_chars": 1500 },
//!   "evidence": ["\"canary\":true"]
//! }
//! ```
//!
//! | Member | Meaning |
//! |---|---|
//! | `turns` | Each turn is `{ call: { tool, args } }` or `{ batch: <batch_run args> }`. `reset: true` starts a new context before the turn. `restart: true` also restarts the server. |
//! | `answer` | A [`Source`]: the turn, the pointer and the derive steps of the answer. |
//! | `provenance` | The source of each argument value (see [`crate::lint`]). |
//! | `budgets` | The calls, total characters and peak characters that the scenario can use. |
//! | `evidence` | Texts that the hint-follower robot must see (see [`crate::follower`]). |
//! | `pair` | Only in `eval/ab/`: the ID of the scenario that answers the same question with single calls. |
//!
//! A `{ "$turn": n, "ptr": "..", "steps"?: [..] }` object in the arguments copies a value
//! of an earlier response, the way an agent copies an ID.

use std::collections::BTreeMap;
use std::path::Path;

use ghidorah_json::Value;

use crate::derive::{self, Source};
use crate::error::{EvalError, parse_json, read_text};

/// The scenarios directory.
pub const DIR: &str = "eval/scenarios";

/// The directory of the batch forms of the A/B pairs (design Section 12.4).
pub const AB_DIR: &str = "eval/ab";

/// The largest number of turns of a scenario.
pub const MAX_TURNS: usize = 32;

/// One turn of a scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    /// `true` starts a new context before the call.
    pub reset: bool,
    /// `true` also restarts the server before the call.
    pub restart: bool,
    /// The tool name: the call tool, or `batch_run` for a batch turn.
    pub tool: String,
    /// The arguments, with `$turn` references.
    pub args: Value,
    /// `true` for a batch turn.
    pub batch: bool,
}

/// The budgets of a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Budgets {
    /// The largest number of calls.
    pub max_calls: u64,
    /// The largest sum of response characters.
    pub max_chars: u64,
    /// The largest response in characters.
    pub max_peak_chars: u64,
}

/// One scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    /// The ID: the file stem.
    pub id: String,
    /// The path of the file, relative to the workspace root.
    pub file: String,
    /// The ID of the frozen question.
    pub question: String,
    /// The turns.
    pub turns: Vec<Turn>,
    /// The source of the answer.
    pub answer: Source,
    /// The provenance entries by JSON pointer into the scenario file.
    pub provenance: BTreeMap<String, String>,
    /// The budgets.
    pub budgets: Budgets,
    /// The evidence texts of the hint-follower robot.
    pub evidence: Vec<String>,
    /// The single-call scenario of an A/B pair, for a file of `eval/ab/`.
    pub pair: Option<String>,
}

fn data(file: &str, message: &str) -> EvalError {
    EvalError::data(file, message)
}

fn turn(file: &str, v: &Value) -> Result<Turn, EvalError> {
    let flag = |key: &str| v.get(key).and_then(Value::as_bool).unwrap_or(false);
    let (tool, args, batch) = if let Some(call) = v.get("call") {
        let tool = call
            .get("tool")
            .and_then(Value::as_str)
            .ok_or_else(|| data(file, "a call turn has no `tool`"))?;
        let args = call.get("args").cloned().unwrap_or_else(crate::host::empty);
        (tool.to_owned(), args, false)
    } else if let Some(args) = v.get("batch") {
        ("batch_run".to_owned(), args.clone(), true)
    } else {
        return Err(data(file, "a turn has neither `call` nor `batch`"));
    };
    let restart = flag("restart");
    Ok(Turn {
        reset: flag("reset") || restart,
        restart,
        tool,
        args,
        batch,
    })
}

/// Parses the scenario file `file` with the text `text`.
///
/// # Errors
///
/// Returns an [`EvalError`] when the text is not valid JSON or a member is missing.
pub fn parse(file: &str, text: &str) -> Result<Scenario, EvalError> {
    let v = parse_json(file, text)?;
    let str_of = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| data(file, &format!("`{key}` is not a string")))
    };
    let turns_v = v
        .get("turns")
        .and_then(Value::as_array)
        .ok_or_else(|| data(file, "`turns` is not an array"))?;
    if turns_v.is_empty() || turns_v.len() > MAX_TURNS {
        return Err(data(file, "a scenario has 1 to 32 turns"));
    }
    let turns = turns_v
        .iter()
        .map(|t| turn(file, t))
        .collect::<Result<Vec<_>, _>>()?;
    let answer = v
        .get("answer")
        .ok_or_else(|| data(file, "`answer` is missing"))
        .and_then(|a| derive::parse_source(a).map_err(|m| data(file, &m)))?;
    let mut provenance = BTreeMap::new();
    if let Some(Value::Object(members)) = v.get("provenance") {
        for (ptr, kind) in members.iter() {
            let kind = kind
                .as_str()
                .ok_or_else(|| data(file, "a provenance entry is not a string"))?;
            provenance.insert(ptr.to_owned(), kind.to_owned());
        }
    }
    let budget = |key: &str| {
        v.pointer(&format!("/budgets/{key}"))
            .and_then(Value::as_u64)
            .ok_or_else(|| data(file, &format!("`budgets.{key}` is not an integer")))
    };
    let evidence = v
        .get("evidence")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    Ok(Scenario {
        id: str_of("id")?,
        file: file.to_owned(),
        question: str_of("question")?,
        turns,
        answer,
        provenance,
        budgets: Budgets {
            max_calls: budget("max_calls")?,
            max_chars: budget("max_chars")?,
            max_peak_chars: budget("max_peak_chars")?,
        },
        evidence,
        pair: v.get("pair").and_then(Value::as_str).map(str::to_owned),
    })
}

/// Reads every `*.json` file of the directory `dir` in name order.
///
/// # Errors
///
/// Returns an [`EvalError`] when the directory or a file does not read, or a file is not a
/// scenario. A file whose `id` is not its stem is bad data.
pub fn read_dir(root: &Path, dir: &str) -> Result<Vec<Scenario>, EvalError> {
    let entries =
        std::fs::read_dir(root.join(dir)).map_err(|e| EvalError::io(&root.join(dir), &e))?;
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        })
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let file = format!("{dir}/{name}");
        let scenario = parse(&file, &read_text(root, &file)?)?;
        if Some(scenario.id.as_str()) != name.strip_suffix(".json") {
            return Err(data(&file, "the `id` is not the file stem"));
        }
        out.push(scenario);
    }
    Ok(out)
}
