//! The frozen inputs of the harness: questions, intents and thresholds (design Section 12.2).
//!
//! WP-06 wrote these files before any tool description existed. WP-30 appended the `pe`
//! group. The harness reads them and never writes them, except the baselines of
//! `eval/thresholds.json` (Section 12.6).

use std::collections::BTreeMap;
use std::path::Path;

use ghidorah_json::Value;

use crate::error::{EvalError, read_json, read_jsonl};
use crate::milli::Milli;

/// The questions path, relative to the workspace root.
pub const QUESTIONS: &str = "eval/questions.jsonl";

/// The held-out intents path.
pub const INTENTS_HELDOUT: &str = "eval/intents/heldout.jsonl";

/// The dev intents path.
pub const INTENTS_DEV: &str = "eval/intents/dev.jsonl";

/// The thresholds path.
pub const THRESHOLDS: &str = "eval/thresholds.json";

/// The minimum scenario count of each category (design Section 12.2).
pub const CATEGORY_MINIMUMS: &[(&str, usize)] = &[
    ("triage", 5),
    ("locate", 5),
    ("understand", 5),
    ("annotate", 5),
    ("verify", 5),
    ("recover", 3),
    ("resume", 2),
    ("abstain", 4),
    ("decompile", 3),
    ("similar", 2),
    ("pe", 5),
];

/// The smallest total scenario count.
pub const MIN_SCENARIOS: usize = 44;

/// The floors that only an ADR amendment lowers (design Section 12.6).
pub const FROZEN_FLOORS: &[(&str, Milli)] = &[
    ("abstain_correctness", Milli(1000)),
    ("answer_correctness", Milli(1000)),
    ("argument_provenance", Milli(1000)),
    ("budget_adherence", Milli(1000)),
    ("context_reset_recall", Milli(600)),
    ("determinism", Milli(1000)),
    ("discoverability", Milli(700)),
    ("hint_follower_reach", Milli(600)),
    ("metamorphic", Milli(1000)),
    ("recall_after_edits", Milli(600)),
    ("repair_rate_r", Milli(1000)),
    ("survey_fact_recall", Milli(600)),
];

/// One frozen question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The ID, for example `q-triage-01`.
    pub id: String,
    /// The category, for example `triage`.
    pub category: String,
    /// The truth file name, for example `crackme.gcc-O2`.
    pub fixture: String,
    /// The fixture binaries that the scenario opens, in order.
    pub binaries: Vec<String>,
    /// The question text.
    pub text: String,
    /// The answer check: `equals`, `glob`, `contains`, `claim` or `abstain`.
    pub check: String,
    /// The frozen answer value.
    pub value: Value,
}

fn text_of(v: &Value, key: &str, path: &str) -> Result<String, EvalError> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| EvalError::data(path, &format!("`{key}` is not a string")))
}

impl Question {
    /// Reads a question from its JSON line.
    ///
    /// # Errors
    ///
    /// Returns [`EvalError::Data`] when a member is missing or has the wrong type.
    pub fn from_json(v: &Value, path: &str) -> Result<Self, EvalError> {
        let answer = v
            .get("answer")
            .ok_or_else(|| EvalError::data(path, "`answer` is missing"))?;
        let binaries = v
            .get("binaries")
            .and_then(Value::as_array)
            .ok_or_else(|| EvalError::data(path, "`binaries` is not an array"))?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        Ok(Self {
            id: text_of(v, "id", path)?,
            category: text_of(v, "category", path)?,
            fixture: text_of(v, "fixture", path)?,
            binaries,
            text: text_of(v, "question", path)?,
            check: text_of(answer, "check", path)?,
            value: answer.get("value").cloned().unwrap_or(Value::Null),
        })
    }
}

/// Reads the frozen questions.
///
/// # Errors
///
/// Returns an [`EvalError`] when the file does not read or a line is not a question.
pub fn read_questions(root: &Path) -> Result<Vec<Question>, EvalError> {
    read_jsonl(root, QUESTIONS)?
        .iter()
        .map(|v| Question::from_json(v, QUESTIONS))
        .collect()
}

/// One discoverability intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// The ID, for example `held-01`.
    pub id: String,
    /// The intent text.
    pub text: String,
    /// The tools that serve the intent.
    pub expect: Vec<String>,
}

/// Reads the intents of `rel`.
///
/// # Errors
///
/// Returns an [`EvalError`] when the file does not read or a line is not an intent.
pub fn read_intents(root: &Path, rel: &str) -> Result<Vec<Intent>, EvalError> {
    read_jsonl(root, rel)?
        .iter()
        .map(|v| {
            Ok(Intent {
                id: text_of(v, "id", rel)?,
                text: text_of(v, "intent", rel)?,
                expect: v
                    .get("expect")
                    .and_then(Value::as_array)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            })
        })
        .collect()
}

/// The gate values of one metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Metric {
    /// The floor, or `None` for a metric with no floor.
    pub floor: Option<Milli>,
    /// The baseline, or `None` before the first bless.
    pub baseline: Option<Milli>,
    /// The tolerance.
    pub tolerance: Milli,
}

/// The thresholds file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thresholds {
    /// The SHA-256 of the questions file.
    pub questions_sha256: String,
    /// The SHA-256 of the held-out intents file.
    pub intents_sha256: String,
    /// The characters per token of `est_tokens`. The default is 3.
    pub chars_per_token: u64,
    /// The metrics by name.
    pub metrics: BTreeMap<String, Metric>,
    /// The file as read, so that a bless keeps the other members.
    pub raw: Value,
}

/// Reads the thresholds.
///
/// # Errors
///
/// Returns an [`EvalError`] when the file does not read or has bad data.
pub fn read_thresholds(root: &Path) -> Result<Thresholds, EvalError> {
    let raw = read_json(root, THRESHOLDS)?;
    let mut metrics = BTreeMap::new();
    if let Some(Value::Object(members)) = raw.get("metrics") {
        for (name, m) in members.iter() {
            metrics.insert(
                name.to_owned(),
                Metric {
                    floor: m.get("floor").and_then(Milli::of_json),
                    baseline: m.get("baseline").and_then(Milli::of_json),
                    tolerance: m
                        .get("tolerance")
                        .and_then(Milli::of_json)
                        .unwrap_or_default(),
                },
            );
        }
    }
    Ok(Thresholds {
        questions_sha256: text_of(&raw, "questions_sha256", THRESHOLDS)?,
        intents_sha256: text_of(&raw, "intents_sha256", THRESHOLDS)?,
        chars_per_token: raw
            .get("chars_per_token")
            .and_then(Value::as_u64)
            .filter(|k| *k > 0)
            .unwrap_or(3),
        metrics,
        raw,
    })
}
