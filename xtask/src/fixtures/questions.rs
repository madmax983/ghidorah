//! The frozen eval inputs: questions, intents and the first thresholds (design Section 12.2).
//!
//! - `eval/questions.jsonl`: one question per line, `{ id, category, fixture, binaries,
//!   question, answer: { check, value, truth_ptr } }`. `fixture` names a truth file.
//!   `binaries` lists the fixture binaries that the scenario opens, in order. `truth_ptr` is an
//!   RFC 6901 pointer into `fixtures/truth/<fixture>.json`.
//! - `eval/intents/{dev,heldout}.jsonl`: one intent per line, `{ id, intent, expect: [tool] }`.
//! - `eval/thresholds.json`: `{ questions_sha256, intents_sha256, metrics }`.
//!
//! Answer rule: the value at `truth_ptr` equals `value`. For `check: glob`, the truth text
//! matches the glob `value` instead.

use std::path::Path;

use crate::json::Value;
use crate::{Error, Finding};

/// The questions path, relative to the workspace root.
pub const QUESTIONS_PATH: &str = "eval/questions.jsonl";

/// The dev intents path, relative to the workspace root.
pub const INTENTS_DEV_PATH: &str = "eval/intents/dev.jsonl";

/// The held-out intents path, relative to the workspace root.
pub const INTENTS_HELDOUT_PATH: &str = "eval/intents/heldout.jsonl";

/// The thresholds path, relative to the workspace root.
pub const THRESHOLDS_PATH: &str = "eval/thresholds.json";

/// The minimum question count of each category. WP-30 appends the `pe` group (5).
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
];

/// The answer checks.
pub const CHECKS: &[&str] = &["equals", "glob", "contains", "claim", "abstain"];

/// The 23 tools of design Section 10.3. A question does not name any of these tools.
pub const TOOLS: &[&str] = &[
    "binary_load",
    "binary_survey",
    "analysis_run",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "mem_read",
    "addr_info",
    "calc",
    "fact_check",
    "type_get",
    "history_list",
    "session_brief",
    "tool_search",
    "symbol_rename",
    "comment_set",
    "note_write",
    "func_edit",
    "type_edit",
    "history_undo",
    "batch_run",
    "func_similar",
];

/// The metrics with a floor (design Section 12.6).
pub const FLOORS: &[(&str, &str)] = &[
    ("discoverability", "0.70"),
    ("context_reset_recall", "0.60"),
    ("survey_fact_recall", "0.60"),
];

/// One frozen question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The question ID, for example `q-triage-01`.
    pub id: String,
    /// The category.
    pub category: String,
    /// The truth file name.
    pub fixture: String,
    /// The question text.
    pub text: String,
    /// The answer check.
    pub check: String,
    /// The frozen answer value.
    pub value: Value,
    /// The pointer into the truth file.
    pub truth_ptr: String,
    /// The fixture binaries that the scenario opens.
    pub binaries: Vec<String>,
}

/// Reads the questions of the workspace.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file does not read, or [`Error::Data`] for a bad line.
pub fn read_questions(root: &Path) -> Result<Vec<Question>, Error> {
    Err(Error::data(
        root.join(QUESTIONS_PATH).display().to_string(),
        "no questions yet",
    ))
}

/// Tells if `text` matches a glob with `*` (any run) and `?` (one character).
///
/// The match runs in linear time with one backtrack point.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    pattern.is_empty() && text.is_empty() && false
}

/// Checks each frozen answer against its truth file.
///
/// # Errors
///
/// Returns an error when the questions or a truth file do not read or parse.
pub fn check_answers(root: &Path) -> Result<Vec<Finding>, Error> {
    Err(Error::data(
        root.join(QUESTIONS_PATH).display().to_string(),
        "no answer check yet",
    ))
}

/// Checks the locks and the shape rules of the frozen inputs.
///
/// - `questions_sha256` and `intents_sha256` of the thresholds equal the file hashes.
/// - The category minimums hold, the IDs are unique and no question text names a tool.
/// - Each intent names known tools. The thresholds give each floor.
///
/// # Errors
///
/// Returns an error when an input file does not read or parse.
pub fn check_locks(root: &Path) -> Result<Vec<Finding>, Error> {
    Err(Error::data(
        root.join(THRESHOLDS_PATH).display().to_string(),
        "no lock check yet",
    ))
}
