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

use std::collections::BTreeSet;
use std::path::Path;

use crate::json::{self, Value};
use crate::verify::tree::{hex, sha256};
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

fn read_text(root: &Path, rel: &str) -> Result<String, Error> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| Error::io(rel, e))
}

fn question(line: &str) -> Result<Question, String> {
    let v = json::parse(line).map_err(|e| e.to_string())?;
    let text = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("`{key}` is not a string"))
    };
    let answer = v.get("answer").ok_or("no `answer`")?;
    let answer_text = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("`answer.{key}` is not a string"))
    };
    let binaries = v
        .get("binaries")
        .and_then(Value::as_array)
        .ok_or("`binaries` is not an array")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    Ok(Question {
        id: text("id")?,
        category: text("category")?,
        fixture: text("fixture")?,
        text: text("question")?,
        check: answer_text("check")?,
        value: answer.get("value").cloned().ok_or("no `answer.value`")?,
        truth_ptr: answer_text("truth_ptr")?,
        binaries,
    })
}

/// Reads the questions of the workspace.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file does not read, or [`Error::Data`] for a bad line.
pub fn read_questions(root: &Path) -> Result<Vec<Question>, Error> {
    let body = read_text(root, QUESTIONS_PATH)?;
    body.lines()
        .enumerate()
        .map(|(i, line)| {
            question(line).map_err(|m| Error::data(QUESTIONS_PATH, format!("line {}: {m}", i + 1)))
        })
        .collect()
}

/// Tells if `text` matches a glob with `*` (any run) and `?` (one character).
///
/// The match runs in linear time with one backtrack point.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(c) if *c == '?' || Some(c) == t.get(ti) => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p.get(pi..)
        .is_some_and(|rest| rest.iter().all(|c| *c == '*'))
}

/// Checks each frozen answer against its truth file.
///
/// # Errors
///
/// Returns an error when the questions or a truth file do not read or parse.
pub fn check_answers(root: &Path) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    for (i, q) in read_questions(root)?.iter().enumerate() {
        let line = i + 1;
        let bad = |detail: String| {
            Finding::new(
                "AC-195",
                QUESTIONS_PATH,
                line,
                format!("{}: {detail}", q.id),
            )
        };
        if !CHECKS.contains(&q.check.as_str()) {
            found.push(bad(format!("unknown check `{}`", q.check)));
            continue;
        }
        let truth = super::truth::read(root, &q.fixture)?;
        let Some(want) = truth.pointer(&q.truth_ptr) else {
            found.push(bad(format!("`{}` is not in the truth file", q.truth_ptr)));
            continue;
        };
        let ok = if q.check == "glob" {
            matches!((q.value.as_str(), want.as_str()), (Some(p), Some(t)) if glob_match(p, t))
        } else {
            *want == q.value
        };
        if !ok {
            found.push(bad(format!(
                "the answer differs from the truth value {want}"
            )));
        }
        for bin in &q.binaries {
            if !root.join(bin).is_file() {
                found.push(bad(format!("binary `{bin}` does not exist")));
            }
        }
    }
    Ok(found)
}

fn intent_ids(
    root: &Path,
    rel: &str,
    found: &mut Vec<Finding>,
    ids: &mut BTreeSet<String>,
) -> Result<(), Error> {
    for (i, line) in read_text(root, rel)?.lines().enumerate() {
        let bad = |d: &str| Finding::new("AC-198b", rel, i + 1, d);
        let Ok(v) = json::parse(line) else {
            found.push(bad("the line is not JSON"));
            continue;
        };
        let id = v.get("id").and_then(Value::as_str).unwrap_or("");
        if !ids.insert(id.to_owned()) {
            found.push(bad("the intent ID is not unique"));
        }
        if v.get("intent")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            found.push(bad("the intent has no text"));
        }
        let expect = v.get("expect").and_then(Value::as_array).unwrap_or(&[]);
        if expect.is_empty()
            || !expect
                .iter()
                .all(|t| t.as_str().is_some_and(|t| TOOLS.contains(&t)))
        {
            found.push(bad("`expect` must list known tools"));
        }
    }
    Ok(())
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
    let mut found = Vec::new();
    let thresholds = json::parse(&read_text(root, THRESHOLDS_PATH)?)
        .map_err(|e| Error::data(THRESHOLDS_PATH, e.to_string()))?;
    let locks = [
        ("questions_sha256", QUESTIONS_PATH, "AC-195"),
        ("intents_sha256", INTENTS_HELDOUT_PATH, "AC-198b"),
    ];
    for (key, rel, ac) in locks {
        let bytes = std::fs::read(root.join(rel)).map_err(|e| Error::io(rel, e))?;
        if thresholds.get(key).and_then(Value::as_str) != Some(hex(&sha256(&bytes)).as_str()) {
            found.push(Finding::new(
                ac,
                THRESHOLDS_PATH,
                0,
                format!("`{key}` differs from the SHA-256 of {rel}"),
            ));
        }
    }
    for (metric, floor) in FLOORS {
        let value = thresholds.pointer(&format!("/metrics/{metric}/floor"));
        if value != Some(&Value::Number((*floor).to_owned())) {
            found.push(Finding::new(
                "AC-198a",
                THRESHOLDS_PATH,
                0,
                format!("`{metric}` needs floor {floor}"),
            ));
        }
    }
    let questions = read_questions(root)?;
    let mut ids = BTreeSet::new();
    for q in &questions {
        if !ids.insert(q.id.clone()) {
            found.push(Finding::new(
                "AC-195",
                QUESTIONS_PATH,
                0,
                format!("ID `{}` is not unique", q.id),
            ));
        }
        let lower = q.text.to_lowercase();
        let words: BTreeSet<&str> = lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .collect();
        if let Some(tool) = TOOLS.iter().find(|t| words.contains(*t)) {
            found.push(Finding::new(
                "AC-195",
                QUESTIONS_PATH,
                0,
                format!("{} names the tool `{tool}`", q.id),
            ));
        }
    }
    for (category, min) in CATEGORY_MINIMUMS {
        let count = questions.iter().filter(|q| q.category == *category).count();
        if count < *min {
            found.push(Finding::new(
                "AC-195",
                QUESTIONS_PATH,
                0,
                format!("`{category}` has {count} questions, not {min}"),
            ));
        }
    }
    let mut intents = BTreeSet::new();
    intent_ids(root, INTENTS_DEV_PATH, &mut found, &mut intents)?;
    intent_ids(root, INTENTS_HELDOUT_PATH, &mut found, &mut intents)?;
    Ok(found)
}
