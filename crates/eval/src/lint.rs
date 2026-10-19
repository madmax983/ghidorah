//! The argument-provenance lint (design Section 12.2, AC-226).
//!
//! Every argument value of every scripted call needs a provenance entry. The entry key is the
//! JSON pointer of the value in the scenario file. The entry names one source:
//!
//! | Kind | The lint accepts the value when |
//! |---|---|
//! | `question` | its text is in the question text, in any letter case |
//! | `question:binaries/<n>` | it is the path of binary `n` of the frozen question |
//! | `schema:<tool>.<arg>` | it is an enum value, the default, a bool, or a value of a tool example. An address or an ID never comes from an example. |
//! | `instructions` | its text is in the server instructions |
//! | `response:<turn>[<ptr>]` | it is in the response of that earlier turn, at the pointer if the entry has one |
//! | `new_name` | it is a new identifier for a `name` argument: not a default name, no address |
//! | `new_text` | it is free text, and each `0x` number in it is in an earlier response |
//!
//! A `$turn` reference is its own source: it must point at an earlier turn of the same
//! context. A batch `$ref` is a source that `batch_run` checks. After a turn with `reset`, no
//! source can point before that turn, and the reset turn calls `session_brief`.
//! The answer source follows the same context rule. A derive operand must not hold the frozen
//! answer, unless the question text holds it.

use std::collections::BTreeSet;

use ghidorah_json::Value;
use ghidorah_tools::registry::shipped;
use ghidorah_tools::{ArgKind, ArgSpec, Session, ToolSpec};

use crate::derive::{self, text_of};
use crate::inputs::Question;
use crate::runner::Outcome;
use crate::scenario::Scenario;

/// One lint finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The scenario ID.
    pub scenario: String,
    /// The JSON pointer into the scenario file.
    pub path: String,
    /// Why the value fails.
    pub reason: String,
}

/// The lint result of one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// The number of argument values that the lint checks.
    pub values: u64,
    /// The values that fail.
    pub findings: Vec<Finding>,
}

/// The global arguments that a scenario can send, with their allowed values.
const GLOBAL_ENUMS: &[(&str, &[&str])] = &[
    ("format", &["concise", "detailed"]),
    ("shape", &["objects", "table"]),
];

/// The global bool arguments.
const GLOBAL_BOOLS: &[&str] = &["count_only", "dry_run", "force"];

struct Leaf {
    path: String,
    value: Value,
    turn: usize,
}

fn leaves(value: &Value, path: &str, turn: usize, out: &mut Vec<Leaf>) {
    match value {
        Value::Object(m) if m.contains_key("$turn") || m.contains_key("$ref") => out.push(Leaf {
            path: path.to_owned(),
            value: value.clone(),
            turn,
        }),
        Value::Object(m) => {
            for (k, v) in m.iter() {
                leaves(v, &format!("{path}/{}", escape(k)), turn, out);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                leaves(v, &format!("{path}/{i}"), turn, out);
            }
        }
        _ => out.push(Leaf {
            path: path.to_owned(),
            value: value.clone(),
            turn,
        }),
    }
}

fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Gives the argument leaves of every turn with their scenario pointers.
fn arg_leaves(scenario: &Scenario) -> Vec<Leaf> {
    let mut out = Vec::new();
    for (i, turn) in scenario.turns.iter().enumerate() {
        if !turn.batch {
            leaves(&turn.args, &format!("/turns/{i}/call/args"), i, &mut out);
            continue;
        }
        let Value::Object(members) = &turn.args else {
            continue;
        };
        for (k, v) in members.iter() {
            match k {
                "return" => {}
                "steps" => {
                    for (s, step) in v.as_array().unwrap_or_default().iter().enumerate() {
                        if let Some(args) = step.get("args") {
                            leaves(
                                args,
                                &format!("/turns/{i}/batch/steps/{s}/args"),
                                i,
                                &mut out,
                            );
                        }
                    }
                }
                _ => leaves(v, &format!("/turns/{i}/batch/{}", escape(k)), i, &mut out),
            }
        }
    }
    out
}

/// Tells if a text looks like an address or an ID.
fn looks_like_address(text: &str) -> bool {
    text.contains("0x")
        || text
            .split_once(':')
            .is_some_and(|(p, _)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase()))
}

/// Gives the forms of a value that a source text can hold.
fn forms(value: &Value) -> Vec<String> {
    match value {
        Value::Number(n) => {
            let mut out = vec![n.as_str().to_owned()];
            if let Some(u) = n.as_u64() {
                out.push(format!("0x{u:x}"));
            }
            out
        }
        other => vec![text_of(other)],
    }
}

fn in_text(value: &Value, text: &str, icase: bool) -> bool {
    let hay = if icase {
        text.to_lowercase()
    } else {
        text.to_owned()
    };
    forms(value).iter().any(|f| {
        let needle = if icase { f.to_lowercase() } else { f.clone() };
        !needle.is_empty() && hay.contains(&needle)
    })
}

fn arg<'a>(args: &'a [ArgSpec], name: &str) -> Option<&'a ArgSpec> {
    args.iter().find(|a| a.name == name)
}

/// Tells if `value` is an enum value, a bool or the default of the argument at `path`.
fn spec_accepts(spec: &ArgSpec, rest: &[&str], value: &Value) -> bool {
    let default_ok = spec.default.is_some_and(|d| {
        ghidorah_json::parse(d, &ghidorah_json::Limits::DEFAULT).is_ok_and(|dv| {
            derive::json_eq(&dv, value)
                || dv
                    .as_array()
                    .is_some_and(|a| a.iter().any(|x| derive::json_eq(x, value)))
        })
    });
    if default_ok && !looks_like_address(&text_of(value)) {
        return true;
    }
    match (spec.kind, rest) {
        (ArgKind::Bool, []) => matches!(value, Value::Bool(_)),
        (ArgKind::Enum(values), []) => value.as_str().is_some_and(|v| values.contains(&v)),
        (ArgKind::List(inner, _), _) => spec_accepts(inner, rest, value),
        (ArgKind::Obj(members), [next, tail @ ..]) => {
            arg(members, next).is_some_and(|m| spec_accepts(m, tail, value))
        }
        _ => false,
    }
}

/// Tells if a tool example holds `value` at the argument path `parts`.
fn example_accepts(tool: &ToolSpec<Session>, parts: &[&str], value: &Value) -> bool {
    if looks_like_address(&text_of(value)) {
        return false;
    }
    let ptr: String = parts.iter().fold(String::new(), |mut acc, p| {
        acc.push('/');
        acc.push_str(p);
        acc
    });
    let texts = tool
        .examples
        .iter()
        .map(|e| e.args)
        .chain(tool.actions.iter().map(|a| a.example));
    texts
        .filter_map(|t| ghidorah_json::parse(t, &ghidorah_json::Limits::DEFAULT).ok())
        .filter_map(|v| v.pointer(&ptr).cloned())
        .any(|v| {
            derive::json_eq(&v, value)
                || v.as_array()
                    .is_some_and(|a| a.iter().any(|x| derive::json_eq(x, value)))
        })
}

fn schema_ok(spec: &str, value: &Value) -> bool {
    let Some((tool_name, path)) = spec.split_once('.') else {
        return false;
    };
    let parts: Vec<&str> = path.split('.').collect();
    if let [one] = parts.as_slice() {
        if let Some((_, values)) = GLOBAL_ENUMS.iter().find(|(n, _)| n == one) {
            return value.as_str().is_some_and(|v| values.contains(&v));
        }
        if GLOBAL_BOOLS.contains(one) {
            return matches!(value, Value::Bool(_));
        }
    }
    let registry = shipped();
    let Some((_, tool)) = registry.get(tool_name) else {
        return false;
    };
    let (Some(first), rest) = (parts.first(), parts.get(1..).unwrap_or_default()) else {
        return false;
    };
    arg(tool.args, first).is_some_and(|a| spec_accepts(a, rest, value))
        || example_accepts(tool, &parts, value)
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Gives the hex numbers `0x..` of a text.
fn hex_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("0x") {
        let tail = &rest[at..];
        let end = tail[2..]
            .find(|c: char| !c.is_ascii_hexdigit())
            .map_or(tail.len(), |e| e + 2);
        out.push(tail[..end].to_owned());
        rest = &tail[end.max(2)..];
    }
    out
}

/// The context of one lint check: the scenario, its question and its run.
struct Check<'a> {
    question: &'a Question,
    outcome: &'a Outcome,
    instructions: &'a str,
    floors: Vec<usize>,
}

impl Check<'_> {
    /// Checks a `response:<turn>[<ptr>]` source.
    fn response(&self, rest: &str, leaf: &Leaf) -> Result<(), String> {
        let (t, ptr) = rest.split_once('/').map_or((rest, ""), |(t, p)| (t, p));
        let t: usize = t
            .parse()
            .map_err(|_| format!("the turn {t} is not a number"))?;
        self.reach(t, leaf.turn)?;
        let response = self
            .outcome
            .responses
            .get(t)
            .ok_or("the turn has no response")?;
        let at = if ptr.is_empty() {
            response.clone()
        } else {
            derive::select(response, &format!("/{ptr}"))?
        };
        if in_text(&leaf.value, &ghidorah_json::write(&at), false)
            || in_text(&leaf.value, &text_of(&at), false)
        {
            Ok(())
        } else {
            Err(format!("the value is not in the response of turn {t}"))
        }
    }

    /// Checks that turn `t` is earlier than `turn` and in the same context.
    fn reach(&self, t: usize, turn: usize) -> Result<(), String> {
        let floor = self.floors.get(turn).copied().unwrap_or(0);
        if t >= turn {
            return Err(format!("turn {t} is not earlier than turn {turn}"));
        }
        if t < floor {
            return Err(format!(
                "turn {t} is before the context reset at turn {floor}"
            ));
        }
        Ok(())
    }

    fn kind(&self, kind: &str, leaf: &Leaf) -> Result<(), String> {
        let v = &leaf.value;
        if kind == "question" {
            return if in_text(v, &self.question.text, true) {
                Ok(())
            } else {
                Err("the value is not in the question text".to_owned())
            };
        }
        if let Some(n) = kind.strip_prefix("question:binaries/") {
            let ok = n
                .parse::<usize>()
                .ok()
                .and_then(|n| self.question.binaries.get(n))
                .is_some_and(|b| v.as_str() == Some(b.as_str()));
            return if ok {
                Ok(())
            } else {
                Err("the value is not that binary of the question".to_owned())
            };
        }
        if let Some(spec) = kind.strip_prefix("schema:") {
            return if schema_ok(spec, v) {
                Ok(())
            } else {
                Err(format!(
                    "the value is not an enum value, default or example of {spec}"
                ))
            };
        }
        if kind == "instructions" {
            return if in_text(v, self.instructions, false) {
                Ok(())
            } else {
                Err("the value is not in the server instructions".to_owned())
            };
        }
        if let Some(rest) = kind.strip_prefix("response:") {
            return self.response(rest, leaf);
        }
        if kind == "new_name" {
            let text = text_of(v);
            let default_name = ["FUN_", "LAB_", "DAT_", "EXT_"]
                .iter()
                .any(|p| text.starts_with(p));
            return if leaf.path.ends_with("/name") && is_identifier(&text) && !default_name {
                Ok(())
            } else {
                Err("a new name is an identifier for a name argument".to_owned())
            };
        }
        if kind == "new_text" {
            let text = v.as_str().ok_or("new text is a string")?;
            let floor = self.floors.get(leaf.turn).copied().unwrap_or(0);
            let seen: Vec<String> = self
                .outcome
                .responses
                .iter()
                .enumerate()
                .filter(|(t, _)| *t >= floor && *t < leaf.turn)
                .map(|(_, r)| ghidorah_json::write(r))
                .collect();
            return match hex_tokens(text)
                .into_iter()
                .find(|h| !seen.iter().any(|s| s.contains(h.as_str())))
            {
                Some(h) => Err(format!(
                    "the number {h} of the text is in no earlier response"
                )),
                None => Ok(()),
            };
        }
        Err(format!("the provenance kind {kind} is not known"))
    }

    fn reference(&self, leaf: &Leaf) -> Result<(), String> {
        if leaf.value.get("$ref").is_some() {
            return Ok(());
        }
        let src = derive::parse_source(&leaf.value)?;
        self.reach(src.turn, leaf.turn)
    }
}

/// Gives the context floor of each turn: the index of the last reset at or before it.
fn floors(scenario: &Scenario) -> Vec<usize> {
    let mut floor = 0;
    scenario
        .turns
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if t.reset {
                floor = i;
            }
            floor
        })
        .collect()
}

/// Lints one scenario with the responses of its run and the server instructions.
#[must_use]
pub fn lint(
    scenario: &Scenario,
    question: &Question,
    outcome: &Outcome,
    instructions: &str,
) -> Report {
    let check = Check {
        question,
        outcome,
        instructions,
        floors: floors(scenario),
    };
    let mut report = Report::default();
    let mut used = BTreeSet::new();
    let fail = |path: &str, reason: String| Finding {
        scenario: scenario.id.clone(),
        path: path.to_owned(),
        reason,
    };
    for (i, turn) in scenario.turns.iter().enumerate() {
        if turn.reset && i > 0 && turn.tool != "session_brief" {
            report.findings.push(fail(
                &format!("/turns/{i}"),
                "a reset turn calls session_brief".to_owned(),
            ));
        }
    }
    for leaf in arg_leaves(scenario) {
        report.values = report.values.saturating_add(1);
        let entry = scenario.provenance.get(&leaf.path);
        if entry.is_some() {
            used.insert(leaf.path.clone());
        }
        let result = match (
            leaf.value.get("$turn").or_else(|| leaf.value.get("$ref")),
            entry,
        ) {
            (Some(_), _) => check.reference(&leaf),
            (None, Some(kind)) => check.kind(kind, &leaf),
            (None, None) => Err("the value has no provenance entry".to_owned()),
        };
        if let Err(reason) = result {
            report.findings.push(fail(&leaf.path, reason));
        }
    }
    for path in scenario.provenance.keys().filter(|p| !used.contains(*p)) {
        report
            .findings
            .push(fail(path, "the entry names no argument value".to_owned()));
    }
    let floor = check.floors.last().copied().unwrap_or(0);
    if scenario.answer.turn < floor || scenario.answer.turn >= scenario.turns.len() {
        report.findings.push(fail(
            "/answer",
            format!("the answer turn is not a turn of the last context, from turn {floor}"),
        ));
    }
    report.findings.extend(
        smuggled(scenario, question)
            .into_iter()
            .map(|r| fail("/answer", r)),
    );
    report
}

/// Gives a reason for each derive operand that holds the frozen answer.
fn smuggled(scenario: &Scenario, question: &Question) -> Vec<String> {
    let mut answers = Vec::new();
    match &question.value {
        Value::Array(items) => answers.extend(items.iter().flat_map(forms)),
        Value::String(_) | Value::Number(_) => answers.extend(forms(&question.value)),
        _ => {}
    }
    let q = question.text.to_lowercase();
    let mut steps = scenario.answer.steps.clone();
    for turn in &scenario.turns {
        collect_steps(&turn.args, &mut steps);
    }
    derive::operands(&steps)
        .into_iter()
        .filter_map(|op| {
            answers
                .iter()
                .find(|a| a.len() > 1 && op.contains(a.as_str()) && !q.contains(&a.to_lowercase()))
                .map(|a| format!("the derive operand {op:?} holds the answer {a:?}"))
        })
        .collect()
}

fn collect_steps(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Object(m) => {
            if m.contains_key("$turn") {
                out.extend(
                    m.get("steps")
                        .and_then(Value::as_array)
                        .unwrap_or_default()
                        .iter()
                        .cloned(),
                );
            }
            for (_, x) in m.iter() {
                collect_steps(x, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|x| collect_steps(x, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
