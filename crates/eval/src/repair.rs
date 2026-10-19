//! The repair robot and the mistake corpus (design Section 12.4, AC-197).
//!
//! Each line of `eval/mistakes.jsonl` is one scripted mistake:
//!
//! ```json
//! {"id":"m01","session":"demo","class":"R","code":"UNKNOWN_ARGUMENT",
//!  "call":{"tool":"func_list","args":{"sortt":"addr"}}}
//! ```
//!
//! | Member | Meaning |
//! |---|---|
//! | `session` | The setup: `none`, `demo`, `stripped`, `two`, `helpers`, `reopen` or `mini` (see [`open`]). |
//! | `setup` | Calls before the mistake. A `$turn` reference in the call points at their responses. |
//! | `class` | The repair class of the code: `R`, `C` or `H` (design Section 10.8). |
//! | `code` | The error code that the call must give. |
//! | `target` | `C` only: the value that the candidates must hold. |
//! | `intended` | `H` only: the tool that the helper call must rank. |
//!
//! The robot sends `next[0]` once for an `R` code, and the call must succeed. For a `C` code it
//! never picks: the candidates must hold the true target. For an `H` code it sends the helper
//! call and reports the rank of the intended tool.

use std::collections::BTreeMap;
use std::path::Path;

use ghidorah_json::Value;
use ghidorah_tools::{Profile, Session};

use crate::derive::text_of;
use crate::error::{EvalError, read_jsonl};
use crate::host::{self, Scratch};
use crate::milli::Milli;
use crate::runner;

/// The corpus path.
pub const CORPUS: &str = "eval/mistakes.jsonl";

/// The smallest corpus size (design Section 12.4).
pub const MIN_MISTAKES: usize = 40;

/// One scripted mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mistake {
    /// The ID.
    pub id: String,
    /// The setup name.
    pub session: String,
    /// The calls before the mistake: `(tool, args)`.
    pub setup: Vec<(String, Value)>,
    /// The repair class: `R`, `C` or `H`.
    pub class: String,
    /// The error code that the call must give.
    pub code: String,
    /// The mistaken call.
    pub tool: String,
    /// Its arguments, with `$turn` references to the setup responses.
    pub args: Value,
    /// The true target of a `C` mistake.
    pub target: Option<String>,
    /// The intended tool of an `H` mistake.
    pub intended: Option<String>,
}

fn call_of(v: &Value) -> Option<(String, Value)> {
    Some((
        v.get("tool")?.as_str()?.to_owned(),
        v.get("args").cloned().unwrap_or_else(host::empty),
    ))
}

/// Reads the mistake corpus.
///
/// # Errors
///
/// Returns an [`EvalError`] when the file does not read or a line has bad data.
pub fn read(root: &Path) -> Result<Vec<Mistake>, EvalError> {
    let mut out = Vec::new();
    for v in read_jsonl(root, CORPUS)? {
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let bad = |k: &str| EvalError::data(CORPUS, &format!("a mistake has no `{k}`"));
        let (tool, args) = v.get("call").and_then(call_of).ok_or_else(|| bad("call"))?;
        out.push(Mistake {
            id: text("id").ok_or_else(|| bad("id"))?,
            session: text("session").ok_or_else(|| bad("session"))?,
            setup: v
                .get("setup")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(call_of)
                .collect(),
            class: text("class").ok_or_else(|| bad("class"))?,
            code: text("code").ok_or_else(|| bad("code"))?,
            tool,
            args,
            target: text("target"),
            intended: text("intended"),
        });
    }
    Ok(out)
}

/// The fixture of the `two` and `helpers` setups.
const SECOND: &str = "fixtures/bin/hello.gcc-O2";

/// The fixture of the `stripped` setup: no symbol, so every name is a default name.
const STRIPPED: &str = "fixtures/bin/crackme.gcc-O2.stripped";

/// The fixture of the `helpers` setup.
const HELPERS: &str = "fixtures/bin/two_helpers.gcc-O2";

fn load(session: &mut Session, args: Value) {
    host::call(session, "binary_load", args);
}

fn demo() -> Value {
    Value::object([("builtin", Value::from("demo"))])
}

fn path(p: &str) -> Value {
    Value::object([("path", Value::from(p))])
}

/// Opens the session of a setup name. `scratch` holds the projects of `reopen`.
///
/// | Name | Session |
/// |---|---|
/// | `none` | no open binary |
/// | `demo` | the demo binary |
/// | `stripped` | the stripped build of the demo program, with default names only |
/// | `two` | the demo binary and `hello.gcc-O2`, so a call must name a binary |
/// | `helpers` | `two_helpers.gcc-O2`, with two functions named `helper` |
/// | `reopen` | a new session over a projects root that holds the demo project |
/// | `mini` | the demo binary in the `mini` profile |
///
/// # Errors
///
/// Returns an [`EvalError`] for an unknown name or a session that does not open.
pub fn open(root: &Path, name: &str, scratch: &Scratch) -> Result<Session, EvalError> {
    let profile = if name == "mini" {
        Profile::Mini
    } else {
        Profile::Full
    };
    let projects = (name == "reopen").then(|| scratch.path());
    let mut s = host::session(root, projects, profile)?;
    match name {
        "none" => {}
        "demo" | "mini" => load(&mut s, demo()),
        "two" => {
            load(&mut s, path(SECOND));
            load(&mut s, demo());
        }
        "stripped" => load(&mut s, path(STRIPPED)),
        "helpers" => load(&mut s, path(HELPERS)),
        "reopen" => {
            load(&mut s, demo());
            drop(s);
            s = host::session(root, projects, profile)?;
        }
        other => {
            return Err(EvalError::data(
                CORPUS,
                &format!("the session {other} is not known"),
            ));
        }
    }
    Ok(s)
}

/// The result of one mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The mistake ID.
    pub id: String,
    /// The class.
    pub class: String,
    /// The expected code.
    pub code: String,
    /// `true` when the call gives the expected code.
    pub triggered: bool,
    /// `R`: `next[0]` succeeds. `C`: the candidates hold the target. `H`: the rank is not 0.
    pub ok: bool,
    /// `H` only: the rank of the intended tool, from 1, or 0 when it is missing.
    pub rank: u64,
}

fn rank_of(response: &Value, tool: &str) -> u64 {
    let names = response
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|i| i.get("name").and_then(Value::as_str))
        .chain(
            response
                .get("next")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(|n| n.get("tool").and_then(Value::as_str)),
        );
    names
        .enumerate()
        .find(|(_, n)| *n == tool)
        .map_or(0, |(i, _)| {
            u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1)
        })
}

/// Gives the error codes of a response: the code of a failed call, or the codes of the
/// failed steps of a batch.
fn codes(response: &Value) -> Vec<&str> {
    let steps = response
        .pointer("/data/steps")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.pointer("/error/code").and_then(Value::as_str));
    response
        .pointer("/error/code")
        .and_then(Value::as_str)
        .into_iter()
        .chain(steps)
        .collect()
}

/// Gives the candidates of the error of a call or of its failed batch steps.
fn candidates(response: &Value) -> Vec<&Value> {
    let top = response
        .pointer("/error/candidates")
        .and_then(Value::as_array)
        .unwrap_or_default();
    let steps = response
        .pointer("/data/steps")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.pointer("/error/candidates").and_then(Value::as_array))
        .flatten();
    top.iter().chain(steps).collect()
}

/// Runs one mistake through the robot.
#[must_use]
pub fn attempt(root: &Path, m: &Mistake) -> Attempt {
    let mut out = Attempt {
        id: m.id.clone(),
        class: m.class.clone(),
        code: m.code.clone(),
        triggered: false,
        ok: false,
        rank: 0,
    };
    let Ok(scratch) = Scratch::new(&m.id) else {
        return out;
    };
    let Ok(mut session) = open(root, &m.session, &scratch) else {
        return out;
    };
    let mut responses = Vec::new();
    for (tool, args) in &m.setup {
        let args = runner::resolve(args, &responses).unwrap_or(Value::Null);
        responses.push(host::call(&mut session, tool, args));
    }
    let Ok(args) = runner::resolve(&m.args, &responses) else {
        return out;
    };
    let response = host::call(&mut session, &m.tool, args);
    out.triggered = codes(&response).contains(&m.code.as_str());
    if !out.triggered {
        return out;
    }
    let first = response.pointer("/next/0").and_then(|n| {
        Some((
            n.get("tool")?.as_str()?.to_owned(),
            n.get("args").cloned().unwrap_or_else(host::empty),
        ))
    });
    match m.class.as_str() {
        "R" => {
            if let Some((tool, args)) = first {
                let r = host::call(&mut session, &tool, args);
                out.ok = r.get("ok").and_then(Value::as_bool) == Some(true) && codes(&r).is_empty();
            }
        }
        "C" => {
            let target = m.target.clone().unwrap_or_default();
            out.ok = candidates(&response).iter().any(|c| {
                ["value", "label", "id", "addr"]
                    .iter()
                    .any(|k| c.get(k).map(text_of).as_deref() == Some(target.as_str()))
            });
        }
        _ => {
            if let (Some((tool, args)), Some(intended)) = (first, &m.intended) {
                let r = host::call(&mut session, &tool, args);
                out.rank = rank_of(&r, intended);
                out.ok = out.rank > 0;
            }
        }
    }
    out
}

/// One row of the scorecard: the attempts of one code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRow {
    /// The class of the code.
    pub class: String,
    /// The number of mistakes.
    pub count: u64,
    /// The mistakes that give the code.
    pub triggered: u64,
    /// The mistakes whose repair check passes.
    pub ok: u64,
    /// The ranks of the intended tool, for an `H` code.
    pub ranks: Vec<u64>,
}

/// The result of the robot over the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Repair {
    /// The attempts in corpus order.
    pub attempts: Vec<Attempt>,
}

impl Repair {
    /// Gives the rows by code name.
    #[must_use]
    pub fn by_code(&self) -> BTreeMap<String, CodeRow> {
        let mut out: BTreeMap<String, CodeRow> = BTreeMap::new();
        for a in &self.attempts {
            let row = out.entry(a.code.clone()).or_insert_with(|| CodeRow {
                class: a.class.clone(),
                count: 0,
                triggered: 0,
                ok: 0,
                ranks: Vec::new(),
            });
            row.count = row.count.saturating_add(1);
            row.triggered = row.triggered.saturating_add(u64::from(a.triggered));
            row.ok = row.ok.saturating_add(u64::from(a.ok));
            if a.class == "H" {
                row.ranks.push(a.rank);
            }
        }
        out
    }

    /// Gives the rate of the class: the attempts that trigger their code and pass.
    #[must_use]
    pub fn rate(&self, class: &str) -> Milli {
        let of: Vec<&Attempt> = self.attempts.iter().filter(|a| a.class == class).collect();
        let ok = of.iter().filter(|a| a.triggered && a.ok).count();
        Milli::ratio(
            u64::try_from(ok).unwrap_or(0),
            u64::try_from(of.len()).unwrap_or(0),
        )
    }
}

/// Runs the robot over every mistake.
#[must_use]
pub fn run(root: &Path, mistakes: &[Mistake]) -> Repair {
    Repair {
        attempts: runner::parallel(mistakes, runner::threads(), |m| attempt(root, m)),
    }
}
