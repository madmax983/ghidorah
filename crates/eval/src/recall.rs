//! Context-reset recall (design Section 12.4, AC-199 and AC-229).
//!
//! Part 1 records ground-truth facts: renames, findings and open todos. Then the context
//! resets. The new context reads `session_brief {}` and the `search` calls that the brief
//! proposes in `next`. Recall is the fraction of facts whose text is in these outputs.
//!
//! The second run applies 50 random scripted edits after part 1 and before the reset. These
//! renames, comments and notes push the facts out of the recent lists. A script makes them
//! with its own session label, as design Section 2.6 tells scripts to do. A `SplitMix64`
//! generator with the seed of `eval/recall.json` picks the edits, so each run is the same.

use std::path::Path;

use ghidorah_json::Value;
use ghidorah_tools::Profile;

use crate::derive::text_of;
use crate::error::{EvalError, read_json};
use crate::host;
use crate::milli::Milli;

/// The fact script path.
pub const SPEC: &str = "eval/recall.json";

/// The session label of the noise edits: a script with its own label (design Section 2.6).
pub const NOISE_SESSION: &str = "script";

/// The largest number of noise edits.
pub const MAX_NOISE: u64 = 500;

/// One ground-truth fact of part 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact {
    /// A rename of `target` to `name`.
    Rename {
        /// The function ID.
        target: String,
        /// The new name.
        name: String,
    },
    /// A finding note with evidence.
    Finding {
        /// The note text.
        text: String,
        /// The evidence IDs.
        evidence: Vec<String>,
    },
    /// An open todo note at an address.
    Todo {
        /// The note text.
        text: String,
        /// The address or ID of the note.
        at: String,
    },
}

impl Fact {
    /// Gives the text that the reads must hold.
    #[must_use]
    pub fn needle(&self) -> &str {
        match self {
            Self::Rename { name, .. } => name,
            Self::Finding { text, .. } | Self::Todo { text, .. } => text,
        }
    }

    /// Gives the tool call that records the fact.
    #[must_use]
    pub fn call(&self) -> (&'static str, Value) {
        match self {
            Self::Rename { target, name } => (
                "symbol_rename",
                Value::object([
                    ("target", Value::from(target.as_str())),
                    ("name", Value::from(name.as_str())),
                ]),
            ),
            Self::Finding { text, evidence } => (
                "note_write",
                Value::object([
                    ("kind", Value::from("finding")),
                    ("text", Value::from(text.as_str())),
                    (
                        "evidence",
                        Value::Array(evidence.iter().map(|e| Value::from(e.as_str())).collect()),
                    ),
                ]),
            ),
            Self::Todo { text, at } => (
                "note_write",
                Value::object([
                    ("kind", Value::from("todo")),
                    ("text", Value::from(text.as_str())),
                    ("at", Value::from(at.as_str())),
                ]),
            ),
        }
    }
}

/// The fact script of `eval/recall.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// The fixture binary, relative to the workspace root.
    pub binary: String,
    /// The facts of part 1.
    pub facts: Vec<Fact>,
    /// The seed of the noise edits.
    pub seed: u64,
    /// The number of noise edits.
    pub edits: u64,
}

fn text(v: &Value, key: &str) -> Result<String, EvalError> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| EvalError::data(SPEC, &format!("`{key}` is not a string")))
}

/// Reads the fact script.
///
/// # Errors
///
/// Returns an [`EvalError`] when the file does not read or a fact has bad data.
pub fn read_spec(root: &Path) -> Result<Spec, EvalError> {
    let v = read_json(root, SPEC)?;
    let mut facts = Vec::new();
    for f in v.get("facts").and_then(Value::as_array).unwrap_or_default() {
        facts.push(match text(f, "kind")?.as_str() {
            "rename" => Fact::Rename {
                target: text(f, "target")?,
                name: text(f, "name")?,
            },
            "finding" => Fact::Finding {
                text: text(f, "text")?,
                evidence: f
                    .get("evidence")
                    .and_then(Value::as_array)
                    .unwrap_or_default()
                    .iter()
                    .map(text_of)
                    .collect(),
            },
            "todo" => Fact::Todo {
                text: text(f, "text")?,
                at: text(f, "at")?,
            },
            other => {
                return Err(EvalError::data(
                    SPEC,
                    &format!("the fact kind {other} is not known"),
                ));
            }
        });
    }
    let num = |p: &str| v.pointer(p).and_then(Value::as_u64);
    Ok(Spec {
        binary: text(&v, "binary")?,
        facts,
        seed: num("/noise/seed").unwrap_or(0),
        edits: num("/noise/edits").unwrap_or(0).min(MAX_NOISE),
    })
}

/// The `SplitMix64` generator of the noise edits.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// Makes a generator with `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Gives the next value.
    pub const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Gives a value in `0..n`, or 0 for an `n` of 0.
    pub fn below(&mut self, n: usize) -> usize {
        let n64 = u64::try_from(n).unwrap_or(u64::MAX);
        if n64 == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % n64).unwrap_or(0)
    }
}

/// Gives the noise calls: renames, comments and notes on functions that hold no fact.
#[must_use]
pub fn noise(spec: &Spec, functions: &[String]) -> Vec<(&'static str, Value)> {
    let taken: Vec<&str> = spec
        .facts
        .iter()
        .filter_map(|f| match f {
            Fact::Rename { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect();
    let free: Vec<&String> = functions
        .iter()
        .filter(|f| !taken.contains(&f.as_str()))
        .collect();
    let mut rng = SplitMix64::new(spec.seed);
    let mut out = Vec::new();
    for k in 0..spec.edits {
        let Some(f) = free.get(rng.below(free.len())) else {
            break;
        };
        let target = Value::from(f.as_str());
        out.push(match rng.below(3) {
            0 => (
                "symbol_rename",
                Value::object([
                    ("target", target),
                    ("name", Value::from(format!("noise_{k}"))),
                ]),
            ),
            1 => (
                "comment_set",
                Value::object([
                    ("target", target),
                    ("kind", Value::from("eol")),
                    ("text", Value::from(format!("Noise comment {k}."))),
                ]),
            ),
            _ => (
                "note_write",
                Value::object([
                    ("kind", Value::from("note")),
                    ("text", Value::from(format!("Noise note {k}."))),
                    ("at", target),
                ]),
            ),
        });
    }
    out
}

/// The result of one recall run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recall {
    /// The facts whose text the reads hold.
    pub found: u64,
    /// The number of facts.
    pub total: u64,
    /// The texts of the facts that the reads do not hold.
    pub missed: Vec<String>,
    /// The number of noise edits that the run applied.
    pub noise: u64,
}

impl Recall {
    /// Gives the recall rate.
    #[must_use]
    pub fn rate(&self) -> Milli {
        Milli::ratio(self.found, self.total)
    }
}

fn ok(response: &Value) -> bool {
    response.get("ok").and_then(Value::as_bool) == Some(true)
}

/// Runs part 1, the noise edits when `with_noise`, the reset and the reads.
///
/// # Errors
///
/// Returns an [`EvalError`] when the session does not open or a part-1 call fails.
pub fn run(root: &Path, spec: &Spec, with_noise: bool) -> Result<Recall, EvalError> {
    let mut session = host::session(root, None, Profile::Full)?;
    let load = host::call(
        &mut session,
        "binary_load",
        Value::object([("path", Value::from(spec.binary.as_str()))]),
    );
    if !ok(&load) {
        return Err(EvalError::data(
            SPEC,
            &format!("the binary does not load: {load}"),
        ));
    }
    for fact in &spec.facts {
        let (tool, args) = fact.call();
        let r = host::call(&mut session, tool, args);
        if !ok(&r) {
            return Err(EvalError::data(SPEC, &format!("a fact call fails: {r}")));
        }
    }
    let mut applied = 0u64;
    if with_noise {
        let list = host::call(
            &mut session,
            "func_list",
            Value::object([("limit", Value::from(1000u64))]),
        );
        let ids: Vec<String> = list
            .pointer("/data/items")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter(|i| {
                i.pointer("/flags")
                    .and_then(Value::as_array)
                    .is_none_or(|f| !f.iter().any(|x| x.as_str() == Some("thunk")))
            })
            .filter_map(|i| i.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        for (tool, args) in noise(spec, &ids) {
            let args = match args {
                Value::Object(mut o) => {
                    o.push("session", Value::from(NOISE_SESSION));
                    Value::Object(o)
                }
                other => other,
            };
            if ok(&host::call(&mut session, tool, args)) {
                applied = applied.saturating_add(1);
            }
        }
    }
    let brief = host::call(&mut session, "session_brief", Value::object::<&str>([]));
    let mut reads = vec![ghidorah_json::write(&brief)];
    for hint in brief
        .get("next")
        .and_then(Value::as_array)
        .unwrap_or_default()
    {
        if hint.get("tool").and_then(Value::as_str) == Some("search") {
            let args = hint.get("args").cloned().unwrap_or(Value::Null);
            reads.push(ghidorah_json::write(&host::call(
                &mut session,
                "search",
                args,
            )));
        }
    }
    let mut found = 0u64;
    let mut missed = Vec::new();
    for fact in &spec.facts {
        let needle = ghidorah_json::write(&Value::from(fact.needle()));
        if reads.iter().any(|r| r.contains(&needle)) {
            found = found.saturating_add(1);
        } else {
            missed.push(fact.needle().to_owned());
        }
    }
    Ok(Recall {
        found,
        total: u64::try_from(spec.facts.len()).unwrap_or(u64::MAX),
        missed,
        noise: applied,
    })
}
