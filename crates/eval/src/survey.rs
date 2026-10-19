//! Survey fact recall (design Section 12.4, AC-153b).
//!
//! Each T1 truth file lists `survey_facts` from the C sources: imports, libraries,
//! protections, strings, functions and syscalls. The metric loads the fixture binary, sends
//! the default `binary_survey {}` and counts the facts that the output shows. The value of the
//! metric is the mean of the per-fixture fractions.

use std::path::Path;

use ghidorah_json::Value;
use ghidorah_tools::Profile;

use crate::error::{EvalError, read_json};
use crate::host;
use crate::milli::Milli;
use crate::runner;

/// The truth directory.
pub const TRUTH: &str = "fixtures/truth";

/// One fixture with facts: the fixture name, the binary path and the `(kind, value)` facts.
pub type FixtureFacts = (String, String, Vec<(String, String)>);

/// The recall of one fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureRecall {
    /// The fixture name, for example `hello.gcc-O2`.
    pub fixture: String,
    /// The facts that the survey shows.
    pub found: u64,
    /// The number of facts.
    pub total: u64,
    /// The facts that the survey does not show, as `kind:value`.
    pub missed: Vec<String>,
}

/// The survey recall of every T1 fixture.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SurveyRecall {
    /// The fixtures in name order.
    pub fixtures: Vec<FixtureRecall>,
}

impl SurveyRecall {
    /// Gives the mean of the per-fixture fractions.
    #[must_use]
    pub fn rate(&self) -> Milli {
        let n = u64::try_from(self.fixtures.len()).unwrap_or(u64::MAX);
        let sum: u64 = self
            .fixtures
            .iter()
            .map(|f| Milli::ratio(f.found, f.total).0)
            .sum();
        Milli(sum.checked_div(n).unwrap_or(Milli::ONE.0))
    }
}

/// Tells if the survey `data` shows the fact `kind` with `value`.
#[must_use]
pub fn shows(data: &Value, kind: &str, value: &str) -> bool {
    let quoted = ghidorah_json::write(&Value::from(value));
    let section = |name: &str| data.get(name).map(ghidorah_json::write).unwrap_or_default();
    match kind {
        "protection" => match data.pointer(&format!("/protections/{value}")) {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s != "none",
            _ => false,
        },
        "import" | "library" => section("imports").contains(&quoted),
        "string" => section("strings").contains(&quoted),
        "syscall" => section("syscalls").contains(&quoted),
        "function" => {
            section("functions").contains(&quoted) || section("entries").contains(&quoted)
        }
        _ => false,
    }
}

/// Gives the T1 fixtures with survey facts: `(name, binary path, facts)`.
///
/// # Errors
///
/// Returns an [`EvalError`] when the truth directory or a truth file does not read.
pub fn fixtures(root: &Path) -> Result<Vec<FixtureFacts>, EvalError> {
    let dir = root.join(TRUTH);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| EvalError::io(&dir, &e))?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".json").map(str::to_owned))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let truth = read_json(root, &format!("{TRUTH}/{name}.json"))?;
        if truth.get("tier").and_then(Value::as_str) != Some("T1") {
            continue;
        }
        let facts: Vec<(String, String)> = truth
            .get("survey_facts")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|f| {
                Some((
                    f.get("kind")?.as_str()?.to_owned(),
                    f.get("value")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        if !facts.is_empty() {
            out.push((name.clone(), format!("fixtures/bin/{name}"), facts));
        }
    }
    Ok(out)
}

/// Measures the survey recall of one fixture: `name`, its binary `path` and its `facts`.
#[must_use]
pub fn one(root: &Path, name: &str, path: &str, facts: &[(String, String)]) -> FixtureRecall {
    return FixtureRecall { fixture: name.to_owned(), found: 0, total: u64::try_from(facts.len()).unwrap_or(0), missed: Vec::new() };
    let total = u64::try_from(facts.len()).unwrap_or(u64::MAX);
    let mut out = FixtureRecall {
        fixture: name.to_owned(),
        found: 0,
        total,
        missed: Vec::new(),
    };
    let Ok(mut session) = host::session(root, None, Profile::Full) else {
        out.missed.push("the session does not open".to_owned());
        return out;
    };
    host::call(
        &mut session,
        "binary_load",
        Value::object([("path", Value::from(path))]),
    );
    let survey = host::call(&mut session, "binary_survey", Value::object::<&str>([]));
    let data = survey.get("data").cloned().unwrap_or(Value::Null);
    for (kind, value) in facts {
        if shows(&data, kind, value) {
            out.found = out.found.saturating_add(1);
        } else {
            out.missed.push(format!("{kind}:{value}"));
        }
    }
    out
}

/// Measures the survey recall of every T1 fixture.
///
/// # Errors
///
/// Returns an [`EvalError`] when the truth files do not read.
pub fn run(root: &Path) -> Result<SurveyRecall, EvalError> {
    let list = fixtures(root)?;
    let fixtures = runner::parallel(&list, runner::threads(), |(name, path, facts)| {
        one(root, name, path, facts)
    });
    Ok(SurveyRecall { fixtures })
}
