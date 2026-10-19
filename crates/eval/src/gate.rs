//! Gates, baselines and the bless log (design Section 12.6).
//!
//! - A metric where higher is better passes when `value >= max(floor, baseline - tolerance)`.
//! - A cost metric passes when `value <= baseline x (1 + tolerance)`, with tolerance 0.10.
//!   The cost baselines of each scenario live in `eval/baseline.json`.
//! - A bless writes the new baselines. It refuses to run when a floor of
//!   `eval/thresholds.json` is below its frozen value. It appends one line
//!   `{ commit, metric, old, new, reason }` to `eval/bless-log.jsonl` for each change.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use ghidorah_json::{Object, Value};

use crate::error::{EvalError, read_json, read_jsonl};
use crate::inputs::{FROZEN_FLOORS, Metric, THRESHOLDS, Thresholds};
use crate::milli::Milli;

/// The cost baseline path.
pub const BASELINE: &str = "eval/baseline.json";

/// The bless log path.
pub const BLESS_LOG: &str = "eval/bless-log.jsonl";

/// The cost fields of each scenario.
pub const COST_FIELDS: [&str; 4] = ["calls", "chars", "peak", "est_tokens"];

/// The cost tolerance in thousandths: 0.10.
pub const COST_TOLERANCE: Milli = Milli(100);

/// The cost of one scenario run.
pub type Cost = BTreeMap<String, u64>;

/// Gives the gate value of a metric where higher is better.
#[must_use]
pub fn bar(metric: &Metric) -> Milli {
    let floor = metric.floor.unwrap_or_default();
    let base = metric
        .baseline
        .map_or(Milli(0), |b| Milli(b.0.saturating_sub(metric.tolerance.0)));
    floor.max(base)
}

/// Tells if a cost value is within `baseline x (1 + tolerance)`.
#[must_use]
pub fn cost_ok(value: u64, baseline: u64, tolerance: Milli) -> bool {
    u128::from(value) * 1000 <= u128::from(baseline) * u128::from(1000 + tolerance.0)
}

/// Reads the cost baselines: scenario ID to field to value.
///
/// # Errors
///
/// Returns an [`EvalError`] when the file does not read.
pub fn read_costs(root: &Path) -> Result<BTreeMap<String, Cost>, EvalError> {
    let v = read_json(root, BASELINE)?;
    let mut out = BTreeMap::new();
    if let Some(Value::Object(members)) = v.get("scenarios") {
        for (id, fields) in members.iter() {
            let mut cost = Cost::new();
            for f in COST_FIELDS {
                if let Some(n) = fields.get(f).and_then(Value::as_u64) {
                    cost.insert(f.to_owned(), n);
                }
            }
            out.insert(id.to_owned(), cost);
        }
    }
    Ok(out)
}

/// One line of the bless log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// The commit at the time of the bless.
    pub commit: String,
    /// The metric: a metric name, or `cost:<scenario>:<field>`.
    pub metric: String,
    /// The old value as JSON text, or `null`.
    pub old: Value,
    /// The new value.
    pub new: Value,
    /// Why the value changes.
    pub reason: String,
}

impl LogLine {
    fn to_json(&self) -> Value {
        Value::object([
            ("commit", Value::from(self.commit.as_str())),
            ("metric", Value::from(self.metric.as_str())),
            ("old", self.old.clone()),
            ("new", self.new.clone()),
            ("reason", Value::from(self.reason.as_str())),
        ])
    }
}

/// Reads the bless log. A missing file is an empty log.
///
/// # Errors
///
/// Returns an [`EvalError`] when a line is not valid JSON.
pub fn read_log(root: &Path) -> Result<Vec<LogLine>, EvalError> {
    if !root.join(BLESS_LOG).exists() {
        return Ok(Vec::new());
    }
    Ok(read_jsonl(root, BLESS_LOG)?
        .iter()
        .map(|v| {
            let text = |k: &str| {
                v.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            LogLine {
                commit: text("commit"),
                metric: text("metric"),
                old: v.get("old").cloned().unwrap_or(Value::Null),
                new: v.get("new").cloned().unwrap_or(Value::Null),
                reason: text("reason"),
            }
        })
        .collect())
}

/// Gives the floors of `thresholds` that are below their frozen value.
#[must_use]
pub fn lowered_floors(thresholds: &Thresholds) -> Vec<String> {
    FROZEN_FLOORS
        .iter()
        .filter(|(name, floor)| {
            thresholds
                .metrics
                .get(*name)
                .and_then(|m| m.floor)
                .is_none_or(|f| f < *floor)
        })
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

/// Checks that the bless log explains every baseline (AC-196b).
///
/// Each cost baseline and each metric baseline needs a log line whose `new` value is the
/// current value. A cost rise above the tolerance needs a reason. No floor is below its frozen
/// value.
#[must_use]
pub fn log_findings(
    thresholds: &Thresholds,
    costs: &BTreeMap<String, Cost>,
    log: &[LogLine],
) -> Vec<String> {
    let mut last: BTreeMap<&str, &LogLine> = BTreeMap::new();
    let mut out = Vec::new();
    for line in log {
        let rise = match (line.old.as_u64(), line.new.as_u64()) {
            (Some(o), Some(n)) => !cost_ok(n, o, COST_TOLERANCE),
            _ => false,
        };
        if line.metric.starts_with("cost:") && rise && line.reason.trim().is_empty() {
            out.push(format!(
                "{}: a cost rise above 10% has no reason",
                line.metric
            ));
        }
        last.insert(line.metric.as_str(), line);
    }
    for (id, cost) in costs {
        for (field, value) in cost {
            let key = format!("cost:{id}:{field}");
            if last.get(key.as_str()).and_then(|l| l.new.as_u64()) != Some(*value) {
                out.push(format!("{key}: the baseline {value} has no bless-log line"));
            }
        }
    }
    for (name, metric) in &thresholds.metrics {
        if let Some(b) = metric.baseline {
            let logged = last.get(name.as_str()).and_then(|l| Milli::of_json(&l.new));
            if logged != Some(b) {
                out.push(format!("{name}: the baseline {b} has no bless-log line"));
            }
        }
    }
    out.extend(
        lowered_floors(thresholds)
            .into_iter()
            .map(|n| format!("{n}: the floor is below its frozen value")),
    );
    out
}

/// The new baselines of a bless.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Blessing {
    /// The metric values where higher is better, by threshold name.
    pub metrics: BTreeMap<String, Milli>,
    /// The cost of each scenario.
    pub costs: BTreeMap<String, Cost>,
}

fn cost_json(costs: &BTreeMap<String, Cost>, per_token: u64) -> Value {
    let mut scenarios = Object::new();
    for (id, cost) in costs {
        let mut o = Object::new();
        for f in COST_FIELDS {
            o.push(f, Value::from(cost.get(f).copied().unwrap_or(0)));
        }
        scenarios.push(id.as_str(), Value::Object(o));
    }
    Value::object([
        ("chars_per_token", Value::from(per_token)),
        ("scenarios", Value::Object(scenarios)),
    ])
}

fn thresholds_json(t: &Thresholds, metrics: &BTreeMap<String, Milli>) -> Value {
    let mut raw = match &t.raw {
        Value::Object(o) => o.clone(),
        _ => Object::new(),
    };
    if let Some(Value::Object(all)) = raw.get_mut("metrics") {
        for (name, value) in metrics {
            if let Some(Value::Object(m)) = all.get_mut(name) {
                m.insert("baseline", value.to_json());
            }
        }
    }
    if !raw.contains_key("chars_per_token") {
        raw.insert("chars_per_token", Value::from(t.chars_per_token));
    }
    Value::Object(raw)
}

fn write(root: &Path, rel: &str, text: &str) -> Result<(), EvalError> {
    std::fs::write(root.join(rel), text).map_err(|e| EvalError::io(&root.join(rel), &e))
}

/// Writes the baselines of `blessing` and appends the bless-log lines. Gives the lines.
///
/// # Errors
///
/// Returns [`EvalError::Bless`] when a floor is below its frozen value, and an I/O error
/// when a file does not write.
pub fn bless(
    root: &Path,
    t: &Thresholds,
    blessing: &Blessing,
    commit: &str,
    reason: &str,
) -> Result<Vec<LogLine>, EvalError> {
    let lowered = lowered_floors(t);
    if !lowered.is_empty() {
        return Err(EvalError::Bless {
            message: format!("a floor is below its frozen value: {}", lowered.join(", ")),
        });
    }
    let old_costs = read_costs(root).unwrap_or_default();
    let mut lines = Vec::new();
    for (name, value) in &blessing.metrics {
        let old = t.metrics.get(name).and_then(|m| m.baseline);
        if old != Some(*value) {
            lines.push(LogLine {
                commit: commit.to_owned(),
                metric: name.clone(),
                old: old.map_or(Value::Null, Milli::to_json),
                new: value.to_json(),
                reason: reason.to_owned(),
            });
        }
    }
    for (id, cost) in &blessing.costs {
        for (field, value) in cost {
            let old = old_costs.get(id).and_then(|c| c.get(field)).copied();
            if old != Some(*value) {
                lines.push(LogLine {
                    commit: commit.to_owned(),
                    metric: format!("cost:{id}:{field}"),
                    old: old.map_or(Value::Null, Value::from),
                    new: Value::from(*value),
                    reason: reason.to_owned(),
                });
            }
        }
    }
    write(
        root,
        BASELINE,
        &(ghidorah_json::write_pretty(&cost_json(&blessing.costs, t.chars_per_token)) + "\n"),
    )?;
    write(
        root,
        THRESHOLDS,
        &(ghidorah_json::write_pretty(&thresholds_json(t, &blessing.metrics)) + "\n"),
    )?;
    let path = root.join(BLESS_LOG);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| EvalError::io(&path, &e))?;
    for line in &lines {
        writeln!(file, "{}", ghidorah_json::write(&line.to_json()))
            .map_err(|e| EvalError::io(&path, &e))?;
    }
    Ok(lines)
}
