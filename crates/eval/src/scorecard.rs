//! The metric values, the gates and the scorecard JSON (design Sections 12.4 to 12.6).
//!
//! `xtask eval --json` prints the scorecard. Its member order is fixed and every number is an
//! integer or a rate with three decimals, so two runs give byte-equal text (AC-200). Its
//! schema golden is `tests/golden/eval/scorecard.schema.json`: the scorecard with each leaf
//! replaced by its type name.

use std::collections::BTreeMap;

use ghidorah_json::{Object, Value};

use crate::ab::{self, Ablation};
use crate::gate::{self, Blessing, COST_FIELDS, Cost};
use crate::milli::Milli;
use crate::report::Report;
use crate::runner::Outcome;

/// Gives the cost of one run: `calls`, `chars`, `peak` and `est_tokens`.
#[must_use]
pub fn cost(o: &Outcome) -> Cost {
    COST_FIELDS
        .iter()
        .zip([o.calls, o.chars, o.peak, o.est_tokens])
        .map(|(k, v)| ((*k).to_owned(), v))
        .collect()
}

/// Gives the first turn and pointer where two runs differ, or `None` when they are equal.
#[must_use]
pub fn first_diff(a: &[Value], b: &[Value]) -> Option<(usize, String)> {
    if a.len() != b.len() {
        return Some((a.len().min(b.len()), String::new()));
    }
    a.iter()
        .zip(b)
        .enumerate()
        .find_map(|(i, (x, y))| diff_ptr(x, y, String::new()).map(|p| (i, p)))
}

fn diff_ptr(a: &Value, b: &Value, at: String) -> Option<String> {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            if x.len() != y.len() {
                return Some(at);
            }
            x.iter().zip(y.iter()).find_map(|((kx, vx), (ky, vy))| {
                if kx == ky {
                    diff_ptr(vx, vy, format!("{at}/{kx}"))
                } else {
                    Some(format!("{at}/{kx}"))
                }
            })
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => x
            .iter()
            .zip(y)
            .enumerate()
            .find_map(|(i, (vx, vy))| diff_ptr(vx, vy, format!("{at}/{i}"))),
        _ => (a != b).then_some(at),
    }
}

fn rate_of(outcomes: &[&Outcome], f: impl Fn(&Outcome) -> bool) -> Milli {
    let ok = outcomes.iter().filter(|o| f(o)).count();
    Milli::ratio(
        u64::try_from(ok).unwrap_or(0),
        u64::try_from(outcomes.len()).unwrap_or(0),
    )
}

impl Report {
    fn all_runs(&self) -> Vec<&Outcome> {
        self.outcomes.iter().chain(&self.ab_outcomes).collect()
    }

    /// Gives the number of linted values and the lint findings.
    #[must_use]
    pub fn provenance(&self) -> (u64, Vec<&crate::lint::Finding>) {
        let values = self.lint.iter().map(|l| l.values).sum();
        (values, self.lint.iter().flat_map(|l| &l.findings).collect())
    }

    /// Gives the abstain outcomes.
    #[must_use]
    pub fn abstains(&self) -> Vec<&Outcome> {
        self.outcomes
            .iter()
            .filter(|o| o.category == "abstain")
            .collect()
    }

    /// Gives the scenarios whose second run differs, with the first turn and pointer.
    #[must_use]
    pub fn nondeterministic(&self) -> Vec<(String, usize, String)> {
        self.outcomes
            .iter()
            .zip(&self.reruns)
            .filter_map(|(a, b)| b.as_ref().map(|b| (a, b)))
            .filter_map(|(a, b)| {
                first_diff(&a.responses, &b.responses).map(|(t, p)| (a.id.clone(), t, p))
            })
            .collect()
    }

    /// Gives the number of scenarios with a second run.
    #[must_use]
    pub fn rerun_count(&self) -> usize {
        self.reruns.iter().flatten().count()
    }

    /// Gives the value of each metric where higher is better, by threshold name.
    #[must_use]
    pub fn metrics(&self) -> BTreeMap<String, Milli> {
        let runs = self.all_runs();
        let (values, findings) = self.provenance();
        let bad = u64::try_from(findings.len())
            .unwrap_or(u64::MAX)
            .min(values);
        let n = u64::try_from(self.rerun_count()).unwrap_or(0);
        let differ = u64::try_from(self.nondeterministic().len()).unwrap_or(0);
        [
            ("abstain_correctness", rate_of(&self.abstains(), |o| o.pass)),
            ("answer_correctness", rate_of(&runs, |o| o.answer_ok)),
            ("argument_provenance", Milli::ratio(values - bad, values)),
            ("budget_adherence", rate_of(&runs, |o| o.budget_ok)),
            ("context_reset_recall", self.recall_reset.rate()),
            ("determinism", Milli::ratio(n.saturating_sub(differ), n)),
            ("discoverability", self.discover.tool_search_top3()),
            ("hint_follower_reach", self.follower.rate()),
            ("metamorphic", self.metamorphic.rate()),
            ("recall_after_edits", self.recall_edits.rate()),
            ("repair_rate_r", self.repair.rate("R")),
            ("survey_fact_recall", self.survey.rate()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }

    /// Gives the gate rows: `(metric, value, bar, pass)` for each metric where higher is better.
    #[must_use]
    pub fn gates(&self) -> Vec<(String, Milli, Milli, bool)> {
        self.metrics()
            .into_iter()
            .map(|(name, value)| {
                let bar = self
                    .thresholds
                    .metrics
                    .get(&name)
                    .map(gate::bar)
                    .unwrap_or_default();
                let pass = value >= bar;
                (name, value, bar, pass)
            })
            .collect()
    }

    /// Gives the cost fields of each run that are above `baseline x 1.10`, as text.
    #[must_use]
    pub fn cost_findings(&self, baselines: &BTreeMap<String, Cost>) -> Vec<String> {
        let mut out = Vec::new();
        for o in self.all_runs() {
            let Some(base) = baselines.get(&o.id) else {
                out.push(format!("{}: no cost baseline", o.id));
                continue;
            };
            for (field, value) in cost(o) {
                let b = base.get(&field).copied().unwrap_or(0);
                if !gate::cost_ok(value, b, gate::COST_TOLERANCE) {
                    out.push(format!(
                        "{}: {field} {value} is above the baseline {b} x 1.10",
                        o.id
                    ));
                }
            }
        }
        out
    }

    /// Gives the A/B pairs.
    #[must_use]
    pub fn pairs(&self) -> Vec<ab::Pair> {
        let ab: Vec<_> = self.ab_scenarios.iter().zip(&self.ab_outcomes).collect();
        ab::pairs(&ab, &self.outcomes)
    }

    /// Gives the ablation sums.
    #[must_use]
    pub fn ablation(&self) -> Ablation {
        let mut out = Ablation::default();
        for ((s, a), t) in self.scenarios.iter().zip(&self.outcomes).zip(&self.tables) {
            if let Some(t) = t {
                out.objects_chars = out.objects_chars.saturating_add(ab::list_chars(s, a));
                out.table_chars = out.table_chars.saturating_add(ab::list_chars(s, t));
            }
            out.star_calls_saved = out.star_calls_saved.saturating_add(ab::star_calls(s, a));
        }
        out
    }

    /// Gives the baselines that a bless writes.
    #[must_use]
    pub fn blessing(&self) -> Blessing {
        Blessing {
            metrics: self.metrics(),
            costs: self
                .all_runs()
                .into_iter()
                .map(|o| (o.id.clone(), cost(o)))
                .collect(),
        }
    }
}

/// Gives the schema of a scorecard: each leaf becomes its type name, and each array holds the
/// merged schema of its items.
#[must_use]
pub fn schema(v: &Value) -> Value {
    match v {
        Value::Null => Value::from("null"),
        Value::Bool(_) => Value::from("bool"),
        Value::Number(n) if n.is_integer() => Value::from("int"),
        Value::Number(_) => Value::from("rate"),
        Value::String(_) => Value::from("str"),
        Value::Array(items) => {
            let merged = items.iter().map(schema).reduce(merge);
            Value::Array(merged.into_iter().collect())
        }
        Value::Object(m) => {
            let mut out = Object::new();
            for (k, x) in m.iter() {
                out.push(k, schema(x));
            }
            Value::Object(out)
        }
    }
}

/// Merges two schemas: the members of both objects, the items of both arrays, else the first
/// type that is not `null`.
fn merge(a: Value, b: Value) -> Value {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut out = x;
            for (k, v) in y.into_members() {
                let merged = match out.remove(&k) {
                    Some(old) => merge(old, v),
                    None => v,
                };
                out.push(k, merged);
            }
            Value::Object(out)
        }
        (Value::Array(x), Value::Array(y)) => {
            Value::Array(x.into_iter().chain(y).reduce(merge).into_iter().collect())
        }
        (a, b) if a == Value::from("null") => b,
        (a, _) => a,
    }
}
