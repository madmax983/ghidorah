//! The scorecard JSON of one run (design Section 12.5).
//!
//! The members come in a fixed order, and each number is an integer or a rate with three
//! decimals. So two runs of the same tree give byte-equal text (AC-200).

use ghidorah_json::{Object, Value};

use crate::ab;
use crate::host::texts;
use crate::milli::Milli;
use crate::report::Report;

fn int(n: u64) -> Value {
    Value::from(n)
}

fn count(n: usize) -> Value {
    Value::from(u64::try_from(n).unwrap_or(u64::MAX))
}

impl Report {
    fn metric_json(&self, name: &str) -> Value {
        self.metrics()
            .get(name)
            .copied()
            .unwrap_or_default()
            .to_json()
    }

    fn scenarios_json(&self) -> Value {
        let rows = self.outcomes.iter().chain(&self.ab_outcomes).map(|o| {
            Value::object([
                ("id", Value::from(o.id.as_str())),
                ("pass", Value::from(o.pass)),
                ("calls", int(o.calls)),
                ("chars", int(o.chars)),
                ("peak", int(o.peak)),
                ("est_tokens", int(o.est_tokens)),
            ])
        });
        Value::Array(rows.collect())
    }

    fn provenance_json(&self) -> Value {
        let (values, findings) = self.provenance();
        let rows = findings.iter().map(|f| {
            Value::object([
                ("scenario", Value::from(f.scenario.as_str())),
                ("path", Value::from(f.path.as_str())),
                ("reason", Value::from(f.reason.as_str())),
            ])
        });
        Value::object([
            ("values", int(values)),
            ("findings", Value::Array(rows.collect())),
            ("rate", self.metric_json("argument_provenance")),
        ])
    }

    fn repair_json(&self) -> Value {
        let rows = self.repair.by_code().into_iter().map(|(code, r)| {
            Value::object([
                ("code", Value::from(code)),
                ("class", Value::from(r.class)),
                ("count", int(r.count)),
                ("triggered", int(r.triggered)),
                ("ok", int(r.ok)),
                (
                    "ranks",
                    Value::Array(r.ranks.into_iter().map(Value::from).collect()),
                ),
            ])
        });
        Value::object([
            ("by_code", Value::Array(rows.collect())),
            ("r_rate", self.repair.rate("R").to_json()),
            ("c_rate", self.repair.rate("C").to_json()),
        ])
    }

    fn follower_json(&self) -> Value {
        let walks = &self.follower.walks;
        let missed: Vec<String> = walks
            .iter()
            .filter(|w| !w.reached)
            .map(|w| w.scenario.clone())
            .collect();
        Value::object([
            ("scenarios", count(walks.len())),
            ("reached", count(walks.iter().filter(|w| w.reached).count())),
            ("rate", self.metric_json("hint_follower_reach")),
            ("missed", texts(&missed)),
        ])
    }

    fn discover_json(&self) -> Value {
        let d = &self.discover;
        Value::object([
            ("intents", int(d.intents)),
            ("tool_search_top3", d.tool_search_top3().to_json()),
            ("raw_top3", d.raw_top3().to_json()),
            ("misses", texts(&d.misses)),
        ])
    }

    fn determinism_json(&self) -> Value {
        let diffs = self.nondeterministic();
        let first = diffs.first().map_or(Value::Null, |(id, turn, ptr)| {
            Value::object([
                ("id", Value::from(id.as_str())),
                ("turn", count(*turn)),
                ("ptr", Value::from(ptr.as_str())),
            ])
        });
        Value::object([
            ("scenarios", count(self.rerun_count())),
            (
                "equal",
                count(self.rerun_count().saturating_sub(diffs.len())),
            ),
            ("rate", self.metric_json("determinism")),
            ("first_diff", first),
        ])
    }

    fn recall_json(&self) -> Value {
        Value::object([
            ("reset", self.metric_json("context_reset_recall")),
            ("after_edits", self.metric_json("recall_after_edits")),
            ("facts", int(self.recall_reset.total)),
            ("noise_edits", int(self.recall_edits.noise)),
        ])
    }

    fn survey_json(&self) -> Value {
        let f = &self.survey.fixtures;
        Value::object([
            ("rate", self.metric_json("survey_fact_recall")),
            ("fixtures", count(f.len())),
            ("facts", int(f.iter().map(|x| x.total).sum())),
            ("found", int(f.iter().map(|x| x.found).sum())),
        ])
    }

    fn abstain_json(&self) -> Value {
        let abstains = self.abstains();
        Value::object([
            ("scenarios", count(abstains.len())),
            ("pass", count(abstains.iter().filter(|o| o.pass).count())),
            ("rate", self.metric_json("abstain_correctness")),
        ])
    }

    fn checks_json(&self) -> [(&'static str, Value); 3] {
        let relations = self.metamorphic.relations.iter().map(|r| {
            Value::object([
                ("name", Value::from(r.name.as_str())),
                ("pass", Value::from(r.pass)),
            ])
        });
        let c = &self.catalog;
        [
            (
                "metamorphic",
                Value::object([
                    ("relations", Value::Array(relations.collect())),
                    ("rate", self.metric_json("metamorphic")),
                ]),
            ),
            (
                "fuzz",
                Value::object([
                    ("cases", int(self.fuzz.cases)),
                    ("violations", count(self.fuzz.violations.len())),
                ]),
            ),
            (
                "catalog",
                Value::object([
                    ("full_chars", int(c.full_chars)),
                    ("mini_chars", int(c.mini_chars)),
                    ("instructions_chars", int(c.instructions_chars)),
                ]),
            ),
        ]
    }

    fn ab_json(&self) -> [(&'static str, Value); 2] {
        let ablation = self.ablation();
        let pairs = self.pairs();
        let rows = pairs.iter().map(|p| {
            Value::object([
                ("id", Value::from(p.id.as_str())),
                ("pass", Value::from(p.pass)),
                ("single_calls", int(p.single_calls)),
                ("batch_calls", int(p.batch_calls)),
                ("single_chars", int(p.single_chars)),
                ("batch_chars", int(p.batch_chars)),
                ("calls_saved", p.calls_saved().to_json()),
                ("chars_saved", p.chars_saved().to_json()),
                ("meets", Value::from(p.meets())),
            ])
        });
        [
            (
                "ablation",
                Value::object([
                    ("objects_chars", int(ablation.objects_chars)),
                    ("table_chars", int(ablation.table_chars)),
                    ("star_calls_saved", int(ablation.star_calls_saved)),
                ]),
            ),
            (
                "ab",
                Value::object([
                    ("pairs", Value::Array(rows.collect())),
                    ("confirms", Value::from(ab::confirms(&pairs))),
                ]),
            ),
        ]
    }

    fn gates_json(&self) -> Value {
        let rows = self.gates().into_iter().map(
            |(name, value, bar, pass): (String, Milli, Milli, bool)| {
                Value::object([
                    ("metric", Value::from(name)),
                    ("value", value.to_json()),
                    ("bar", bar.to_json()),
                    ("pass", Value::from(pass)),
                ])
            },
        );
        Value::Array(rows.collect())
    }

    /// Gives the scorecard JSON.
    #[must_use]
    pub fn scorecard(&self) -> Value {
        let mut out = Object::new();
        out.push("scenarios", self.scenarios_json());
        out.push("answer_correctness", self.metric_json("answer_correctness"));
        out.push("budget_adherence", self.metric_json("budget_adherence"));
        out.push("provenance", self.provenance_json());
        out.push("repair", self.repair_json());
        out.push("hint_follower", self.follower_json());
        out.push("discoverability", self.discover_json());
        out.push("determinism", self.determinism_json());
        out.push("recall", self.recall_json());
        out.push("survey_recall", self.survey_json());
        out.push("abstain", self.abstain_json());
        for (k, v) in self.checks_json().into_iter().chain(self.ab_json()) {
            out.push(k, v);
        }
        let g = &self.hint_graph;
        out.push(
            "hint_graph",
            Value::object([
                ("unreached", texts(&g.unreached)),
                ("no_next", texts(&g.no_next)),
            ]),
        );
        out.push("gates", self.gates_json());
        Value::Object(out)
    }
}
