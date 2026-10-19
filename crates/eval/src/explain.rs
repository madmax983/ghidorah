//! The failure list of one eval run: `ghidorah-eval --explain`.

use ghidorah_json::Value;

use crate::report::Report;

fn texts(v: &[String]) -> Value {
    Value::Array(v.iter().map(|s| Value::from(s.as_str())).collect())
}

impl Report {
    /// Gives the failures of the run as one JSON object. It lists the failed scenarios, the
    /// mistakes that the robot does not repair and the walks that miss evidence. It also lists
    /// the recall misses, the survey misses, the lint findings and the second runs that differ.
    #[must_use]
    pub fn explain(&self) -> Value {
        let scenarios = self
            .outcomes
            .iter()
            .chain(&self.ab_outcomes)
            .filter(|o| !o.pass)
            .map(|o| {
                Value::object([
                    ("id", Value::from(o.id.as_str())),
                    ("error", o.error.as_deref().map_or(Value::Null, Value::from)),
                    ("answer", o.answer.clone().unwrap_or(Value::Null)),
                ])
            });
        let mistakes = self
            .repair
            .attempts
            .iter()
            .filter(|a| !(a.triggered && a.ok))
            .map(|a| {
                Value::object([
                    ("id", Value::from(a.id.as_str())),
                    ("code", Value::from(a.code.as_str())),
                    ("triggered", Value::from(a.triggered)),
                    ("rank", Value::from(a.rank)),
                ])
            });
        let walks = self.follower.walks.iter().filter(|w| !w.reached).map(|w| {
            Value::object([
                ("scenario", Value::from(w.scenario.as_str())),
                ("calls", Value::from(w.calls)),
                ("missing", texts(&w.missing)),
            ])
        });
        let survey = self
            .survey
            .fixtures
            .iter()
            .filter(|f| !f.missed.is_empty())
            .map(|f| {
                Value::object([
                    ("fixture", Value::from(f.fixture.as_str())),
                    ("missed", texts(&f.missed)),
                ])
            });
        let (_, findings) = self.provenance();
        let lint = findings.iter().map(|f| {
            Value::object([
                ("scenario", Value::from(f.scenario.as_str())),
                ("path", Value::from(f.path.as_str())),
                ("reason", Value::from(f.reason.as_str())),
            ])
        });
        let differ = self.nondeterministic().into_iter().map(|(id, turn, ptr)| {
            Value::object([
                ("id", Value::from(id)),
                ("turn", Value::from(u64::try_from(turn).unwrap_or(0))),
                ("ptr", Value::from(ptr)),
            ])
        });
        Value::object([
            ("scenarios", Value::Array(scenarios.collect())),
            ("mistakes", Value::Array(mistakes.collect())),
            ("walks", Value::Array(walks.collect())),
            ("recall_reset", texts(&self.recall_reset.missed)),
            ("recall_edits", texts(&self.recall_edits.missed)),
            ("survey", Value::Array(survey.collect())),
            ("lint", Value::Array(lint.collect())),
            ("differ", Value::Array(differ.collect())),
            ("fuzz", texts(&self.fuzz.violations)),
        ])
    }
}
