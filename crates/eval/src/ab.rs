//! The A/B surface comparison and the ablation (design Sections 12.4 and 12.8).
//!
//! Five questions have two scripts: single calls in `eval/scenarios/` and a `batch_run` form
//! in `eval/ab/`. A pair meets the ADR-0014 decision rule when the batch form saves 30% of
//! calls and 20% of characters. The rule confirms `batch_run` when 4 of the 5 pairs meet it.
//!
//! The ablation runs the scenarios again with `shape: "table"` on each list call, and counts
//! the calls that the `*` references of the scripts save.

use ghidorah_json::Value;

use crate::milli::Milli;
use crate::runner::Outcome;
use crate::scenario::Scenario;

/// The smallest call saving of the decision rule.
pub const MIN_CALLS_SAVED: Milli = Milli(300);

/// The smallest character saving of the decision rule.
pub const MIN_CHARS_SAVED: Milli = Milli(200);

/// The number of pairs that must meet the rule.
pub const MIN_PAIRS: usize = 4;

/// One A/B pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    /// The ID of the single-call scenario.
    pub id: String,
    /// `true` when both forms pass.
    pub pass: bool,
    /// The calls of the single form.
    pub single_calls: u64,
    /// The calls of the batch form.
    pub batch_calls: u64,
    /// The characters of the single form.
    pub single_chars: u64,
    /// The characters of the batch form.
    pub batch_chars: u64,
}

impl Pair {
    /// Gives the fraction of calls that the batch form saves.
    #[must_use]
    pub fn calls_saved(&self) -> Milli {
        Milli::ratio(
            self.single_calls.saturating_sub(self.batch_calls),
            self.single_calls,
        )
    }

    /// Gives the fraction of characters that the batch form saves.
    #[must_use]
    pub fn chars_saved(&self) -> Milli {
        Milli::ratio(
            self.single_chars.saturating_sub(self.batch_chars),
            self.single_chars,
        )
    }

    /// Tells if the pair meets the decision rule.
    #[must_use]
    pub fn meets(&self) -> bool {
        self.pass && self.calls_saved() >= MIN_CALLS_SAVED && self.chars_saved() >= MIN_CHARS_SAVED
    }
}

/// Gives the pairs of the batch forms `ab` with the single-call outcomes `single`.
#[must_use]
pub fn pairs(ab: &[(&Scenario, &Outcome)], single: &[Outcome]) -> Vec<Pair> {
    ab.iter()
        .filter_map(|(s, b)| {
            let id = s.pair.as_ref()?;
            let a = single.iter().find(|o| &o.id == id)?;
            Some(Pair {
                id: id.clone(),
                pass: a.pass && b.pass,
                single_calls: a.calls,
                batch_calls: b.calls,
                single_chars: a.chars,
                batch_chars: b.chars,
            })
        })
        .collect()
}

/// Tells if the pairs confirm `batch_run` under the decision rule.
#[must_use]
pub fn confirms(pairs: &[Pair]) -> bool {
    pairs.iter().filter(|p| p.meets()).count() >= MIN_PAIRS
}

/// The list tools whose calls take `shape: "table"` in the ablation.
pub const LIST_TOOLS: &[&str] = &["func_list", "xref_list", "search", "history_list"];

/// Gives the calls that the `*` references of a run save: one call per extra value.
#[must_use]
pub fn star_calls(scenario: &Scenario, outcome: &Outcome) -> u64 {
    let mut saved = 0u64;
    for (turn, sent) in scenario.turns.iter().zip(&outcome.sent) {
        if turn.batch {
            continue;
        }
        if let (Value::Object(script), Value::Object(args)) = (&turn.args, sent) {
            for (key, v) in script.iter() {
                let star = v.get("$turn").is_some()
                    && v.get("ptr")
                        .and_then(Value::as_str)
                        .is_some_and(|p| p.contains('*'));
                if let (true, Some(Value::Array(values))) = (star, args.get(key)) {
                    saved = saved
                        .saturating_add(u64::try_from(values.len()).unwrap_or(0).saturating_sub(1));
                }
            }
        }
    }
    saved
}

/// The ablation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ablation {
    /// The characters of the list calls in the default `objects` shape.
    pub objects_chars: u64,
    /// The characters of the same calls with `shape: "table"`.
    pub table_chars: u64,
    /// The calls that the `*` references save over one call per value.
    pub star_calls_saved: u64,
}

/// Gives the characters of the list calls of a run.
#[must_use]
pub fn list_chars(scenario: &Scenario, outcome: &Outcome) -> u64 {
    scenario
        .turns
        .iter()
        .zip(&outcome.responses)
        .filter(|(t, _)| LIST_TOOLS.contains(&t.tool.as_str()))
        .map(|(_, r)| crate::host::chars(r))
        .sum()
}
