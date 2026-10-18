//! The JSON of verdicts and why trees.

use std::collections::BTreeMap;

use ghidorah_analysis::Rule;
use ghidorah_analysis::facts::{Evidence, Gap, Node, Outcome, fact_name};
use ghidorah_json::{Object, Value};

use crate::errors::ToolError;

/// The largest number of evidence items and gaps of one verdict.
pub const MAX_ITEMS: usize = 20;

/// Gives the verdict entry of a claim. On a partial analysis, `basis.complete` is false.
#[must_use]
pub fn verdict(claim: &Value, out: &Outcome, partial: bool) -> Value {
    let evidence = out
        .evidence
        .iter()
        .take(MAX_ITEMS)
        .map(|e| Value::from(Evidence::text(e)))
        .collect();
    let gaps = out
        .gaps
        .iter()
        .take(MAX_ITEMS)
        .map(|g| Value::from(Gap::text(g)))
        .collect();
    let mut basis = Object::new();
    basis.push("complete", Value::Bool(out.complete() && !partial));
    basis.push("gaps", Value::Array(gaps));
    if out.stopped {
        basis.push("stopped_by", Value::from("fuel"));
    }
    Value::object([
        ("claim", claim.clone()),
        ("verdict", Value::from(out.verdict.name())),
        ("evidence", Value::Array(evidence)),
        ("basis", Value::Object(basis)),
    ])
}

/// Gives the entry of an item whose input does not resolve: `{ <key>: input, error }`.
#[must_use]
pub fn error(key: &str, input: &Value, error: &ToolError) -> Value {
    Value::object([(key, input.clone()), ("error", error.to_json())])
}

/// Gives the JSON of a why tree. Each rule of the tree goes into `rules` with its doc line.
#[must_use]
pub fn tree(node: &Node, rules: &mut BTreeMap<String, &'static str>) -> Value {
    let mut out = Object::new();
    out.push("id", Value::from(node.id.as_str()));
    out.push("fact", Value::from(fact_name(&node.key)));
    if let Some(rule) = &node.rule {
        let doc = Rule::parse(rule.as_str()).map_or("", Rule::doc);
        rules.insert(rule.as_str().to_owned(), doc);
        out.push("rule", Value::from(rule.as_str()));
    }
    if let Some(source) = node.source {
        out.push("source", Value::from(source.name()));
    }
    let premises = node.premises.iter().map(|n| tree(n, rules)).collect();
    out.push("premises", Value::Array(premises));
    if node.truncated {
        out.push("truncated", Value::Bool(true));
    }
    if node.cycle {
        out.push("cycle", Value::Bool(true));
    }
    Value::Object(out)
}

/// Gives the rules list `[{ rule, doc }]` in code order.
#[must_use]
pub fn rules(rules: &BTreeMap<String, &'static str>) -> Value {
    Value::Array(
        rules
            .iter()
            .map(|(rule, doc)| {
                Value::object([
                    ("rule", Value::from(rule.as_str())),
                    ("doc", Value::from(*doc)),
                ])
            })
            .collect(),
    )
}
