//! The registry lint (AC-129a to AC-129f, AC-222).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_json::{Limits, Value};

use super::{
    LintFinding, LintRule, MAX_ACTION_LINE, MAX_DESCRIPTION, Registry, first_sentence, is_name,
    resource_word, schema_root_problem,
};
use crate::args::{check_value, globals_of, parse};
use crate::schema::input_schema;
use crate::spec::{ArgKind, ArgSpec, GroupRule, Role, ToolSpec};

/// The first tool and name of each role and kind: `(role, kind key) -> (name, tool)`.
type Vocabulary = BTreeMap<(Role, String), (&'static str, &'static str)>;

/// Collects the findings of one tool.
struct Out<'a> {
    tool: &'a str,
    found: Vec<LintFinding>,
}

impl Out<'_> {
    fn add(&mut self, rule: LintRule, detail: String) {
        self.found.push(LintFinding {
            tool: self.tool.to_owned(),
            rule,
            detail,
        });
    }
}

/// Runs the lint over every tool of `registry`. The findings are in tool order, then rule order.
#[must_use]
pub fn lint<S: 'static>(registry: &Registry<S>) -> Vec<LintFinding> {
    let mut all = Vec::new();
    let mut names = BTreeSet::new();
    let mut vocabulary = Vocabulary::new();
    for tool in registry.tools() {
        let mut out = Out {
            tool: tool.name,
            found: Vec::new(),
        };
        if !is_name(tool.name) {
            out.add(
                LintRule::Name,
                "the name does not match the name pattern".to_owned(),
            );
        }
        if !names.insert(tool.name) {
            out.add(LintRule::Name, "the name is not unique".to_owned());
        }
        if let Some(problem) = schema_root_problem(&input_schema(tool)) {
            out.add(LintRule::SchemaRoot, problem);
        }
        annotations(tool, &mut out);
        description(tool, &mut out);
        actions(tool, &mut out);
        for spec in tool.args {
            vocabulary_of(tool.name, spec, &mut vocabulary, &mut out);
        }
        args(tool, &mut out);
        examples(tool, &mut out);
        out.found.sort();
        all.append(&mut out.found);
    }
    all
}

fn annotations<S: 'static>(tool: &ToolSpec<S>, out: &mut Out<'_>) {
    let a = tool.annotations;
    if a.open_world {
        out.add(LintRule::Annotations, "openWorldHint is true".to_owned());
    }
    if a.read_only == tool.mutating {
        out.add(
            LintRule::Annotations,
            "readOnlyHint does not agree with mutating".to_owned(),
        );
    }
    if a.read_only && a.destructive {
        out.add(
            LintRule::Annotations,
            "a read-only tool is destructive".to_owned(),
        );
    }
    if tool.actions.iter().any(|x| x.destructive) && !a.destructive {
        out.add(
            LintRule::Annotations,
            "a destructive action needs destructiveHint".to_owned(),
        );
    }
}

fn description<S: 'static>(tool: &ToolSpec<S>, out: &mut Out<'_>) {
    if tool.description.chars().count() > MAX_DESCRIPTION {
        out.add(
            LintRule::Description,
            format!("the description has more than {MAX_DESCRIPTION} characters"),
        );
    }
    if tool.title.is_empty() || tool.description.is_empty() {
        out.add(
            LintRule::Description,
            "the title or the description is empty".to_owned(),
        );
    }
    let first = first_sentence(tool.description);
    if first != tool.summary {
        out.add(
            LintRule::FirstSentence,
            "the summary is not the first sentence of the description".to_owned(),
        );
    }
    let word = resource_word(tool.name).to_ascii_lowercase();
    if !first.to_ascii_lowercase().contains(&word) {
        out.add(
            LintRule::FirstSentence,
            format!("the first sentence does not hold the resource word {word}"),
        );
    }
}

fn actions<S: 'static>(tool: &ToolSpec<S>, out: &mut Out<'_>) {
    let Some(selector) = tool.selector() else {
        if !tool.actions.is_empty() {
            out.add(
                LintRule::Actions,
                "the tool has actions but no selector".to_owned(),
            );
        }
        return;
    };
    let ArgKind::Enum(values) = selector.kind else {
        out.add(LintRule::Actions, "the selector is not an enum".to_owned());
        return;
    };
    let listed: Vec<&str> = tool.actions.iter().map(|a| a.value).collect();
    if listed != values {
        out.add(
            LintRule::Actions,
            "the actions differ from the selector values".to_owned(),
        );
    }
    for action in tool.actions {
        let line = action.line;
        if line.is_empty() || line.contains('\n') || line.chars().count() > MAX_ACTION_LINE {
            out.add(
                LintRule::Actions,
                format!("the action {} has no single description line", action.value),
            );
        }
        let value = ghidorah_json::parse(action.example, &Limits::DEFAULT).ok();
        let picked = value
            .as_ref()
            .and_then(|v| v.get(selector.name))
            .and_then(Value::as_str);
        if picked != Some(action.value) {
            out.add(
                LintRule::Actions,
                format!(
                    "the example of the action {} has another selector value",
                    action.value
                ),
            );
        }
        if !tool.examples.iter().any(|e| e.args == action.example) {
            out.add(
                LintRule::Actions,
                format!(
                    "the example of the action {} is not an executed example",
                    action.value
                ),
            );
        }
    }
}

/// Gives the key of an argument kind for the vocabulary rule.
fn kind_key(kind: &ArgKind) -> String {
    match kind {
        ArgKind::Addr => "addr".to_owned(),
        ArgKind::AddrList(_) => "addr_list".to_owned(),
        ArgKind::Id(kinds) => {
            let prefixes: Vec<&str> = kinds.iter().map(|k| k.prefix()).collect();
            format!("id:{}", prefixes.join(","))
        }
        ArgKind::Int { .. } => "int".to_owned(),
        ArgKind::Str(_) => "str".to_owned(),
        ArgKind::Enum(values) => format!("enum:{}", values.join(",")),
        ArgKind::Bool => "bool".to_owned(),
        ArgKind::Obj(_) => "obj".to_owned(),
        ArgKind::List(item, _) => format!("list:{}", kind_key(&item.kind)),
        ArgKind::Json => "json".to_owned(),
    }
}

fn vocabulary_of(
    tool: &'static str,
    spec: &'static ArgSpec,
    vocabulary: &mut Vocabulary,
    out: &mut Out<'_>,
) {
    if let Some(fixed) = spec.role.fixed_name()
        && fixed != spec.name
    {
        out.add(
            LintRule::Vocabulary,
            format!("the argument {} has the role of {fixed}", spec.name),
        );
    }
    if spec.role != Role::Param {
        let key = (spec.role, kind_key(&spec.kind));
        let (first, owner) = *vocabulary.entry(key).or_insert((spec.name, tool));
        if first != spec.name {
            out.add(
                LintRule::Vocabulary,
                format!(
                    "the argument {} has the role and kind of the argument {first} of {owner}",
                    spec.name
                ),
            );
        }
    }
    if let ArgKind::Obj(members) = spec.kind {
        for member in members {
            vocabulary_of(tool, member, vocabulary, out);
        }
    }
}

fn args<S: 'static>(tool: &ToolSpec<S>, out: &mut Out<'_>) {
    let globals: Vec<&str> = globals_of(tool).iter().map(|g| g.name).collect();
    level(tool, tool.args, &globals, out);
    for group in tool.groups {
        for member in group.members {
            match tool.arg(member) {
                None => out.add(
                    LintRule::Args,
                    format!("the group member {member} is not an argument"),
                ),
                Some(spec) if spec.required && group.rule == GroupRule::ExactlyOne => out.add(
                    LintRule::Args,
                    format!("the group member {member} is required"),
                ),
                Some(_) => {}
            }
        }
    }
}

/// Checks the arguments of one object level. `taken` holds the names of the level above.
fn level<S: 'static>(
    tool: &ToolSpec<S>,
    specs: &'static [ArgSpec],
    taken: &[&str],
    out: &mut Out<'_>,
) {
    let mut seen: BTreeSet<&str> = taken.iter().copied().collect();
    for spec in specs {
        if !is_name(spec.name) {
            out.add(
                LintRule::Args,
                format!("the argument name {} is not valid", spec.name),
            );
        }
        if !seen.insert(spec.name) {
            out.add(
                LintRule::Args,
                format!("the argument name {} is not unique", spec.name),
            );
        }
        if spec.doc.is_empty() {
            out.add(
                LintRule::Args,
                format!("the argument {} has no doc", spec.name),
            );
        }
        if let Some(text) = spec.default {
            let sound = ghidorah_json::parse(text, &Limits::DEFAULT)
                .is_ok_and(|v| check_value(spec, &v).is_ok());
            if !sound || spec.required {
                out.add(
                    LintRule::Args,
                    format!("the default of {} is not sound", spec.name),
                );
            }
        }
        for (selector, value) in spec.required_when.iter().chain(spec.forbidden_when) {
            let known = tool.arg(selector).is_some_and(|s| {
                s.role == Role::Selector && matches!(s.kind, ArgKind::Enum(v) if v.contains(value))
            });
            if !known {
                out.add(
                    LintRule::Args,
                    format!(
                        "the rule of {} names an unknown action {selector}={value}",
                        spec.name
                    ),
                );
            }
        }
        if let ArgKind::Obj(members) = spec.kind {
            level(tool, members, &[], out);
        }
    }
    for spec in specs {
        for alias in spec.aliases {
            if !is_name(alias) || !seen.insert(alias) {
                out.add(
                    LintRule::Args,
                    format!("the alias {alias} of {} is not free", spec.name),
                );
            }
        }
    }
}

fn examples<S: 'static>(tool: &ToolSpec<S>, out: &mut Out<'_>) {
    if tool.examples.is_empty() {
        out.add(LintRule::Examples, "the tool has no example".to_owned());
    }
    for example in tool.examples {
        let parsed = ghidorah_json::parse(example.args, &Limits::DEFAULT)
            .ok()
            .map(|value| parse(tool, &value, None));
        match parsed {
            Some(Ok(_)) => {}
            Some(Err(e)) => out.add(
                LintRule::Examples,
                format!("the example {} gives {}", example.args, e.code),
            ),
            None => out.add(
                LintRule::Examples,
                format!("the example {} is not JSON", example.args),
            ),
        }
        let json = std::path::Path::new(example.golden)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        if !json {
            out.add(
                LintRule::Examples,
                format!("the golden {} is not a JSON file", example.golden),
            );
        }
    }
}
