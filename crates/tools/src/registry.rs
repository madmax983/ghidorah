//! The tool registry and the registry lint (design Section 10.1, ADR-0005).
//!
//! [`shipped`] is the plain list of the shipped tools in the fixed `tools/list` order.
//! Each WP adds its `&handlers::<tool>::SPEC` items in one register commit (Section 14.1).
//! [`Registry::new`] makes any other registry, for example a test registry.
//!
//! The lint checks every tool of a registry:
//!
//! | Rule | Check | AC |
//! |---|---|---|
//! | [`LintRule::Name`] | The name matches `^[a-z][a-z0-9_]{0,40}$` and is unique. | AC-129a |
//! | [`LintRule::SchemaRoot`] | The schema root is an object with `additionalProperties: false` and no combinator. | AC-129b |
//! | [`LintRule::Annotations`] | The tool has all four annotations, `openWorldHint` is false, and they agree with `mutating`. | AC-129c |
//! | [`LintRule::Description`] | The description has at most 1,000 characters, and the tool has a title. | AC-129d |
//! | [`LintRule::FirstSentence`] | The summary is the first sentence, and it holds the resource word of the name. | AC-129e |
//! | [`LintRule::Actions`] | Each action has one line and one example, and the actions match the selector. | AC-129f |
//! | [`LintRule::Vocabulary`] | A role has its fixed name, and one kind and role has one name in all tools. | AC-222 |
//! | [`LintRule::Args`] | Argument names are valid and unique, and docs, defaults, groups and rules are sound. | - |
//! | [`LintRule::Examples`] | Each tool has an example, and each example parses. | AC-132a |

mod lint;

use std::fmt;

pub use lint::lint;

use crate::schema::ROOT_COMBINATORS;
use crate::session::Session;
use crate::spec::ToolSpec;

/// The largest number of characters in a description.
pub const MAX_DESCRIPTION: usize = 1_000;

/// The largest number of characters in an action line.
pub const MAX_ACTION_LINE: usize = 200;

/// The longest tool or argument name.
pub const MAX_NAME: usize = 41;

/// A list of tools.
pub struct Registry<S: 'static> {
    tools: &'static [&'static ToolSpec<S>],
}

impl<S: 'static> Clone for Registry<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: 'static> Copy for Registry<S> {}

impl<S: 'static> fmt::Debug for Registry<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("tools", &self.names())
            .finish()
    }
}

impl<S: 'static> Registry<S> {
    /// Makes a registry of `tools` in this order.
    #[must_use]
    pub const fn new(tools: &'static [&'static ToolSpec<S>]) -> Self {
        Self { tools }
    }

    /// Gives the tools in registry order.
    #[must_use]
    pub const fn tools(&self) -> &'static [&'static ToolSpec<S>] {
        self.tools
    }

    /// Gives the index and the spec of the tool `name`, or `None`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<(usize, &'static ToolSpec<S>)> {
        self.tools
            .iter()
            .enumerate()
            .find(|(_, tool)| tool.name == name)
            .map(|(i, tool)| (i, *tool))
    }

    /// Gives the tool names in registry order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.tools.iter().map(|tool| tool.name).collect()
    }
}

/// The shipped tools in the fixed `tools/list` order (design Section 10.4).
///
/// Each handler WP adds its `SPEC` items at their catalog positions: one line per tool.
static SHIPPED: &[&ToolSpec<Session>] = &[
    &crate::handlers::load::SPEC,
    &crate::handlers::survey::SPEC,
    &crate::handlers::analysis_run::SPEC,
    &crate::handlers::func_list::SPEC,
    &crate::handlers::func_get::SPEC,
    &crate::handlers::xref_list::SPEC,
    &crate::handlers::search::SPEC,
    &crate::handlers::mem_read::SPEC,
    &crate::handlers::addr_info::SPEC,
    &crate::handlers::calc::SPEC,
    &crate::handlers::fact_check::SPEC,
    &crate::handlers::type_get::SPEC,
    &crate::handlers::history_list::SPEC,
    &crate::handlers::session_brief::SPEC,
    &crate::handlers::tool_search::SPEC,
    &crate::handlers::symbol_rename::SPEC,
    &crate::handlers::comment_set::SPEC,
    &crate::handlers::note_write::SPEC,
    &crate::handlers::func_edit::SPEC,
    &crate::handlers::type_edit::SPEC,
    &crate::handlers::history_undo::SPEC,
];

/// Gives the shipped registry: the plain list of the shipped tools.
#[must_use]
pub fn shipped() -> Registry<Session> {
    Registry::new(SHIPPED)
}

/// One rule of the registry lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LintRule {
    /// AC-129a.
    Name,
    /// AC-129b.
    SchemaRoot,
    /// AC-129c.
    Annotations,
    /// AC-129d.
    Description,
    /// AC-129e.
    FirstSentence,
    /// AC-129f.
    Actions,
    /// AC-222.
    Vocabulary,
    /// Argument names, docs, defaults, groups and action rules.
    Args,
    /// Examples.
    Examples,
}

/// One finding of the registry lint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LintFinding {
    /// The tool name.
    pub tool: String,
    /// The broken rule.
    pub rule: LintRule,
    /// What is wrong.
    pub detail: String,
}

impl fmt::Display for LintFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:?}: {}", self.tool, self.rule, self.detail)
    }
}

/// Tells if `name` matches `^[a-z][a-z0-9_]{0,40}$`.
#[must_use]
pub fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= MAX_NAME
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Gives the resource word of a tool name: the part before the first `_`.
#[must_use]
pub fn resource_word(name: &str) -> &str {
    name.split('_').next().unwrap_or(name)
}

/// Gives the first sentence of `text`: the text up to the first `.`, `!` or `?` that ends
/// the text or comes before a space.
#[must_use]
pub fn first_sentence(text: &str) -> &str {
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let next = bytes.get(i + 1);
        if matches!(b, b'.' | b'!' | b'?') && next.is_none_or(u8::is_ascii_whitespace) {
            return text.get(..=i).unwrap_or(text);
        }
    }
    text
}

/// Gives the problem of the root of an input schema, or `None` when the root is sound.
///
/// A sound root is an object schema with `properties`, `additionalProperties: false` and no
/// combinator of [`crate::schema::ROOT_COMBINATORS`].
#[must_use]
pub fn schema_root_problem(schema: &ghidorah_json::Value) -> Option<String> {
    use ghidorah_json::Value;
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Some("the root type is not object".to_owned());
    }
    if schema
        .get("properties")
        .and_then(Value::as_object)
        .is_none()
    {
        return Some("the root has no properties object".to_owned());
    }
    if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
        return Some("the root does not set additionalProperties to false".to_owned());
    }
    ROOT_COMBINATORS
        .iter()
        .find(|key| schema.get(key).is_some())
        .map(|key| format!("the root has the combinator {key}"))
}
