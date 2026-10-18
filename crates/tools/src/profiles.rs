//! Profiles, the tool allowlist and the `tools/list` entries (design Section 10.3, ADR-0005).
//!
//! A profile is registry data: each [`ToolSpec`] lists the profiles that hold it.
//! The server flag `--tools a,b` adds an allowlist on top of the profile. Every profile keeps
//! the registry order (AC-130c).
//!
//! | Profile | Tools | Annotations in `tools/list` |
//! |---|---|---|
//! | `full` | every tool | as registered |
//! | `readonly` | the read-only tools and `batch_run` | `readOnlyHint: true`, `destructiveHint: false` (Section 11.7) |
//! | `mini` | 10 core tools | as registered |

use std::collections::BTreeSet;

use ghidorah_json::Value;

use crate::registry::Registry;
use crate::schema::{Detail, catalog_schema};
use crate::spec::{Profile, ToolSpec};

/// The largest number of tools in the `full` profile (AC-130a).
pub const MAX_FULL: usize = 25;

/// The largest number of tools in the `mini` profile (AC-130a).
pub const MAX_MINI: usize = 10;

/// The largest `tools/list` of `full` in characters (AC-131a).
pub const MAX_FULL_CHARS: usize = 24_000;

/// The largest `tools/list` of `mini` in characters (AC-131b).
pub const MAX_MINI_CHARS: usize = 6_000;

/// The active profile and the optional allowlist of a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSet {
    profile: Profile,
    allow: Option<BTreeSet<String>>,
}

impl Default for ProfileSet {
    fn default() -> Self {
        Self::new(Profile::Full, None)
    }
}

/// Parses a profile name: `full`, `readonly` or `mini`.
#[must_use]
pub fn parse_profile(text: &str) -> Option<Profile> {
    Profile::ALL.into_iter().find(|p| p.as_str() == text)
}

impl ProfileSet {
    /// Makes the set of `profile` with the allowlist `allow`, or no allowlist for `None`.
    #[must_use]
    pub fn new(profile: Profile, allow: Option<Vec<String>>) -> Self {
        Self {
            profile,
            allow: allow.map(|names| names.into_iter().collect()),
        }
    }

    /// Gives the profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// Gives the allowlist, or `None` when every tool of the profile is active.
    #[must_use]
    pub const fn allowlist(&self) -> Option<&BTreeSet<String>> {
        self.allow.as_ref()
    }

    /// Tells if the active tools hold the tool `name` of `registry`.
    #[must_use]
    pub fn holds<S: 'static>(&self, registry: &Registry<S>, name: &str) -> bool {
        registry
            .get(name)
            .is_some_and(|(_, tool)| self.holds_tool(tool))
    }

    /// Tells if the active tools hold `tool`.
    fn holds_tool<S: 'static>(&self, tool: &ToolSpec<S>) -> bool {
        tool.profiles.contains(&self.profile)
            && self.allow.as_ref().is_none_or(|a| a.contains(tool.name))
    }

    /// Gives the active tools of `registry` in registry order.
    #[must_use]
    pub fn tools<S: 'static>(&self, registry: &Registry<S>) -> Vec<&'static ToolSpec<S>> {
        registry
            .tools()
            .iter()
            .copied()
            .filter(|tool| self.holds_tool(tool))
            .collect()
    }

    /// Gives the allowlist names that name no tool of `registry`, in name order.
    #[must_use]
    pub fn unknown<S: 'static>(&self, registry: &Registry<S>) -> Vec<String> {
        self.allow
            .iter()
            .flatten()
            .filter(|name| registry.get(name).is_none())
            .cloned()
            .collect()
    }

    /// Gives the MCP annotations of `tool` in this profile:
    /// `{ title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint }`.
    #[must_use]
    pub fn annotations<S: 'static>(&self, tool: &ToolSpec<S>) -> Value {
        let a = tool.annotations;
        let readonly = self.profile == Profile::Readonly;
        Value::object([
            ("title", Value::from(tool.title)),
            ("readOnlyHint", Value::Bool(a.read_only || readonly)),
            ("destructiveHint", Value::Bool(a.destructive && !readonly)),
            ("idempotentHint", Value::Bool(a.idempotent)),
            ("openWorldHint", Value::Bool(a.open_world)),
        ])
    }

    /// Gives the `tools/list` entry of `tool` in this profile:
    /// `{ name, title, description, inputSchema, annotations }`.
    #[must_use]
    pub fn entry<S: 'static>(&self, tool: &ToolSpec<S>) -> Value {
        let (detail, text) = match self.profile {
            Profile::Mini => (Detail::Compact, tool.summary),
            Profile::Full | Profile::Readonly => (Detail::Catalog, tool.description),
        };
        let mut hints = self.annotations(tool);
        if let Some(object) = hints.as_object_mut() {
            let _ = object.remove("title");
        }
        let mut out = ghidorah_json::Object::new();
        out.push("name", Value::from(tool.name));
        if detail != Detail::Compact {
            out.push("title", Value::from(tool.title));
        }
        out.push("description", Value::from(text));
        out.push("inputSchema", catalog_schema(tool, detail));
        out.push("annotations", hints);
        Value::Object(out)
    }

    /// Gives the `tools` array of `tools/list`: one entry per active tool in registry order.
    #[must_use]
    pub fn tools_list<S: 'static>(&self, registry: &Registry<S>) -> Value {
        Value::Array(
            self.tools(registry)
                .into_iter()
                .map(|tool| self.entry(tool))
                .collect(),
        )
    }
}
