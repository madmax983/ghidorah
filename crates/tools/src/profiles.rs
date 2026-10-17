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
    let _ = text;
    None
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
        let _ = (registry, name);
        false
    }

    /// Gives the active tools of `registry` in registry order.
    #[must_use]
    pub fn tools<S: 'static>(&self, registry: &Registry<S>) -> Vec<&'static ToolSpec<S>> {
        let _ = registry;
        Vec::new()
    }

    /// Gives the allowlist names that name no tool of `registry`, in name order.
    #[must_use]
    pub fn unknown<S: 'static>(&self, registry: &Registry<S>) -> Vec<String> {
        let _ = registry;
        Vec::new()
    }

    /// Gives the MCP annotations of `tool` in this profile:
    /// `{ title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint }`.
    #[must_use]
    pub fn annotations<S: 'static>(&self, tool: &ToolSpec<S>) -> Value {
        let _ = tool;
        Value::Null
    }

    /// Gives the `tools/list` entry of `tool` in this profile:
    /// `{ name, title, description, inputSchema, annotations }`.
    #[must_use]
    pub fn entry<S: 'static>(&self, tool: &ToolSpec<S>) -> Value {
        let _ = tool;
        Value::Null
    }

    /// Gives the `tools` array of `tools/list`: one entry per active tool in registry order.
    #[must_use]
    pub fn tools_list<S: 'static>(&self, registry: &Registry<S>) -> Value {
        let _ = registry;
        Value::Array(Vec::new())
    }
}
