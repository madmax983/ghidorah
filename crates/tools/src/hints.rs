//! Executable hints: `next` calls and warning remedies (design Section 10.6, AC-143).
//!
//! A hint is a complete call. The pipeline keeps a hint only when it names a tool of the
//! registry and the active profile, and when its arguments pass the strict parser of that
//! tool. A result keeps at most [`MAX_NEXT`] hints. Hint arguments carry IDs and addresses
//! only, never binary text (ADR-0022).

use std::fmt;

use ghidorah_json::Value;

use crate::args;
use crate::registry::Registry;

/// The largest number of `next` calls in one result.
pub const MAX_NEXT: usize = 3;

/// The `why` of a repair call that renames or removes unknown keys.
pub const WHY_NAMES: &str = "Send the call with the argument names of the schema.";

/// The `why` of a repair call that clamps a value to its cap.
pub const WHY_CLAMP: &str = "Send the call with the value at its cap.";

/// The `why` of a repair call that sends an address as hex text.
pub const WHY_HEX: &str = "Send the address as a 0x hex string.";

/// The `why` of a `tool_search` call for the schema of a tool.
pub const WHY_SCHEMA: &str = "Get the schema and the examples of the tool.";

/// The `why` of a `tool_search` call for an unknown tool name.
pub const WHY_SEARCH: &str = "Search the tools for the name.";

/// The `why` of a repair call with the current rev.
pub const WHY_REV: &str = "Send the call again with the current rev.";

/// The `why` of a repair call without the cursor.
pub const WHY_FIRST_PAGE: &str = "Start again at the first page.";

/// The `why` of an `analysis_run` call on a partial result.
pub const WHY_ANALYSIS: &str = "Finish the analysis of the binary.";

/// The `why` of a `session_brief` call when no binary is open.
pub const WHY_BRIEF: &str = "List the projects on disk and the open binaries.";

/// The page hint of a list with more items.
pub const HINT_NEXT_PAGE: &str = "Send page.next_cursor as cursor to get the next page.";

/// The page hint of a list whose next item does not fit the budget.
pub const HINT_TOO_BIG: &str =
    "The next item does not fit in max_chars. Raise max_chars, or add fields for smaller items.";

/// Every fixed text that the pipeline sends to an agent. Test `ac_024` checks them.
pub const TEXTS: [&str; 11] = [
    WHY_NAMES,
    WHY_CLAMP,
    WHY_HEX,
    WHY_SCHEMA,
    WHY_SEARCH,
    WHY_REV,
    WHY_FIRST_PAGE,
    WHY_ANALYSIS,
    WHY_BRIEF,
    HINT_NEXT_PAGE,
    HINT_TOO_BIG,
];

/// One executable call: `{ tool, args, why }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The tool name.
    pub tool: String,
    /// The arguments: a JSON object.
    pub args: Value,
    /// Why the agent sends the call: one STE sentence with no binary text.
    pub why: String,
}

impl Call {
    /// Makes a call.
    #[must_use]
    pub fn new(tool: &str, args: Value, why: &str) -> Self {
        Self {
            tool: tool.to_owned(),
            args,
            why: why.to_owned(),
        }
    }

    /// Gives the JSON form `{ tool, args, why }`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

/// Why the pipeline drops a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintError {
    /// The registry has no tool with the name.
    UnknownTool,
    /// The active profile does not hold the tool.
    NotInProfile,
    /// The arguments fail the strict parser of the tool. The code tells why.
    Args(ghidorah_base::ErrorCode),
}

impl fmt::Display for HintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool => {
                f.write_str("The hint names a tool that the registry does not hold.")
            }
            Self::NotInProfile => f.write_str("The hint names a tool outside the active profile."),
            Self::Args(code) => write!(f, "The hint arguments fail the parser with {code}."),
        }
    }
}

impl std::error::Error for HintError {}

/// Checks one hint against `registry`. `in_profile` tells if the active profile holds a tool.
///
/// # Errors
///
/// Returns [`HintError`] when the tool is unknown or outside the profile, or when the
/// arguments fail the strict parser of the tool.
pub fn check<S: 'static>(
    registry: &Registry<S>,
    in_profile: &dyn Fn(&str) -> bool,
    call: &Call,
) -> Result<(), HintError> {
    let _ = (registry, in_profile, call, args::parse_strict::<S>);
    Err(HintError::UnknownTool)
}

/// Gives the valid hints of `calls` in their order, at most [`MAX_NEXT`].
#[must_use]
pub fn keep_valid<S: 'static>(
    registry: &Registry<S>,
    in_profile: &dyn Fn(&str) -> bool,
    calls: Vec<Call>,
) -> Vec<Call> {
    let _ = (registry, in_profile, calls);
    Vec::new()
}
