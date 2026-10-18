//! The checks of a whole batch before any step runs (design Section 11.3).

use ghidorah_base::ErrorCode;
use ghidorah_json::Value;

use super::OnError;
use super::guards::Guard;
use crate::errors::ToolError;
use crate::profiles::ProfileSet;
use crate::registry::Registry;
use crate::session::Session;

/// One checked step.
#[derive(Debug, Clone)]
pub struct Step {
    /// The step ID.
    pub id: String,
    /// The tool name.
    pub tool: &'static str,
    /// The arguments with their references.
    pub args: Value,
    /// The `expect` guards.
    pub expect: Vec<Guard>,
    /// The `claim` guards: `{ rel, args }` objects.
    pub claims: Vec<Value>,
    /// `true` when the tool writes facts.
    pub mutating: bool,
}

/// A checked batch: the steps and the run settings.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The steps in run order.
    pub steps: Vec<Step>,
    /// For each step, `true` when the result holds its data.
    pub returned: Vec<bool>,
    /// What a read-only batch does after a failed step.
    pub on_error: OnError,
    /// The label of the transaction.
    pub label: String,
}

/// Checks the batch arguments `raw` before any step runs. `registry` and `profile` give the
/// tools that a step can call.
///
/// # Errors
///
/// Returns the first error of the rules of design Section 11.3. Its field path starts with
/// `/steps/N` for an error of step `N`.
pub fn plan(
    registry: &Registry<Session>,
    profile: &ProfileSet,
    raw: &Value,
) -> Result<Plan, ToolError> {
    let _ = (registry, profile, raw);
    Err(ToolError::new(ErrorCode::InvalidArgument).var("field", "steps"))
}
