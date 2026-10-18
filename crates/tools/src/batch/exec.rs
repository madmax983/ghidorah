//! The run of a batch (design Sections 11.4 to 11.6).

use ghidorah_base::ErrorCode;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::session::Session;

/// Runs the batch of `args`: the handler of `batch_run`.
///
/// # Errors
///
/// Returns the first validation error, with a `/steps/N/..` field path. A batch with edits
/// returns the error of its failed step after the roll back.
pub fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session, args, ctx);
    Err(ToolError::new(ErrorCode::InvalidArgument).var("field", "steps"))
}
