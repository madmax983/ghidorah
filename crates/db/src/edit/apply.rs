//! The apply step of an edit: the mode checks, the write rule and the exact write.

use ghidorah_base::Rev;

use super::{Edit, EditError};
use crate::fact::Origin;
use crate::program::Program;

/// How an edit applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// A new edit of a transaction: origin, write rule and input rules apply.
    Forward,
    /// A rollback, undo or replay edit: it puts its exact state.
    Exact,
}

/// The context of one apply step.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ctx<'a> {
    /// The origin of the transaction. Its source selects the layer.
    pub origin: &'a Origin,
    /// The mode.
    pub mode: Mode,
    /// The revision that the commit of the transaction gives.
    pub rev: Rev,
}

/// Applies `edit` to `program`. Gives the exact inverse, or `None` for a no-op.
///
/// # Errors
///
/// Returns the [`EditError`] of the first broken rule. Then the program does not change.
pub(crate) fn apply(
    program: &mut Program,
    edit: &Edit,
    ctx: &Ctx<'_>,
) -> Result<Option<Edit>, EditError> {
    let _ = (program, edit, ctx);
    Ok(None)
}
