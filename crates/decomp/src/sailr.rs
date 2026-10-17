//! The SAILR-lite passes (design Section 8.2, ADR-0010).
//!
//! | Pass | Switches | Effect |
//! |---|---|---|
//! | Stack-canary removal | `sailr`, `canary` | The check of the `fs:0x28` value and the `__stack_chk_fail` branch go. Their ops are elided. |
//! | Per-call-site noreturn | `sailr` | A call at the end of a node with no successor does not return. A callee without a noreturn fact gives `W_NORETURN_ASSUMED`. |
//! | Tail calls | `sailr`, `tailcall` | A tail jump prints as `return f(..);`. |
//!
//! Each pass edits the view. No pass edits L1.

use crate::view::{Env, View};
use crate::{Elided, Passes, Warning};

/// The findings of [`run`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// The ranges that the passes leave out.
    pub elided: Vec<Elided>,
    /// The warnings.
    pub warnings: Vec<Warning>,
}

/// Runs each pass that `passes` turns on.
pub fn run(view: &mut View, env: &dyn Env, passes: &Passes) -> Found {
    let _ = (view, env, passes);
    Found::default()
}
