//! `batch_run`: dependent tool steps in one call (design Section 11, ADR-0014).
//!
//! A batch is a list of 1 to [`MAX_STEPS`] steps. Each step calls one registered tool through
//! the same dispatcher as a direct call. A step argument can take a value of an earlier step
//! through a reference `{ "$ref": "s1", "ptr": "/data/items/*/id", "partial"?: true }`.
//! The `*` segment maps over each item of an array. The executor has no loop, no condition
//! and no variable, so it knows the cost and the end of a batch before the run.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | `validate` | The checks of the whole batch before a step runs | Section 11.3 |
//! | `refs` | References: their places, their types and their values | Sections 11.2, 11.3 |
//! | `exec` | The run of the steps, the transaction and the result | Sections 11.4, 11.6 |
//! | [`guards`] | The `expect` guards and the `claim` guards | Section 11.2 |
//! | `budget` | The shares of `max_chars`, the fuel and the resume bindings | Section 11.5 |
//!
//! Rules:
//!
//! | Rule | Result |
//! |---|---|
//! | A step of `batch_run`, `binary_load` or `analysis_run` | `INVALID_ARGUMENT` |
//! | A step outside the active profile, or an edit step in `readonly` | `TOOL_NOT_IN_PROFILE` |
//! | A destructive tool or action | `TOOL_NOT_IN_PROFILE` with `details.reason: "destructive_in_batch"` |
//! | A key of [`STEP_GLOBALS`] in step args | `INVALID_ARGUMENT`; `next[0]` moves the key to the top level |
//! | A reference to a missing or later step, or of the wrong type | `BAD_REFERENCE` |
//! | A `*` reference above the cap of its list | `LIMIT_EXCEEDED` before the run, `PLUCK_TOO_LONG` in the run |
//! | A reference to a truncated page without `partial: true` | `BAD_REFERENCE` with `details.source_truncated` |
//! | A step after a failed step that it refers to | `SKIPPED_DEPENDENCY` |
//! | A failed guard | `EXPECT_FAILED` with `details.actual` |
//! | A batch with edits | one transaction and one rev, or a full roll back |
//! | A read-only batch out of fuel or time | the done steps, `stopped_by` and `resume` |

mod exec;
pub mod guards;
mod validate;

pub use exec::run;
pub use guards::{Guard, GuardOp, OPS};
pub use validate::{Plan, Step, plan};

/// The largest number of steps in one batch.
pub const MAX_STEPS: usize = 32;

/// The longest step ID.
pub const MAX_STEP_ID: usize = 16;

/// The largest number of `expect` guards or `claim` guards of one step.
pub const MAX_GUARDS: usize = 8;

/// The default fuel of a batch.
pub const DEFAULT_FUEL: u64 = 2_000_000;

/// The largest fuel of a batch.
pub const MAX_FUEL: u64 = 20_000_000;

/// The largest size of the resume bindings in characters.
pub const MAX_BINDINGS_CHARS: u64 = 8_000;

/// The global arguments that go only at the top level of a batch (Section 11.2).
pub const STEP_GLOBALS: [&str; 6] = [
    "binary_id",
    "max_chars",
    "max_steps",
    "dry_run",
    "expected_rev",
    "session",
];

/// The tools that never run as a step.
pub const NOT_IN_BATCH: [&str; 3] = ["batch_run", "binary_load", "analysis_run"];

/// The value of `details.reason` for a destructive step.
pub const DESTRUCTIVE: &str = "destructive_in_batch";

/// The `why` of a repair call that moves a global argument to the top level.
pub const WHY_TOP: &str = "Send the global argument at the top level of the batch.";

/// The `why` of a direct call in place of a destructive step.
pub const WHY_DIRECT: &str = "Send the destructive step as a direct call.";

/// The `why` of a repair call that adds a limit to a source step.
pub const WHY_LIMIT: &str = "Send the batch with a limit on the source step.";

/// The `why` of the replay of a batch that stopped on its fuel.
pub const WHY_RESUME: &str = "Run the steps that did not complete.";

/// Every fixed text of the batch executor that an agent reads.
pub const TEXTS: &[&str] = &[WHY_TOP, WHY_DIRECT, WHY_LIMIT, WHY_RESUME];

/// What a read-only batch does after a failed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OnError {
    /// The batch stops.
    Stop,
    /// The batch runs the steps that do not refer to a failed step.
    Continue,
}
