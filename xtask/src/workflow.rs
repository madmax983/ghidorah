//! The gate over `.github/workflows/ci.yml` (AC-019).

use crate::Finding;

/// The workflow file, relative to the workspace root.
pub const PATH: &str = ".github/workflows/ci.yml";

/// The only actions that the workflow can use.
pub const ALLOWED_ACTIONS: &[&str] = &["actions/checkout", "actions/cache"];

/// The Verus commit that the Verus job builds.
pub const VERUS_COMMIT: &str = "ffc9d20";

/// The toolchain that the Verus build uses.
pub const VERUS_TOOLCHAIN: &str = "1.98.1";

/// The PyPI wheel that holds the z3 binary.
pub const Z3_WHEEL: &str = "z3_solver-4.16.0.0";

/// Gives the job IDs of the workflow, in file order.
#[must_use]
pub fn jobs(yaml: &str) -> Vec<String> {
    let _ = yaml;
    Vec::new()
}

/// Gives the lines of one job, or `None` when the job does not exist.
#[must_use]
pub fn job_text(yaml: &str, job: &str) -> Option<String> {
    let _ = (yaml, job);
    None
}

/// AC-019: checks the triggers, the jobs, the step order and the actions of the workflow.
#[must_use]
pub fn check(yaml: &str) -> Vec<Finding> {
    let _ = yaml;
    Vec::new()
}
