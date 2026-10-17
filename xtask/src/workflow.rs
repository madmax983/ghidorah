//! The gate over `.github/workflows/ci.yml` (AC-019).
//!
//! The reader knows the YAML subset of the workflow: top-level keys at column 0,
//! job IDs at an indent of 2 and `uses:` lines.

use crate::Finding;

/// The workflow file, relative to the workspace root.
pub const PATH: &str = ".github/workflows/ci.yml";

/// The only actions that the workflow can use.
pub const ALLOWED_ACTIONS: &[&str] = &["actions/checkout", "actions/cache"];

/// The Verus commit that the Verus job builds.
pub const VERUS_COMMIT: &str = "ffc9d20";

/// The toolchain that the Verus build uses.
pub const VERUS_TOOLCHAIN: &str = "1.98.1";

/// The wheel on the Python package index that holds the z3 binary.
pub const Z3_WHEEL: &str = "z3_solver-4.16.0.0";

/// The tier-1 commands, in the order that the tier-1 job must run them.
pub const TIER1_ORDER: &[&str] = &[
    "cargo fmt --all -- --check",
    "cargo clippy --workspace --all-targets -- -D warnings",
    "cargo test --workspace",
    "cargo xtask cov",
];

/// Text that the Verus job must hold.
pub const VERUS_NEEDS: &[&str] = &[
    "https://github.com/verus-lang/verus",
    VERUS_COMMIT,
    VERUS_TOOLCHAIN,
    "rustc-dev",
    "llvm-tools",
    Z3_WHEEL,
    "z3_solver-4.16.0.0.data/data/bin/z3",
    "actions/cache@",
    "cargo xtask verify",
];

/// Text that the tier-2 job must hold.
pub const TIER2_NEEDS: &[&str] = &["clang", "llvm", "--include-ignored"];

fn top_block(yaml: &str, key: &str) -> Option<String> {
    let mut lines = yaml.lines();
    let head = format!("{key}:");
    let first = lines.by_ref().find(|l| l.starts_with(&head))?;
    let mut block = first.to_owned();
    for line in lines {
        if line.starts_with(|c: char| !c.is_whitespace() && c != '#') {
            break;
        }
        block.push('\n');
        block.push_str(line);
    }
    Some(block)
}

fn job_id(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    let id = rest.trim_end().strip_suffix(':')?;
    let valid = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    valid.then_some(id)
}

/// Gives the job IDs of the workflow, in file order.
#[must_use]
pub fn jobs(yaml: &str) -> Vec<String> {
    top_block(yaml, "jobs")
        .map(|block| {
            block
                .lines()
                .filter_map(job_id)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Gives the lines of one job, or `None` when the job does not exist.
#[must_use]
pub fn job_text(yaml: &str, job: &str) -> Option<String> {
    let block = top_block(yaml, "jobs")?;
    let mut lines = block.lines();
    lines.by_ref().find(|l| job_id(l) == Some(job))?;
    let body: Vec<&str> = lines.take_while(|l| job_id(l).is_none()).collect();
    Some(body.join("\n"))
}

fn finding(line: usize, detail: impl Into<String>) -> Finding {
    Finding::new("AC-019", PATH, line, detail)
}

fn check_actions(yaml: &str, found: &mut Vec<Finding>) {
    for (index, line) in yaml.lines().enumerate() {
        let Some((_, spec)) = line.split_once("uses:") else {
            continue;
        };
        let spec = spec.trim().trim_matches(['"', '\'']);
        let (action, version) = spec.split_once('@').unwrap_or((spec, ""));
        if !ALLOWED_ACTIONS.contains(&action) {
            found.push(finding(
                index + 1,
                format!("action `{action}` is not allowed"),
            ));
        } else if version.is_empty() {
            found.push(finding(index + 1, format!("pin a version of `{action}`")));
        }
    }
}

fn check_needs(yaml: &str, job: &str, needs: &[&str], found: &mut Vec<Finding>) {
    let Some(text) = job_text(yaml, job) else {
        found.push(finding(0, format!("add the job `{job}`")));
        return;
    };
    for need in needs {
        if !text.contains(need) {
            found.push(finding(0, format!("job `{job}` must contain `{need}`")));
        }
    }
}

/// AC-019: checks the triggers, the jobs, the step order and the actions of the workflow.
#[must_use]
pub fn check(yaml: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    let on = top_block(yaml, "on").unwrap_or_default();
    for trigger in ["push", "pull_request"] {
        if !on.contains(trigger) {
            found.push(finding(0, format!("run on `{trigger}`")));
        }
    }
    check_actions(yaml, &mut found);
    check_needs(yaml, "tier1", TIER1_ORDER, &mut found);
    if let Some(text) = job_text(yaml, "tier1") {
        let places: Vec<Option<usize>> = TIER1_ORDER.iter().map(|c| text.find(c)).collect();
        if places.iter().all(Option::is_some) && !places.is_sorted() {
            found.push(finding(
                0,
                "tier1 must run fmt, clippy, test and cov in this order",
            ));
        }
    }
    check_needs(yaml, "tier2", TIER2_NEEDS, &mut found);
    check_needs(yaml, "verus", VERUS_NEEDS, &mut found);
    found
}
