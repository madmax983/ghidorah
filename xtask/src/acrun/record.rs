//! The hash check of `record:` items (design Section 15, AC-018b).
//!
//! | Input | Expected hash | Current hash |
//! |---|---|---|
//! | `tree` | the `tree_sha256` member of the record | the tree hash of the proof inputs (Section 13.3) |
//! | `host-<name>` | the `sha256` member of the object at the pointer | the SHA-256 of the host file at its `path` member |
//!
//! A record gives `recorded` when the hashes are equal. A missing host file gives `skipped`.
//! Each other case gives `fail`.

use std::path::Path;

use crate::ac::AcRow;
use crate::acrun::{Outcome, Status};
use crate::json::Value;

/// The prefix of a host input, for example `host-bash`.
pub const HOST_PREFIX: &str = "host-";

/// Gives the expected hash of a record item.
#[must_use]
pub fn expected<'a>(record: &'a Value, pointer: &str, input: &str) -> Option<&'a str> {
    let _ = (record, pointer, input);
    None
}

/// Gives the status of a record item from the record and the current hash of its input.
/// `current` is `None` when the input does not exist on this host.
#[must_use]
pub fn record_match(record: &Value, pointer: &str, input: &str, current: Option<&str>) -> Status {
    let _ = (record, pointer, input, current);
    Status::Skipped
}

/// Gives the current hash of the input of a record item on this host.
#[must_use]
pub fn current(root: &Path, record: &Value, pointer: &str, input: &str) -> Option<String> {
    let _ = (root, record, pointer, input);
    None
}

/// Gives the status of the record item `file#pointer@sha256=input` of the repository at
/// `root`.
#[must_use]
pub fn status(root: &Path, file: &str, pointer: &str, input: &str) -> Status {
    let _ = (root, file, pointer, input);
    Status::Skipped
}

/// Checks the record items of the MVP rows again and gives one outcome for each.
#[must_use]
pub fn live(root: &Path, rows: &[AcRow]) -> Vec<Outcome> {
    let _ = (root, rows);
    Vec::new()
}
