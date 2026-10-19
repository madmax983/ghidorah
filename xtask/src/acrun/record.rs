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

use crate::ac::{AcRow, Evidence};
use crate::acrun::{Outcome, Status};
use crate::json::{self, Value};
use crate::verify;

/// The prefix of a host input, for example `host-bash`.
pub const HOST_PREFIX: &str = "host-";

/// The tree input.
pub const TREE: &str = "tree";

/// Gives the expected hash of a record item.
#[must_use]
pub fn expected<'a>(record: &'a Value, pointer: &str, input: &str) -> Option<&'a str> {
    let at = record.pointer(pointer)?;
    if input == TREE {
        record.get("tree_sha256")?.as_str()
    } else if input.starts_with(HOST_PREFIX) {
        at.get("sha256")?.as_str()
    } else {
        None
    }
}

/// Gives the status of a record item from the record and the current hash of its input.
/// `current` is `None` when the input does not exist on this host.
#[must_use]
pub fn record_match(record: &Value, pointer: &str, input: &str, current: Option<&str>) -> Status {
    let Some(want) = expected(record, pointer, input) else {
        return Status::Fail;
    };
    match current {
        Some(have) if have == want => Status::Recorded,
        None if input.starts_with(HOST_PREFIX) => Status::Skipped,
        _ => Status::Fail,
    }
}

/// Gives the current hash of the input of a record item on this host.
#[must_use]
pub fn current(root: &Path, record: &Value, pointer: &str, input: &str) -> Option<String> {
    if input == TREE {
        return verify::tree_sha256(root).ok();
    }
    let path = record.pointer(pointer)?.get("path")?.as_str()?;
    let bytes = std::fs::read(path).ok()?;
    Some(verify::tree::hex(&verify::tree::sha256(&bytes)))
}

/// Gives the status of the record item `file#pointer@sha256=input` of the repository at
/// `root`.
#[must_use]
pub fn status(root: &Path, file: &str, pointer: &str, input: &str) -> Status {
    let record = std::fs::read_to_string(root.join(file))
        .ok()
        .and_then(|text| json::parse(&text).ok());
    let Some(record) = record else {
        return Status::Fail;
    };
    let now = current(root, &record, pointer, input);
    record_match(&record, pointer, input, now.as_deref())
}

/// Checks the record items of the MVP rows again and gives one outcome for each.
#[must_use]
pub fn live(root: &Path, rows: &[AcRow]) -> Vec<Outcome> {
    let mut out = Vec::new();
    for row in rows.iter().filter(|r| r.is_gate()) {
        for item in &row.evidence {
            if let Evidence::Record {
                file,
                pointer,
                input,
            } = item
            {
                out.push(Outcome {
                    ac: row.id.clone(),
                    tier: item.tier(),
                    kind: item.kind(),
                    status: status(root, file, pointer, input),
                });
            }
        }
    }
    out
}
