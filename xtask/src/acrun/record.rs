//! The hash check of `record:` items (design Section 15, AC-018b).
//!
//! | Input | Expected hash | Current hash |
//! |---|---|---|
//! | `tree` | the `tree_sha256` member of the record | the tree hash of the proof inputs (Section 13.3) |
//! | `host-<name>` | the `sha256` member of the object at the pointer | the SHA-256 of the host file at its `path` member |
//!
//! A record gives `recorded` when the hashes are equal and the record holds the claim of its AC.
//! A missing host file, or a host file with another hash, gives `skipped`. A stale tree gives
//! `skipped` with a warning. Under a proof requirement, it gives `fail` (design Section 13.3).
//! Each other case gives `fail`.
//!
//! | Input | Claim |
//! |---|---|
//! | `tree` | Each kernel row at the pointer has `status: verified`, `errors: 0` and `verified >= spec_items`. Each kernel has a negative row, and each of its negative rows has `ok: true`. |
//! | `host-<name>` | The object at the pointer has `mismatches: 0` and `agree == insns`. |
//!
//! So a record of a failed run never gives `recorded` or `skipped`.
//!
//! `GHIDORAH_REQUIRE_PROOFS=1` and an evidence run require proofs. The caller reads the variable
//! once and gives the result to [`live`] or [`status`].

use std::collections::BTreeSet;
use std::path::Path;

use crate::ac::{AcRow, Evidence};
use crate::acrun::{Outcome, Status};
use crate::json::{self, Value};
use crate::verify;

/// The prefix of a host input, for example `host-bash`.
pub const HOST_PREFIX: &str = "host-";

/// The tree input.
pub const TREE: &str = "tree";

/// The variable that makes a stale proof record fail. Its value is `1` (design Section 13.3).
pub const REQUIRE_PROOFS: &str = "GHIDORAH_REQUIRE_PROOFS";

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

/// Tells if one kernel row holds the claims of a proof, with the negative rows of the record.
fn kernel_claims(name: &str, row: &Value, negatives: &[Value]) -> bool {
    let number = |key: &str| row.get(key).and_then(Value::as_u64);
    let own: Vec<&Value> = negatives
        .iter()
        .filter(|n| n.get("kernel").and_then(Value::as_str) == Some(name))
        .collect();
    row.get("status").and_then(Value::as_str) == Some("verified")
        && number("errors") == Some(0)
        && number("verified")
            .zip(number("spec_items"))
            .is_some_and(|(verified, items)| verified >= items)
        && !own.is_empty()
        && own
            .iter()
            .all(|n| n.get("ok").and_then(Value::as_bool) == Some(true))
}

/// Tells if the kernel rows at `pointer` hold the claims of a proof.
///
/// The pointer names one kernel row, for example `/kernels/K1`, or the object of all rows.
fn tree_claims(record: &Value, pointer: &str) -> bool {
    let Some(at) = record.pointer(pointer) else {
        return false;
    };
    let rows: Vec<(&str, &Value)> = if at.get("status").is_some() {
        let name = at
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| pointer.rsplit('/').next())
            .unwrap_or_default();
        vec![(name, at)]
    } else {
        at.as_object()
            .map(|rows| rows.iter().map(|(k, v)| (k.as_str(), v)).collect())
            .unwrap_or_default()
    };
    let negatives = record
        .get("negatives")
        .and_then(Value::as_array)
        .unwrap_or_default();
    !rows.is_empty()
        && rows
            .iter()
            .all(|(name, row)| kernel_claims(name, row, negatives))
}

/// Tells if the host record at `pointer` holds a full agreement.
fn host_claims(record: &Value, pointer: &str) -> bool {
    let Some(at) = record.pointer(pointer) else {
        return false;
    };
    let number = |key: &str| at.get(key).and_then(Value::as_u64);
    number("mismatches") == Some(0) && number("insns").is_some_and(|n| number("agree") == Some(n))
}

/// Tells if the record holds the claim of the record item (see the module table).
#[must_use]
pub fn claims(record: &Value, pointer: &str, input: &str) -> bool {
    if input == TREE {
        tree_claims(record, pointer)
    } else {
        input.starts_with(HOST_PREFIX) && host_claims(record, pointer)
    }
}

/// Gives the status of a record item from the record and the current hash of its input.
/// `current` is `None` when the input does not exist on this host.
///
/// A record that does not hold its [`claims`] gives `fail`, also on a host without the input.
/// A host input with no file or another hash gives `skipped`, because the record names the
/// files of the recording host. A stale tree gives `skipped`, or `fail` with `require_proofs`.
#[must_use]
pub fn record_match(
    record: &Value,
    pointer: &str,
    input: &str,
    current: Option<&str>,
    require_proofs: bool,
) -> Status {
    let Some(want) = expected(record, pointer, input) else {
        return Status::Fail;
    };
    if !claims(record, pointer, input) {
        return Status::Fail;
    }
    match current {
        Some(have) if have == want => Status::Recorded,
        _ if input.starts_with(HOST_PREFIX) => Status::Skipped,
        Some(_) if !require_proofs => Status::Skipped,
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
/// `root`. `require_proofs` makes a stale tree give `fail` (see [`record_match`]).
#[must_use]
pub fn status(root: &Path, file: &str, pointer: &str, input: &str, require_proofs: bool) -> Status {
    let record = std::fs::read_to_string(root.join(file))
        .ok()
        .and_then(|text| json::parse(&text).ok());
    let Some(record) = record else {
        return Status::Fail;
    };
    let now = current(root, &record, pointer, input);
    record_match(&record, pointer, input, now.as_deref(), require_proofs)
}

/// Checks the record items of the MVP rows again and gives one outcome for each.
///
/// Without `require_proofs`, a stale tree gives `skipped`, and the command writes one warning
/// for each stale record file on stderr (design Section 13.3).
#[must_use]
pub fn live(root: &Path, rows: &[AcRow], require_proofs: bool) -> Vec<Outcome> {
    let mut out = Vec::new();
    let mut stale = BTreeSet::new();
    for row in rows.iter().filter(|r| r.is_gate()) {
        for item in &row.evidence {
            if let Evidence::Record {
                file,
                pointer,
                input,
            } = item
            {
                let status = status(root, file, pointer, input, require_proofs);
                if status == Status::Skipped && input == TREE {
                    stale.insert(file.as_str());
                }
                out.push(Outcome {
                    ac: row.id.clone(),
                    tier: item.tier(),
                    kind: item.kind(),
                    status,
                });
            }
        }
    }
    warn_stale(&stale);
    out
}

/// Writes the warning of design Section 13.3 for each stale proof record.
#[expect(
    clippy::print_stderr,
    reason = "a stale proof record is a warning without GHIDORAH_REQUIRE_PROOFS=1"
)]
fn warn_stale(files: &BTreeSet<&str>) {
    for file in files {
        eprintln!("warning: {file} is stale; run `cargo xtask verify`");
    }
}
