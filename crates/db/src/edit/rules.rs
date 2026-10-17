//! The input rules of edits: the fact keys, the normal form and the target rule.

use super::Edit;
use crate::why::FactKey;

/// Gives the keys of the facts that `edit` names, in key order.
pub(super) fn keys(edit: &Edit) -> Vec<FactKey> {
    let _ = edit;
    Vec::new()
}
