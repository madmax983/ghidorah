//! The members of a set note: the operand of `set.members` and the set operations.
//!
//! | Member | Meaning |
//! |---|---|
//! | an ID text, for example `fn:0x401130` | one ID. The set keeps the canonical ID text. |
//! | an address text, for example `0x401130` | the one address |
//! | `{ start, size }` | `size` addresses from `start` |
//! | `{ start, end }` | the addresses from `start` to `end`, with `end` exclusive |
//!
//! `start`, `size` and `end` are `0x` hex texts or JSON integers. One operand holds IDs or
//! addresses, not both. An empty operand takes the kind of the old members.

use ghidorah_base::{ErrorCode, Id, Range, hex};
use ghidorah_db::{SetMembers, SetOp};
use ghidorah_json::Value;

use crate::errors::ToolError;

/// Gives the `INVALID_ARGUMENT` error of the member list at `path`.
fn bad(path: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", path.trim_start_matches('/'))
        .path(path)
        .detail("expected", Value::from(expected))
}

/// Gives the number of a member part: a `0x` hex text or a JSON integer.
fn number(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::String(text) => hex::parse_u64(text),
        other => other.as_u64(),
    }
}

/// Gives the range of a range member `{ start, size }` or `{ start, end }`.
fn range(value: &Value) -> Option<Range> {
    let object = value.as_object()?;
    if object
        .iter()
        .any(|(k, _)| !matches!(k, "start" | "size" | "end"))
    {
        return None;
    }
    let start = number(object.get("start"))?;
    match (number(object.get("size")), number(object.get("end"))) {
        (Some(size), None) => Range::with_len(start, size),
        (None, Some(end)) => Range::new(start, end.checked_sub(1)?).filter(|_| end > start),
        _ => None,
    }
}

/// The text of the expected member forms.
const EXPECTED: &str = "an ID, a 0x address, or a range with start and size or with start and end";

/// Parses the member list `list` of the argument at `path`.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for a member of another form, or for a list with IDs and
/// addresses.
pub(super) fn parse(list: &[Value], path: &str) -> Result<SetMembers, ToolError> {
    let mut ids = Vec::new();
    let mut ranges = Vec::new();
    for (i, member) in list.iter().enumerate() {
        let at = format!("{path}/{i}");
        match member {
            Value::String(text) => match (Id::parse(text), hex::parse_u64(text)) {
                (Ok(id), _) => ids.push(id.to_string()),
                (Err(_), Some(addr)) => ranges.push(Range::single(addr)),
                (Err(_), None) => return Err(bad(&at, EXPECTED)),
            },
            Value::Object(_) => ranges.push(range(member).ok_or_else(|| bad(&at, EXPECTED))?),
            _ => return Err(bad(&at, EXPECTED)),
        }
    }
    if !ids.is_empty() && !ranges.is_empty() {
        return Err(bad(path, "IDs or addresses, not both in one set"));
    }
    if ranges.is_empty() {
        return Ok(SetMembers::ids(ids));
    }
    let mut out = no_addrs();
    if let SetMembers::Addrs(set) = &mut out {
        for r in ranges {
            set.insert(r);
        }
    }
    Ok(out)
}

/// Gives an empty address set.
#[expect(
    clippy::default_trait_access,
    reason = "the tools crate has no edge to the kernel crate, so the RangeSet type has no name here"
)]
fn no_addrs() -> SetMembers {
    SetMembers::Addrs(Default::default())
}

/// Gives an empty set of the kind of `members`.
fn empty_like(members: &SetMembers) -> SetMembers {
    match members {
        SetMembers::Addrs(_) => no_addrs(),
        SetMembers::Ids(_) => SetMembers::Ids(Vec::new()),
    }
}

/// Gives the members after `op` with `operand` over the old members `old`.
///
/// A missing or empty old set takes the kind of the operand. An empty operand takes the kind
/// of the old members.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` at `path` when one set holds IDs and the other addresses.
pub(super) fn combine(
    old: Option<&SetMembers>,
    op: SetOp,
    operand: SetMembers,
    path: &str,
) -> Result<SetMembers, ToolError> {
    let Some(old) = old.filter(|o| o.count() > 0) else {
        return Ok(match op {
            SetOp::Replace | SetOp::Union => operand,
            SetOp::Intersect | SetOp::Subtract => empty_like(&operand),
        });
    };
    let operand = if operand.count() == 0 {
        empty_like(old)
    } else {
        operand
    };
    old.apply(op, &operand)
        .map_err(|_| bad(path, "members of the kind of the set: IDs or addresses"))
}
