//! The JCS text of the `why` and `units` rows with no JSON value step.
//!
//! These two members hold most rows of an analysis layer. Each writer adds the bytes of
//! `write_jcs_into` on the JSON form of the row. A part with no plain form, for example an
//! integer of 16 digits or more, goes through the JSON form of its row.
//! The member names of each object go in JCS order.

use std::fmt::Write as _;

use ghidorah_base::Address;
use ghidorah_json::{JcsError, write_jcs_into};

use super::tables::{unit_row, why_row};
use super::values::Json;
use crate::listing::CodeUnit;
use crate::why::{FactKey, Why};

/// The largest integer with at most 15 digits. JCS writes each such integer as its lexeme.
const MAX_PLAIN: u64 = 999_999_999_999_999;

/// Adds `text` as a JSON string if no byte of it needs an escape. Gives `None` if not.
fn push_plain(out: &mut String, text: &str) -> Option<()> {
    if text.bytes().any(|b| b == b'"' || b == b'\\' || b < 0x20) {
        return None;
    }
    out.push('"');
    out.push_str(text);
    out.push('"');
    Some(())
}

/// Adds `n` as a JCS number if it has at most 15 digits. Gives `None` if not.
fn push_uint(out: &mut String, n: u64) -> Option<()> {
    if n > MAX_PLAIN {
        return None;
    }
    write!(out, "{n}").ok()
}

/// Adds the text of `a` as a JSON string. The text is an optional prefix and hex digits.
fn push_addr(out: &mut String, a: Address) -> Option<()> {
    write!(out, "\"{a}\"").ok()
}

/// Adds the JCS text of the fact keys that name one address. Gives `None` for the others.
fn push_plain_key(out: &mut String, key: &FactKey) -> Option<()> {
    let (name, kind, at) = match key {
        FactKey::CodeUnit(o) => ("at", "code_unit", Address::ram(*o)),
        FactKey::Data(o) => ("at", "data", Address::ram(*o)),
        FactKey::Entry(o) => ("at", "entry", Address::ram(*o)),
        FactKey::Reloc(o) => ("at", "reloc", Address::ram(*o)),
        FactKey::Fde(o) => ("at", "fde", Address::ram(*o)),
        FactKey::JumpTable(j) => ("at", "jump_table", j.0),
        FactKey::FlowOverride(a) => ("at", "flow_override", *a),
        FactKey::Str(s) => ("at", "string", s.0),
        FactKey::Func(f) => ("func", "func", f.0),
        FactKey::Signature(f) => ("func", "signature", f.0),
        FactKey::Noreturn(f) => ("func", "noreturn", f.0),
        _ => return None,
    };
    out.push_str("{\"");
    out.push_str(name);
    out.push_str("\":");
    push_addr(out, at)?;
    out.push_str(",\"k\":\"");
    out.push_str(kind);
    out.push_str("\"}");
    Some(())
}

/// Adds the JCS text of `key` to `out`.
///
/// # Errors
///
/// Returns the [`JcsError`] of the JSON form of a key with no plain form.
fn push_key(out: &mut String, key: &FactKey) -> Result<(), JcsError> {
    let start = out.len();
    if push_plain_key(out, key).is_some() {
        return Ok(());
    }
    out.truncate(start);
    write_jcs_into(&key.enc(), out)
}

/// Adds the JCS text of the why row of `key` to `out`.
///
/// # Errors
///
/// Returns the [`JcsError`] of a part that has no JCS form.
pub(super) fn push_why(
    out: &mut String,
    key: &FactKey,
    order: u64,
    why: &Why,
) -> Result<(), JcsError> {
    let start = out.len();
    out.push_str("{\"key\":");
    push_key(out, key)?;
    out.push_str(",\"order\":");
    if push_uint(out, order).is_some() {
        out.push_str(",\"premises\":[");
        for (i, premise) in why.premises.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_key(out, premise)?;
        }
        out.push_str("],\"rule\":");
        if push_plain(out, why.rule.as_str()).is_some() {
            out.push('}');
            return Ok(());
        }
    }
    out.truncate(start);
    write_jcs_into(&why_row(key, order, why), out)
}

/// Adds the JCS text of the unit row at the RAM offset `at` to `out`.
///
/// # Errors
///
/// Returns the [`JcsError`] of a part that has no JCS form.
pub(super) fn push_unit(out: &mut String, at: u64, unit: CodeUnit) -> Result<(), JcsError> {
    let CodeUnit::Insn { len, flow, flags } = unit;
    let start = out.len();
    let mut plain = || {
        out.push_str("{\"at\":");
        push_addr(out, Address::ram(at))?;
        out.push_str(",\"flags\":");
        push_uint(out, u64::from(flags))?;
        out.push_str(",\"flow\":");
        push_plain(out, flow.name())?;
        out.push_str(",\"len\":");
        push_uint(out, u64::from(len))?;
        out.push('}');
        Some(())
    };
    if plain().is_some() {
        return Ok(());
    }
    out.truncate(start);
    write_jcs_into(&unit_row(at, unit), out)
}
