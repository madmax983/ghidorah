//! The errors of the resolver and their candidates (design Section 10.5).
//!
//! Candidate labels and values carry addresses and the input text of the agent. A label never
//! holds binary text.

use std::collections::BTreeSet;

use ghidorah_base::addr_expr::Readings;
use ghidorah_base::{Address, ErrorCode, Fuel, FuncId, did_you_mean, hex};
use ghidorah_db::Program;
use ghidorah_json::Value;

use super::Site;
use super::table::{Family, accepted};
use crate::errors::{Candidate, ToolError};
use crate::hints::{Call, WHY_HEX};

/// The fuel of one did-you-mean scan (Section 10.5).
pub const DYM_FUEL: u64 = 1_000_000;

/// Gives the field name of a site for the message: the pointer without its first `/`.
fn field<'a>(site: &Site<'a>) -> &'a str {
    let name = site.path.strip_prefix('/').unwrap_or(site.path);
    if name.is_empty() { "target" } else { name }
}

/// Adds the field path of `site` to `error`.
pub(super) fn at(site: &Site<'_>, error: ToolError) -> ToolError {
    if site.path.is_empty() || error.field_path.is_some() {
        error
    } else {
        error.path(site.path)
    }
}

/// Tells if `addr` is in a mapped region. An EXTERNAL address counts as mapped.
pub(super) fn mapped(program: &Program, addr: Address) -> bool {
    !addr.is_ram() || program.mem().region_at(addr.off).is_some()
}

/// Gives `ADDRESS_INVALID`. `repair` is the corrected text of a repair call.
pub(super) fn address_invalid(site: &Site<'_>, repair: Option<String>) -> ToolError {
    let error = at(
        site,
        ToolError::new(ErrorCode::AddressInvalid).var("field", field(site)),
    );
    match (repair, site.repair) {
        (Some(text), Some(make)) => error.next(make(&text)),
        _ => error,
    }
}

/// Adds the repair call of an `ADDRESS_INVALID` error (design Section 10.8). The repair call is
/// the same call with `0x` before the address text at the field path of the error.
///
/// Only a text of 1 to 16 hex digits with at least one letter gets the call. Other errors and
/// errors with a repair call stay the same.
#[must_use]
pub(crate) fn hex_repair(tool: &str, args: &Value, error: ToolError) -> ToolError {
    if error.code != ErrorCode::AddressInvalid || !error.next.is_empty() {
        return error;
    }
    let Some(tokens) = error
        .field_path
        .as_deref()
        .and_then(|p| p.strip_prefix('/'))
        .map(|p| p.split('/').collect::<Vec<_>>())
    else {
        return error;
    };
    let mut fixed = args.clone();
    let mut slot = Some(&mut fixed);
    for token in &tokens {
        slot = match slot {
            Some(Value::Object(o)) => o.get_mut(token),
            Some(Value::Array(a)) => token.parse::<usize>().ok().and_then(|i| a.get_mut(i)),
            _ => None,
        };
    }
    let Some(slot) = slot else {
        return error;
    };
    let text = slot
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let bare = (1..=16).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_hexdigit())
        && text.bytes().any(|b| b.is_ascii_alphabetic());
    if !bare {
        return error;
    }
    *slot = Value::from(format!("0x{text}"));
    error.next(Call::new(tool, fixed, WHY_HEX))
}

/// Gives `ADDRESS_BASE_AMBIGUOUS` with the decimal and the hex reading of a text of digits.
///
/// `rewrite` gives the candidate value for one reading, for example the expression with the
/// digits replaced by `0x` hex.
pub(super) fn base_ambiguous(
    program: &Program,
    readings: Readings,
    rewrite: &dyn Fn(u64) -> String,
    site: &Site<'_>,
) -> ToolError {
    let mut candidates = Vec::new();
    for (value, reading) in [(readings.decimal, "decimal"), (readings.hex, "hex")] {
        let Some(value) = value else { continue };
        let state = if mapped(program, Address::ram(value)) {
            "mapped"
        } else {
            "not mapped"
        };
        let mut candidate =
            Candidate::text(&rewrite(value), &format!("{reading} reading, {state}"));
        candidate.addr = Some(hex::u64_text(value));
        candidates.push(candidate);
    }
    at(
        site,
        ToolError::new(ErrorCode::AddressBaseAmbiguous)
            .var("field", field(site))
            .candidates(candidates),
    )
}

/// Gives `AMBIGUOUS_NAME` for a symbol name with the addresses `addrs` in address order.
pub(super) fn ambiguous(
    program: &Program,
    name: &str,
    addrs: &[Address],
    site: &Site<'_>,
) -> ToolError {
    let candidates = addrs
        .iter()
        .map(|addr| {
            let func = program.func(FuncId(*addr)).is_some();
            let kind = if func { "function" } else { "symbol" };
            let mut c = Candidate::text(&format!("{name}@{addr}"), &format!("{kind} at {addr}"));
            c.id = func.then(|| FuncId(*addr).to_string());
            c.addr = Some(addr.to_string());
            c.kind = Some(kind.to_owned());
            c
        })
        .collect();
    at(
        site,
        ToolError::new(ErrorCode::AmbiguousName).candidates(candidates),
    )
}

/// Gives `AMBIGUOUS_NAME` for a section name with the IDs `ids` of its sections.
pub(super) fn ambiguous_ids(ids: Vec<(String, Address)>, site: &Site<'_>) -> ToolError {
    let candidates = ids
        .into_iter()
        .map(|(id, addr)| {
            let mut c = Candidate::text(&id, &format!("section at {addr}"));
            c.id = Some(id);
            c.addr = Some(addr.to_string());
            c.kind = Some("section".to_owned());
            c
        })
        .collect();
    at(
        site,
        ToolError::new(ErrorCode::AmbiguousName).candidates(candidates),
    )
}

/// Gives `NOT_FOUND` of `kind` with the did-you-mean candidates of `query` among `names`.
pub(super) fn not_found<'a>(
    kind: &str,
    query: &str,
    names: impl IntoIterator<Item = &'a str>,
    site: &Site<'_>,
) -> ToolError {
    let mut fuel = Fuel::new(DYM_FUEL);
    let candidates = did_you_mean(query, names, &mut fuel)
        .into_iter()
        .map(|s| Candidate::text(&s.name, kind))
        .collect();
    at(
        site,
        ToolError::new(ErrorCode::NotFound)
            .var("kind", kind)
            .detail("kind", Value::from(kind))
            .candidates(candidates),
    )
}

/// Gives the names that a name input can match: symbol names of both layers and section
/// names, in name order.
pub(super) fn names(program: &Program) -> BTreeSet<&str> {
    let mut out: BTreeSet<&str> = program.base().symbols().names().map(|(n, _)| n).collect();
    out.extend(program.analysis().symbols().names().map(|(n, _)| n));
    out.extend(
        program
            .binary()
            .sections
            .iter()
            .filter_map(|s| s.name.as_str()),
    );
    out.retain(|n| !n.is_empty());
    out
}

/// Gives `ADDRESS_UNMAPPED` with the nearest mapped addresses below and above `addr`.
pub(super) fn unmapped(program: &Program, addr: Address, site: &Site<'_>) -> ToolError {
    let mut below = None;
    let mut above = None;
    for region in program.mem().regions() {
        if region.va.last < addr.off {
            below = Some(region.va.last);
        } else if region.va.first > addr.off && above.is_none() {
            above = Some(region.va.first);
        }
    }
    let candidates = [
        (below, "nearest mapped address below"),
        (above, "nearest mapped address above"),
    ]
    .into_iter()
    .filter_map(|(a, label)| {
        a.map(|a| {
            let text = hex::u64_text(a);
            let mut c = Candidate::text(&text, label);
            c.addr = Some(text);
            c
        })
    })
    .collect();
    at(
        site,
        ToolError::new(ErrorCode::AddressUnmapped).candidates(candidates),
    )
}

/// Gives `INVALID_ARGUMENT` for an input kind that `family` does not accept.
pub(super) fn invalid_kind(family: Family, site: &Site<'_>) -> ToolError {
    let kinds = accepted(family).iter().map(|k| Value::from(*k)).collect();
    at(
        site,
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", field(site))
            .detail(
                "expected",
                Value::from("an input of a kind in details.accepted"),
            )
            .detail("accepted", Value::Array(kinds)),
    )
}

/// Gives `INVALID_ARGUMENT` with the text of `details.expected`.
pub(super) fn invalid(expected: &str, site: &Site<'_>) -> ToolError {
    at(
        site,
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", field(site))
            .detail("expected", Value::from(expected)),
    )
}

/// Gives `NOT_IN_FUNCTION`.
pub(super) fn not_in_function(site: &Site<'_>) -> ToolError {
    at(site, ToolError::new(ErrorCode::NotInFunction))
}
