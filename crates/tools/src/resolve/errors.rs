//! The errors of the resolver and their candidates (design Section 10.5).
//!
//! Candidate labels and values carry addresses, IDs, binary names and the input text of the
//! agent. A hostile binary name starts with `"` or holds a character that `BinText` escapes.
//! Its candidate value is an ID or an address, and its label is the escaped name (AC-146a).
//! So no candidate holds a raw control or bidi character from the binary.

use std::collections::BTreeSet;

use ghidorah_base::addr_expr::{AddrExprError, Readings};
use ghidorah_base::bintext::escapes;
use ghidorah_base::{
    Address, ErrorCode, Fuel, FuncId, IdError, IdKind, SectionId, SymId, did_you_mean, hex,
};
use ghidorah_db::Program;
use ghidorah_json::Value;

use super::Site;
use super::table::{Family, accepted};
use crate::errors::{Candidate, ToolError};
use crate::handlers::func_sections::safe;
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

/// Gives the error of the address text `text` that does not parse.
///
/// A text with a registered ID prefix and a bad body gives `INVALID_ARGUMENT` that names the ID
/// kind ([`bad_id`]). Other syntax errors give `ADDRESS_INVALID`.
pub(super) fn syntax(text: &str, error: AddrExprError, site: &Site<'_>) -> ToolError {
    let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
    match (error, IdKind::of_text(trimmed)) {
        (AddrExprError::BadId(e), Some(kind)) => at(site, bad_id(field(site), kind, &e)),
        _ => address_invalid(site, error.repair_text()),
    }
}

/// Gives `INVALID_ARGUMENT` for a text with the ID prefix of `kind` and a body that does not
/// parse. `details.expected` names the ID kind. `details.reason` tells which part is bad.
pub(crate) fn bad_id(field: &str, kind: IdKind, error: &IdError) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", field)
        .detail(
            "expected",
            Value::from(format!(
                "an ID with the prefix {kind} and a body that parses"
            )),
        )
        .detail("reason", Value::from(error.to_string()))
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

/// Tells if the binary name `name` is hostile: it starts with `"` or holds a character that
/// `BinText` escapes. A candidate never shows such a name raw.
fn hostile(name: &str) -> bool {
    name.starts_with('"') || name.chars().any(escapes)
}

/// Gives `AMBIGUOUS_NAME` for a symbol name with the addresses `addrs` in address order.
///
/// The value of each candidate is `<name>@<addr>`. For a hostile name, the value is the
/// address, and the label is the escaped name.
pub(super) fn ambiguous(
    program: &Program,
    name: &str,
    addrs: &[Address],
    site: &Site<'_>,
) -> ToolError {
    let shown = hostile(name).then(|| safe(name));
    let candidates = addrs
        .iter()
        .map(|addr| {
            let func = program.func(FuncId(*addr)).is_some();
            let kind = if func { "function" } else { "symbol" };
            let mut c = match &shown {
                Some(label) => Candidate::text(&addr.to_string(), label),
                None => Candidate::text(&format!("{name}@{addr}"), &format!("{kind} at {addr}")),
            };
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

/// The texts of one did-you-mean scan of `NOT_FOUND`.
///
/// A list of IDs gives each ID text as a candidate value. The binary names of [`names`] give
/// each hostile name as its ID.
pub(super) trait Pool<'a> {
    /// Gives the texts in a fixed order, and the program of binary names.
    fn parts(self) -> (Vec<&'a str>, Option<&'a Program>);
}

impl<'a, I: Iterator<Item = &'a str>> Pool<'a> for I {
    fn parts(self) -> (Vec<&'a str>, Option<&'a Program>) {
        (self.collect(), None)
    }
}

/// The names that a name input can match: symbol names of both layers and section names, in
/// name order.
pub(super) struct Names<'a> {
    program: &'a Program,
    set: BTreeSet<&'a str>,
}

impl<'a> Pool<'a> for Names<'a> {
    fn parts(self) -> (Vec<&'a str>, Option<&'a Program>) {
        (self.set.into_iter().collect(), Some(self.program))
    }
}

/// Gives the candidate of the hostile binary name `name`. The value is the `sym:` ID of a
/// symbol, else the `sec:` ID of the first section with this name. The label is the escaped
/// name. A name with no such ID gives `None`.
fn escaped(program: &Program, name: &str) -> Option<Candidate> {
    let (id, kind) = if program.addrs_named(name).is_empty() {
        let id = program
            .binary()
            .sections
            .iter()
            .filter(|s| s.name.as_str() == Some(name))
            .find_map(|s| SectionId::new(u16::try_from(s.index).ok()?, name).ok())?;
        (id.to_string(), "section")
    } else {
        (SymId::new(name).ok()?.to_string(), "symbol")
    };
    let mut c = Candidate::text(&id, &safe(name));
    c.id = Some(id);
    c.kind = Some(kind.to_owned());
    Some(c)
}

/// Gives `NOT_FOUND` of `kind` with the did-you-mean candidates of `query` among `names`.
///
/// The value of each candidate is the matched text. A hostile binary name of [`names`] gives
/// its ID instead, with the escaped name as the label.
pub(super) fn not_found<'a>(
    kind: &str,
    query: &str,
    names: impl Pool<'a>,
    site: &Site<'_>,
) -> ToolError {
    let (texts, program) = names.parts();
    let mut fuel = Fuel::new(DYM_FUEL);
    let candidates = did_you_mean(query, texts, &mut fuel)
        .into_iter()
        .filter_map(|s| match program.filter(|_| hostile(&s.name)) {
            Some(p) => escaped(p, &s.name),
            None => Some(Candidate::text(&s.name, kind)),
        })
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
pub(super) fn names(program: &Program) -> Names<'_> {
    let mut set: BTreeSet<&str> = program.base().symbols().names().map(|(n, _)| n).collect();
    set.extend(program.analysis().symbols().names().map(|(n, _)| n));
    set.extend(
        program
            .binary()
            .sections
            .iter()
            .filter_map(|s| s.name.as_str()),
    );
    set.retain(|n| !n.is_empty());
    Names { program, set }
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
