//! The rule order of the resolver: IDs, names and offsets (design Section 10.5).

use ghidorah_base::addr_expr::{NameExpr, OffsetExpr, OffsetValue};
use ghidorah_base::{AddrExpr, Address, Id, SectionId, SegmentId};
use ghidorah_db::Program;

use super::errors::{self, names};
use super::table::value_of;
use super::{Named, Resolved, Rule, Site};
use crate::errors::ToolError;

/// Gives the result of one rule.
fn found(named: Named, rule: Rule, text: &str) -> Resolved {
    Resolved {
        named,
        rule,
        matched: text.to_owned(),
    }
}

/// Resolves a parsed address expression. `text` is the trimmed input text.
pub(super) fn expr(
    program: &Program,
    expr: &AddrExpr,
    text: &str,
    site: &Site<'_>,
) -> Result<Resolved, ToolError> {
    match expr {
        AddrExpr::Integer(v) => Ok(found(Named::Addr(Address::ram(*v)), Rule::Integer, text)),
        AddrExpr::Hex(v) => Ok(found(Named::Addr(Address::ram(*v)), Rule::Hex, text)),
        AddrExpr::Id(id) => by_id(program, id, text, site),
        AddrExpr::Digits(readings) => Err(errors::base_ambiguous(
            program,
            *readings,
            &|v| format!("{v:#x}"),
            site,
        )),
        AddrExpr::Name(name) => by_name(program, name, site),
        AddrExpr::Offset(offset) => by_offset(program, offset, text, site),
    }
}

/// Resolves the symbol names of rule 4 and of `sym:`: exactly one address, or an error.
fn by_symbol(
    program: &Program,
    name: &str,
    rule: Rule,
    text: &str,
    site: &Site<'_>,
) -> Option<Result<Resolved, ToolError>> {
    match program.addrs_named(name).as_slice() {
        [] => None,
        [one] => Some(Ok(found(Named::Addr(*one), rule, text))),
        many => Some(Err(errors::ambiguous(program, name, many, site))),
    }
}

/// Resolves rules 4 to 8 for a name text.
fn by_name(program: &Program, name: &NameExpr, site: &Site<'_>) -> Result<Resolved, ToolError> {
    let text = name.text.as_str();
    if let Some(result) = by_symbol(program, text, Rule::Symbol, text, site) {
        return result;
    }
    let sections: Vec<(String, Address)> = program
        .binary()
        .sections
        .iter()
        .filter(|s| s.name.as_str() == Some(text))
        .filter_map(|s| {
            let start = Address::ram(s.va?.first);
            let index = u16::try_from(s.index).ok()?;
            let id = SectionId::new(index, text).ok()?;
            Some((id.to_string(), start))
        })
        .collect();
    match sections.as_slice() {
        [] => {}
        [(_, start)] => return Ok(found(Named::Addr(*start), Rule::Section, text)),
        _ => return Err(errors::ambiguous_ids(sections, site)),
    }
    if let Some(default) = name.default {
        return Ok(found(Named::Addr(default.addr), Rule::DefaultName, text));
    }
    if let Some(at) = &name.at {
        let addr = Address::ram(at.addr);
        if program
            .symbols_at(addr)
            .iter()
            .any(|s| s.name.value == at.name)
        {
            return Ok(found(Named::Addr(addr), Rule::NameAt, text));
        }
    }
    if let Some(split) = &name.split {
        return by_offset(program, split, text, site);
    }
    if let Some(value) = name.bare_hex {
        return Err(errors::address_invalid(site, Some(format!("{value:#x}"))));
    }
    Err(errors::not_found("name", text, names(program), site))
}

/// Resolves rule 3: an ID.
fn by_id(program: &Program, id: &Id, text: &str, site: &Site<'_>) -> Result<Resolved, ToolError> {
    let named = match id {
        Id::Func(f) => {
            if program.func(*f).is_none() {
                let ids: Vec<String> = program.funcs().iter().map(|v| v.id().to_string()).collect();
                return Err(errors::not_found(
                    "function",
                    text,
                    ids.iter().map(String::as_str),
                    site,
                ));
            }
            Named::Func(*f)
        }
        Id::Block(b) => Named::Addr(b.0),
        Id::Op(op) => Named::Addr(Address::ram(op.addr)),
        Id::Import(i) => {
            if !program.imports().contains_key(i) {
                let ids: Vec<String> = program.imports().keys().map(ToString::to_string).collect();
                return Err(errors::not_found(
                    "import",
                    text,
                    ids.iter().map(String::as_str),
                    site,
                ));
            }
            Named::Import(i.clone())
        }
        Id::Export(e) => {
            if !program.exports().contains_key(e) {
                let ids: Vec<String> = program.exports().keys().map(ToString::to_string).collect();
                return Err(errors::not_found(
                    "export",
                    text,
                    ids.iter().map(String::as_str),
                    site,
                ));
            }
            Named::Export(e.clone())
        }
        Id::Syscall(s) => Named::Syscall(s.clone()),
        Id::Section(s) => Named::Region(section_start(program, s, text, site)?),
        Id::Segment(s) => Named::Region(segment_start(program, *s, text, site)?),
        Id::Str(s) => Named::Str(*s),
        Id::JumpTable(j) => Named::JumpTable(*j),
        Id::External(off) => Named::External(Address::external(*off)),
        Id::File(f) => Named::Region(file_va(program, f.0, site)?),
        Id::Sym(s) => {
            return by_symbol(program, s.as_str(), Rule::Id, text, site).unwrap_or_else(|| {
                Err(errors::not_found(
                    "symbol",
                    s.as_str(),
                    names(program),
                    site,
                ))
            });
        }
        Id::Var(_) | Id::Note(_) | Id::Set(_) | Id::Type(_) | Id::Tx(_) | Id::Ref(_) => {
            Named::Other(id.kind())
        }
    };
    Ok(found(named, Rule::Id, text))
}

/// Gives the start of the section of a `sec:` ID.
fn section_start(
    program: &Program,
    id: &SectionId,
    text: &str,
    site: &Site<'_>,
) -> Result<Address, ToolError> {
    let section = program
        .binary()
        .sections
        .iter()
        .find(|s| s.index == u32::from(id.index()) && s.name.as_str() == Some(id.name()));
    let Some(section) = section else {
        let ids: Vec<String> = program
            .binary()
            .sections
            .iter()
            .filter_map(|s| {
                let index = u16::try_from(s.index).ok()?;
                SectionId::new(index, s.name.as_str()?).ok()
            })
            .map(|id| id.to_string())
            .collect();
        return Err(errors::not_found(
            "section",
            text,
            ids.iter().map(String::as_str),
            site,
        ));
    };
    section
        .va
        .map(|va| Address::ram(va.first))
        .ok_or_else(|| errors::invalid("a section with an address", site))
}

/// Gives the start of the segment of a `seg:` ID.
fn segment_start(
    program: &Program,
    id: SegmentId,
    text: &str,
    site: &Site<'_>,
) -> Result<Address, ToolError> {
    let segment = program
        .binary()
        .segments
        .iter()
        .find(|s| s.index == u32::from(id.0));
    let Some(segment) = segment else {
        let ids: Vec<String> = program
            .binary()
            .segments
            .iter()
            .map(|s| format!("seg:{}", s.index))
            .collect();
        return Err(errors::not_found(
            "segment",
            text,
            ids.iter().map(String::as_str),
            site,
        ));
    };
    segment
        .va
        .map(|va| Address::ram(va.first))
        .ok_or_else(|| errors::invalid("a segment with an address", site))
}

/// Gives the address that maps the file offset `off`: the first region in address order.
fn file_va(program: &Program, off: u64, site: &Site<'_>) -> Result<Address, ToolError> {
    program
        .mem()
        .regions()
        .find_map(|r| {
            let delta = off.checked_sub(r.file_off)?;
            (delta < r.file_size).then(|| r.va.first.checked_add(delta))?
        })
        .map(Address::ram)
        .ok_or_else(|| {
            errors::at(
                site,
                ToolError::new(ghidorah_base::ErrorCode::AddressUnmapped),
            )
        })
}

/// Resolves rule 8: a term with a `0x` offset.
fn by_offset(
    program: &Program,
    offset: &OffsetExpr,
    text: &str,
    site: &Site<'_>,
) -> Result<Resolved, ToolError> {
    let sign = text.rfind(['+', '-']).unwrap_or(text.len());
    let (left, right) = text.split_at(sign);
    let mark = right.get(..1).unwrap_or("+");
    let tail = right.get(1..).unwrap_or_default();
    let base = match &*offset.term {
        AddrExpr::Integer(v) | AddrExpr::Hex(v) => Address::ram(*v),
        AddrExpr::Digits(readings) => {
            let rewrite = |v: u64| format!("{v:#x}{mark}{tail}");
            return Err(errors::base_ambiguous(program, *readings, &rewrite, site));
        }
        AddrExpr::Id(id) => value_of(program, &by_id(program, id, left, site)?)?,
        AddrExpr::Name(name) => value_of(program, &by_name(program, name, site)?)?,
        AddrExpr::Offset(_) => return Err(errors::address_invalid(site, None)),
    };
    let delta = match offset.offset {
        OffsetValue::Hex(v) => v,
        OffsetValue::Digits(readings) => {
            let rewrite = |v: u64| format!("{left}{mark}{v:#x}");
            return Err(errors::base_ambiguous(program, readings, &rewrite, site));
        }
    };
    let off = if offset.negative {
        base.off.checked_sub(delta)
    } else {
        base.off.checked_add(delta)
    };
    off.map(|off| {
        found(
            Named::Addr(Address::new(base.space, off)),
            Rule::Offset,
            text,
        )
    })
    .ok_or_else(|| errors::address_invalid(site, None))
}
