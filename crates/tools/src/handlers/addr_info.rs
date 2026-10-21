//! `addr_info`: tell what is at an address (design Section 10.4, tool 9).
//!
//! The result of one address is `{ input, addr, resolved_from, region, section, func?,
//! symbol?, code_unit, override?, xrefs_in, xrefs_out, notes, comments?, refs?,
//! file_offset }`. `resolved_from` gives the rule of design Section 10.5 that resolved the
//! input. `code_unit` is `{ kind: insn | data | undefined, len, mnem?, text?, type? }`.
//! `include` adds `comments` (each kind with its text and source) and `refs` (the references
//! in and out). With `targets`, the result is `{ items: [{ input, ok, data | error }],
//! ok_count, error_count }` in input order (AC-144).

use ghidorah_base::{Address, BinText, Caps, FileOffset, FuncId, SectionId, SymId};
use ghidorah_db::{CommentKind, FlowOverride, Program};
use ghidorah_json::{Object, Value};

use super::func_sections::{self as fs, Namer};
use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, Group, GroupRule, Profile, Role, ToolSpec};

/// The largest number of targets of one call.
pub const MAX_TARGETS: usize = 50;

/// The largest number of references in each list of `refs`.
pub const MAX_REFS: usize = 20;

const INCLUDE_ITEM: ArgSpec = ArgSpec::new(
    "part",
    Role::Param,
    ArgKind::Enum(&["refs", "comments"]),
    "One optional part of the result.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The address: a 0x hex string, a name or an ID.",
    ),
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(MAX_TARGETS),
        "Up to 50 addresses. Each item gets its own result.",
    ),
    ArgSpec::new(
        "include",
        Role::Param,
        ArgKind::List(&INCLUDE_ITEM, 2),
        "The optional parts: refs and comments.",
    ),
];

const FIELDS: &[Field] = &[
    Field::opt("input", OutputShape::Any),
    Field::opt("addr", OutputShape::Str),
    Field::opt("resolved_from", OutputShape::Any),
    Field::opt("region", OutputShape::Any),
    Field::opt("section", OutputShape::Any),
    Field::opt("func", OutputShape::Any),
    Field::opt("symbol", OutputShape::Any),
    Field::opt("code_unit", OutputShape::Any),
    Field::opt("override", OutputShape::Any),
    Field::opt("xrefs_in", OutputShape::Int),
    Field::opt("xrefs_out", OutputShape::Int),
    Field::opt("notes", OutputShape::Int),
    Field::opt("comments", OutputShape::Any),
    Field::opt("refs", OutputShape::Any),
    Field::opt("file_offset", OutputShape::Nullable(&OutputShape::Addr)),
    Field::opt("items", OutputShape::Any),
    Field::opt("ok_count", OutputShape::Int),
    Field::opt("error_count", OutputShape::Int),
];

/// `addr_info`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Describe addresses",
    summary: "Tell what is at an address: region, section, function, symbol, code unit, overrides, comments and xref counts.",
    description: "Tell what is at an address: region, section, function, symbol, code unit, overrides, comments and xref counts. \
                  Send target, or targets for up to 50 addresses. \
                  Send include with refs or comments for those lists.",
    args: ARGS,
    groups: &[Group {
        members: &["target", "targets"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[
        Example {
            args: r#"{"target":"main"}"#,
            golden: "tests/golden/tools/addr_info.1.json",
        },
        Example {
            args: r#"{"targets":["0x1091","imp:puts","0x2004"],"include":["refs","comments"]}"#,
            golden: "tests/golden/tools/addr_info.2.json",
        },
    ],
    ..ToolSpec::base("addr_info", run)
};

/// The optional parts of one call.
#[derive(Debug, Clone, Copy)]
struct Parts {
    refs: bool,
    comments: bool,
}

/// Gives the ID of the section `s`: the [`SectionId`] text of its exact name. So the ID
/// parses back to `s`.
///
/// A name that is not UTF-8 or an index above `u16::MAX` has no section ID. Then the ID is
/// the start address of the section, else its file offset. An ID never holds a cut name.
#[must_use]
pub(crate) fn section_id(s: &ghidorah_loader::Section) -> String {
    let id = s
        .name
        .as_str()
        .zip(u16::try_from(s.index).ok())
        .and_then(|(name, index)| SectionId::new(index, name).ok());
    match (id, s.va) {
        (Some(id), _) => id.to_string(),
        (None, Some(va)) => Address::ram(va.first).to_string(),
        (None, None) => FileOffset(s.file_off).to_string(),
    }
}

/// Gives the display text of the binary name `name`: the escapes of `BinText` once, at most
/// [`fs::NAME_CHARS`] characters. A UTF-8 name gives the text of [`fs::safe`].
#[must_use]
pub(crate) fn shown(name: &BinText) -> String {
    name.render(Caps::new(fs::NAME_CHARS, 0)).text
}

/// Gives the ID of the symbol `name` at `addr` (design Section 3.5). Each ID resolves to
/// `addr`.
///
/// | Case | ID |
/// |---|---|
/// | `addrs_named(name)` is exactly `[addr]` | the [`SymId`] text of the exact name |
/// | a function starts at `addr` | the function ID |
/// | `addr` is not 0 | the address |
/// | else | `None` |
///
/// The caller gives the `imp:` ID of an undefined import symbol for `None`. An ID never
/// holds a cut name.
#[must_use]
pub(crate) fn symbol_id(p: &Program, name: &str, addr: Address) -> Option<String> {
    let only = p.addrs_named(name).as_slice() == [addr];
    if let Some(id) = only.then(|| SymId::new(name).ok()).flatten() {
        return Some(id.to_string());
    }
    let func = FuncId(addr);
    if p.func(func).is_some() {
        return Some(func.to_string());
    }
    (addr.off != 0).then(|| addr.to_string())
}

/// Gives the section that holds `addr`: `{ id, name }`, or `null`.
fn section(p: &Program, addr: Address) -> Value {
    let found = p.binary().sections.iter().find(|s| {
        s.va.is_some_and(|r| addr.is_ram() && r.first <= addr.off && addr.off <= r.last)
    });
    found.map_or(Value::Null, |s| {
        Value::object([
            ("id", Value::from(section_id(s))),
            ("name", Value::from(shown(&s.name))),
        ])
    })
}

/// Gives the code unit at `addr`: an instruction, a data definition or `undefined`.
fn code_unit(p: &Program, addr: Address, namer: &Namer) -> Value {
    let mut out = Object::new();
    if addr.is_ram()
        && p.code_unit(addr.off).is_some()
        && let Some(insn) = fs::decode(p, addr.off)
    {
        let row = fs::row(p, &insn, namer);
        out.push("kind", Value::from("insn"));
        out.push("len", Value::from(insn.len()));
        out.push("mnem", Value::from(insn.mnem().name()));
        out.push("text", row.get("t").cloned().unwrap_or_default());
        return Value::Object(out);
    }
    if let Some(def) = addr.is_ram().then(|| p.data_def(addr.off)).flatten() {
        out.push("kind", Value::from("data"));
        out.push("len", Value::from(def.value.len));
        if let Some(text) = fs::type_text(p, def.value.ty) {
            out.push("type", Value::from(text));
        }
        return Value::Object(out);
    }
    out.push("kind", Value::from("undefined"));
    out.push("len", Value::from(1));
    Value::Object(out)
}

/// Gives the flow override at `addr`, or `None`.
fn flow_override(p: &Program, addr: Address) -> Option<Value> {
    let fact = p.flow_override(addr)?;
    let mut out = Object::new();
    out.push("kind", Value::from(fact.value.name()));
    match &fact.value {
        FlowOverride::Fallthrough(to) => out.push("to", fs::addr(*to)),
        FlowOverride::IndirectTargets(list) => {
            out.push(
                "targets",
                Value::Array(list.iter().map(|a| fs::addr(*a)).collect()),
            );
        }
        FlowOverride::CallAsJump | FlowOverride::JumpAsCall => {}
    }
    out.push("source", Value::from(fact.source.name()));
    Some(Value::Object(out))
}

/// Gives the comments at `addr`: `[{ kind, text, source }]` in kind order.
fn comments(p: &Program, addr: Address) -> Value {
    let list = CommentKind::ALL
        .iter()
        .filter_map(|k| {
            p.comment(addr, *k).map(|f| {
                Value::object([
                    ("kind", Value::from(k.name())),
                    ("text", Value::from(f.value.as_str())),
                    ("source", Value::from(f.source.name())),
                ])
            })
        })
        .collect();
    Value::Array(list)
}

/// Gives the references in and out of `addr`, at most [`MAX_REFS`] of each.
fn refs(p: &Program, addr: Address) -> Value {
    let list = |refs: Vec<&ghidorah_db::Fact<ghidorah_db::Ref>>, key: &str| {
        let items = refs
            .iter()
            .take(MAX_REFS)
            .map(|r| {
                let k = r.value.key;
                let other = if key == "from" { k.from } else { k.to };
                Value::object([(key, fs::addr(other)), ("kind", Value::from(k.kind.name()))])
            })
            .collect();
        Value::Array(items)
    };
    Value::object([
        ("in", list(p.refs_to(addr), "from")),
        ("out", list(p.refs_from(addr), "to")),
    ])
}

/// Gives the result of one address input.
fn info(
    p: &Program,
    input: &Value,
    path: &str,
    parts: Parts,
    namer: &Namer,
) -> Result<Value, ToolError> {
    let (addr, resolved) = crate::resolve::address(p, input, &fs::site(path))?;
    let region = addr.is_ram().then(|| p.mem().region_at(addr.off)).flatten();
    let mut out = Object::new();
    out.push("input", input.clone());
    out.push("addr", fs::addr(addr));
    out.push("resolved_from", resolved.resolved_from());
    out.push(
        "region",
        region.map_or(Value::Null, |r| {
            Value::object([
                ("name", Value::from(fs::safe(&r.name))),
                ("perms", Value::from(r.perms.to_string())),
            ])
        }),
    );
    out.push("section", section(p, addr));
    if let Some(owner) = p.owner_of(addr) {
        out.push(
            "func",
            Value::object([
                ("id", Value::from(owner.to_string())),
                ("name", Value::from(namer.of(p, owner.0))),
                ("offset", fs::hex(addr.off.saturating_sub(owner.0.off))),
            ]),
        );
    }
    if let Some(symbol) = p.primary_symbol(addr) {
        out.push(
            "symbol",
            Value::object([
                ("name", Value::from(namer.at(p, addr, &symbol.name.value))),
                ("source", Value::from(symbol.name.source.name())),
                ("kind", Value::from(symbol.kind.name())),
            ]),
        );
    }
    out.push("code_unit", code_unit(p, addr, namer));
    if let Some(o) = flow_override(p, addr) {
        out.push("override", o);
    }
    out.push("xrefs_in", Value::from(p.refs_to(addr).len()));
    out.push("xrefs_out", Value::from(p.refs_from(addr).len()));
    let notes = p.notes().iter().filter(|n| n.at == Some(addr)).count();
    out.push("notes", Value::from(notes));
    if parts.comments {
        out.push("comments", comments(p, addr));
    }
    if parts.refs {
        out.push("refs", refs(p, addr));
    }
    let file = addr
        .is_ram()
        .then(|| p.mem().va_to_file(addr.off))
        .flatten();
    out.push("file_offset", file.map_or(Value::Null, fs::hex));
    Ok(Value::Object(out))
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    let wanted = |part: &str| {
        args.list("include")
            .unwrap_or_default()
            .iter()
            .any(|v| v.as_str() == Some(part))
    };
    let parts = Parts {
        refs: wanted("refs"),
        comments: wanted("comments"),
    };
    let namer = Namer::new();
    let out = if let Some(targets) = args.list("targets") {
        fs::per_item(&ctx.inactive, "targets", targets, |i, input| {
            info(p, input, &fs::item_path("targets", i), parts, &namer)
        })
    } else {
        let input = args.get("target").cloned().unwrap_or_default();
        match info(p, &input, "/target", parts, &namer)? {
            Value::Object(object) => object,
            _ => Object::new(),
        }
    };
    namer.finish(ctx);
    Ok(Payload::Object(out))
}
