//! `type_get`: get a C type with its layout (design Sections 9.3 and 10.4, tool 12).
//!
//! The call names a type in one of two ways:
//!
//! | Argument | Input | Type |
//! |---|---|---|
//! | `target` | a `t:` ID, for example `t:sockaddr_in` or `t:#<fnv64>` | the type of the reference |
//! | `target` | a name: a typedef, a tag or a primitive type, for example `size_t` | the typedef first, then the tag, then the primitive type |
//! | `c` | C type text in `type` mode, for example `struct timespec *` | the parsed type |
//!
//! The parse of `c` uses a copy of the type store, so the call changes no type. The result is
//! `{ id, name, kind, c?, size, align, layout?, fields? }`:
//!
//! - `kind` is `prim`, `ptr`, `array`, `struct`, `union`, `enum`, `typedef`, `func` or `qual`.
//! - `c` (with `decl`) is the C definition, for example `struct timespec { long tv_sec; .. };`.
//! - `size` and `align` follow the natural layout of the data model. A type with no size, for
//!   example `void` or a function type, has `null`.
//! - `layout` (with `layout`) has one line per field: `+0x8 long tv_nsec`. `fields` holds
//!   `{ name, offset, size, type }` for each field of a record.

use ghidorah_base::{ErrorCode, Fuel, Id, did_you_mean};
use ghidorah_json::{Object, Value};
use ghidorah_types::{CParseError, DataModel, Prim, Type, TypeId, TypeStore, layout, parse_type};

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::{Candidate, ToolError};
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, Group, GroupRule, Profile, Role, ToolSpec};

/// The parts of the result in schema order.
pub const PARTS: [&str; 2] = ["decl", "layout"];

/// The longest type name or `t:` ID.
pub const MAX_TARGET: usize = 1_024;

/// The longest C type text.
pub const MAX_C: usize = 4_000;

/// The largest number of did-you-mean candidates of an unknown name.
pub const MAX_CANDIDATES: usize = 5;

/// The fuel of the did-you-mean scan of an unknown name.
const DYM_FUEL: u64 = 100_000;

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const PART: ArgSpec = ArgSpec::new(
    "part",
    Role::Param,
    ArgKind::Enum(&PARTS),
    "One part of the result.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Str(MAX_TARGET),
        "The type: a t: ID or a type name, for example t:sockaddr_in or size_t.",
    ),
    ArgSpec::new(
        "c",
        Role::Param,
        ArgKind::Str(MAX_C),
        "The C type text, for example struct sockaddr_in *.",
    ),
    ArgSpec::new(
        "include",
        Role::Param,
        ArgKind::List(&PART, 2),
        "The parts of the result: decl for the C definition, layout for the fields.",
    )
    .default_json(r#"["decl","layout"]"#),
];

const FIELD: &[Field] = &[
    Field::req("name", OutputShape::Str),
    Field::req("offset", OutputShape::Int),
    Field::req("size", OutputShape::Int),
    Field::req("type", OutputShape::Str),
];
const FIELD_ITEM: OutputShape = OutputShape::Obj(FIELD);

const FIELDS: &[Field] = &[
    Field::req("id", OutputShape::Str),
    Field::req("name", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("kind", OutputShape::Str),
    Field::opt("c", OutputShape::Str),
    Field::req("size", OutputShape::Nullable(&OutputShape::Int)),
    Field::req("align", OutputShape::Nullable(&OutputShape::Int)),
    Field::opt("layout", OutputShape::List(&OutputShape::Str)),
    Field::opt("fields", OutputShape::List(&FIELD_ITEM)),
];

/// `type_get`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Get a C type",
    summary: "Get a C type with its definition and its layout: size, alignment and field offsets.",
    description: "Get a C type with its definition and its layout: size, alignment and field offsets. \
                  Send target with a t: ID or a type name, or send c with C type text. \
                  The text c can name the prelude types, for example struct sockaddr_in, size_t and FILE. \
                  The layout follows the natural rules of the data model of the binary, with no bit-fields. \
                  A type with no size, for example void, has size null.",
    args: ARGS,
    groups: &[Group {
        members: &["target", "c"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[
        Example {
            args: r#"{"target":"t:sockaddr_in"}"#,
            golden: "tests/golden/tools/type_get.1.json",
        },
        Example {
            args: r#"{"c":"struct timespec *","include":["decl"]}"#,
            golden: "tests/golden/tools/type_get.2.json",
        },
        Example {
            args: r#"{"target":"size_t"}"#,
            golden: "tests/golden/tools/type_get.3.json",
        },
    ],
    ..ToolSpec::base("type_get", run)
};

/// Gives the `C_PARSE_ERROR` of C text at the argument path `path` (design Section 9.2).
///
/// Each item of `details.errors` is `{ code, at: { line, col, byte, len }, snippet,
/// expected, candidates, hint }`.
#[must_use]
pub fn parse_error(error: &CParseError, path: &str) -> ToolError {
    let texts =
        |list: &[String]| Value::Array(list.iter().map(|t| Value::from(t.as_str())).collect());
    let list = error
        .errors
        .iter()
        .map(|d| {
            let at = Value::object([
                ("line", Value::from(d.at.line)),
                ("col", Value::from(d.at.col)),
                ("byte", Value::from(d.at.byte)),
                ("len", Value::from(d.at.len)),
            ]);
            Value::object([
                ("code", Value::from(d.code.name())),
                ("at", at),
                ("snippet", Value::from(d.snippet.as_str())),
                ("expected", texts(&d.expected)),
                ("candidates", texts(&d.candidates)),
                ("hint", Value::from(d.hint.as_str())),
            ])
        })
        .collect();
    ToolError::new(ErrorCode::CParseError)
        .path(path)
        .detail("errors", Value::Array(list))
}

/// Gives the kind name of a type: `prim`, `ptr`, `array`, `struct`, `union`, `enum`,
/// `typedef`, `func` or `qual`.
const fn kind_name(ty: &Type) -> &'static str {
    match ty {
        Type::Prim(_) => "prim",
        Type::Ptr(_) => "ptr",
        Type::Array { .. } => "array",
        Type::Record(r) => r.kind.keyword(),
        Type::Enum(_) => "enum",
        Type::Typedef { .. } => "typedef",
        Type::Func(_) => "func",
        Type::Qual { .. } => "qual",
    }
}

/// Gives the name of a type, or `None` for a type with no name.
fn type_name(ty: &Type) -> Option<&str> {
    match ty {
        Type::Prim(p) => Some(p.c_name()),
        Type::Record(r) => r.name.as_deref(),
        Type::Enum(e) => e.name.as_deref(),
        Type::Typedef { name, .. } => Some(name),
        _ => None,
    }
}

/// Gives `NOT_FOUND` for the type name `text` with the nearest names as candidates.
fn unknown(store: &TypeStore, text: &str) -> ToolError {
    let names: Vec<String> = store
        .tag_names()
        .chain(store.typedef_names())
        .map(str::to_owned)
        .chain(Prim::ALL.iter().map(|p| p.c_name().to_owned()))
        .collect();
    let mut fuel = Fuel::new(DYM_FUEL);
    let candidates = did_you_mean(text, names.iter().map(String::as_str), &mut fuel)
        .into_iter()
        .take(MAX_CANDIDATES)
        .map(|s| {
            let mut c = Candidate::text(&s.name, "type");
            c.kind = Some("type".to_owned());
            c
        })
        .collect();
    ToolError::new(ErrorCode::NotFound)
        .var("kind", "type")
        .path("/target")
        .detail("kind", Value::from("type"))
        .candidates(candidates)
}

/// Finds the type of `target` in `store`: a `t:` ID, a typedef, a tag or a primitive name.
/// Other text parses in `type` mode in `store`.
fn lookup(store: &mut TypeStore, target: &str) -> Result<TypeId, ToolError> {
    let text = target.trim();
    if text.starts_with("t:") {
        return match Id::parse(text) {
            Ok(Id::Type(r)) => store.by_ref(&r).ok_or_else(|| unknown(store, text)),
            _ => Err(unknown(store, text)),
        };
    }
    let named = store
        .lookup_typedef(text)
        .or_else(|| store.lookup_tag(text))
        .or_else(|| Prim::from_c_name(text).map(|p| store.prim(p)));
    if let Some(id) = named {
        return Ok(id);
    }
    parse_type(store, text).map_err(|_| unknown(store, text))
}

/// Gives the layout lines and the field rows of the fields of `shape`.
fn field_parts(store: &TypeStore, shape: Option<&layout::Layout>) -> (Value, Value) {
    let list = shape.map(|l| l.fields.as_slice()).unwrap_or_default();
    let lines = list
        .iter()
        .map(|f| {
            let decl = store.c_decl(f.ty, &f.name).unwrap_or_default();
            Value::from(format!("+{:#x} {decl}", f.offset))
        })
        .collect();
    let rows = list
        .iter()
        .map(|f| {
            Value::object([
                ("name", Value::from(f.name.as_str())),
                ("offset", Value::from(f.offset)),
                ("size", Value::from(f.size)),
                ("type", Value::from(store.c_text(f.ty).unwrap_or_default())),
            ])
        })
        .collect();
    (Value::Array(lines), Value::Array(rows))
}

/// Gives the result object of the type `id` with the parts `decl` and `layout`.
fn render(store: &TypeStore, model: &DataModel, id: TypeId, decl: bool, fields: bool) -> Object {
    let ty = store.get(id);
    let shape = layout::sysv(store, id, model).ok();
    let mut out = Object::new();
    let reference = store
        .type_ref(id)
        .map_or(Value::Null, |r| Value::from(r.to_string()));
    out.push("id", reference);
    out.push(
        "name",
        ty.and_then(type_name).map_or(Value::Null, Value::from),
    );
    out.push("kind", Value::from(ty.map_or("prim", kind_name)));
    if decl {
        let text = store.c_definition(id).unwrap_or_default();
        out.push("c", Value::from(text));
    }
    let size = shape.as_ref().map_or(Value::Null, |l| Value::from(l.size));
    let align = shape.as_ref().map_or(Value::Null, |l| Value::from(l.align));
    out.push("size", size);
    out.push("align", align);
    if fields {
        let (lines, rows) = field_parts(store, shape.as_ref());
        out.push("layout", lines);
        out.push("fields", rows);
    }
    out
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    let mut store = p.types().store().clone();
    let id = match args.str("c") {
        Some(c) => parse_type(&mut store, c).map_err(|e| parse_error(&e, "/c"))?,
        None => lookup(&mut store, args.str("target").unwrap_or_default())?,
    };
    let parts: Vec<&str> = args
        .list("include")
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let out = render(
        &store,
        p.types().model(),
        id,
        parts.contains(&"decl"),
        parts.contains(&"layout"),
    );
    Ok(Payload::Object(out))
}
