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

use ghidorah_base::ErrorCode;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
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

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session, args, ctx);
    Err(ToolError::new(ErrorCode::InternalError))
}
