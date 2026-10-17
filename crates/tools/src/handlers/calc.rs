//! `calc`: calculate numbers and addresses (design Section 10.4, tool 10).
//!
//! The expression grammar is in [`crate::calc`]. Name and ID terms use the resolver of
//! [`crate::resolve`] with the address rules, so a symbol, a section, a default name or an
//! ID is a value. With no open binary, only number terms work.
//!
//! Output: `{ value, unsigned, signed, views, address? }`. `value` is hex text. `unsigned`,
//! `signed` and each view are decimal text, because output has no JSON integer above 2^53.
//! `address` exists with a bound binary: `{ mapped, region, file_offset, func }`.

use ghidorah_base::IdKind;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, BinaryArg, Example, Profile, Role, ToolSpec};

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const ARGS: &[ArgSpec] = &[ArgSpec::new(
    "expr",
    Role::Param,
    ArgKind::Str(crate::calc::MAX_EXPR_CHARS),
    "The expression, for example main+0x10 or (0x401000 & ~0xfff) >> 0x4.",
)
.required()];

const VIEWS: &[Field] = &[
    Field::req("u8", OutputShape::Str),
    Field::req("u16", OutputShape::Str),
    Field::req("u32", OutputShape::Str),
    Field::req("u64", OutputShape::Str),
    Field::req("i8", OutputShape::Str),
    Field::req("i16", OutputShape::Str),
    Field::req("i32", OutputShape::Str),
    Field::req("i64", OutputShape::Str),
];
const FUNC: &[Field] = &[
    Field::req("id", OutputShape::Id(IdKind::Func)),
    Field::req("name", OutputShape::Text),
];
const FUNC_SHAPE: OutputShape = OutputShape::Obj(FUNC);
const ADDRESS: &[Field] = &[
    Field::req("mapped", OutputShape::Bool),
    Field::req("region", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("file_offset", OutputShape::Nullable(&OutputShape::Addr)),
    Field::req("func", OutputShape::Nullable(&FUNC_SHAPE)),
];
const FIELDS: &[Field] = &[
    Field::req("value", OutputShape::Addr),
    Field::req("unsigned", OutputShape::Str),
    Field::req("signed", OutputShape::Str),
    Field::req("views", OutputShape::Obj(VIEWS)),
    Field::opt("address", OutputShape::Obj(ADDRESS)),
];

/// `calc`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Calculate values",
    summary: "Calculate numbers and addresses: bases, widths, signedness and file offsets.",
    description: "Calculate numbers and addresses: bases, widths, signedness and file offsets. \
                  The expression takes the operators + - * / % << >> & | ^ ~ and parentheses. \
                  A term is a 0x hex number, a symbol, a section name, a default name such as FUN_00401000 or an ID such as fn:0x401000. \
                  A term of digits only is an error, because the server does not guess the base. \
                  The arithmetic uses 64 bits and wraps. Division is unsigned. \
                  The result gives the value as hex text, the unsigned and signed decimal text and a view of each width. \
                  With an open binary, the result also tells the region, the file offset and the function at the value.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[
        Example {
            args: r#"{"expr":"main+0x10"}"#,
            golden: "tests/golden/tools/calc.1.json",
        },
        Example {
            args: r#"{"expr":"(0x401000 & ~0xfff) >> 0x4"}"#,
            golden: "tests/golden/tools/calc.2.json",
        },
        Example {
            args: r#"{"expr":"-0x1 * 0x3 / 0x2 % 0x7 + 0x10 - 0x4 | 0x100 ^ 0x5 << 0x1"}"#,
            golden: "tests/golden/tools/calc.3.json",
        },
    ],
    binary: BinaryArg::Optional,
    ..ToolSpec::base("calc", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session, args, ctx);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}
