//! `calc`: calculate numbers and addresses (design Section 10.4, tool 10).
//!
//! The expression grammar is in [`crate::calc`]. Name and ID terms use the resolver of
//! [`crate::resolve`] with the address rules, so a symbol, a section, a default name or an
//! ID is a value. With no open binary, only number terms work.
//!
//! Output: `{ value, unsigned, signed, views, address? }`. `value` is hex text. `unsigned`,
//! `signed` and each view are decimal text, because output has no JSON integer above 2^53.
//! `address` exists with a bound binary: `{ mapped, region, file_offset, func }`.

use ghidorah_base::{Address, BinText, Caps, ErrorCode, IdKind, hex};
use ghidorah_db::Program;
use ghidorah_json::{Limits, Object, Value};

use crate::args::{Args, Format};
use crate::calc::{signed_text, views};
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::hints::{Call, WHY_HEX};
use crate::outshape::{Field, OutputShape};
use crate::resolve::{Site, resolve_text, value_of};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, BinaryArg, Example, Profile, Role, ToolSpec};

/// The `why` of the repair call of `BINARY_REQUIRED`.
pub const WHY_BINARY: &str = "Send the call with the most recent binary_id.";

/// The `why` of the `addr_info` hint on a mapped value.
pub const WHY_ADDR: &str = "Tell what is at the address.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_BINARY, WHY_ADDR];

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
                  The arithmetic uses 64 bits and wraps, and division is unsigned. \
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

/// Gives the call of `args` with the argument `key` set to `value`.
fn with(args: &Args, key: &str, value: Value) -> Value {
    let mut object = args.canonical().as_object().cloned().unwrap_or_default();
    let _ = object.insert(key, value);
    Value::Object(object)
}

/// Gives the `BinText` JSON of a binary name.
fn bin_text(name: &str, format: Format) -> Value {
    let caps = match format {
        Format::Concise => Caps::DEFAULT,
        Format::Detailed => Caps::DETAILED,
    };
    let json = BinText::new(name.as_bytes()).to_json(caps);
    ghidorah_json::parse(&json, &Limits::DEFAULT).unwrap_or_default()
}

/// Gives the `address` member: what the value is in the program.
fn address_of(program: &Program, value: u64, format: Format) -> Value {
    let region = program.mem().region_at(value);
    let func = program.owner_of(Address::ram(value)).map(|id| {
        let name = program.name(id.0).map(|n| n.text).unwrap_or_default();
        Value::object([
            ("id", Value::from(id.to_string())),
            ("name", bin_text(&name, format)),
        ])
    });
    Value::object([
        ("mapped", Value::Bool(region.is_some())),
        (
            "region",
            region
                .map(|r| Value::from(r.name.as_str()))
                .unwrap_or_default(),
        ),
        (
            "file_offset",
            program
                .mem()
                .va_to_file(value)
                .map(|off| Value::from(hex::u64_text(off)))
                .unwrap_or_default(),
        ),
        ("func", func.unwrap_or_default()),
    ])
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let expr = args.str("expr").unwrap_or_default();
    let program = match &ctx.frame.binary_id {
        Some(_) => Some(&session.bound(&ctx.frame)?.program),
        None => None,
    };
    let unbound = || -> ToolError {
        if session.binaries().next().is_none() {
            return ToolError::new(ErrorCode::NoBinaryOpen);
        }
        let error = session.binary_required();
        match session.recent() {
            Some(id) => {
                let call = with(args, "binary_id", Value::from(id.to_string()));
                error.next(Call::new("calc", call, WHY_BINARY))
            }
            None => error,
        }
    };
    let mut term = |name: &str| -> Result<u64, ToolError> {
        let Some(p) = program else {
            return Err(unbound());
        };
        let repair = |fixed: &str| {
            Call::new(
                "calc",
                with(args, "expr", Value::from(expr.replacen(name, fixed, 1))),
                WHY_HEX,
            )
        };
        let site = Site {
            path: "/expr",
            repair: Some(&repair),
        };
        let resolved = resolve_text(p, name, &site)?;
        value_of(p, &resolved).map(|a| a.off)
    };
    let value = crate::calc::eval(expr, &mut term)?;
    let mut out = Object::new();
    out.push("value", Value::from(hex::u64_text(value)));
    out.push("unsigned", Value::from(value.to_string()));
    out.push("signed", Value::from(signed_text(value)));
    out.push("views", views(value));
    if let Some(p) = program {
        let address = address_of(p, value, ctx.format);
        if address.get("mapped") == Some(&Value::Bool(true)) {
            ctx.hint(Call::new(
                "addr_info",
                Value::object([("target", Value::from(hex::u64_text(value)))]),
                WHY_ADDR,
            ));
        }
        out.push("address", address);
    }
    Ok(Payload::Object(out))
}
