//! `mem_read`: read memory in one form (design Section 10.4, tool 8).
//!
//! The result is `{ addr, len, hex, text, values?, fields?, rows?, next_cursor?, region }`.
//! The read never crosses the end of the region of `target`. Bytes past the file size of a
//! region read as zero (design Section 3.3).
//!
//! | `as` | Result |
//! |---|---|
//! | `hex` (default) | the bytes as `hex` and as binary text |
//! | `u8` to `u64`, `i8` to `i64`, `ptr` | `values`: `count` values, unsigned as hex text, signed as decimal text |
//! | `cstr` | the bytes up to the first 0 byte |
//! | `utf16` | the UTF-16LE code units up to the first 0 unit |
//! | `insn` | `rows`: a linear sweep of `count` instructions (default 100, max 500) with the row shape of `func_get` (AC-216) |
//! | `type` | `fields`: the C type `c` with its field paths, offsets, types and values |
//!
//! The sweep gives `next_cursor` when the region has more bytes. Send it as `cursor` with the
//! same `target` for the next rows. A sweep needs no function. A byte that does not decode
//! gives a row with `m: "(bad)"`, and the sweep goes on at the next byte.

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ActionSpec, ArgKind, ArgSpec, Example, Profile, Role, ToolSpec};

/// The forms of `as` in schema order.
pub const FORMS: [&str; 14] = [
    "hex", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "ptr", "cstr", "utf16", "insn",
    "type",
];

/// The default read length in bytes.
pub const DEFAULT_LEN: i64 = 256;

/// The largest read length in bytes.
pub const MAX_LEN: i64 = 4_096;

/// The default number of rows of a sweep.
pub const DEFAULT_ROWS: i64 = 100;

/// The largest number of rows of a sweep.
pub const MAX_ROWS: i64 = 500;

/// The largest depth of nested records in `fields`.
pub const MAX_FIELD_DEPTH: usize = 4;

/// The largest number of array elements in `fields`.
pub const MAX_ELEMENTS: u64 = 16;

/// The `why` of the repair call without the cursor.
pub const WHY_RESTART: &str = "Start the sweep again at the target.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_RESTART];

/// The forms other than `type`, for the rule of `c`.
const NOT_TYPE: &[(&str, &str)] = &[
    ("as", "hex"),
    ("as", "u8"),
    ("as", "u16"),
    ("as", "u32"),
    ("as", "u64"),
    ("as", "i8"),
    ("as", "i16"),
    ("as", "i32"),
    ("as", "i64"),
    ("as", "ptr"),
    ("as", "cstr"),
    ("as", "utf16"),
    ("as", "insn"),
];

/// The forms other than `insn`, for the rule of `cursor`.
const NOT_INSN: &[(&str, &str)] = &[
    ("as", "hex"),
    ("as", "u8"),
    ("as", "u16"),
    ("as", "u32"),
    ("as", "u64"),
    ("as", "i8"),
    ("as", "i16"),
    ("as", "i32"),
    ("as", "i64"),
    ("as", "ptr"),
    ("as", "cstr"),
    ("as", "utf16"),
    ("as", "type"),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The address: a 0x hex string, a name or an ID.",
    )
    .required(),
    ArgSpec::new(
        "len",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: MAX_LEN,
        },
        "The number of bytes to read, at most 4096.",
    )
    .default_json("256"),
    ArgSpec::new(
        "as",
        Role::Selector,
        ArgKind::Enum(&FORMS),
        "The form of the result.",
    )
    .default_json("\"hex\""),
    ArgSpec::new(
        "count",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: MAX_ROWS,
        },
        "The number of values or instructions.",
    ),
    ArgSpec::new(
        "c",
        Role::Param,
        ArgKind::Str(1_000),
        "The C type text, for example struct sockaddr_in.",
    )
    .required_when(&[("as", "type")])
    .forbidden_when(NOT_TYPE),
    ArgSpec::new(
        "cursor",
        Role::PageCursor,
        ArgKind::Str(1_024),
        "The next_cursor of the previous sweep.",
    )
    .forbidden_when(NOT_INSN),
];

const ACTIONS: &[ActionSpec] = &[
    action(
        "hex",
        "Read the bytes as hex and as escaped text.",
        r#"{"target":"0x2004","as":"hex","len":32}"#,
    ),
    action(
        "u8",
        "Read unsigned 8-bit values.",
        r#"{"target":"0x2004","as":"u8","count":4}"#,
    ),
    action(
        "u16",
        "Read unsigned 16-bit values.",
        r#"{"target":"0x2004","as":"u16","count":4}"#,
    ),
    action(
        "u32",
        "Read unsigned 32-bit values.",
        r#"{"target":"0x2004","as":"u32","count":4}"#,
    ),
    action(
        "u64",
        "Read unsigned 64-bit values.",
        r#"{"target":"0x2004","as":"u64","count":2}"#,
    ),
    action(
        "i8",
        "Read signed 8-bit values.",
        r#"{"target":"0x2004","as":"i8","count":4}"#,
    ),
    action(
        "i16",
        "Read signed 16-bit values.",
        r#"{"target":"0x2004","as":"i16","count":4}"#,
    ),
    action(
        "i32",
        "Read signed 32-bit values.",
        r#"{"target":"0x2004","as":"i32","count":4}"#,
    ),
    action(
        "i64",
        "Read signed 64-bit values.",
        r#"{"target":"0x2004","as":"i64","count":2}"#,
    ),
    action(
        "ptr",
        "Read pointers and name their targets.",
        r#"{"target":"0x3db0","as":"ptr","count":2}"#,
    ),
    action(
        "cstr",
        "Read a text up to its 0 byte.",
        r#"{"target":"0x2004","as":"cstr"}"#,
    ),
    action(
        "utf16",
        "Read a UTF-16LE text up to its 0 unit.",
        r#"{"target":"0x2004","as":"utf16","len":16}"#,
    ),
    action(
        "insn",
        "Disassemble a linear sweep of instructions.",
        r#"{"target":"main","as":"insn","count":5}"#,
    ),
    action(
        "type",
        "Read a C type with its field paths.",
        r#"{"target":"0x2004","as":"type","c":"struct timespec"}"#,
    ),
];

/// Makes one action that is not destructive.
const fn action(value: &'static str, line: &'static str, example: &'static str) -> ActionSpec {
    ActionSpec {
        value,
        line,
        example,
        destructive: false,
    }
}

const FIELDS: &[Field] = &[
    Field::req("addr", OutputShape::Addr),
    Field::req("len", OutputShape::Int),
    Field::req("hex", OutputShape::Str),
    Field::req("text", OutputShape::Text),
    Field::opt("values", OutputShape::Any),
    Field::opt("fields", OutputShape::Any),
    Field::opt("type", OutputShape::Any),
    Field::opt("rows", OutputShape::Any),
    Field::opt("next_cursor", OutputShape::Str),
    Field::req("region", OutputShape::Any),
];

/// `mem_read`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Read memory",
    summary: "Read memory as hex, text, integers, pointers, a C type with field paths, or instructions in a linear sweep.",
    description: "Read memory as hex, text, integers, pointers, a C type with field paths, or instructions in a linear sweep. \
                  The read stops at the end of the region of the target. \
                  The form insn gives disassembly rows and needs no function. Send next_cursor as cursor for the next rows. \
                  The form type takes C type text in c, for example struct sockaddr_in. \
                  Text from the binary comes back escaped, with the exact bytes in hex.",
    args: ARGS,
    actions: ACTIONS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[
        example(
            r#"{"target":"0x2004","as":"hex","len":32}"#,
            "tests/golden/tools/mem_read.1.json",
        ),
        example(
            r#"{"target":"0x2004","as":"u8","count":4}"#,
            "tests/golden/tools/mem_read.2.json",
        ),
        example(
            r#"{"target":"0x2004","as":"u16","count":4}"#,
            "tests/golden/tools/mem_read.3.json",
        ),
        example(
            r#"{"target":"0x2004","as":"u32","count":4}"#,
            "tests/golden/tools/mem_read.4.json",
        ),
        example(
            r#"{"target":"0x2004","as":"u64","count":2}"#,
            "tests/golden/tools/mem_read.5.json",
        ),
        example(
            r#"{"target":"0x2004","as":"i8","count":4}"#,
            "tests/golden/tools/mem_read.6.json",
        ),
        example(
            r#"{"target":"0x2004","as":"i16","count":4}"#,
            "tests/golden/tools/mem_read.7.json",
        ),
        example(
            r#"{"target":"0x2004","as":"i32","count":4}"#,
            "tests/golden/tools/mem_read.8.json",
        ),
        example(
            r#"{"target":"0x2004","as":"i64","count":2}"#,
            "tests/golden/tools/mem_read.9.json",
        ),
        example(
            r#"{"target":"0x3db0","as":"ptr","count":2}"#,
            "tests/golden/tools/mem_read.10.json",
        ),
        example(
            r#"{"target":"0x2004","as":"cstr"}"#,
            "tests/golden/tools/mem_read.11.json",
        ),
        example(
            r#"{"target":"0x2004","as":"utf16","len":16}"#,
            "tests/golden/tools/mem_read.12.json",
        ),
        example(
            r#"{"target":"main","as":"insn","count":5}"#,
            "tests/golden/tools/mem_read.13.json",
        ),
        example(
            r#"{"target":"0x2004","as":"type","c":"struct timespec"}"#,
            "tests/golden/tools/mem_read.14.json",
        ),
    ],
    ..ToolSpec::base("mem_read", run)
};

/// Makes the executed example of an action: its example and its golden file.
const fn example(args: &'static str, golden: &'static str) -> Example {
    Example { args, golden }
}

fn run(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = session.bound(&ctx.frame)?;
    Ok(Payload::Object(ghidorah_json::Object::new()))
}
