//! `mem_read`: read memory in one form (design Section 10.4, tool 8).
//!
//! The result is `{ addr, len, hex?, text?, values?, fields?, type?, rows?, next_cursor?,
//! region }`. A sweep has no `hex` and no `text`: its rows hold the bytes.
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

mod typed;

use ghidorah_base::{Address, Caps, ErrorCode, Limits};
use ghidorah_db::Program;
use ghidorah_json::{Object, Value};
use ghidorah_loader::Region;

use super::func_sections::{self as fs, CursorScope, Namer};
use crate::args::Args;
use crate::dispatch::{Ctx, KeyPart, Payload, SortKey};
use crate::errors::ToolError;
use crate::hints::Call;
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
    Field::opt("hex", OutputShape::Str),
    Field::opt("text", OutputShape::Text),
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
                  The form insn gives disassembly rows and needs no function. \
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

/// The arguments that a sweep cursor does not bind.
const CURSOR_FREE: [&str; 3] = ["cursor", "count", "len"];

/// Gives the width in bytes and the signedness of an integer form.
fn width(form: &str) -> Option<(u64, bool)> {
    Some(match form {
        "u8" => (1, false),
        "u16" => (2, false),
        "u32" => (4, false),
        "u64" | "ptr" => (8, false),
        "i8" => (1, true),
        "i16" => (2, true),
        "i32" => (4, true),
        "i64" => (8, true),
        _ => return None,
    })
}

/// Gives the bytes of the read: at most `len` bytes, and never past the end of `region`.
fn read(p: &Program, region: &Region, at: u64, len: u64) -> Vec<u8> {
    let left = region.va.last.saturating_sub(at).saturating_add(1);
    p.mem()
        .read(at, len.min(left), &Limits::DEFAULT)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

/// Gives the members `addr`, `len`, `hex` and `text` of the bytes `bytes` at `at`.
fn byte_members(at: u64, bytes: &[u8], caps: Caps) -> Object {
    let shown = bytes.get(..caps.hex_bytes).unwrap_or(bytes);
    let mut out = Object::new();
    out.push("addr", fs::hex(at));
    out.push("len", Value::from(bytes.len()));
    out.push("hex", Value::from(ghidorah_base::hex::encode(shown)));
    out.push("text", fs::bin_text(bytes, caps));
    out
}

/// Gives the values of an integer form. A pointer names its target when the target has a name.
fn values(p: &Program, bytes: &[u8], w: u64, signed: bool, ptr: bool, namer: &Namer) -> Value {
    let step = usize::try_from(w).unwrap_or(8);
    let list = bytes
        .chunks_exact(step)
        .map(|chunk| {
            let mut word = [0u8; 8];
            for (dst, src) in word.iter_mut().zip(chunk) {
                *dst = *src;
            }
            let raw = u64::from_le_bytes(word);
            if signed {
                let shift = 64u32.saturating_sub(u32::try_from(w.saturating_mul(8)).unwrap_or(64));
                let v = i64::from_le_bytes(word)
                    .wrapping_shl(shift)
                    .wrapping_shr(shift);
                return Value::from(v.to_string());
            }
            if !ptr {
                return fs::hex(raw);
            }
            let mut out = Object::new();
            out.push("v", fs::hex(raw));
            let target = Address::ram(raw);
            let label = p
                .primary_symbol(target)
                .map(|s| namer.text(&s.name.value))
                .or_else(|| {
                    p.func(ghidorah_base::FuncId(target))
                        .map(|_| namer.of(p, target))
                });
            if let Some(name) = label {
                out.push("name", Value::from(name));
            }
            Value::Object(out)
        })
        .collect();
    Value::Array(list)
}

/// Gives the result of the sweep form from `start`.
fn sweep(
    p: &Program,
    region: &Region,
    start: u64,
    count: usize,
    scope: &CursorScope<'_>,
    namer: &Namer,
) -> Object {
    let mut rows = Vec::new();
    let mut at = start;
    let mut end = false;
    while rows.len() < count {
        if at > region.va.last {
            end = true;
            break;
        }
        let (row, len) = match fs::decode(p, at) {
            Some(insn) => (fs::row(p, &insn, namer), u64::from(insn.len())),
            None => (fs::bad_row(p, at, 1), 1),
        };
        rows.push(row);
        let Some(next) = at.checked_add(len) else {
            end = true;
            break;
        };
        at = next;
    }
    let mut out = Object::new();
    out.push("addr", fs::hex(start));
    out.push("len", Value::from(at.saturating_sub(start)));
    out.push("rows", Value::Array(rows));
    if !end && at <= region.va.last {
        let key = SortKey(vec![KeyPart::Int(at)]);
        out.push("next_cursor", Value::from(scope.encode(key)));
    }
    out
}

/// Gives the start of a sweep: the address of its cursor, else the target.
fn start_of(
    args: &Args,
    scope: &CursorScope<'_>,
    region: &Region,
    target: u64,
) -> Result<u64, ToolError> {
    let Some(text) = args.str("cursor") else {
        return Ok(target);
    };
    let key = scope.decode(text)?;
    match key.0.as_slice() {
        [KeyPart::Int(at)] if region.va.first <= *at && *at <= region.va.last && *at >= target => {
            Ok(*at)
        }
        _ => Err(ToolError::new(ErrorCode::CursorInvalid)),
    }
}

/// Adds the repair call of a cursor error: the call without `cursor`.
fn restart(args: &Args, error: ToolError) -> ToolError {
    let mut object = args.canonical().as_object().cloned().unwrap_or_default();
    let _ = object.remove("cursor");
    error.next(Call::new("mem_read", Value::Object(object), WHY_RESTART))
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    let input = args.get("target").cloned().unwrap_or_default();
    let (addr, _) = crate::resolve::address(p, &input, &fs::site("/target"))?;
    let Some(region) = addr.is_ram().then(|| p.mem().region_at(addr.off)).flatten() else {
        return Err(ToolError::new(ErrorCode::InvalidArgument)
            .var("field", "target")
            .path("/target")
            .detail(
                "expected",
                Value::from("an address with bytes in a mapped region"),
            ));
    };
    let at = addr.off;
    let form = args.str("as").unwrap_or("hex");
    let caps = fs::caps(ctx);
    let namer = Namer::new();
    let len = u64::try_from(args.int("len").unwrap_or(DEFAULT_LEN)).unwrap_or(256);
    let mut out = match form {
        "insn" => {
            fs::x86_only(p)?;
            let frame = ctx.frame.clone();
            let scope = CursorScope {
                session,
                frame: &frame,
                args,
                drop: &CURSOR_FREE,
                section: fs::SWEEP,
            };
            let start = start_of(args, &scope, region, at).map_err(|e| restart(args, e))?;
            let count = usize::try_from(args.int("count").unwrap_or(DEFAULT_ROWS)).unwrap_or(100);
            sweep(p, region, start, count, &scope, &namer)
        }
        "type" => {
            let typed = typed::parse(p, args.str("c").unwrap_or_default())?;
            let bytes = read(p, region, at, typed.size);
            let mut out = byte_members(at, &bytes, caps);
            let c = typed.store.c_text(typed.id).unwrap_or_default();
            out.push(
                "type",
                Value::object([
                    ("c", Value::from(c)),
                    ("size", Value::from(typed.size)),
                    ("align", Value::from(typed.align)),
                ]),
            );
            out.push(
                "fields",
                Value::Array(typed::fields(p, &typed, &bytes, caps)),
            );
            out
        }
        "cstr" => {
            let bytes = read(p, region, at, len);
            let text = bytes.split(|b| *b == 0).next().unwrap_or_default();
            byte_members(at, text, caps)
        }
        "utf16" => {
            let bytes = read(p, region, at, len);
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|u| *u != 0)
                .collect();
            let raw = bytes
                .get(..units.len().saturating_mul(2))
                .unwrap_or_default();
            let mut out = byte_members(at, raw, caps);
            let text = String::from_utf16_lossy(&units);
            let mut shown = ghidorah_base::BinText::new(text.into_bytes()).render(caps);
            shown.hex = ghidorah_base::hex::encode(raw.get(..caps.hex_bytes).unwrap_or(raw));
            shown.len = raw.len();
            let _ = out.insert("text", fs::rendered(shown));
            out
        }
        other => match width(other) {
            Some((w, signed)) => {
                let count = args
                    .int("count")
                    .map_or(len / w, |c| u64::try_from(c).unwrap_or(1));
                let bytes = read(p, region, at, count.max(1).saturating_mul(w));
                let mut out = byte_members(at, &bytes, caps);
                out.push(
                    "values",
                    values(p, &bytes, w, signed, other == "ptr", &namer),
                );
                out
            }
            None => byte_members(at, &read(p, region, at, len), caps),
        },
    };
    out.push(
        "region",
        Value::object([
            ("name", Value::from(fs::safe(&region.name))),
            ("perms", Value::from(region.perms.to_string())),
        ]),
    );
    namer.finish(ctx);
    Ok(Payload::Object(out))
}
