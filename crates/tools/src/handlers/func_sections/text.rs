//! Text renderers: names, binary text, addresses, budgets and the per-item results of a list
//! input.

use std::cell::Cell;

use ghidorah_base::{Address, BinText, Caps, ErrorCode, Rendered, WarningCode};
use ghidorah_db::Program;
use ghidorah_json::{Object, Value};

use crate::args::Format;
use crate::content::cost;
use crate::dispatch::Ctx;
use crate::envelope::Warning;
use crate::errors::ToolError;
use crate::resolve::Site;

/// The largest number of characters of a name in output.
pub const NAME_CHARS: usize = 256;

/// The characters of the result that a handler keeps free for each copy of the envelope
/// members around `data`: the frame, the warnings and the `next` calls.
pub const RESERVE: u64 = 700;

/// Gives the output text of a binary-derived name: the escapes of `BinText`, at most
/// [`NAME_CHARS`] characters.
#[must_use]
pub fn safe(raw: &str) -> String {
    BinText::new(raw.as_bytes())
        .render(Caps::new(NAME_CHARS, 0))
        .text
}

/// Tells if `name` is a mangled name: `_Z`, `_R` or an MSVC name that starts with `?`.
#[must_use]
pub fn is_mangled(name: &str) -> bool {
    name.starts_with("_Z") || name.starts_with("_R") || name.starts_with('?')
}

/// Renders names for one result and keeps its mangled-name flag (design Section 9.6).
#[derive(Debug, Default)]
pub struct Namer {
    mangled: Cell<bool>,
}

impl Namer {
    /// Makes a namer with no mangled name.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives the output text of the name `raw` and notes a mangled name.
    #[must_use]
    pub fn text(&self, raw: &str) -> String {
        if is_mangled(raw) {
            self.mangled.set(true);
        }
        safe(raw)
    }

    /// Gives the name of `addr`: the primary symbol, else the default name, else the address.
    #[must_use]
    pub fn of(&self, program: &Program, addr: Address) -> String {
        program
            .name(addr)
            .map_or_else(|| addr.to_string(), |n| self.text(&n.text))
    }

    /// Tells if a name of the result is mangled.
    #[must_use]
    pub fn mangled(&self) -> bool {
        self.mangled.get()
    }

    /// Adds `W_NOT_DEMANGLED` to the call once when a name of the result is mangled.
    pub fn finish(&self, ctx: &mut Ctx) {
        let known = ctx
            .warnings
            .iter()
            .any(|w| w.code == WarningCode::NotDemangled);
        if self.mangled() && !known {
            ctx.warn(Warning::new(WarningCode::NotDemangled));
        }
    }
}

/// Gives the caps of binary text for the format of the call.
#[must_use]
pub fn caps(ctx: &Ctx) -> Caps {
    match ctx.format {
        Format::Detailed => Caps::DETAILED,
        Format::Concise => Caps::DEFAULT,
    }
}

/// Gives the one JSON shape of a rendered binary text.
#[must_use]
pub fn rendered(r: Rendered) -> Value {
    let mut out = Object::new();
    out.push("text", Value::from(r.text));
    out.push("hex", Value::from(r.hex));
    out.push("len", Value::from(r.len));
    if r.truncated {
        out.push("truncated", Value::Bool(true));
    }
    out.push("src", Value::from(ghidorah_base::bintext::SRC));
    Value::Object(out)
}

/// Gives the one JSON shape of the binary text `bytes`.
#[must_use]
pub fn bin_text(bytes: &[u8], caps: Caps) -> Value {
    rendered(BinText::new(bytes).render(caps))
}

/// Gives the binary text of the string fact at `at`, or `None` when no string starts there.
#[must_use]
pub fn string_text(program: &Program, at: u64, caps: Caps) -> Option<Value> {
    let info = program.string(at)?;
    ghidorah_analysis::analyzers::strings::render(program, at, info, caps).map(rendered)
}

/// Gives the text of an address: `0x..` or `ext:0x..`.
#[must_use]
pub fn addr(a: Address) -> Value {
    Value::from(a.to_string())
}

/// Gives the `0x` hex text of a value.
#[must_use]
pub fn hex(v: u64) -> Value {
    Value::from(ghidorah_base::hex::u64_text(v))
}

/// Gives the characters of the result that `data` can use: the budget minus the reserve of
/// each copy.
#[must_use]
pub fn room(ctx: &Ctx) -> u64 {
    let reserve = RESERVE.saturating_mul(ctx.budget.mode.copies());
    ctx.budget.limit().saturating_sub(reserve)
}

/// Gives the characters that `value` adds to the result of the call, every copy included.
#[must_use]
pub fn chars(ctx: &Ctx, value: &Value) -> u64 {
    cost(&ghidorah_json::write(value), ctx.budget.mode)
}

/// Gives the number of characters of the compact JSON of `value`.
#[must_use]
pub fn size(value: &Value) -> u64 {
    u64::try_from(ghidorah_json::write(value).chars().count()).unwrap_or(u64::MAX)
}

/// Gives the site of the item `index` of the list argument `name`, for error paths.
#[must_use]
pub fn item_path(name: &str, index: usize) -> String {
    format!("/{name}/{index}")
}

/// Gives a site with the field path `path` and no repair call.
#[must_use]
pub fn site(path: &str) -> Site<'_> {
    Site { path, repair: None }
}

/// Gives `UNSUPPORTED_ARCH` when the program has no x86-64 code.
///
/// # Errors
///
/// Returns `UNSUPPORTED_ARCH` for another machine.
pub fn x86_only(program: &Program) -> Result<(), ToolError> {
    if program.meta().arch.is_x86_64() {
        Ok(())
    } else {
        Err(ToolError::new(ErrorCode::UnsupportedArch))
    }
}

/// Gives the per-item result of a list input: `{ items: [{ input, ok, data | error }],
/// ok_count, error_count }` in input order (AC-144). `one` renders one item.
pub fn per_item(
    name: &str,
    inputs: &[Value],
    mut one: impl FnMut(usize, &Value) -> Result<Value, ToolError>,
) -> Object {
    let (mut ok, mut bad) = (0u64, 0u64);
    let mut list = Vec::with_capacity(inputs.len());
    for (i, input) in inputs.iter().enumerate() {
        let mut item = Object::new();
        item.push("input", input.clone());
        match one(i, input) {
            Ok(data) => {
                ok = ok.saturating_add(1);
                item.push("ok", Value::Bool(true));
                item.push("data", data);
            }
            Err(mut error) => {
                bad = bad.saturating_add(1);
                if error.field_path.is_none() {
                    error.field_path = Some(item_path(name, i));
                }
                item.push("ok", Value::Bool(false));
                item.push("error", error.to_json());
            }
        }
        list.push(Value::Object(item));
    }
    let mut out = Object::new();
    out.push("items", Value::Array(list));
    out.push("ok_count", Value::from(ok));
    out.push("error_count", Value::from(bad));
    out
}

/// Parses the glob `pattern` of the argument at `path`.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for a pattern that does not parse.
pub fn glob(pattern: &str, path: &str) -> Result<ghidorah_base::Glob, ToolError> {
    ghidorah_base::Glob::new(pattern).map_err(|e| {
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", path.trim_start_matches('/'))
            .path(path)
            .detail("expected", Value::from(e.to_string()))
    })
}
