//! The `decomp` section of `func_get` and the L1 IR rows (design Sections 6.4, 8.3 and 10.4).
//!
//! The section of one function is one window of lines of its decompile:
//!
//! ```text
//! { text, line_start, line_count, total_lines, next_cursor?, line_map, elided, vars,
//!   calls, strings, metrics, warnings }
//! ```
//!
//! `decomp_opts.lines` gives the first line and the most lines of the window. The default
//! window is the first 150 lines. A window that does not fit its share keeps the lines that
//! fit and gets a `next_cursor`. `line_map`, `calls` and `strings` hold only the rows of the
//! window. Send `next_cursor` in `cursors.decomp` for the next window.

use ghidorah_base::{Address, Caps, Fuel, FuncId, StringId};
use ghidorah_db::Program;
use ghidorah_decomp::print::CallTarget;
use ghidorah_decomp::window::DEFAULT_LINES;
use ghidorah_decomp::{Opts, Output, Passes, Remedy, WarningRow};
use ghidorah_json::{Object, Value};

use super::IrRows;
use super::text::{hex, string_text};
use crate::args::Args;
use crate::handlers::func_get::remedy;
use crate::hints::Call;

/// The section byte of a `func_get` decompile cursor.
pub const DECOMP: u8 = 4;

/// The `why` of the remedy call that reads the disassembly of a function.
pub const WHY_DISASM: &str = "Read the disassembly of the function.";

/// The `why` of the remedy call that reads one instruction.
pub const WHY_INSN: &str = "Read the instruction at the address.";

/// The decompile options of one call: the window and the passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompOpts {
    /// The number of the first line, from 1.
    pub start: usize,
    /// The most lines of the window.
    pub count: usize,
    /// The options of the decompiler.
    pub opts: Opts,
}

/// Gives the integer at `pointer` of `value` as a `usize`.
fn int_at(value: Option<&Value>, pointer: &str) -> Option<usize> {
    value
        .and_then(|v| v.pointer(pointer))
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
}

/// Gives the decompile options of the call: `decomp_opts.lines` and `decomp_opts.passes`.
#[must_use]
pub fn opts(args: &Args) -> DecompOpts {
    let given = args.get("decomp_opts");
    let flag = |name: &str| {
        given
            .and_then(|v| v.pointer(&format!("/passes/{name}")))
            .and_then(Value::as_bool)
            .unwrap_or(true)
    };
    DecompOpts {
        start: int_at(given, "/lines/start").unwrap_or(1).max(1),
        count: int_at(given, "/lines/count")
            .unwrap_or(DEFAULT_LINES)
            .max(1),
        opts: Opts {
            passes: Passes {
                fold: flag("fold"),
                sailr: flag("sailr"),
                canary: flag("canary"),
                tailcall: flag("tailcall"),
            },
            ..Opts::default()
        },
    }
}

/// Gives a JSON integer of a `usize`.
fn int(n: usize) -> Value {
    Value::from(u64::try_from(n).unwrap_or(u64::MAX))
}

/// The parts of a decompile section that the remedy calls read. They are the program, the
/// function and the check of a call.
#[derive(Clone, Copy)]
pub struct Remedies<'a> {
    /// The program.
    pub program: &'a Program,
    /// The function of the decompile.
    pub func: FuncId,
    /// Keeps a call that the agent can send, or drops it.
    pub check: &'a dyn Fn(Call) -> Option<Call>,
}

/// Gives the remedy call of a warning row, or `None` when no complete call exists.
fn remedy(r: Remedy, ctx: &Remedies<'_>) -> Option<Value> {
    let call = match r {
        Remedy::Disasm(at) => Call::new(
            "func_get",
            Value::object([
                ("target", hex(at)),
                ("include", Value::Array(vec![Value::from("disasm")])),
            ]),
            WHY_DISASM,
        ),
        Remedy::Insn(at) => Call::new(
            "mem_read",
            Value::object([
                ("target", hex(at)),
                ("as", Value::from("insn")),
                ("count", Value::from(1)),
            ]),
            WHY_INSN,
        ),
        Remedy::JumpTable(at) => remedy::site(ctx.program, ctx.func, at, true)?,
        Remedy::CallTargets(at) => remedy::site(ctx.program, ctx.func, at, false)?,
    };
    (ctx.check)(call).map(|c| c.to_json())
}

/// Gives the JSON row of one warning.
fn warning(w: &WarningRow, ctx: &Remedies<'_>) -> Value {
    let info = w.code.info();
    let mut out = Object::new();
    out.push("code", Value::from(info.name));
    out.push("num", Value::from(info.num));
    out.push("at", hex(w.at));
    out.push("message", Value::from(info.message));
    if let Some(r) = w.remedy.and_then(|r| remedy(r, ctx)) {
        out.push("remedy", r);
    }
    Value::Object(out)
}

/// Gives the members of an output that every window shares: the elided ranges, the
/// variables, the metrics and the warnings.
fn shared(out: &Output, ctx: &Remedies<'_>) -> Vec<(&'static str, Value)> {
    let elided = out
        .elided
        .iter()
        .map(|e| {
            Value::object([
                ("start", hex(e.start)),
                ("size", Value::from(e.size)),
                ("reason", Value::from(e.reason.name())),
            ])
        })
        .collect();
    let vars = out
        .vars
        .iter()
        .map(|v| {
            Value::object([
                ("id", Value::from(v.id.to_string())),
                ("name", Value::from(v.name.as_str())),
                ("type", Value::from(v.ty.as_str())),
                ("storage", Value::from(v.id.storage.to_string())),
                ("source", Value::from(v.source)),
            ])
        })
        .collect();
    let m = out.metrics;
    let metrics = Value::object([
        ("goto_count", Value::from(m.goto_count)),
        ("label_count", Value::from(m.label_count)),
        ("max_nesting", Value::from(m.max_nesting)),
        ("stmt_count", Value::from(m.stmt_count)),
        ("fallback_mode", Value::from(m.mode.fallback_mode())),
        (
            "validation",
            Value::object([("structure", Value::from(m.validation.name()))]),
        ),
    ]);
    vec![
        ("elided", Value::Array(elided)),
        ("vars", Value::Array(vars)),
        ("metrics", metrics),
        (
            "warnings",
            Value::Array(out.warnings.iter().map(|w| warning(w, ctx)).collect()),
        ),
    ]
}

/// Gives the section value of the window of `count` lines from the line `start`. `cursor`
/// gives the cursor text of a next line. `remedies` gives the remedy calls of the warnings.
#[must_use]
pub fn value(
    remedies: &Remedies<'_>,
    out: &Output,
    start: usize,
    count: usize,
    caps: Caps,
    cursor: &dyn Fn(usize) -> String,
) -> Value {
    let program = remedies.program;
    let w = out.window(start, count);
    let mut o = Object::new();
    o.push("text", Value::from(w.text()));
    o.push("line_start", int(w.start));
    o.push("line_count", int(w.count));
    o.push("total_lines", int(w.total()));
    if let Some(next) = w.next() {
        o.push("next_cursor", Value::from(cursor(next)));
    }
    let rows = w
        .rows()
        .into_iter()
        .map(|r| {
            let mut row = Object::new();
            row.push("line", int(r.line));
            row.push("start", hex(r.start));
            row.push("size", Value::from(r.size));
            row.push(
                "ops",
                Value::Array(r.ops.iter().map(|op| Value::from(op.to_string())).collect()),
            );
            if let Some(kind) = r.comment {
                row.push("comment", Value::from(kind.name()));
            }
            Value::Object(row)
        })
        .collect();
    o.push("line_map", Value::Array(rows));
    let mut members = shared(out, remedies).into_iter();
    if let Some((name, elided)) = members.next() {
        o.push(name, elided);
    }
    if let Some((name, vars)) = members.next() {
        o.push(name, vars);
    }
    let calls = w
        .calls()
        .into_iter()
        .map(|(line, c)| {
            let target = match &c.target {
                CallTarget::Addr(a) => hex(*a),
                CallTarget::Syscall(id) => Value::from(id.as_str()),
            };
            Value::object([
                ("line", int(line)),
                ("target", target),
                ("name", Value::from(c.name.as_str())),
            ])
        })
        .collect();
    o.push("calls", Value::Array(calls));
    let strings = w
        .strings()
        .into_iter()
        .filter_map(|(line, addr)| {
            let text = string_text(program, addr, caps)?;
            Some(Value::object([
                ("line", int(line)),
                ("id", Value::from(StringId(Address::ram(addr)).to_string())),
                ("text", text),
            ]))
        })
        .collect();
    o.push("strings", Value::Array(strings));
    for (name, v) in members {
        o.push(name, v);
    }
    Value::Object(o)
}

/// Gives the L1 IR rows of `func` after `after`, at most `limit` rows. Each row is
/// `{ a, ops }` with one text per live op of the L1 form: the phis of a block come first at
/// its address.
///
/// # Errors
///
/// Returns the text of the build error of the L1 form.
pub fn l1_rows(
    program: &Program,
    func: FuncId,
    after: Option<u64>,
    limit: usize,
    fuel: &mut Fuel,
) -> Result<IrRows, String> {
    let l1 = ghidorah_decomp::l1_rows(program, func, &ghidorah_x86::lift::Names, fuel)
        .map_err(|e| e.to_string())?;
    let mut out = IrRows {
        rows: Vec::new(),
        more: false,
        intrinsic: l1.intrinsic,
        lift_ver: l1.lift_ver,
    };
    for (addr, ops) in l1.rows {
        let ops: Vec<Value> = ops.into_iter().map(Value::from).collect();
        if after.is_some_and(|a| addr <= a) {
            continue;
        }
        if out.rows.len() >= limit {
            out.more = true;
            break;
        }
        let mut item = Object::new();
        item.push("a", hex(addr));
        item.push("ops", Value::Array(ops));
        out.rows.push(Value::Object(item));
    }
    Ok(out)
}
