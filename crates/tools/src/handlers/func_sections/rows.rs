//! Disassembly rows, IR rows and the section cursors (design Sections 5.4 and 10.9).

use std::collections::BTreeMap;

use ghidorah_base::{Address, ErrorCode, Fuel, FuncId, Limits, sha256};
use ghidorah_db::{CodeUnit, CommentKind, Program};
use ghidorah_json::{Object, Value};
use ghidorah_x86::{Insn, MAX_LEN, Opts, Symbolizer};

use super::text::{Namer, hex};
use crate::args::Args;
use crate::cursor::{Cursor, MAX_CURSOR_CHARS, PAGING_ARGS, Spill};
use crate::dispatch::SortKey;
use crate::envelope::Frame;
use crate::errors::ToolError;
use crate::session::Session;

/// The section byte of a `func_get` disassembly cursor.
pub const DISASM: u8 = 1;

/// The section byte of a `func_get` IR cursor.
pub const IR: u8 = 2;

/// The section byte of a `mem_read` sweep cursor.
pub const SWEEP: u8 = 3;

/// The largest number of characters of a string note in a display text.
pub const NOTE_CHARS: usize = 48;

/// The names and notes of the display text: symbols, function names and strings.
struct Syms<'a> {
    program: &'a Program,
    namer: &'a Namer,
}

impl Symbolizer for Syms<'_> {
    fn name(&self, addr: u64) -> Option<String> {
        let a = Address::ram(addr);
        if let Some(symbol) = self.program.primary_symbol(a) {
            return Some(self.namer.text(&symbol.name.value));
        }
        self.program
            .func(FuncId(a))
            .and_then(|_| self.program.default_name(a))
            .map(|d| d.to_string())
    }

    fn note(&self, addr: u64) -> Option<String> {
        if let Some(info) = self.program.string(addr)
            && let Some(bytes) =
                ghidorah_analysis::analyzers::strings::bytes(self.program, addr, info)
        {
            let caps = ghidorah_base::Caps::new(NOTE_CHARS, 0);
            let text = ghidorah_base::BinText::new(bytes).render(caps).text;
            return Some(format!("{addr:#x} \"{text}\""));
        }
        self.name(addr).map(|n| format!("{addr:#x} {n}"))
    }
}

/// Decodes the instruction at `at` in any mapped region. The read stops at the region end.
#[must_use]
pub fn decode(program: &Program, at: u64) -> Option<Insn> {
    let region = program.mem().region_at(at)?;
    let left = region.va.last.checked_sub(at)?.saturating_add(1);
    let len = left.min(MAX_LEN as u64);
    let bytes = program.mem().read(at, len, &Limits::DEFAULT).ok()?;
    ghidorah_x86::decode(&bytes, at, &Opts::DEFAULT).ok()
}

/// Gives the comments at `at` as `{ <kind>: text }` in kind order, or `None`.
fn comments(program: &Program, at: Address) -> Option<Value> {
    let mut out = Object::new();
    for kind in CommentKind::ALL {
        if let Some(fact) = program.comment(at, kind) {
            out.push(kind.name(), Value::from(fact.value.as_str()));
        }
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Gives the hex text of the `len` bytes at `at`.
fn bytes_hex(program: &Program, at: u64, len: u64) -> String {
    program
        .mem()
        .read(at, len, &Limits::DEFAULT)
        .map(|b| ghidorah_base::hex::encode(&b))
        .unwrap_or_default()
}

/// Gives the disassembly row of `insn`: `{ a, n, b, m, t, f, c? }`.
#[must_use]
pub fn row(program: &Program, insn: &Insn, namer: &Namer) -> Value {
    let at = insn.addr();
    let syms = Syms { program, namer };
    let mut out = Object::new();
    out.push("a", hex(at));
    out.push("n", Value::from(insn.len()));
    out.push(
        "b",
        Value::from(bytes_hex(program, at, u64::from(insn.len()))),
    );
    out.push("m", Value::from(insn.mnem().name()));
    out.push("t", Value::from(ghidorah_x86::print(insn, &syms)));
    out.push("f", Value::from(insn.flow().name()));
    if let Some(c) = comments(program, Address::ram(at)) {
        out.push("c", c);
    }
    Value::Object(out)
}

/// Gives the row of `len` bytes at `at` that do not decode: `m` and `t` are `(bad)`.
#[must_use]
pub fn bad_row(program: &Program, at: u64, len: u64) -> Value {
    let mut out = Object::new();
    out.push("a", hex(at));
    out.push("n", Value::from(len));
    out.push("b", Value::from(bytes_hex(program, at, len)));
    out.push("m", Value::from("(bad)"));
    out.push("t", Value::from("(bad)"));
    out.push("f", Value::from(ghidorah_x86::Flow::Invalid.name()));
    if let Some(c) = comments(program, Address::ram(at)) {
        out.push("c", c);
    }
    Value::Object(out)
}

/// Gives the code units of the body of `func`: start and length in address order. The
/// analysis layer comes first.
#[must_use]
pub fn body_units(program: &Program, func: FuncId) -> Vec<(u64, u8)> {
    let mut out: BTreeMap<u64, u8> = BTreeMap::new();
    let Some(view) = program.func(func) else {
        return Vec::new();
    };
    for layer in program.layers() {
        for r in view.func.body.ranges() {
            for (at, unit) in layer.listing().units_in(*r) {
                let CodeUnit::Insn { len, .. } = unit;
                out.entry(at).or_insert(*len);
            }
        }
    }
    out.into_iter().collect()
}

/// Gives the disassembly rows of the body of `func` after the address `after`, at most
/// `limit` rows, and tells if more rows follow.
#[must_use]
pub fn body_rows(
    program: &Program,
    func: FuncId,
    after: Option<u64>,
    limit: usize,
    namer: &Namer,
) -> (Vec<Value>, bool) {
    let units: Vec<(u64, u8)> = body_units(program, func)
        .into_iter()
        .filter(|(at, _)| after.is_none_or(|a| *at > a))
        .collect();
    let more = units.len() > limit;
    let rows = units
        .into_iter()
        .take(limit)
        .map(|(at, len)| match decode(program, at) {
            Some(insn) => row(program, &insn, namer),
            None => bad_row(program, at, u64::from(len)),
        })
        .collect();
    (rows, more)
}

/// The IR rows of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrRows {
    /// The rows `{ a, ops }` in address order.
    pub rows: Vec<Value>,
    /// `true` when more rows follow the rows.
    pub more: bool,
    /// `true` when an instruction lifts to `Intrinsic`.
    pub intrinsic: bool,
    /// The lifter version.
    pub lift_ver: u32,
}

/// Gives the L0 IR rows of `func` after `after`, at most `limit` rows. Each row is
/// `{ a, ops }` with one text per op: the op ID and the op.
///
/// # Errors
///
/// Returns the text of the build error of the function IR.
pub fn ir_rows(
    program: &Program,
    func: FuncId,
    after: Option<u64>,
    limit: usize,
    fuel: &mut Fuel,
) -> Result<IrRows, String> {
    let opts = ghidorah_analysis::fir::Opts::DEFAULT;
    let ir =
        ghidorah_analysis::fir::build(program, func, &opts, fuel).map_err(|e| e.to_string())?;
    let mut out = IrRows {
        rows: Vec::new(),
        more: false,
        intrinsic: false,
        lift_ver: ir.lift_ver,
    };
    for span in ir.arena.insns() {
        if after.is_some_and(|a| span.addr <= a) {
            continue;
        }
        if out.rows.len() >= limit {
            out.more = true;
            break;
        }
        let mut texts = Vec::new();
        for op in ir.arena.span_ops(span).unwrap_or_default() {
            out.intrinsic |= op.opc.name() == "Intrinsic";
            texts.push(Value::from(format!("{} {op}", op.id)));
        }
        let mut item = Object::new();
        item.push("a", hex(span.addr));
        item.push("ops", Value::Array(texts));
        out.rows.push(Value::Object(item));
    }
    Ok(out)
}

/// Gives the args hash of a query without the arguments of `drop` and the paging arguments.
fn query_hash(args: &Args, frame: &Frame, drop: &[&str]) -> [u8; 8] {
    let mut object = Object::new();
    for (name, value) in args.values() {
        if !PAGING_ARGS.contains(&name) && !drop.contains(&name) {
            object.push(name, value.clone());
        }
    }
    if let Some(id) = &frame.binary_id {
        object.push("$binary", Value::from(id.as_str()));
    }
    let value = Value::Object(object);
    let text = ghidorah_json::write_jcs(&value).unwrap_or_else(|_| ghidorah_json::write(&value));
    let digest = sha256(text.as_bytes());
    let mut out = [0u8; 8];
    for (dst, src) in out.iter_mut().zip(digest) {
        *dst = src;
    }
    out
}

/// The parts of the call that a section cursor binds.
#[derive(Debug, Clone, Copy)]
pub struct CursorScope<'a> {
    /// The session of the call: it gives the index of the tool.
    pub session: &'a Session,
    /// The frame of the call.
    pub frame: &'a Frame,
    /// The arguments of the call.
    pub args: &'a Args,
    /// The arguments that do not change the query, for example the page size.
    pub drop: &'a [&'a str],
    /// The section byte.
    pub section: u8,
}

impl CursorScope<'_> {
    /// Gives the cursor that holds `key`.
    fn cursor(&self, key: SortKey) -> Cursor {
        let index = self
            .session
            .active_registry()
            .get(self.args.tool())
            .map_or(0, |(i, _)| i);
        Cursor {
            tool_index: u16::try_from(index).unwrap_or(u16::MAX),
            args_hash: query_hash(self.args, self.frame, self.drop),
            section: self.section,
            analysis_rev: None,
            key,
        }
    }

    /// Gives the cursor text of `key`.
    #[must_use]
    pub fn encode(&self, key: SortKey) -> String {
        ghidorah_base::hex::encode(&self.cursor(key).to_bytes(&mut Spill::new()))
    }

    /// Gives the key of the cursor text `text`.
    ///
    /// # Errors
    ///
    /// Returns `CURSOR_INVALID` for a cursor that does not decode or belongs to another query.
    pub fn decode(&self, text: &str) -> Result<SortKey, ToolError> {
        let invalid = || ToolError::new(ErrorCode::CursorInvalid);
        let lower = text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if text.is_empty() || text.len() > MAX_CURSOR_CHARS || !lower {
            return Err(invalid());
        }
        let bytes = ghidorah_base::hex::decode(text).map_err(|_| invalid())?;
        let found = Cursor::from_bytes(&bytes, &Spill::new())?;
        let want = self.cursor(found.key.clone());
        let same = found.tool_index == want.tool_index
            && found.args_hash == want.args_hash
            && found.section == want.section
            && found.analysis_rev.is_none();
        if same { Ok(found.key) } else { Err(invalid()) }
    }
}
