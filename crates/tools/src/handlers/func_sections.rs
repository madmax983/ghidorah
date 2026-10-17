//! The renderers of the read tools: the sections of `func_get`, the disassembly rows, the
//! names and the binary text (design Sections 5.4, 9.6, 10.4, 10.9 and 10.16).
//!
//! A disassembly row is `{ a, n, b, m, t, f, c? }`: the address, the length, the bytes in
//! hex, the canonical mnemonic, the display text, the flow kind and the comments at the
//! address. `func_get` and `mem_read { as: "insn" }` give the same rows (AC-216).
//!
//! | Module | Content |
//! |---|---|
//! | `text` | [`Namer`], binary text, address texts, budgets and per-item results |
//! | `rows` | disassembly rows, IR rows and [`CursorScope`] for section cursors |
//! | `lists` | the other sections of `func_get` |
//!
//! Names from the binary pass through [`Namer`]: it escapes them like `BinText`, caps them
//! at [`NAME_CHARS`] characters and notes a mangled name, so a result carries
//! `W_NOT_DEMANGLED` once (AC-115a).

mod lists;
mod rows;
mod text;

use ghidorah_analysis::CallGraph;
use ghidorah_base::{Caps, FuncId};
use ghidorah_db::Program;
use ghidorah_json::Value;

pub use lists::{func_ref, jump_table, table_ids, type_text};
pub use rows::{
    CursorScope, DISASM, IR, IrRows, SWEEP, bad_row, body_rows, body_units, decode, ir_rows, row,
};
pub use text::{
    NAME_CHARS, Namer, addr, bin_text, caps, chars, glob, hex, item_path, per_item, rendered, room,
    safe, site, size, string_text, x86_only,
};

/// The `why` of the repair call that drops the section cursors.
pub const WHY_FIRST_ROWS: &str = "Read the sections again from their first rows.";

/// Every fixed text of the renderers that an agent reads.
pub const TEXTS: &[&str] = &[WHY_FIRST_ROWS];

/// The parts of one function render that every section shares.
#[derive(Debug, Clone, Copy)]
pub struct Render<'a> {
    /// The program.
    pub program: &'a Program,
    /// The call graph of the program.
    pub graph: &'a CallGraph,
    /// The namer of the result.
    pub namer: &'a Namer,
    /// The caps of binary text.
    pub caps: Caps,
}

/// Gives the full value of a section that has no rows, or `None` for a row section and an
/// unknown name.
#[must_use]
pub fn section(r: &Render<'_>, name: &str, func: FuncId) -> Option<Value> {
    let p = r.program;
    Some(match name {
        "summary" => lists::summary(p, r.graph, func),
        "xrefs" => lists::xrefs(p, func, r.namer),
        "callers" => lists::callers(p, r.graph, func, r.namer),
        "callees" => lists::callees(p, r.graph, func, r.namer),
        "strings" => lists::strings(p, func, r.caps),
        "vars" => lists::vars(p, func),
        "notes" => lists::notes(p, func),
        "why" => lists::why(p, func),
        "cfg" => lists::cfg(p, func),
        "jumptables" => lists::jumptables(p, func),
        _ => return None,
    })
}
