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

use ghidorah_base::{Caps, Fuel, FuncId};
use ghidorah_db::Program;
use ghidorah_decomp::{Opts, Output};
use ghidorah_json::Value;

use super::IrRows;
use crate::args::Args;

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

/// Gives the decompile options of the call: `decomp_opts.lines` and `decomp_opts.passes`.
#[must_use]
pub fn opts(args: &Args) -> DecompOpts {
    let _ = args;
    DecompOpts {
        start: 1,
        count: 0,
        opts: Opts::default(),
    }
}

/// Gives the decompile of `func` with `opts`.
///
/// # Errors
///
/// Returns the text of the decompile error.
pub fn output(
    program: &Program,
    func: FuncId,
    opts: &Opts,
    fuel: &mut Fuel,
) -> Result<Output, String> {
    let _ = (program, func, opts, fuel);
    Err(String::new())
}

/// Gives the section value of the window of `count` lines from the line `start`. `cursor`
/// gives the cursor text of a next line.
#[must_use]
pub fn value(
    program: &Program,
    out: &Output,
    start: usize,
    count: usize,
    caps: Caps,
    cursor: &dyn Fn(usize) -> String,
) -> Value {
    let _ = (program, out, start, count, caps, cursor);
    Value::Null
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
    let _ = (program, func, after, limit, fuel);
    Err(String::new())
}
