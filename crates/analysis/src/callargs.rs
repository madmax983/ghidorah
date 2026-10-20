//! Call-site argument values (design Section 7.11). Derived data: `xref_list { args: true }`
//! computes them on demand.
//!
//! Block-local evaluation (design Section 6.6) gives the value of each argument register at
//! the call. [`classify`] gives the kind of a value:
//!
//! | Value | Kind |
//! |---|---|
//! | the start of a string fact, or of a NUL-terminated text in a read-only region | `str` |
//! | a function entry | `func` |
//! | another address in a mapped region | `addr` |
//! | another constant | `int` |
//! | no value | `unknown` |
//!
//! The argument count comes from the parameters of the callee ([`crate::cc::params`]), or from
//! the Tier-0 prototype of an import. A positional convention counts the floating slots too. A
//! call with no known callee gives six arguments.

use ghidorah_base::{Address, Fuel, FuncId, Limits};
use ghidorah_db::{Encoding, Program, Types};
use ghidorah_ir::{Loc, LocalValue, Opc, local};
use ghidorah_loader::Perms;

use crate::code::{decode_at, slot_of};
use crate::fir::{self, FirError, FuncIr, Image, Opts};
use crate::work::import_slots;

/// The largest text of a string value in bytes.
pub const MAX_TEXT: usize = 256;

/// The value of one argument.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArgValue {
    /// An integer.
    Int(u64),
    /// A pointer to a string, with the string bytes as text.
    Str {
        /// The address.
        addr: u64,
        /// The text, at most [`MAX_TEXT`] bytes.
        text: String,
    },
    /// A pointer to a function.
    Func(FuncId),
    /// Another address.
    Addr(u64),
    /// No value.
    Unknown,
}

impl ArgValue {
    /// Gives the kind name: `int`, `str`, `func`, `addr` or `unknown`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Str { .. } => "str",
            Self::Func(_) => "func",
            Self::Addr(_) => "addr",
            Self::Unknown => "unknown",
        }
    }
}

/// Gives the kind of the value `v` in `program`.
#[must_use]
pub fn classify(program: &Program, v: LocalValue) -> ArgValue {
    let a = match v {
        LocalValue::Unknown => return ArgValue::Unknown,
        LocalValue::Const(c) => return ArgValue::Int(c),
        LocalValue::Addr(a) => a,
    };
    if program.func(FuncId(Address::ram(a))).is_some() {
        return ArgValue::Func(FuncId(Address::ram(a)));
    }
    match text_at(program, a) {
        Some(text) => ArgValue::Str { addr: a, text },
        None => ArgValue::Addr(a),
    }
}

/// Gives the bytes at `addr` of a region that is not executable, at most `len` bytes.
fn data_bytes(program: &Program, addr: u64, len: u64) -> Option<Vec<u8>> {
    let region = program.mem().region_at(addr)?;
    if region.perms.contains(Perms::EXECUTE) {
        return None;
    }
    let left = region.va.last.checked_sub(addr)?.saturating_add(1);
    let bytes = program
        .mem()
        .read(addr, len.min(left), &Limits::DEFAULT)
        .ok()?;
    Some(bytes.to_vec())
}

/// Gives the text of the string at `addr`: a string fact, else a NUL-terminated run of
/// printable ASCII, tabs and line ends in a region that is not executable.
fn text_at(program: &Program, addr: u64) -> Option<String> {
    let cap = u64::try_from(MAX_TEXT).unwrap_or(u64::MAX);
    if let Some(info) = program.string(addr) {
        let bytes = data_bytes(program, addr, u64::from(info.len).min(cap))?;
        return Some(match info.encoding {
            Encoding::Utf16Le => {
                let units: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                    .collect();
                String::from_utf16_lossy(&units)
            }
            Encoding::Ascii | Encoding::Utf8 => String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    let bytes = data_bytes(program, addr, cap.saturating_add(1))?;
    let end = bytes.iter().position(|b| *b == 0)?;
    let text = bytes.get(..end)?;
    let printable = |b: &u8| matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r');
    (!text.is_empty() && text.iter().all(printable))
        .then(|| String::from_utf8_lossy(text).into_owned())
}

/// Gives the values of `regs` before the op `op` of `fir`.
#[must_use]
pub fn values(
    program: &Program,
    fir: &FuncIr,
    op: u32,
    regs: &[Loc],
    fuel: &mut Fuel,
) -> Vec<ArgValue> {
    let image = Image(program);
    let scope = fir.scope(&image);
    regs.iter()
        .map(|r| classify(program, local::value_at(&scope, op, *r, fuel)))
        .collect()
}

/// Gives the argument count of a call to `target`: the parameters of the function or the
/// prototype of the import of a slot.
fn arg_count(program: &Program, target: Callee, fuel: &mut Fuel) -> usize {
    let count = match target {
        Callee::Func(t) => crate::cc::params(program, FuncId(Address::ram(t)), fuel)
            .ok()
            .map(|(p, _)| {
                let positional = crate::cc::conv_of(program).positional;
                if positional {
                    p.int.saturating_add(p.float)
                } else {
                    p.int
                }
            }),
        Callee::Import(name) => {
            Types::prototype(&name).map(|p| u8::try_from(p.sig.params.len()).unwrap_or(u8::MAX))
        }
        Callee::None => None,
    };
    count.map_or(DEFAULT_ARGS, usize::from).min(DEFAULT_ARGS)
}

/// The callee of a call site.
enum Callee {
    /// A function entry.
    Func(u64),
    /// The import with this name, through its slot.
    Import(String),
    /// No known callee.
    None,
}

/// The argument count of a call with no known callee.
const DEFAULT_ARGS: usize = 6;

/// Gives the argument values of the call at `site` in its published function. A `jmp` to a
/// function, a tail call, also counts as a call site.
///
/// # Errors
///
/// Returns [`FirError::NoFunc`] when no function holds `site`, [`FirError::NoEntry`] when no
/// call or jump starts at `site`, and the errors of the IR build.
pub fn at(program: &Program, site: u64, fuel: &mut Fuel) -> Result<Vec<ArgValue>, FirError> {
    let owner = program
        .owner_of(Address::ram(site))
        .ok_or_else(|| FirError::NoFunc(crate::fir::func_id(site)))?;
    let ir = fir::build(program, owner, &Opts::DEFAULT, fuel)?;
    let op = [Opc::Call, Opc::CallInd, Opc::Jump, Opc::JumpInd]
        .into_iter()
        .find_map(|opc| ir.find_op(site, opc))
        .ok_or(FirError::NoEntry(site))?;
    let insn = decode_at(program, site).ok_or(FirError::Decode(site))?;
    let callee = match (insn.target(), slot_of(&insn)) {
        (Some(t), _) => Callee::Func(t),
        (None, Some(slot)) => import_slots(program)
            .get(&slot)
            .and_then(|(id, _)| id.name().map(str::to_owned))
            .map_or(Callee::None, Callee::Import),
        (None, None) => Callee::None,
    };
    let count = arg_count(program, callee, fuel);
    let conv = crate::cc::conv_of(program);
    let regs: Vec<Loc> = conv
        .int_args
        .iter()
        .take(count)
        .filter_map(|n| crate::cc::loc_of(n))
        .collect();
    Ok(values(program, &ir, op, &regs, fuel))
}
