//! The Intel syntax printer (design Section 5.4).
//!
//! The text follows GNU objdump in Intel mode, with three changes: lower case size
//! keywords, a space after each comma, and brackets around absolute memory
//! (`fs:[0x28]`). A RIP-relative operand gets a note with its target after ` ; `.
//! Agents read the canonical mnemonic, not this text.

use std::fmt::Write as _;

use crate::flow::Flow;
use crate::insn::{Insn, Slot, tag};
use crate::operand::Operand;
use crate::regs::{Reg, Seg};
use crate::tables::mnem::Mnem;

/// Gives names and notes for addresses in the display text.
///
/// The implementer gives escaped and capped text, for example through `BinText`.
pub trait Symbolizer {
    /// Gives the name of a branch or call target.
    fn name(&self, addr: u64) -> Option<String> {
        let _ = addr;
        None
    }

    /// Gives the note text for the target of a RIP-relative operand.
    fn note(&self, addr: u64) -> Option<String> {
        let _ = addr;
        None
    }
}

/// A symbolizer that knows no names.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSymbols;

impl Symbolizer for NoSymbols {}

/// The predicates of the `cmpps` family for immediates 0 to 7.
const CMP_PRED: [&str; 8] = ["eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord"];

/// Gives the size keyword of a memory width in bytes.
const fn size_word(bytes: u8) -> Option<&'static str> {
    match bytes {
        1 => Some("byte"),
        2 => Some("word"),
        4 => Some("dword"),
        6 => Some("fword"),
        8 => Some("qword"),
        10 => Some("tbyte"),
        16 => Some("xmmword"),
        32 => Some("ymmword"),
        64 => Some("zmmword"),
        _ => None,
    }
}

const fn mask(width: u8) -> u64 {
    match width {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

fn hex(v: u64) -> String {
    format!("0x{v:x}")
}

fn signed_hex(v: i64) -> String {
    if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("+0x{v:x}")
    }
}

fn is_string(m: Mnem) -> bool {
    matches!(
        m,
        Mnem::Movs | Mnem::Stos | Mnem::Lods | Mnem::Ins | Mnem::Outs
    )
}

fn is_compare_string(m: Mnem) -> bool {
    matches!(m, Mnem::Cmps | Mnem::Scas)
}

/// Gives the prefix words before the mnemonic, for example `lock ` or `data16 cs `.
fn prefix_words(insn: &Insn) -> String {
    let p = insn.prefixes();
    let m = insn.mnem();
    let mut out = String::new();
    if p.lock() {
        out.push_str("lock ");
    }
    if p.rep() && !p.rep_used() {
        out.push_str(if is_string(m) { "rep " } else { "repz " });
    }
    if p.repne() && !p.rep_used() {
        let branch = insn.flow().is_branch() && !is_compare_string(m);
        out.push_str(if branch { "bnd " } else { "repnz " });
    }
    let used = u8::from(p.osz_used());
    for _ in used..p.count_66() {
        out.push_str("data16 ");
    }
    if p.asz() && !p.asz_used() {
        out.push_str("addr32 ");
    }
    if let Some(seg) = insn.seg_override() {
        let indirect = matches!(insn.flow(), Flow::IJmp | Flow::ICall);
        let shown = (0..usize::from(insn.n_ops)).any(|i| {
            insn.slot(i).is_some_and(|s| {
                matches!(s.kind(), tag::STR_SRC | tag::XLAT)
                    || (seg.has_base() && matches!(s.kind(), tag::MEM | tag::MOFFS))
            })
        });
        if seg == Seg::Ds && indirect {
            out.push_str("notrack ");
        } else if !shown {
            out.push_str(seg.name());
            out.push(' ');
        }
    }
    out
}

/// Gives the text of a memory slot.
fn mem_text(insn: &Insn, i: usize, slot: Slot) -> String {
    let mut out = String::new();
    if slot.kind() != tag::MOFFS
        && let Some(w) = size_word(slot.size)
    {
        out.push_str(w);
        out.push_str(" ptr ");
    }
    let Some(Operand::Mem(m)) = insn.op(i) else {
        return out;
    };
    let explicit_seg = matches!(slot.kind(), tag::STR_SRC | tag::STR_DST | tag::XLAT);
    if let Some(seg) = m.seg
        && (explicit_seg || seg.has_base())
    {
        out.push_str(seg.name());
        out.push(':');
    }
    out.push('[');
    match (slot.kind(), m.base, m.index) {
        (tag::XLAT, Some(b), _) => out.push_str(b.name()),
        (_, None, None) => {
            let a = m.disp.cast_unsigned() & mask(if m.addr_width == 32 { 4 } else { 8 });
            out.push_str(&hex(a));
        }
        (_, base, index) => {
            if let Some(b) = base {
                out.push_str(b.name());
            }
            if let Some(i) = index {
                if base.is_some() {
                    out.push('+');
                }
                let _ = write!(out, "{}*{}", i.name(), m.scale);
            }
            let has_disp = insn.raw().disp_size > 0 && matches!(slot.kind(), tag::MEM);
            if has_disp {
                out.push_str(&signed_hex(m.disp));
            }
        }
    }
    out.push(']');
    out
}

fn slot_text<S: Symbolizer + ?Sized>(insn: &Insn, i: usize, sym: &S) -> Option<String> {
    let slot = insn.slot(i)?;
    Some(match slot.kind() {
        tag::REG => {
            Reg::from_bits(slot.reg).map_or_else(|| "?".to_owned(), |r| r.name().to_owned())
        }
        tag::ST0 => "st".to_owned(),
        tag::IMM => hex(insn.imm.cast_unsigned() & mask(slot.size)),
        tag::IMM2 => hex(u64::from(insn.imm2)),
        tag::ONE => "1".to_owned(),
        tag::TARGET => {
            let a = insn.target().unwrap_or(0);
            sym.name(a).unwrap_or_else(|| hex(a))
        }
        tag::MEM | tag::MOFFS | tag::STR_SRC | tag::STR_DST | tag::XLAT => mem_text(insn, i, slot),
        _ => "?".to_owned(),
    })
}

/// Gives the display text of the operand at `index`.
#[must_use]
pub fn operand_text<S: Symbolizer + ?Sized>(insn: &Insn, index: usize, sym: &S) -> Option<String> {
    slot_text(insn, index, sym)
}

/// Gives the Intel display text of an instruction.
#[must_use]
pub fn print<S: Symbolizer + ?Sized>(insn: &Insn, sym: &S) -> String {
    if let Some(form) = insn.opaque() {
        return format!("(vector {} {:02x})", form.map.name(), form.opcode);
    }
    let mut out = prefix_words(insn);
    let mut n = usize::from(insn.n_ops());
    let m = insn.mnem();
    let cmp_suffix = match m {
        Mnem::Cmpps => Some("ps"),
        Mnem::Cmppd => Some("pd"),
        Mnem::Cmpss => Some("ss"),
        Mnem::Cmpsd => Some("sd"),
        _ => None,
    };
    let pred = n
        .checked_sub(1)
        .and_then(|last| insn.slot(last))
        .filter(|s| s.kind() == tag::IMM)
        .and_then(|_| CMP_PRED.get(usize::try_from(insn.imm).ok()?));
    match (cmp_suffix, pred) {
        (Some(suffix), Some(p)) => {
            let _ = write!(out, "cmp{p}{suffix}");
            n = n.saturating_sub(1);
        }
        _ => out.push_str(m.name()),
    }
    for i in 0..n {
        out.push_str(if i == 0 { " " } else { ", " });
        out.push_str(&slot_text(insn, i, sym).unwrap_or_default());
    }
    if let Some(t) = insn.ops().find_map(|op| match op {
        Operand::Mem(mem) if mem.is_rip_relative() => mem.abs_target,
        _ => None,
    }) {
        out.push_str(" ; ");
        out.push_str(&sym.note(t).unwrap_or_else(|| hex(t)));
    }
    out
}
