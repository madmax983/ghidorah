//! Relative address tables: the clang form of a constant table of pointers.
//!
//! Clang can put a table of 32-bit offsets in place of a table of pointers. Each entry is the
//! distance from the table start to its target. The code that reads an element has this form:
//!
//! ```text
//! lea    B, [rip+T]
//! movsxd R, dword [B+I*4]
//! add    R, B            ; or: add B, R
//! ```
//!
//! `B`, `R` and `I` are general-purpose registers. Other instructions can come between, but
//! none of them changes `B` or `R`, and none of them changes the flow. The `add` is at most
//! [`MAX_WINDOW`] instructions after the `lea`.
//!
//! The walk of a table reads one entry after the other from `T`. It stops at the first of:
//!
//! - [`MAX_CASES`] entries, the cap of a jump table;
//! - an entry outside the file bytes of a region without execute permission;
//! - an entry whose target is not in readable data, or is in the table;
//! - an entry that holds a symbol, a reference target, a pointer slot or an entry of a table.
//!
//! A jump table of the same form has code targets, so its walk stops at the first entry.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Limits};
use ghidorah_db::{Program, RefKey, RefType};
use ghidorah_loader::Perms;
use ghidorah_x86::{Flow, Insn, Mnem, Operand, Reg, RegClass};

use super::{DataRefs, SLOT_SIZE};
use crate::code::decode_at;
use crate::jumptable::MAX_CASES;

/// The largest number of instructions from the `lea` to the `add`.
pub const MAX_WINDOW: usize = 8;

/// The size of a table entry in bytes.
pub const ENTRY_SIZE: u32 = 4;

/// One entry of a relative table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    /// The target: the table start plus the signed value of the entry.
    pub to: u64,
    /// The address of the `lea` that gives the table start.
    pub site: u64,
}

impl Entry {
    /// Gives the key of the reference from the entry at `at`.
    #[must_use]
    pub const fn key(&self, at: u64) -> RefKey {
        RefKey {
            from: Address::ram(at),
            op_index: 0,
            to: Address::ram(self.to),
            kind: RefType::Data,
        }
    }
}

/// Gives the register of a register operand.
fn reg_op(op: Option<Operand>) -> Option<Reg> {
    match op {
        Some(Operand::Reg { reg, .. }) => Some(reg),
        _ => None,
    }
}

/// Tells if `reg` is a 64-bit general-purpose register.
fn gpr64(reg: Reg) -> bool {
    reg.class() == RegClass::Gpr && reg.width_bits() == 64
}

/// Gives the base register and the table start of `lea B, [rip+T]`.
fn lea_base(insn: &Insn) -> Option<(Reg, u64)> {
    if insn.mnem() != Mnem::Lea {
        return None;
    }
    let base = reg_op(insn.op(0)).filter(|r| gpr64(*r))?;
    let mem = insn.mem().filter(ghidorah_x86::Mem::is_rip_relative)?;
    Some((base, mem.abs_target?))
}

/// Gives the destination of `movsxd R, dword [base+I*4]`.
fn entry_load(insn: &Insn, base: Reg) -> Option<Reg> {
    if insn.mnem() != Mnem::Movsxd {
        return None;
    }
    let dst = reg_op(insn.op(0)).filter(|r| gpr64(*r) && *r != base)?;
    let Some(Operand::Mem(m)) = insn.op(1) else {
        return None;
    };
    let form = m.base == Some(base)
        && m.index.is_some()
        && m.scale == 4
        && m.disp == 0
        && m.seg.is_none()
        && m.width_bytes == 4;
    form.then_some(dst)
}

/// Tells if `insn` is `add dst, base` or `add base, dst`.
fn base_add(insn: &Insn, base: Reg, dst: Reg) -> bool {
    insn.mnem() == Mnem::Add
        && matches!(
            (reg_op(insn.op(0)), reg_op(insn.op(1))),
            (Some(a), Some(b)) if (a == dst && b == base) || (a == base && b == dst)
        )
}

/// Gives the table start of the relative table read that starts with the instruction `lea`.
/// Another instruction gives `None`.
#[must_use]
pub fn table_of(program: &Program, lea: &Insn) -> Option<u64> {
    let (base, table) = lea_base(lea)?;
    let mut at = lea.next_addr();
    let mut dst = None;
    for _ in 0..MAX_WINDOW {
        let insn = decode_at(program, at).filter(|i| i.flow() == Flow::Seq)?;
        let written = insn.regs_written();
        match dst {
            None => match entry_load(&insn, base) {
                Some(r) => dst = Some(r),
                None if written.contains(base) => return None,
                None => {}
            },
            Some(r) if base_add(&insn, base, r) => return Some(table),
            Some(r) if written.contains(base) || written.contains(r) => return None,
            Some(_) => {}
        }
        at = insn.next_addr();
    }
    None
}

/// Gives the signed value of the entry at `at`. The 4 bytes are file bytes of one region
/// without execute permission.
fn read_entry(program: &Program, at: u64) -> Option<i64> {
    let last = at.checked_add(u64::from(ENTRY_SIZE) - 1)?;
    let region = program.mem().region_at(at)?;
    let in_file = last
        .checked_sub(region.va.first)
        .is_some_and(|off| off < region.file_size);
    if region.perms.contains(Perms::EXECUTE) || !region.va.contains(last) || !in_file {
        return None;
    }
    let bytes = program.mem().read(at, 4, &Limits::DEFAULT).ok()?;
    let word: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(i64::from(i32::from_le_bytes(word)))
}

/// Tells if `at` is in readable data: a mapped region with read and without execute permission.
fn readable_data(program: &Program, at: u64) -> bool {
    program
        .mem()
        .region_at(at)
        .is_some_and(|r| r.perms.contains(Perms::READ) && !r.perms.contains(Perms::EXECUTE))
}

/// The addresses that stop a walk.
struct Stops {
    /// The reference targets, the pointer slots and the symbols.
    marks: BTreeSet<u64>,
    /// The pointer slots.
    slots: BTreeSet<u64>,
}

impl Stops {
    /// Tells if the entry `first..=last` holds a stop. The table start `skip` does not count.
    fn hit(&self, out: &BTreeMap<u64, Entry>, first: u64, last: u64, skip: u64) -> bool {
        let from = if first == skip {
            first.saturating_add(1)
        } else {
            first
        };
        let slot_from = first.saturating_sub(u64::from(SLOT_SIZE) - 1);
        let entry_from = first.saturating_sub(u64::from(ENTRY_SIZE) - 1);
        (from <= last && self.marks.range(from..=last).next().is_some())
            || self.slots.range(slot_from..=last).next().is_some()
            || out.range(entry_from..=last).next().is_some()
    }
}

/// Adds the entries of the table at `table` to `out`. The `lea` at `site` gives the table.
fn walk(program: &Program, table: u64, site: u64, stops: &Stops, out: &mut BTreeMap<u64, Entry>) {
    let mut targets = BTreeSet::new();
    let mut at = table;
    for _ in 0..MAX_CASES {
        let Some(last) = at.checked_add(u64::from(ENTRY_SIZE) - 1) else {
            break;
        };
        let own = at != table && targets.range(at..=last).next().is_some();
        if own || stops.hit(out, at, last, table) {
            break;
        }
        let Some(to) = read_entry(program, at).and_then(|v| table.checked_add_signed(v)) else {
            break;
        };
        if !readable_data(program, to) || (table..=last).contains(&to) {
            break;
        }
        targets.insert(to);
        out.insert(at, Entry { to, site });
        let Some(next) = last.checked_add(1) else {
            break;
        };
        at = next;
    }
}

/// Gives the entries of the relative tables of `data` by address.
///
/// The tables go in address order. The first site of a table start gives the table.
#[must_use]
pub(crate) fn entries(program: &Program, data: &DataRefs) -> BTreeMap<u64, Entry> {
    let mut out = BTreeMap::new();
    if data.sites.is_empty() {
        return out;
    }
    let mut marks: BTreeSet<u64> = data
        .operands
        .iter()
        .filter(|k| k.to.is_ram())
        .map(|k| k.to.off)
        .collect();
    for (at, slot) in &data.slots {
        marks.insert(*at);
        if slot.to.is_ram() {
            marks.insert(slot.to.off);
        }
    }
    marks.extend(
        program
            .binary()
            .symbols
            .iter()
            .map(|s| s.addr)
            .filter(|a| *a != 0),
    );
    let stops = Stops {
        marks,
        slots: data.slots.keys().copied().collect(),
    };
    let mut first: BTreeMap<u64, u64> = BTreeMap::new();
    for (site, table) in &data.sites {
        first.entry(*table).or_insert(*site);
    }
    for (table, site) in first {
        walk(program, table, site, &stops, &mut out);
    }
    out
}
