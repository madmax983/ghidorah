//! Code reads: executable memory, one decoded instruction and the import slot of a site.
//!
//! An instruction never crosses the end of its region. The decoder reads at most 15 bytes.

use ghidorah_base::{Address, ImportId, Limits};
use ghidorah_db::{FlowKind, Program};
use ghidorah_loader::Perms;
use ghidorah_x86::{Flow, Insn, MAX_LEN, Opts, decode};

/// Tells if `at` is in an executable region.
#[must_use]
pub fn is_exec(program: &Program, at: u64) -> bool {
    program
        .mem()
        .region_at(at)
        .is_some_and(|r| r.perms.contains(Perms::EXECUTE))
}

/// Tells if `at` is in a mapped region.
#[must_use]
pub fn is_mapped(program: &Program, at: u64) -> bool {
    program.mem().region_at(at).is_some()
}

/// Decodes the instruction at `at` in an executable region. Bad bytes give `None`.
#[must_use]
pub fn decode_at(program: &Program, at: u64) -> Option<Insn> {
    let region = program.mem().region_at(at)?;
    if !region.perms.contains(Perms::EXECUTE) {
        return None;
    }
    let left = region.va.last.saturating_sub(at).saturating_add(1);
    let len = left.min(MAX_LEN as u64);
    let bytes = program.mem().read(at, len, &Limits::DEFAULT).ok()?;
    decode(&bytes, at, &Opts::DEFAULT).ok()
}

/// Gives the flow kind of the listing for a decoder flow kind.
#[must_use]
pub const fn flow_kind(flow: Flow) -> Option<FlowKind> {
    Some(match flow {
        Flow::Seq => FlowKind::Seq,
        Flow::Jmp => FlowKind::Jmp,
        Flow::Jcc => FlowKind::Jcc,
        Flow::Call => FlowKind::Call,
        Flow::ICall => FlowKind::ICall,
        Flow::IJmp => FlowKind::IJmp,
        Flow::Ret => FlowKind::Ret,
        Flow::Trap => FlowKind::Trap,
        Flow::Invalid => return None,
    })
}

/// Gives the slot of an indirect call or jump through a RIP-relative or absolute memory
/// operand: `call [rip+slot]` or `jmp [slot]`.
#[must_use]
pub fn slot_of(insn: &Insn) -> Option<u64> {
    if !matches!(insn.flow(), Flow::ICall | Flow::IJmp) {
        return None;
    }
    let mem = insn.mem()?;
    if mem.index.is_some() {
        return None;
    }
    mem.abs_target
}

/// Gives the import whose slot is `slot`, with its EXTERNAL address.
#[must_use]
pub fn slot_import(program: &Program, slot: u64) -> Option<(&ImportId, Address)> {
    let slot = Address::ram(slot);
    program
        .imports()
        .values()
        .find(|row| row.slot == Some(slot))
        .map(|row| (&row.id, row.ext))
}
