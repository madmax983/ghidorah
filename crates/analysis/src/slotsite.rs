//! Indirect jumps and calls through a register that holds an import slot (design Section 7.8).
//!
//! The C runtime of gcc and clang loads a weak import slot into a register, tests it and
//! jumps or calls through the register:
//!
//! ```text
//! mov rax, [rip + slot]    ; the GOT slot of _ITM_deregisterTMCloneTable
//! test rax, rax
//! je done
//! jmp rax
//! ```
//!
//! [`site_target`] finds the slot of such a site. It runs the block-local walk of the IR
//! ([`ghidorah_ir::local`]) on the target of the jump or the call. In [`SlotMemory`], each
//! byte of an import slot reads as a byte of the slot address. The site goes through the slot
//! when the walk gives the slot address with one 8-byte load of that slot. So the value is the
//! slot value with no change. The walk stops at a merge point, so each path to the site loads
//! the same slot.
//!
//! A file with no dynamic import of the weak symbol has the constant 0 in place of the load:
//! `mov eax, 0`. The walk then gives 0 ([`SiteTarget::Null`]). The guard skips the site, and
//! a jump or a call to address 0 has no target.
//!
//! `JumpTables` (band 410) records each such site ([`crate::irfacts`] field `slot_sites`).
//! Then `Disasm` handles a slot site like `jmp [rip + slot]`: a reference to the EXTERNAL
//! address of the import, a slot exit or a slot call, and the noreturn flag of the import. A
//! null site gets [`crate::ctx::UNIT_NULL_TARGET`]: no reference and no CFG edge.

use ghidorah_base::Fuel;
use ghidorah_ir::Opc;
use ghidorah_ir::local::{self, Memory, Query};

use crate::fir::FuncIr;

/// The size of an import slot in bytes.
const SLOT_SIZE: u64 = 8;

/// The fuel of the walk at one site.
pub const SITE_FUEL: u64 = 100_000;

/// The memory of the walk: each byte of an import slot reads as a byte of the slot address.
/// Other bytes come from the image.
pub struct SlotMemory<'a> {
    /// The read-only image.
    pub image: &'a dyn Memory,
    /// Tells if an address is the start of an import slot.
    pub is_slot: &'a dyn Fn(u64) -> bool,
}

impl Memory for SlotMemory<'_> {
    fn read(&self, addr: u64) -> Option<u8> {
        let first = addr.saturating_sub(SLOT_SIZE - 1);
        for slot in (first..=addr).rev() {
            if (self.is_slot)(slot) {
                let at = usize::try_from(addr.checked_sub(slot)?).ok()?;
                return slot.to_le_bytes().get(at).copied();
            }
        }
        self.image.read(addr)
    }

    fn mapped(&self, addr: u64) -> bool {
        self.image.mapped(addr)
    }
}

/// The target of an indirect site that the walk finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SiteTarget {
    /// The value of the import slot at this address.
    Slot(u64),
    /// The constant 0.
    Null,
}

/// Gives the target of the indirect jump or call at `site` of `fir`, or `None`.
///
/// `opc` is `JumpInd` or `CallInd`. The site goes through a slot when the walk of its target
/// in `mem` gives the slot address with one 8-byte load of that slot. A walk that gives 0 is
/// a null site (see the module doc).
#[must_use]
pub fn site_target(fir: &FuncIr, mem: &SlotMemory<'_>, site: u64, opc: Opc) -> Option<SiteTarget> {
    let index = fir.find_op(site, opc)?;
    let scope = fir.scope(mem);
    let outcome = local::eval(&scope, &Query::arg(index, 0), &mut Fuel::new(SITE_FUEL));
    let value = outcome.value.value()?;
    if value == 0 {
        return Some(SiteTarget::Null);
    }
    let one_load = outcome.loads.as_slice() == [(value, 8)];
    (one_load && (mem.is_slot)(value)).then_some(SiteTarget::Slot(value))
}
