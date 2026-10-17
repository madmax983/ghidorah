//! `References` (band 600): the data references of operands, relocations and address tables
//! (design Section 7.5).
//!
//! | Source | Reference | Rule |
//! |---|---|---|
//! | a RIP-relative or absolute memory operand that points into mapped memory | `read`, `write` or `read_write` by the access, `data` for an address-only operand | `R_OPERAND_REF` |
//! | an immediate of 4 or more bytes that points into mapped memory, in a file at a fixed address | `data` | `R_OPERAND_REF` |
//! | the slot of an `R_X86_64_RELATIVE`, RELR, `R_X86_64_64` or `R_X86_64_GLOB_DAT` relocation | `data` from the slot | `R_RELOC_PTR` |
//! | an element of an init, fini or preinit array | `data` from the slot | `R_ADDR_TABLE` |
//! | a run of 2 or more pointers in a data section of a file at a fixed address | `data` from each slot | `R_ADDR_TABLE` |
//!
//! Rules:
//!
//! - A slot is 8 bytes outside executable memory. Two slots never overlap: the lower slot
//!   stays. Each slot gets a `void *` data definition. So each reference starts at an
//!   instruction or at a data slot (AC-085a).
//! - A target is a mapped RAM address or the EXTERNAL address of an import.
//! - A position-independent file has no immediate references and no address tables. Its
//!   pointers have relocations, so the relocation rule is exact.
//! - An address table skips each slot with a relocation of any type.
//!
//! A change of the references queues `Strings`, because a string at a target is referenced.

use std::collections::BTreeMap;

use ghidorah_base::Address;
use ghidorah_db::{Program, RefKey, RefType};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Reloc;
use ghidorah_x86::{Access, Insn};

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::Why;

/// The smallest immediate that can be an address.
pub const MIN_IMM: u64 = 0x1_0000;

/// The smallest number of pointers of an address table.
pub const MIN_TABLE: u64 = 2;

/// The size of a pointer slot in bytes.
pub const SLOT_SIZE: u32 = 8;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::References,
    name: "References",
    priority: 600,
    triggers: &[Trigger::Bytes, Trigger::Instructions],
    version: 1,
    grain: Grain::Whole,
    options: &[
        Opt {
            name: "min_imm",
            value: MIN_IMM,
            doc: "The smallest immediate that can be an address.",
        },
        Opt {
            name: "min_table",
            value: MIN_TABLE,
            doc: "The smallest number of pointers of an address table.",
        },
    ],
    doc: "Adds the data references of operands, relocations and address tables.",
};

/// One pointer slot: its target and its why-record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot {
    /// The target: a mapped RAM address or the EXTERNAL address of an import.
    pub to: Address,
    /// The why-record of the slot.
    pub why: Why,
}

/// The data references of the work state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DataRefs {
    /// The operand references by key, each with its why-record.
    pub operands: BTreeMap<RefKey, Why>,
    /// The pointer slots by address.
    pub slots: BTreeMap<u64, Slot>,
}

/// Gives the reference type of a memory access.
#[must_use]
pub const fn ref_kind(access: Access) -> RefType {
    match access {
        Access::Read => RefType::Read,
        Access::Write => RefType::Write,
        Access::ReadWrite => RefType::ReadWrite,
        Access::Address => RefType::Data,
    }
}

/// Gives the data references of the instruction `insn`: the operand index, the target and the
/// type of each one, in operand order.
#[must_use]
pub fn operand_refs(program: &Program, insn: &Insn) -> Vec<(i8, Address, RefType)> {
    let _ = (program, insn);
    Vec::new()
}

/// Gives the target of the pointer that the relocation `reloc` puts in its slot.
#[must_use]
pub fn reloc_target(program: &Program, reloc: &Reloc) -> Option<Address> {
    let _ = (program, reloc);
    None
}

/// Gives the pointer slots of `program` by address.
#[must_use]
pub fn slots(program: &Program) -> BTreeMap<u64, Slot> {
    let _ = program;
    BTreeMap::new()
}

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}
