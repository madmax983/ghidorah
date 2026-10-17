//! `DataPtrSeeds` (band 450): seed 11 of design Section 7.3, code pointers in data.
//!
//! A code pointer is an aligned 8-byte value in an initialized region without execute
//! permission. The value is an address in an executable region.
//!
//! | File | Code pointer |
//! |---|---|
//! | a file with `R_X86_64_RELATIVE` or `R_X86_64_64` relocations | the value that such a relocation puts in its slot |
//! | a file without such relocations | a value in a run of [`MIN_RUN`] or more code pointers |
//!
//! The analyzer tests each target. A target that passes the tests starts a function with the
//! reason `DataPtr`, confidence [`CONFIDENCE`] and `R_DATA_CODE_PTR`. The tests are:
//!
//! - A padding head (`nop`, `int3` or a 0 byte) moves the target to the next other instruction.
//! - The start is in an executable region and not in the PLT area.
//! - The start is not a jump-table case target.
//! - No other function holds the start in its body or in a declared extent.
//! - No function with a reason of seeds 1 to 10 starts there. A `Call` reason does not count.
//! - A linear decode gives at least [`MIN_INSNS`] valid instructions before bad bytes or the
//!   end of the region.
//!
//! The band is above the bands of seeds 1 to 10 and of `JumpTables`. So the tests see the
//! bodies of these seeds and the resolved jump tables. Each step tests every pointer again,
//! and a `DataPtr` reason that fails a test goes.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Limits, Range};
use ghidorah_db::{FactKey, FlowOverride, Program, StartReason};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::{Perms, Reloc, RelocForm, Section, SectionKind};
use ghidorah_x86::{Flow, Mnem};

use crate::analyzers::refs::reloc_target;
use crate::code::{decode_at, is_exec};
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::{Rule, Why};

/// The confidence of a `DataPtr` start.
pub const CONFIDENCE: u8 = 70;

/// The smallest number of valid instructions of a linear decode from a start.
pub const MIN_INSNS: u64 = 4;

/// The smallest number of code pointers in a run, in a file without pointer relocations.
pub const MIN_RUN: u64 = 2;

/// The largest number of padding bytes before a start.
pub const MAX_PADDING: u64 = 64;

/// The largest number of bytes of one section that the run scan reads.
pub const MAX_SCAN_BYTES: u64 = 16 << 20;

/// The size of a pointer slot in bytes.
const SLOT: u64 = 8;
/// `R_X86_64_64`.
const R_64: u32 = 1;
/// `R_X86_64_RELATIVE`.
const R_RELATIVE: u32 = 8;
/// `SHT_PROGBITS`.
const SHT_PROGBITS: u32 = 1;
/// `SHT_INIT_ARRAY`, `SHT_FINI_ARRAY` and `SHT_PREINIT_ARRAY`.
const SHT_ARRAYS: [u32; 3] = [14, 15, 16];
/// `SHF_EXECINSTR`.
const SHF_EXECINSTR: u64 = 0x4;
/// The PE section flag `IMAGE_SCN_MEM_EXECUTE`.
const SCN_MEM_EXECUTE: u64 = 0x2000_0000;
/// The sections with relative encodings that the run scan skips.
const NO_SCAN: [&str; 3] = [".eh_frame", ".eh_frame_hdr", ".gcc_except_table"];
/// The reasons that do not make a start known to the tests: the two seeds and `Call`.
/// A `Call` reason can come from the body of a seed itself, for example a recursive call.
const SHARED: [StartReason; 3] = [
    StartReason::Call,
    StartReason::DataPtr,
    StartReason::AddrTaken,
];

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::DataPtrSeeds,
    name: "DataPtrSeeds",
    priority: 450,
    triggers: &[Trigger::Bytes, Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[
        Opt {
            name: "min_insns",
            value: MIN_INSNS,
            doc: "The smallest number of valid instructions of a linear decode from a start.",
        },
        Opt {
            name: "min_run",
            value: MIN_RUN,
            doc: "The smallest number of code pointers in a run without relocations.",
        },
    ],
    doc: "Starts a function at each code pointer in data that no body holds.",
};

/// One code pointer in data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pointer {
    /// The address of the 8-byte slot.
    pub slot: u64,
    /// The value: an address in an executable region.
    pub target: u64,
    /// A relocation gives the value.
    pub relocated: bool,
}

impl Pointer {
    /// Gives the premise of a seed: the relocation, or the data slot of a pointer run.
    #[must_use]
    pub const fn premise(&self) -> FactKey {
        if self.relocated {
            FactKey::Reloc(self.slot)
        } else {
            FactKey::Data(self.slot)
        }
    }
}

/// The code-pointer state of a work state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CodePtrs {
    /// The code pointers in data, or `None` before the first step of `DataPtrSeeds`.
    pub pointers: Option<Vec<Pointer>>,
    /// The address-taken sites of the code units, each with its target.
    pub sites: BTreeMap<u64, u64>,
}

/// Reads the little-endian `u64` at `at`.
fn read_u64(program: &Program, at: u64) -> Option<u64> {
    let bytes = program.mem().read(at, SLOT, &Limits::DEFAULT).ok()?;
    let word: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(word))
}

/// Tells if the 8 bytes at `at` are an aligned slot in the file bytes of one region without
/// execute permission.
fn slot_ok(program: &Program, at: u64) -> bool {
    let Some(last) = at.checked_add(SLOT - 1) else {
        return false;
    };
    at.is_multiple_of(SLOT)
        && program.mem().region_at(at).is_some_and(|r| {
            !r.perms.contains(Perms::EXECUTE)
                && r.va.contains(last)
                && last
                    .checked_sub(r.va.first)
                    .is_some_and(|off| off < r.file_size)
        })
}

/// Tells if `r` is a pointer relocation: `R_X86_64_RELATIVE` or `R_X86_64_64`.
const fn is_pointer_reloc(r: &Reloc) -> bool {
    matches!(r.kind.0, R_RELATIVE | R_64)
}

/// Gives the value that the pointer relocation `r` puts in its slot.
fn reloc_value(program: &Program, r: &Reloc) -> Option<u64> {
    match r.kind.0 {
        R_RELATIVE => match r.form {
            RelocForm::Rela => Some(r.addend.cast_unsigned()),
            RelocForm::Rel | RelocForm::Relr => read_u64(program, r.offset),
        },
        R_64 => reloc_target(program, r)
            .filter(Address::is_ram)
            .map(|a| a.off),
        _ => None,
    }
}

/// Tells if the run scan reads the section `s`: a data section or an array without execute
/// permission.
fn scanned(s: &Section) -> bool {
    match s.kind {
        SectionKind::Elf(kind) => {
            let skipped = s.name.as_str().is_some_and(|n| NO_SCAN.contains(&n));
            let data = kind == SHT_PROGBITS || SHT_ARRAYS.contains(&kind);
            data && !skipped && s.flags & SHF_EXECINSTR == 0
        }
        SectionKind::Pe => s.flags & SCN_MEM_EXECUTE == 0,
    }
}

/// Gives the ranges of the run scan: the scanned sections, or each region without execute
/// permission of a file with no section headers.
fn scan_scope(program: &Program) -> Vec<Range> {
    let sections = &program.binary().sections;
    if sections.iter().all(|s| s.va.is_none()) {
        return program
            .mem()
            .regions()
            .filter(|r| !r.perms.contains(Perms::EXECUTE))
            .map(|r| r.va)
            .collect();
    }
    sections
        .iter()
        .filter(|s| scanned(s))
        .filter_map(|s| s.va)
        .collect()
}

/// Moves the pointers of `run` into `out` when the run has [`MIN_RUN`] or more pointers.
fn flush(run: &mut Vec<Pointer>, out: &mut BTreeMap<u64, Pointer>) {
    if u64::try_from(run.len()).unwrap_or(0) >= MIN_RUN {
        out.extend(run.iter().map(|p| (p.slot, *p)));
    }
    run.clear();
}

/// Adds the runs of code pointers in the aligned slots of `va` to `out`.
fn scan(program: &Program, va: Range, out: &mut BTreeMap<u64, Pointer>) {
    let skip = va.first.wrapping_neg() % SLOT;
    let Some(first) = va.first.checked_add(skip) else {
        return;
    };
    let len = u64::try_from(va.len())
        .unwrap_or(u64::MAX)
        .saturating_sub(skip)
        .min(MAX_SCAN_BYTES);
    let Ok(bytes) = program.mem().read(first, len, &Limits::DEFAULT) else {
        return;
    };
    let mut run = Vec::new();
    for (chunk, i) in bytes.chunks_exact(8).zip(0u64..) {
        let Some(slot) = i.checked_mul(SLOT).and_then(|o| first.checked_add(o)) else {
            break;
        };
        let word: [u8; 8] = chunk.try_into().unwrap_or_default();
        let target = u64::from_le_bytes(word);
        if slot_ok(program, slot) && is_exec(program, target) {
            run.push(Pointer {
                slot,
                target,
                relocated: false,
            });
        } else {
            flush(&mut run, out);
        }
    }
    flush(&mut run, out);
}

/// Gives the code pointers in the data of `program` in slot order.
#[must_use]
pub fn pointers(program: &Program) -> Vec<Pointer> {
    let b = program.binary();
    if !b.arch.is_x86_64() {
        return Vec::new();
    }
    let mut out = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for r in b.relocs.iter().filter(|r| is_pointer_reloc(r)) {
        if !seen.insert(r.offset) {
            continue;
        }
        if let Some(target) = reloc_value(program, r)
            && slot_ok(program, r.offset)
            && is_exec(program, target)
        {
            let p = Pointer {
                slot: r.offset,
                target,
                relocated: true,
            };
            out.insert(p.slot, p);
        }
    }
    if seen.is_empty() {
        for va in scan_scope(program) {
            scan(program, va, &mut out);
        }
    }
    out.into_values().collect()
}

/// Gives the first address at or after `target` that is not padding.
///
/// Padding is a `nop` form, `int3` or a 0 byte. Bad bytes, an address outside executable
/// memory and more than [`MAX_PADDING`] padding bytes give `None`.
#[must_use]
pub fn skip_padding(program: &Program, target: u64) -> Option<u64> {
    let mut at = target;
    loop {
        if at.checked_sub(target)? > MAX_PADDING || !is_exec(program, at) {
            return None;
        }
        let zero = program.mem().read(at, 1, &Limits::DEFAULT).ok()?.first() == Some(&0);
        let len = if zero {
            1
        } else {
            let insn = decode_at(program, at)?;
            if !insn.is_nop() && insn.mnem() != Mnem::Int3 {
                return Some(at);
            }
            u64::from(insn.len())
        };
        at = at.checked_add(len)?;
    }
}

/// Counts the valid instructions of a linear decode from `at`, up to `max`. The count stops
/// at bad bytes and at the end of the executable region.
#[must_use]
pub fn linear_insns(program: &Program, at: u64, max: u64) -> u64 {
    let mut count = 0u64;
    let mut pc = at;
    while count < max {
        let Some(insn) = decode_at(program, pc).filter(|i| i.flow() != Flow::Invalid) else {
            break;
        };
        count = count.saturating_add(1);
        let Some(next) = pc.checked_add(u64::from(insn.len())) else {
            break;
        };
        pc = next;
    }
    count
}

/// Gives the RAM offsets of `addrs`.
fn ram(addrs: &[Address]) -> impl Iterator<Item = u64> + '_ {
    addrs.iter().filter(|a| a.is_ram()).map(|a| a.off)
}

/// Gives the case targets of the resolved jump tables.
///
/// The tables are the method A tables of the work state, the agent tables and the agent cases
/// of indirect jumps.
pub(crate) fn case_targets(ctx: &AnalysisCtx<'_>) -> BTreeSet<u64> {
    let program = ctx.program();
    let base = program.base();
    let mut out = BTreeSet::new();
    for r in ctx.ir().tables.values().filter(|r| r.table.resolved) {
        out.extend(ram(&r.table.targets));
    }
    for (_, t) in base.jumptables().iter() {
        out.extend(ram(&t.value.targets));
    }
    for (at, f) in base.overrides().iter() {
        if let FlowOverride::IndirectTargets(targets) = &f.value
            && decode_at(program, at.off).is_some_and(|i| i.flow() == Flow::IJmp)
        {
            out.extend(ram(targets));
        }
    }
    out
}

/// Gives the start of a seed at the code pointer `target` by the tests of the module, or
/// `None` when a test fails.
pub(crate) fn start_at(ctx: &AnalysisCtx<'_>, cases: &BTreeSet<u64>, target: u64) -> Option<u64> {
    let program = ctx.program();
    if cases.contains(&target) {
        return None;
    }
    let at = skip_padding(program, target)?;
    let other = |owner: u64| owner != at;
    let held = ctx.owner(at).is_some_and(other) || ctx.extent_owner(at).is_some_and(other);
    let known = ctx
        .work
        .funcs
        .get(&at)
        .is_some_and(|f| f.reasons.keys().any(|r| !SHARED.contains(r)));
    if held || known || ctx.in_plt(at) || cases.contains(&at) {
        return None;
    }
    (linear_insns(program, at, MIN_INSNS) >= MIN_INSNS).then_some(at)
}

/// Puts the reason `reason` on each start of `want` and removes it from each other function.
pub(crate) fn seed(
    ctx: &mut AnalysisCtx<'_>,
    reason: StartReason,
    confidence: u8,
    want: BTreeMap<u64, Why>,
) {
    let lost: Vec<u64> = ctx
        .funcs()
        .filter(|(e, f)| f.reasons.contains_key(&reason) && !want.contains_key(e))
        .map(|(e, _)| e)
        .collect();
    for entry in lost {
        let _ = ctx.remove_reason(entry, reason);
    }
    for (entry, why) in want {
        let _ = ctx.add_reason(entry, reason, confidence, why);
    }
}

/// Runs one step: every code pointer gets the tests again. The ranges only queue the step.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = ranges;
    let program = ctx.program();
    if !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let list = ctx
        .work
        .codeptrs
        .pointers
        .take()
        .unwrap_or_else(|| pointers(program));
    let cases = case_targets(ctx);
    let mut work = 1u64;
    let mut want = BTreeMap::new();
    for p in &list {
        work = work.saturating_add(1);
        if let Some(at) = start_at(ctx, &cases, p.target) {
            want.entry(at)
                .or_insert_with(|| Why::new(Rule::DataCodePtr, vec![p.premise()]));
        }
    }
    ctx.work.codeptrs.pointers = Some(list);
    seed(ctx, StartReason::DataPtr, CONFIDENCE, want);
    Step { work }
}
