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
//! - A slot is 8 bytes in one region outside executable memory. Two slots never overlap: the
//!   lower slot stays. Each slot gets a `void *` data definition. So each reference starts at
//!   an instruction or at a data slot (AC-085a).
//! - A target is a mapped RAM address or the EXTERNAL address of an import.
//! - A position-independent file has no immediate references and no address tables. Its
//!   pointers have relocations, so the relocation rule is exact.
//! - An address table skips each slot that holds the place of a relocation of any type.
//! - The first relocation of a place in table order gives the slot.
//!
//! A change of the references queues `Strings`, because a reference marks the string at its target.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Limits, Range};
use ghidorah_db::codec::edit_to_json;
use ghidorah_db::{DataDef, Edit, FactKey, Origin, Program, Ref, RefKey, RefType};
use ghidorah_json::Value;
use ghidorah_kernel::RangeSet;
use ghidorah_loader::pe::{REL_DIR64, REL_HIGHLOW};
use ghidorah_loader::{Format, Kind, Perms, Reloc, RelocForm, SectionKind, Sym, SymTable};
use ghidorah_types::{Prim, Type, TypeId};
use ghidorah_x86::{Access, Insn, Operand};

use crate::code::{decode_at, is_mapped};
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::sched::ALL;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::{Rule, Why};
use crate::work::Work;

/// The smallest immediate that can be an address.
pub const MIN_IMM: u64 = 0x1_0000;

/// The smallest number of pointers of an address table.
pub const MIN_TABLE: u64 = 2;

/// The size of a pointer slot in bytes.
pub const SLOT_SIZE: u32 = 8;

/// The largest number of bytes of one section that the table scan reads.
pub const MAX_TABLE_BYTES: u64 = 16 << 20;

/// `SHT_PROGBITS`.
const SHT_PROGBITS: u32 = 1;
/// `SHT_INIT_ARRAY`, `SHT_FINI_ARRAY` and `SHT_PREINIT_ARRAY`.
const SHT_ARRAYS: [u32; 3] = [14, 15, 16];
/// `SHF_EXECINSTR`.
const SHF_EXECINSTR: u64 = 4;
/// `SHN_UNDEF`.
const SHN_UNDEF: u32 = 0;
/// `R_X86_64_64`.
const R_64: u32 = 1;
/// `R_X86_64_GLOB_DAT`.
const R_GLOB_DAT: u32 = 6;
/// `R_X86_64_RELATIVE`.
const R_RELATIVE: u32 = 8;
/// The sections with relative encodings that the table scan skips.
const NO_TABLES: [&str; 3] = [".eh_frame", ".eh_frame_hdr", ".gcc_except_table"];

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

impl Slot {
    /// Gives the key of the reference from the slot at `at`.
    #[must_use]
    pub const fn key(&self, at: u64) -> RefKey {
        RefKey {
            from: Address::ram(at),
            op_index: 0,
            to: self.to,
            kind: RefType::Data,
        }
    }
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

/// Tells if `program` loads at a fixed address, so that an immediate can be an address.
fn fixed(program: &Program) -> bool {
    matches!(program.meta().kind, Kind::Exec | Kind::Raw)
}

/// Gives the data references of the instruction `insn`: the operand index, the target and the
/// type of each one, in operand order. A `nop` has none.
#[must_use]
pub fn operand_refs(program: &Program, insn: &Insn) -> Vec<(i8, Address, RefType)> {
    let mut out = Vec::new();
    if insn.is_nop() {
        return out;
    }
    let imm_ok = fixed(program);
    for (i, index) in (0..usize::from(insn.n_ops())).zip(0i8..) {
        let found = match insn.op(i) {
            Some(Operand::Mem(m)) => m.abs_target.map(|t| (t, ref_kind(m.access))),
            Some(Operand::Imm { value, width, .. }) if imm_ok && width >= 4 => {
                let v = value.cast_unsigned();
                (v >= MIN_IMM).then_some((v, RefType::Data))
            }
            _ => None,
        };
        if let Some((to, kind)) = found
            && is_mapped(program, to)
        {
            out.push((index, Address::ram(to), kind));
        }
    }
    out
}

/// Reads the little-endian `u64` at `at`.
fn read_u64(program: &Program, at: u64) -> Option<u64> {
    let bytes = program.mem().read(at, 8, &Limits::DEFAULT).ok()?;
    let word: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(word))
}

/// The symbol and import indexes of a relocation pass.
struct Names<'p> {
    syms: BTreeMap<(SymTable, u32), &'p Sym>,
    imports: BTreeMap<&'p [u8], Address>,
}

impl<'p> Names<'p> {
    fn of(program: &'p Program) -> Self {
        let b = program.binary();
        let syms = b.symbols.iter().map(|s| ((s.table, s.index), s)).collect();
        let mut imports = BTreeMap::new();
        for row in program.imports().values() {
            if let Some(name) = b.imports.get(row.index).and_then(|i| i.name.as_ref()) {
                imports.entry(name.as_bytes()).or_insert(row.ext);
            }
        }
        Self { syms, imports }
    }

    /// Gives the target of the symbol of `r` plus `addend`. An undefined symbol gives its import.
    fn symbol(&self, program: &Program, r: &Reloc, addend: i64) -> Option<Address> {
        let sym = self.syms.get(&(r.sym_table, r.sym?))?;
        if sym.shndx == SHN_UNDEF {
            return self.imports.get(sym.name.as_bytes()).copied();
        }
        let to = sym.addr.checked_add_signed(addend)?;
        is_mapped(program, to).then_some(Address::ram(to))
    }

    fn target(&self, program: &Program, r: &Reloc) -> Option<Address> {
        if program.meta().format == Format::Pe32Plus {
            return pe_target(program, r);
        }
        let in_place = || read_u64(program, r.offset).map(u64::cast_signed);
        let addend = match r.form {
            RelocForm::Rela => Some(r.addend),
            RelocForm::Rel | RelocForm::Relr => None,
        };
        match r.kind.0 {
            R_RELATIVE => {
                let to = addend.or_else(in_place)?.cast_unsigned();
                is_mapped(program, to).then_some(Address::ram(to))
            }
            R_64 => self.symbol(program, r, addend.or_else(in_place)?),
            R_GLOB_DAT => self.symbol(program, r, 0),
            _ => None,
        }
    }
}

/// Gives the target of a PE base relocation: the value in its slot, 8 bytes for `DIR64` and
/// 4 bytes for `HIGHLOW`.
fn pe_target(program: &Program, r: &Reloc) -> Option<Address> {
    let to = match r.kind.0 {
        REL_DIR64 => read_u64(program, r.offset)?,
        REL_HIGHLOW => {
            let bytes = program.mem().read(r.offset, 4, &Limits::DEFAULT).ok()?;
            u64::from(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
        }
        _ => return None,
    };
    is_mapped(program, to).then_some(Address::ram(to))
}

/// Gives the target of the pointer that the relocation `reloc` puts in its slot.
#[must_use]
pub fn reloc_target(program: &Program, reloc: &Reloc) -> Option<Address> {
    if !program.binary().arch.is_x86_64() {
        return None;
    }
    Names::of(program).target(program, reloc)
}

/// Tells if the 8 bytes at `at` are one slot: in one region without execute permission.
fn slot_place(program: &Program, at: u64) -> bool {
    let Some(last) = at.checked_add(u64::from(SLOT_SIZE) - 1) else {
        return false;
    };
    program
        .mem()
        .region_at(at)
        .is_some_and(|r| !r.perms.contains(Perms::EXECUTE) && r.va.contains(last))
}

/// Gives the pointer candidates of one section: arrays always, tables in a file at a fixed
/// address. A table slot skips each place of `relocated`.
fn section_slots(
    program: &Program,
    va: Range,
    array: bool,
    relocated: &BTreeSet<u64>,
    out: &mut BTreeMap<u64, Slot>,
) {
    let len = u64::try_from(va.len())
        .unwrap_or(u64::MAX)
        .min(MAX_TABLE_BYTES);
    let Ok(bytes) = program.mem().read(va.first, len, &Limits::DEFAULT) else {
        return;
    };
    let skip = usize::try_from(va.first.wrapping_neg() & 7).unwrap_or(0);
    let mut run: Vec<(u64, u64)> = Vec::new();
    for (chunk, i) in bytes
        .get(skip..)
        .unwrap_or_default()
        .chunks_exact(8)
        .zip(0u64..)
    {
        let Some(at) = u64::try_from(skip)
            .ok()
            .and_then(|s| va.first.checked_add(s)?.checked_add(i.checked_mul(8)?))
        else {
            break;
        };
        let word: [u8; 8] = chunk.try_into().unwrap_or_default();
        let to = u64::from_le_bytes(word);
        let place = relocated.range(at..at.saturating_add(8)).next().is_some();
        let pointer = (array || to >= MIN_IMM) && is_mapped(program, to);
        if place || !pointer {
            flush(array, &mut run, out);
        } else {
            run.push((at, to));
        }
    }
    flush(array, &mut run, out);
}

/// Moves the pointers of `run` into `out` when they form an array or a table.
fn flush(array: bool, run: &mut Vec<(u64, u64)>, out: &mut BTreeMap<u64, Slot>) {
    if array || u64::try_from(run.len()).unwrap_or(0) >= MIN_TABLE {
        for (at, to) in run.iter().copied() {
            out.entry(at).or_insert_with(|| Slot {
                to: Address::ram(to),
                why: Why::bare(Rule::AddrTable),
            });
        }
    }
    run.clear();
}

/// Gives the pointer slots of `program` by address.
#[must_use]
pub fn slots(program: &Program) -> BTreeMap<u64, Slot> {
    let mut found: BTreeMap<u64, Slot> = BTreeMap::new();
    let b = program.binary();
    if !b.arch.is_x86_64() {
        return found;
    }
    let names = Names::of(program);
    let mut relocated = BTreeSet::new();
    for r in &b.relocs {
        if !relocated.insert(r.offset) {
            continue;
        }
        if let Some(to) = names.target(program, r) {
            let why = Why::new(Rule::RelocPtr, vec![FactKey::Reloc(r.offset)]);
            found.insert(r.offset, Slot { to, why });
        }
    }
    let tables = program.meta().kind == Kind::Exec;
    for s in &b.sections {
        let (Some(va), SectionKind::Elf(kind)) = (s.va, s.kind) else {
            continue;
        };
        let array = SHT_ARRAYS.contains(&kind);
        let skipped = s.name.as_str().is_some_and(|n| NO_TABLES.contains(&n));
        let table = tables && kind == SHT_PROGBITS && !skipped;
        if s.flags & SHF_EXECINSTR == 0 && (array || table) {
            section_slots(program, va, array, &relocated, &mut found);
        }
    }
    let mut out = BTreeMap::new();
    let mut free = 0u64;
    for (at, slot) in found {
        if at >= free && slot_place(program, at) {
            free = at.saturating_add(u64::from(SLOT_SIZE));
            out.insert(at, slot);
        }
    }
    out
}

/// Gives the addresses outside executable memory.
fn data_space(program: &Program) -> RangeSet {
    let mut out = RangeSet::new();
    for r in program.mem().regions() {
        if !r.perms.contains(Perms::EXECUTE) {
            out.insert(r.va);
        }
    }
    out
}

/// Runs one step over `ranges`: the operand references of the code units in the ranges and the
/// pointer slots in the ranges.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    let mut fresh = BTreeMap::new();
    for r in ranges.ranges() {
        for at in ctx.work.units.range(r.first..=r.last).map(|(at, _)| *at) {
            work = work.saturating_add(1);
            let Some(insn) = decode_at(program, at) else {
                continue;
            };
            for (op_index, to, kind) in operand_refs(program, &insn) {
                let key = RefKey {
                    from: Address::ram(at),
                    op_index,
                    to,
                    kind,
                };
                fresh.insert(key, Why::new(Rule::OperandRef, vec![FactKey::CodeUnit(at)]));
            }
        }
    }
    let data = &mut ctx.work.data;
    let old: BTreeMap<RefKey, Why> = data
        .operands
        .iter()
        .filter(|(k, _)| ranges.contains(k.from.off))
        .map(|(k, w)| (*k, w.clone()))
        .collect();
    let mut changed = old != fresh;
    if changed {
        data.operands.retain(|k, _| !ranges.contains(k.from.off));
        data.operands.extend(fresh);
    }
    let mut moved = RangeSet::new();
    if !ranges.intersect(&data_space(program)).is_empty() {
        let all = slots(program);
        work = work.saturating_add(u64::try_from(all.len()).unwrap_or(u64::MAX));
        let fresh: BTreeMap<u64, Slot> = all
            .into_iter()
            .filter(|(at, _)| ranges.contains(*at))
            .collect();
        let data = &mut ctx.work.data;
        let old: BTreeMap<u64, Slot> = data
            .slots
            .iter()
            .filter(|(at, _)| ranges.contains(**at))
            .map(|(at, s)| (*at, s.clone()))
            .collect();
        if old != fresh {
            for at in old.keys().chain(fresh.keys()) {
                if let Some(r) = Range::with_len(*at, u64::from(SLOT_SIZE)) {
                    moved.insert(r);
                }
            }
            data.slots.retain(|at, _| !ranges.contains(*at));
            data.slots.extend(fresh);
            changed = true;
        }
    }
    if changed {
        ctx.touch();
        ctx.emit(Trigger::Data, moved);
        ctx.requeue(AnalyzerId::Strings, ALL);
    }
    Step { work }
}

/// Gives the ID of the `void *` type, or of `unsigned long` when the store has no such type.
fn ptr_type(program: &Program) -> TypeId {
    let store = program.types().store();
    let void = store.prim(Prim::Void);
    store
        .ids()
        .find(|id| store.get(*id) == Some(&Type::Ptr(void)))
        .unwrap_or_else(|| store.prim(Prim::ULong))
}

/// Adds the data references of `work` to the facts of a publish step. An operand reference
/// needs a code unit of a function in `kept`. Gives the data rows of the slots.
pub(crate) fn collect(
    program: &Program,
    work: &Work,
    kept: &BTreeSet<u64>,
    refs: &mut Vec<Ref>,
    whys: &mut BTreeMap<FactKey, Why>,
) -> Vec<Value> {
    for (key, why) in &work.data.operands {
        let owner = work.units.get(&key.from.off).map(|u| u.owner);
        if owner.is_some_and(|o| kept.contains(&o)) {
            refs.push(Ref {
                key: *key,
                primary: true,
            });
            whys.insert(FactKey::Ref(*key), why.clone());
        }
    }
    let origin = Origin::analysis();
    let def = DataDef {
        ty: ptr_type(program),
        len: SLOT_SIZE,
    };
    let mut rows = Vec::with_capacity(work.data.slots.len());
    for (at, slot) in &work.data.slots {
        let addr = Address::ram(*at);
        let edit = Edit::SetDataDef {
            at: addr,
            def: Some(origin.fact(def)),
        };
        let fact = edit_to_json(&edit).get("def").cloned().unwrap_or_default();
        rows.push(Value::object([
            ("at", Value::from(addr.to_string())),
            ("def", fact),
        ]));
        whys.insert(FactKey::Data(*at), slot.why.clone());
        let key = slot.key(*at);
        refs.push(Ref { key, primary: true });
        whys.insert(
            FactKey::Ref(key),
            Why::new(slot.why.rule, vec![FactKey::Data(*at)]),
        );
    }
    rows
}
