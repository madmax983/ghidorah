//! `CallingConvention` (band 800): parameter recovery and the varargs flag (design Section
//! 7.10).
//!
//! [`recover`] finds the live-in registers of the L0 body: a register that a path reads before
//! a write. A `xor r, r` or `sub r, r` reads no register. A call writes the registers that the
//! callee does not keep, so a read after a call is not a live-in read.
//!
//! - The parameters are the argument registers among the live-in registers, filled up to the
//!   highest one. The integer and the floating registers count apart.
//! - A store of a callee-saved register to the frame, as a push does, is not a read. A `Put`
//!   of `Stack(k)` after the frame rewrite is such a store.
//! - A read of the frame slot `k` at the first stack-parameter offset or above adds the stack
//!   parameters up to `k`.
//! - Varargs: a `test al, al` prologue, or the integer save area: 64-bit stores of the last
//!   argument registers, `r9` included, to slots that go up by 8 in register order. The
//!   registers of the save area are not named parameters.
//!
//! [`params`] gives the parameters of a function: an agent signature first, then the Tier-0
//! prototype of its name, then [`recover`]. ELF binaries use [`SYSV_X86_64`].

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId};
use ghidorah_db::{Program, Types};
use ghidorah_ir::{Arena, Arg, Loc, Node, Op, Opc, Val, local, rpo};
use ghidorah_kernel::RangeSet;
use ghidorah_types::cc::SYSV_X86_64;
use ghidorah_types::{CallConv, Sig};

use crate::ctx::AnalysisCtx;
use crate::fir::{self, FirError, FuncIr, Opts};
use crate::irfacts::work_ir;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// Gives the spec of `CallingConvention` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "CallingConvention",
        priority: 800,
        triggers: &[Trigger::Instructions, Trigger::Signatures],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Recovers the parameters and the varargs flag of each function.",
    }
}

/// The parameters of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Params {
    /// The integer and pointer parameters in registers.
    pub int: u8,
    /// The floating parameters in registers.
    pub float: u8,
    /// The parameters on the stack.
    pub stack: u8,
    /// The function takes a variable argument list.
    pub varargs: bool,
}

impl Params {
    /// Gives the count of the named parameters.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.int as u32 + self.float as u32 + self.stack as u32
    }
}

/// Where the parameters of [`params`] come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamSource {
    /// The signature fact of the function.
    Signature,
    /// The Tier-0 prototype of the name of the function.
    Prototype,
    /// The recovery from the body.
    Recovered,
}

/// Gives the calling convention of the binary format of `program`.
#[must_use]
pub const fn conv_of(program: &Program) -> &'static CallConv {
    let _ = program;
    &SYSV_X86_64
}

/// Gives the location of a register name of a convention table, for example `rdi` or `xmm2`.
#[must_use]
pub fn loc_of(name: &str) -> Option<Loc> {
    const GPRS: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    if let Some(n) = GPRS.iter().position(|g| *g == name) {
        return Loc::gpr(u8::try_from(n).ok()?);
    }
    if name == "al" {
        return Some(Loc::RAX);
    }
    let n: u8 = name.strip_prefix("xmm")?.parse().ok()?;
    Loc::xmm(n)
}

/// The registers that a call writes: the caller-saved general registers and every XMM
/// register of the `SysV` table.
fn call_defs() -> BTreeSet<Loc> {
    let mut out: BTreeSet<Loc> = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
        .iter()
        .filter_map(|n| loc_of(n))
        .collect();
    out.extend((0..16u8).filter_map(Loc::xmm));
    out
}

/// The live-in reads and the writes of one block.
#[derive(Debug, Default)]
struct BlockUse {
    uses: BTreeSet<Loc>,
    defs: BTreeSet<Loc>,
}

/// The use step over the ops of one block.
struct Uses<'a> {
    arena: &'a Arena,
    saved: BTreeSet<Loc>,
    src: BTreeMap<Val, BTreeSet<Loc>>,
    out: BlockUse,
}

impl Uses<'_> {
    /// Gives the live-in registers of an argument.
    fn src_of(&self, a: Arg) -> BTreeSet<Loc> {
        a.as_v()
            .and_then(|v| self.src.get(&v).cloned())
            .unwrap_or_default()
    }

    /// Records the reads of an argument.
    fn read(&mut self, a: Arg) {
        let regs = self.src_of(a);
        self.out.uses.extend(regs);
    }

    /// Records the reads of a value that goes to the frame. The store of one callee-saved
    /// register, as a push does, is not a read.
    fn save(&mut self, a: Arg) {
        let regs = self.src_of(a);
        let push = regs.len() == 1 && regs.iter().all(|l| self.saved.contains(l));
        if !push {
            self.out.uses.extend(regs);
        }
    }

    /// Runs one op.
    fn op(&mut self, op: &Op, call_defs: &BTreeSet<Loc>) {
        let pass = |s: &mut Self, from: Arg| {
            if let Some(out) = op.out {
                let regs = s.src_of(from);
                s.src.insert(out, regs);
            }
        };
        match op.opc {
            Opc::Get => {
                if let (Some(out), Some(loc)) = (op.out, op.a[0].as_loc()) {
                    let live = loc.is_gpr() || loc.is_xmm();
                    let regs = if live && !self.out.defs.contains(&loc) {
                        BTreeSet::from([loc])
                    } else {
                        BTreeSet::new()
                    };
                    self.src.insert(out, regs);
                }
            }
            Opc::Trunc | Opc::ZExt | Opc::SExt | Opc::Copy | Opc::Extract => pass(self, op.a[0]),
            Opc::Xor | Opc::Sub if local::same_value(self.arena, op.a[0], op.a[1]) => {
                if let Some(out) = op.out {
                    self.src.insert(out, BTreeSet::new());
                }
            }
            Opc::Put => {
                let dst = op.a[0].as_loc();
                if matches!(dst, Some(Loc::Stack(_))) {
                    self.save(op.a[1]);
                } else {
                    self.read(op.a[1]);
                }
                if let Some(loc) = dst.filter(|l| l.is_gpr() || l.is_xmm()) {
                    self.out.defs.insert(loc);
                }
            }
            Opc::Store => {
                self.read(op.a[0]);
                self.save(op.a[1]);
            }
            Opc::Call | Opc::CallInd => {
                self.read(op.a[0]);
                self.out.defs.extend(call_defs.iter().copied());
            }
            Opc::Syscall | Opc::Intrinsic => {
                self.read(op.a[1]);
                if let Some(e) = self.arena.effect(op) {
                    for loc in e.uses.iter().filter(|l| l.is_gpr() || l.is_xmm()) {
                        if !self.out.defs.contains(&loc) {
                            self.out.uses.insert(loc);
                        }
                    }
                    self.out
                        .defs
                        .extend(e.defs.iter().filter(|l| l.is_gpr() || l.is_xmm()));
                }
            }
            _ => {
                for a in op.a {
                    self.read(a);
                }
            }
        }
    }
}

/// Gives the live-in registers of the entry block of `fir`. With `any_push`, the push of any
/// one register is not a read. Else only the push of a callee-saved register is not a read.
fn live_in(fir: &FuncIr, conv: &CallConv, any_push: bool) -> BTreeSet<Loc> {
    let saved: BTreeSet<Loc> = if any_push {
        (0..16u8).filter_map(Loc::gpr).collect()
    } else {
        conv.callee_saved.iter().filter_map(|n| loc_of(n)).collect()
    };
    let defs = call_defs();
    let mut blocks: Vec<BlockUse> = Vec::new();
    for b in &fir.body.blocks {
        let mut step = Uses {
            arena: &fir.arena,
            saved: saved.clone(),
            src: BTreeMap::new(),
            out: BlockUse::default(),
        };
        let first = usize::try_from(b.first).unwrap_or(usize::MAX);
        let count = usize::try_from(b.count).unwrap_or(0);
        for span in fir.arena.insns().iter().skip(first).take(count) {
            for op in fir.arena.span_ops(span).unwrap_or_default() {
                step.op(op, &defs);
            }
        }
        blocks.push(step.out);
    }
    let order: Vec<Node> = rpo(&fir.body.cfg).into_iter().rev().collect();
    let mut live: BTreeMap<Node, BTreeSet<Loc>> = BTreeMap::new();
    let rounds = order.len().saturating_mul(4).saturating_add(8);
    for _ in 0..rounds {
        let mut changed = false;
        for node in &order {
            let Some(b) = blocks.get(node.index()) else {
                continue;
            };
            let mut set: BTreeSet<Loc> = BTreeSet::new();
            for s in fir.body.cfg.succs(*node) {
                set.extend(live.get(s).into_iter().flatten().copied());
            }
            set.retain(|l| !b.defs.contains(l));
            set.extend(b.uses.iter().copied());
            if live.get(node) != Some(&set) {
                live.insert(*node, set);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    live.remove(&fir.body.cfg.entry()).unwrap_or_default()
}

/// Tells if the code at the entry of `fir` obeys `conv` (the FETCH rule of design Section 7.3).
///
/// Each live-in register must be an argument register of `conv` or the stack pointer. A push
/// of one register is not a read, because compilers push a scratch register to align the stack.
#[must_use]
pub fn obeys(fir: &FuncIr, conv: &CallConv) -> bool {
    let mut allowed: BTreeSet<Loc> = conv
        .int_args
        .iter()
        .chain(conv.float_args.iter())
        .filter_map(|n| loc_of(n))
        .collect();
    allowed.extend(loc_of("rsp"));
    live_in(fir, conv, true).iter().all(|l| allowed.contains(l))
}

/// Gives the count of the registers of `names` up to the highest one in `live`.
fn filled(names: &[&str], live: &BTreeSet<Loc>) -> u8 {
    let top = names
        .iter()
        .rposition(|n| loc_of(n).is_some_and(|l| live.contains(&l)));
    top.map_or(0, |i| u8::try_from(i.saturating_add(1)).unwrap_or(u8::MAX))
}

/// Gives the ops of the entry block of `fir` with their arena indexes.
fn entry_ops(fir: &FuncIr) -> Vec<(u32, Op)> {
    let mut out = Vec::new();
    let Some(b) = fir.body.blocks.get(fir.body.cfg.entry().index()) else {
        return out;
    };
    let first = usize::try_from(b.first).unwrap_or(usize::MAX);
    let count = usize::try_from(b.count).unwrap_or(0);
    for span in fir.arena.insns().iter().skip(first).take(count) {
        for k in 0..span.count {
            if let Some(i) = span.first.checked_add(k)
                && let Some(op) = fir.arena.op(i)
            {
                out.push((i, *op));
            }
        }
    }
    out
}

/// Gives the register of the `Get` that defines `a`, for a full-width read.
fn get_reg(arena: &Arena, a: Arg) -> Option<Loc> {
    let op = arena.op(arena.def_of(a.as_v()?)?)?;
    (op.opc == Opc::Get).then(|| op.a[0].as_loc()).flatten()
}

/// Tells if the entry block tests `al`: the guard of the XMM save area of a varargs function.
fn tests_al(fir: &FuncIr) -> bool {
    let arena = &fir.arena;
    let is_al = |a: Arg| {
        a.as_v()
            .and_then(|v| arena.def_of(v))
            .and_then(|d| arena.op(d))
            .is_some_and(|t| {
                t.opc == Opc::Trunc && t.w == 8 && get_reg(arena, t.a[0]) == Some(Loc::RAX)
            })
    };
    entry_ops(fir).iter().any(|(_, op)| {
        let test = matches!(op.opc, Opc::TestZ | Opc::TestNZ)
            || op.flag_op() == Some(ghidorah_ir::FlagOp::X86Logic);
        test && is_al(op.a[0]) && is_al(op.a[1])
    })
}

/// Gives the first register of the integer save area of a varargs function. The save area
/// stores the last argument registers in register order to 64-bit slots that go up by 8.
fn save_area(fir: &FuncIr, conv: &CallConv) -> Option<u8> {
    let frame = fir.frame.as_ref()?;
    let mut slots: BTreeMap<usize, i64> = BTreeMap::new();
    for (i, op) in entry_ops(fir) {
        let Some(access) = frame.access.get(&i) else {
            continue;
        };
        if !matches!(op.opc, Opc::Store | Opc::Put) || access.size != 8 {
            continue;
        }
        let Some(reg) = get_reg(&fir.arena, op.a[1]) else {
            continue;
        };
        if let Some(n) = conv.int_args.iter().position(|a| loc_of(a) == Some(reg)) {
            slots.entry(n).or_insert(access.off);
        }
    }
    let last = conv.int_args.len().checked_sub(1)?;
    let mut first = last;
    let mut off = *slots.get(&last)?;
    while let Some(prev) = first.checked_sub(1)
        && slots.get(&prev) == Some(&off.checked_sub(8)?)
    {
        first = prev;
        off = off.checked_sub(8)?;
    }
    (first < last).then(|| u8::try_from(first).unwrap_or(u8::MAX))
}

/// Recovers the parameters of `fir` by the rules of the module doc.
#[must_use]
pub fn recover(fir: &FuncIr, conv: &CallConv) -> Params {
    let live = live_in(fir, conv, false);
    let first = i64::from(conv.stack_arg_offset);
    let stack = fir
        .frame
        .as_ref()
        .and_then(|f| f.stack_args(first).into_iter().next_back())
        .map_or(0, |k| {
            let n = k.saturating_sub(first) / 8 + 1;
            u8::try_from(n).unwrap_or(u8::MAX)
        });
    let area = save_area(fir, conv);
    let al = tests_al(fir);
    let varargs = area.is_some() || al;
    let int = area.unwrap_or_else(|| filled(conv.int_args, &live));
    let float = if varargs {
        0
    } else {
        filled(conv.float_args, &live)
    };
    Params {
        int,
        float,
        stack,
        varargs,
    }
}

/// Gives the parameters of a signature.
fn from_sig(sig: &Sig) -> Params {
    Params {
        int: u8::try_from(sig.params.len()).unwrap_or(u8::MAX),
        float: 0,
        stack: 0,
        varargs: sig.variadic,
    }
}

/// Gives the parameters of the published function `id` and their source.
///
/// # Errors
///
/// Returns [`FirError::NoFunc`] when no function starts at `id`, and the [`FirError`] of the
/// function IR when the recovery needs it.
pub fn params(
    program: &Program,
    id: FuncId,
    fuel: &mut Fuel,
) -> Result<(Params, ParamSource), FirError> {
    let view = program.func(id).ok_or(FirError::NoFunc(id))?;
    if let Some(sig) = view.sig.and_then(|s| program.types().sig(s.value)) {
        return Ok((from_sig(sig), ParamSource::Signature));
    }
    if let Some(proto) = program
        .name(id.0)
        .filter(|n| !n.is_default())
        .and_then(|n| Types::prototype(&n.text))
    {
        return Ok((from_sig(&proto.sig), ParamSource::Prototype));
    }
    let ir = fir::build(program, id, &Opts::DEFAULT, fuel)?;
    Ok((recover(&ir, conv_of(program)), ParamSource::Recovered))
}

/// Gives the varargs flag that a base fact sets for the function `entry`: its agent
/// signature, then the Tier-0 prototype of its base symbol name.
fn known_varargs(program: &Program, entry: u64) -> Option<bool> {
    let addr = Address::ram(entry);
    if let Some(sig) = program
        .base()
        .funcs()
        .get(FuncId(addr))
        .and_then(|f| f.sig.as_ref())
        .and_then(|s| program.types().sig(s.value))
    {
        return Some(sig.variadic);
    }
    let name = program.base().symbols().primary(addr)?;
    Types::prototype(&name.name.value).map(|p| p.sig.variadic)
}

/// The fuel of one function IR of the analyzer.
const IR_FUEL: u64 = 1_000_000;

/// Runs one step over `ranges`: each function that the ranges touch gets its varargs flag
/// again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let conv = conv_of(program);
    let mut work = 1u64;
    for entry in ctx.touching(ranges) {
        work = work.saturating_add(1);
        let varargs = match known_varargs(program, entry) {
            Some(v) => v,
            None => match work_ir(ctx, entry, &mut Fuel::new(IR_FUEL)) {
                Ok(ir) => {
                    work = work.saturating_add(u64::try_from(ir.units.len()).unwrap_or(0));
                    recover(&ir, conv).varargs
                }
                Err(_) => false,
            },
        };
        if ctx.ir().varargs.contains(&entry) != varargs {
            let ir = ctx.ir_mut();
            if varargs {
                ir.varargs.insert(entry);
            } else {
                ir.varargs.remove(&entry);
            }
        }
    }
    let gone: Vec<u64> = ctx
        .ir()
        .varargs
        .iter()
        .copied()
        .filter(|e| !ctx.is_entry(*e))
        .collect();
    if !gone.is_empty() {
        let ir = ctx.ir_mut();
        for e in gone {
            ir.varargs.remove(&e);
        }
    }
    Step { work }
}
