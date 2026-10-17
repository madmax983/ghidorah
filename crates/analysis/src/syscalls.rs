//! `Syscalls` (band 810): Linux syscall sites (design Section 7.11). ELF only.
//!
//! Block-local evaluation gives `rax` at each `Syscall` op. The x86-64 table of
//! `ghidorah-types` gives the name. The arguments come from `rdi rsi rdx r10 r8 r9`. The
//! argument count is the parameter count of the Tier-0 prototype with the syscall name, else
//! six. Each site gets the `EOL` note `sys:<name>`, or `sys:<number>` for a number with no
//! name, with `R_SYSCALL_NUMBER`. [`sites`] gives the sites of a program on demand.

use std::collections::BTreeMap;

use ghidorah_base::{Fuel, FuncId, Limits, SyscallId};
use ghidorah_db::{FactKey, Program, Types};
use ghidorah_ir::{Loc, Opc, local};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Format;
use ghidorah_types::syscalls::ARG_REGS;

use crate::callargs::ArgValue;
use crate::ctx::AnalysisCtx;
use crate::fir::{FuncIr, Image, Opts};
use crate::irfacts::{SysRec, work_ir};
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The largest number of syscall arguments.
pub const MAX_ARGS: usize = 6;

/// Gives the spec of `Syscalls` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "Syscalls",
        priority: 810,
        triggers: &[Trigger::Instructions],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Names the syscall sites from the value of rax.",
    }
}

/// One syscall site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Site {
    /// The address of the `syscall` instruction.
    pub site: u64,
    /// The function of the site.
    pub func: FuncId,
    /// The value of `rax`, or `None` for an unknown value.
    pub nr: Option<u64>,
    /// The name of the number in the syscall table.
    pub name: Option<&'static str>,
    /// The argument values.
    pub args: Vec<ArgValue>,
}

impl Site {
    /// Gives the `sys:` ID: the name, else the number.
    #[must_use]
    pub fn id(&self) -> Option<SyscallId> {
        if let Some(id) = self.name.and_then(|n| SyscallId::by_name(n).ok()) {
            return Some(id);
        }
        let nr = u16::try_from(self.nr?).ok()?;
        Some(SyscallId::by_number(nr))
    }

    /// Gives the text of the site note: `sys:<name>` or `sys:<number>`.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        self.id().map(|id| id.to_string())
    }
}

/// One `syscall` op of a function IR: the site, the op index and the value of `rax`.
struct Number {
    site: u64,
    op: u32,
    nr: Option<u64>,
}

/// Gives the `syscall` ops of `fir` with the value of `rax` before each one.
fn numbers(program: &Program, fir: &FuncIr, fuel: &mut Fuel) -> Vec<Number> {
    let image = Image(program);
    let scope = fir.scope(&image);
    fir.units
        .keys()
        .filter_map(|at| {
            let op = fir.find_op(*at, Opc::Syscall)?;
            let nr = local::value_at(&scope, op, Loc::RAX, fuel).value();
            Some(Number { site: *at, op, nr })
        })
        .collect()
}

/// Gives the name of a syscall number in the x86-64 table.
fn name_of(nr: Option<u64>) -> Option<&'static str> {
    ghidorah_types::syscalls::x86_64().ok()?.name(nr?)
}

/// Gives the argument registers of a syscall: the parameter count of the Tier-0 prototype of
/// its name, else six.
fn arg_regs(name: Option<&str>) -> Vec<Loc> {
    let count = name
        .and_then(Types::prototype)
        .map_or(MAX_ARGS, |p| p.sig.params.len().min(MAX_ARGS));
    ARG_REGS
        .iter()
        .take(count)
        .filter_map(|n| crate::cc::loc_of(n))
        .collect()
}

/// Gives the syscall sites of `fir` in address order.
#[must_use]
pub fn of_fir(program: &Program, fir: &FuncIr, fuel: &mut Fuel) -> Vec<Site> {
    numbers(program, fir, fuel)
        .into_iter()
        .map(|n| {
            let name = name_of(n.nr);
            let args = crate::callargs::values(program, fir, n.op, &arg_regs(name), fuel);
            Site {
                site: n.site,
                func: fir.func,
                nr: n.nr,
                name,
                args,
            }
        })
        .collect()
}

/// The bytes of the `syscall` instruction.
const SYSCALL: [u8; 2] = [0x0f, 0x05];

/// Tells if a code unit holds a `syscall` instruction.
fn is_syscall(program: &Program, at: u64, len: u8) -> bool {
    len == 2
        && program
            .mem()
            .read(at, 2, &Limits::DEFAULT)
            .is_ok_and(|b| b.as_ref() == SYSCALL)
}

/// Gives the syscall sites of every published function of `program` in address order. A
/// format other than ELF has none.
#[must_use]
pub fn sites(program: &Program, fuel: &mut Fuel) -> Vec<Site> {
    if program.meta().format != Format::Elf64Le {
        return Vec::new();
    }
    let mut out = Vec::new();
    for view in program.funcs() {
        let Some(units) = crate::fir::units_of(program, view.id()) else {
            continue;
        };
        if !units.iter().any(|(at, u)| is_syscall(program, *at, u.len)) {
            continue;
        }
        if let Ok(ir) = crate::fir::build(program, view.id(), &Opts::DEFAULT, fuel) {
            out.extend(of_fir(program, &ir, fuel));
        }
    }
    out.sort();
    out
}

/// The fuel of one function IR of the analyzer.
const IR_FUEL: u64 = 1_000_000;

/// Runs one step over `ranges`: each function that the ranges touch gets its site notes
/// again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if program.meta().format != Format::Elf64Le || !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    for entry in ctx.touching(ranges) {
        work = work.saturating_add(1);
        let units = ctx.units_of(entry);
        let mut notes = BTreeMap::new();
        if units.iter().any(|(at, u)| is_syscall(program, *at, u.len))
            && let Ok(ir) = work_ir(ctx, entry, &mut Fuel::new(IR_FUEL))
        {
            for n in numbers(program, &ir, &mut Fuel::new(IR_FUEL)) {
                let site = Site {
                    site: n.site,
                    func: ir.func,
                    nr: n.nr,
                    name: name_of(n.nr),
                    args: Vec::new(),
                };
                if let Some(text) = site.note() {
                    let why = Why::new(Rule::SyscallNumber, vec![FactKey::CodeUnit(n.site)]);
                    notes.insert(
                        n.site,
                        SysRec {
                            owner: entry,
                            text,
                            why,
                        },
                    );
                }
            }
        }
        let old: BTreeMap<u64, SysRec> = ctx
            .ir()
            .syscalls
            .iter()
            .filter(|(_, r)| r.owner == entry)
            .map(|(s, r)| (*s, r.clone()))
            .collect();
        if old != notes {
            let ir = ctx.ir_mut();
            ir.syscalls.retain(|_, r| r.owner != entry);
            ir.syscalls.extend(notes);
        }
    }
    Step { work }
}
