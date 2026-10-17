//! `AddrTakenSeeds` (band 460): seed 12 of design Section 7.3, address-taken code.
//!
//! An instruction of a body takes the address of code in two forms:
//!
//! | Instruction | Taken address | File |
//! |---|---|---|
//! | `lea` with a RIP-relative memory operand | the operand address | every file |
//! | `mov` with a 32-bit immediate | the immediate | a file at a fixed address (`ET_EXEC`) |
//!
//! An address in an executable region is a target. [`super::dataptr`] gives the tests of each
//! target. A target that passes them starts a function with the reason `AddrTaken`, confidence
//! [`CONFIDENCE`] and `R_ADDR_TAKEN`. The premise is the code unit of the first site.
//!
//! A step decodes the code units in its ranges again. Then every target gets the tests again,
//! and an `AddrTaken` reason that fails a test goes.

use std::collections::BTreeMap;

use ghidorah_db::{FactKey, Program, StartReason};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Kind;
use ghidorah_x86::{Insn, Mem, Mnem, Operand};

use crate::analyzers::dataptr::{case_targets, seed, start_at};
use crate::code::{decode_at, is_exec};
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The confidence of an `AddrTaken` start.
pub const CONFIDENCE: u8 = 75;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::AddrTakenSeeds,
    name: "AddrTakenSeeds",
    priority: 460,
    triggers: &[Trigger::Bytes, Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each address-taken code target that no body holds.",
};

/// Gives the value of a 32-bit immediate operand of `insn`: an immediate of 4 bytes, or of
/// 8 bytes that the encoding sign-extends from 4.
fn imm32(insn: &Insn) -> Option<u64> {
    (0..usize::from(insn.n_ops())).find_map(|i| match insn.op(i) {
        Some(Operand::Imm {
            value,
            width,
            signed,
        }) if width == 4 || (width == 8 && signed) => u64::try_from(value).ok(),
        _ => None,
    })
}

/// Gives the code address that `insn` takes, or `None`. The address is in an executable
/// region of `program`.
#[must_use]
pub fn taken(program: &Program, insn: &Insn) -> Option<u64> {
    let target = match insn.mnem() {
        Mnem::Lea => insn
            .mem()
            .filter(Mem::is_rip_relative)
            .and_then(|m| m.abs_target),
        Mnem::Mov if program.meta().kind == Kind::Exec => imm32(insn),
        _ => None,
    }?;
    is_exec(program, target).then_some(target)
}

/// Runs one step: the sites of the code units in `ranges`, then the tests of every target.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    let mut sites = std::mem::take(&mut ctx.work.codeptrs.sites);
    for r in ranges.ranges() {
        let stale: Vec<u64> = sites.range(r.first..=r.last).map(|(at, _)| *at).collect();
        for at in stale {
            sites.remove(&at);
        }
        for at in ctx.work.units.range(r.first..=r.last).map(|(at, _)| *at) {
            work = work.saturating_add(1);
            if let Some(target) = decode_at(program, at).and_then(|i| taken(program, &i)) {
                sites.insert(at, target);
            }
        }
    }
    let mut first: BTreeMap<u64, u64> = BTreeMap::new();
    for (site, target) in &sites {
        first.entry(*target).or_insert(*site);
    }
    ctx.work.codeptrs.sites = sites;
    let cases = case_targets(ctx);
    let mut want = BTreeMap::new();
    for (target, site) in first {
        work = work.saturating_add(1);
        if let Some(at) = start_at(ctx, &cases, target) {
            want.entry(at)
                .or_insert_with(|| Why::new(Rule::AddrTaken, vec![FactKey::CodeUnit(site)]));
        }
    }
    seed(ctx, StartReason::AddrTaken, CONFIDENCE, want);
    Step { work }
}
