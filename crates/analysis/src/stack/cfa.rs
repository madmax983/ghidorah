//! The CFA cross-check and the `StackFrames` analyzer (band 700, design Section 7.9).
//!
//! [`cfa_check`] compares the tracked offset at each call site with the CFA row of the FDE
//! (AC-091). A known offset that differs is a [`Mismatch`].

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::Fuel;
use ghidorah_db::FlowKind;
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Fde;

use super::{DWARF_RBP, DWARF_RSP, Frame};
use crate::ctx::AnalysisCtx;
use crate::irfacts::work_ir;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// Gives the CFA row of `fde` that holds `pc`: the DWARF register and the needed offset of
/// that register from `SP0`.
#[must_use]
pub fn cfa_rule(fde: &Fde, pc: u64) -> Option<(u16, i64)> {
    let row = fde.cfa_rows.iter().rfind(|r| r.pc <= pc)?;
    Some((row.reg, 8i64.checked_sub(row.offset)?))
}

/// Compares the tracked offset at each call site of `calls` with the CFA rows of `fde`.
#[must_use]
pub fn cfa_check(frame: &Frame, fde: &Fde, calls: &[u64]) -> Vec<Mismatch> {
    let mut out = Vec::new();
    for site in calls {
        let Some((reg, cfa)) = cfa_rule(fde, *site) else {
            continue;
        };
        let tracked = match reg {
            DWARF_RSP => frame.sp.get(site),
            DWARF_RBP => frame.bp.get(site),
            _ => continue,
        }
        .and_then(|s| s.offset());
        if let Some(t) = tracked
            && t != cfa
        {
            out.push(Mismatch {
                site: *site,
                tracked: t,
                cfa,
            });
        }
    }
    out
}

/// One call site where the tracked offset differs from the CFA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mismatch {
    /// The call site.
    pub site: u64,
    /// The tracked offset.
    pub tracked: i64,
    /// The offset that the CFA row gives.
    pub cfa: i64,
}

/// Gives the spec of `StackFrames` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "StackFrames",
        priority: 700,
        triggers: &[Trigger::Instructions],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Tracks the stack of each function and compares it with the CFA rows.",
    }
}

/// The fuel of one function IR of the analyzer.
const IR_FUEL: u64 = 1_000_000;

/// Gives the FDE that holds `site`, by the FDE starts in `starts`.
fn fde_at<'a>(fdes: &'a [Fde], starts: &BTreeMap<u64, usize>, site: u64) -> Option<&'a Fde> {
    let (_, i) = starts.range(..=site).next_back()?;
    fdes.get(*i).filter(|f| f.range.contains(site))
}

/// Runs one step over `ranges`: each function that the ranges touch gets its CFA
/// cross-check again. A site with a mismatch gives `W_SP_MISMATCH`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let fdes = &program.binary().fdes;
    let starts: BTreeMap<u64, usize> = fdes
        .iter()
        .enumerate()
        .map(|(i, f)| (f.range.first, i))
        .collect();
    let mut work = 1u64;
    for entry in ctx.touching(ranges) {
        work = work.saturating_add(1);
        let units = ctx.units_of(entry);
        let calls: Vec<u64> = units
            .iter()
            .filter(|(_, u)| matches!(u.flow, FlowKind::Call | FlowKind::ICall))
            .map(|(at, _)| *at)
            .collect();
        let mut sites = BTreeSet::new();
        if calls.iter().any(|c| fde_at(fdes, &starts, *c).is_some())
            && let Ok(ir) = work_ir(ctx, entry, &mut Fuel::new(IR_FUEL))
            && let Some(frame) = &ir.frame
        {
            work = work.saturating_add(u64::try_from(ir.units.len()).unwrap_or(0));
            for c in &calls {
                if let Some(fde) = fde_at(fdes, &starts, *c) {
                    sites.extend(cfa_check(frame, fde, &[*c]).into_iter().map(|m| m.site));
                }
            }
        }
        let old = ctx.ir().mismatches.get(&entry).cloned().unwrap_or_default();
        if old != sites {
            let ir = ctx.ir_mut();
            if sites.is_empty() {
                ir.mismatches.remove(&entry);
            } else {
                ir.mismatches.insert(entry, sites);
            }
        }
    }
    Step { work }
}
