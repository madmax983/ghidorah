//! Lift coverage of the T1 fixtures (AC-071).
//!
//! Each instruction of the objdump listing of a T1 fixture lifts. No instruction lifts to
//! `Unimpl`. A template lift has no `Intrinsic` op. Each other instruction lifts to one
//! `Intrinsic` or `Syscall` op whose effect holds the registers and flags of the decoder.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_ir::{Arena, Builder, Loc, LocSet, Opc};
use ghidorah_x86::lift::{self, LiftKind};
use ghidorah_x86::{Insn, RegSet, lift as lift_insn};

use crate::common::{fixture_bytes, listings, root, section_code};
use crate::json;

/// Gives the names of the T1 fixtures from `fixtures/manifest.json`.
pub fn t1_fixtures() -> BTreeSet<String> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    json::parse(&text)
        .get("fixtures")
        .arr()
        .iter()
        .filter(|f| f.get("tier").str() == "T1")
        .map(|f| f.get("name").str().to_owned())
        .collect()
}

fn locs(regs: RegSet) -> LocSet {
    regs.iter().filter_map(lift::loc).collect()
}

fn lift_one(insn: &Insn) -> Arena {
    let mut b = Builder::new();
    lift_insn(insn, &mut b).unwrap_or_else(|e| panic!("{:#x}: {e}", insn.addr()));
    b.finish()
}

/// Checks the ops of one instruction. Gives the lift kind name or a failure.
fn check(insn: &Insn) -> Result<&'static str, String> {
    let arena = lift_one(insn);
    if arena.ops().iter().any(|op| op.opc == Opc::Unimpl) {
        return Err("Unimpl".to_owned());
    }
    let effect_op = arena
        .ops()
        .iter()
        .find(|op| matches!(op.opc, Opc::Intrinsic | Opc::Syscall));
    match lift::kind(insn) {
        LiftKind::Template(_) if effect_op.is_none() => Ok("template"),
        LiftKind::Template(row) => Err(format!("template {} with an effect op", row.template)),
        LiftKind::Unimpl => Err("kind Unimpl".to_owned()),
        kind @ (LiftKind::Intrinsic | LiftKind::Syscall) => {
            let op = effect_op.ok_or("no effect op")?;
            let e = arena.effect(op).ok_or("no effect")?;
            let mut defs = locs(insn.regs_written());
            let mut uses = locs(insn.regs_read());
            if !insn.flags_written().is_empty() {
                defs.insert(Loc::Flags);
            }
            if !insn.flags_read().is_empty() {
                uses.insert(Loc::Flags);
            }
            if e.defs.union(defs) != e.defs || e.uses.union(uses) != e.uses {
                return Err(format!("effect {e:?} misses {defs:?} or {uses:?}"));
            }
            Ok(if kind == LiftKind::Syscall {
                "syscall"
            } else {
                "intrinsic"
            })
        }
    }
}

#[test]
fn ac_071_lift_coverage() {
    let t1 = t1_fixtures();
    assert!(t1.len() >= 100, "only {} T1 fixtures", t1.len());
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut intrinsic_mnems: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut fixtures = 0;
    for l in listings().iter().filter(|l| t1.contains(&l.fixture)) {
        fixtures += 1;
        let file = fixture_bytes(&l.fixture);
        let mut sections = BTreeMap::new();
        for i in &l.insns {
            let code = sections
                .entry(i.section.clone())
                .or_insert_with(|| section_code(&file, &i.section));
            let off = usize::try_from(i.addr - code.addr).expect("offset");
            let insn = crate::common::dec(&code.bytes[off..], i.addr)
                .unwrap_or_else(|e| panic!("{} {:#x}: {e}", l.fixture, i.addr));
            match check(&insn) {
                Ok(kind) => {
                    *counts.entry(kind).or_default() += 1;
                    if kind == "intrinsic" {
                        *intrinsic_mnems
                            .entry(insn.mnem().name().to_owned())
                            .or_default() += 1;
                    }
                }
                Err(m) => failures.push(format!("{} {:#x} {}: {m}", l.fixture, i.addr, i.text)),
            }
        }
    }
    assert!(fixtures >= 100, "only {fixtures} T1 listings");
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures[..failures.len().min(20)].join("\n")
    );
    let total: usize = counts.values().sum();
    let template = counts.get("template").copied().unwrap_or_default();
    assert!(total > 30_000, "only {total} instructions");
    assert!(
        template * 100 >= total * 99,
        "template share {template} of {total}; intrinsic forms: {intrinsic_mnems:?}"
    );
}
