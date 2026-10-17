//! AC-256: SSA and every pass keep the interpreter result on random L0 programs.

use std::collections::BTreeMap;

use ghidorah_ir::{Opc, StopReason};
use ghidorah_testkit::rng::Xoshiro256ss;

use crate::ssagen::{check_program, random_program};

/// The count of random programs of AC-256.
const PROGRAMS: u64 = 10_000;

/// Gives a short name of a stop reason for the case counts.
const fn kind(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Returned => "returned",
        StopReason::FuelExhausted => "fuel",
        StopReason::UnmappedRead(_) | StopReason::UnmappedWrite(_) => "unmapped",
        StopReason::DivZero => "div_zero",
        StopReason::CallUnresolved(_) | StopReason::Syscall | StopReason::Intrinsic => "effect",
        _ => "other",
    }
}

#[test]
fn ac_256_ssa_random_programs() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x0256);
    let mut stops: BTreeMap<&str, u64> = BTreeMap::new();
    let mut with_phis = 0u64;
    for case in 0..PROGRAMS {
        let p = random_program(&mut rng);
        let image = crate::ssagen::ram_image(case);
        let want = crate::ssagen::run_l0(
            &p.arena,
            &image,
            &crate::ssagen::pool_opts(),
            &p.setup,
            p.entry,
            crate::ssagen::RUN_FUEL,
        );
        *stops.entry(kind(want.stop.reason)).or_default() += 1;
        let built = crate::ssagen::build(&p.arena, p.body.clone(), &crate::ssagen::pool_opts());
        if built
            .order()
            .iter()
            .any(|&i| built.arena().op(i).is_some_and(|op| op.opc == Opc::Phi))
        {
            with_phis += 1;
        }
        check_program(&p, case, &format!("case {case}"));
    }
    // The generator reaches each kind of stop, and many programs merge values.
    for name in ["returned", "fuel", "unmapped", "div_zero", "effect"] {
        let count = stops.get(name).copied().unwrap_or(0);
        assert!(count >= 100, "only {count} runs stop as {name}: {stops:?}");
    }
    assert!(with_phis >= 2_000, "only {with_phis} programs have phis");
}
