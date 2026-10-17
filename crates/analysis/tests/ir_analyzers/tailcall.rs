//! The decision rules of `TailCallsAndParts` (design Section 7.3).

use ghidorah_analysis::tailcall::{Candidate, Decision, Jump, decide};

const F: u64 = 0x1000;
const T: u64 = 0x2000;

fn jump(from: u64, conditional: bool, height: Option<i64>) -> Jump {
    Jump {
        site: from + 0x10,
        from,
        conditional,
        height,
    }
}

fn fde_target(jumps: Vec<Jump>) -> Candidate {
    Candidate {
        target: T,
        is_func: true,
        fde_only: true,
        jumps,
        ..Candidate::default()
    }
}

#[test]
fn decide_fde_targets() {
    // An unconditional jump at height 0 from one function: a tail call.
    let c = fde_target(vec![jump(F, false, Some(0))]);
    assert_eq!(decide(&c), Decision::TailCall);
    // A conditional jump: a cold part (parse_digit.cold).
    let c = fde_target(vec![jump(F, true, Some(0))]);
    assert_eq!(decide(&c), Decision::Cold { parent: F });
    // A jump with a frame on the stack: a cold part (parse_number.cold).
    let c = fde_target(vec![jump(F, false, Some(-24))]);
    assert_eq!(decide(&c), Decision::Cold { parent: F });
    let c = fde_target(vec![jump(F, false, None)]);
    assert_eq!(decide(&c), Decision::Cold { parent: F });
    // The flow of the target comes back into the source: a cold part.
    let mut c = fde_target(vec![jump(F, false, Some(0))]);
    c.returns_into_source = true;
    assert_eq!(decide(&c), Decision::Cold { parent: F });
    // Two source functions, a call or another start reason keep the function.
    let c = fde_target(vec![jump(F, true, Some(-8)), jump(0x3000, true, Some(-8))]);
    assert_eq!(decide(&c), Decision::Keep);
    let mut c = fde_target(vec![jump(F, true, Some(-8))]);
    c.called = true;
    assert_eq!(decide(&c), Decision::Keep);
    let mut c = fde_target(vec![jump(F, true, Some(-8))]);
    c.fde_only = false;
    assert_eq!(decide(&c), Decision::Keep);
    // No jump: nothing to decide.
    assert_eq!(decide(&fde_target(Vec::new())), Decision::Keep);
}

#[test]
fn decide_targets_with_no_function() {
    let base = Candidate {
        target: T,
        jumps: vec![jump(F, false, Some(0))],
        ..Candidate::default()
    };
    // Outside the declared extent of the source: a tail call (register_tm_clones).
    let c = Candidate {
        outside_extent: true,
        ..base.clone()
    };
    assert_eq!(decide(&c), Decision::TailCall);
    // A source with no extent needs an endbr64 head.
    let c = Candidate {
        no_extent: true,
        ..base.clone()
    };
    assert_eq!(decide(&c), Decision::Keep);
    let c = Candidate {
        no_extent: true,
        endbr: true,
        ..base.clone()
    };
    assert_eq!(decide(&c), Decision::TailCall);
    // Inside the extent of the source: a part of its body.
    assert_eq!(decide(&base), Decision::Keep);
    // A conditional jump or a height other than 0 is no tail call.
    let c = Candidate {
        outside_extent: true,
        jumps: vec![jump(F, true, Some(0))],
        ..base.clone()
    };
    assert_eq!(decide(&c), Decision::Keep);
    let c = Candidate {
        outside_extent: true,
        jumps: vec![jump(F, false, Some(-8))],
        ..base
    };
    assert_eq!(decide(&c), Decision::Keep);
}
