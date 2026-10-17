//! The SSA checker: each rule finds its break, and a clean form has no violation.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "the test programs name each IR value with one letter"
)]

use ghidorah_ir::ssa::{Opts, Ssa};
use ghidorah_ir::{Arena, Arg, Loc, Node, OpId, Opc, Rule, Val, Violation, check};

use crate::common::program;
use crate::ssagen::{body, build};

const NIL: Arg = Arg::Nil;

/// A diamond: A goes to B or C. B adds 1 to rax. C sets rax to 3. D gives rbx = rax + 2.
/// E is a block that no edge reaches.
fn diamond() -> (Arena, Ssa) {
    let arena = program(|b| {
        b.begin(0x1000, 4)?;
        let s = b.get(Loc::RSI)?;
        let c = b.binary(Opc::Ne, 64, s.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x1008))?;
        b.begin(0x1004, 4)?;
        let x = b.get(Loc::RAX)?;
        let y = b.binary(Opc::Add, 64, x.into(), Arg::k(1))?;
        b.put(Loc::RAX, y.into())?;
        b.flow(Opc::Jump, Arg::k(0x100c), NIL)?;
        b.begin(0x1008, 4)?;
        b.put(Loc::RAX, Arg::k(3))?;
        b.begin(0x100c, 4)?;
        let z = b.get(Loc::RAX)?;
        let w = b.binary(Opc::Add, 64, z.into(), Arg::k(2))?;
        b.put(Loc::RBX, w.into())?;
        b.flow(Opc::Ret, NIL, NIL)?;
        b.begin(0x1010, 4)?;
        let u = b.binary(Opc::Add, 64, Arg::k(1), Arg::k(2))?;
        b.put(Loc::RDX, u.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let opts = Opts {
        ret_uses: std::iter::once(Loc::RBX).collect(),
        ..Opts::default()
    };
    let ssa = build(
        &arena,
        body(&arena, &[0x1000, 0x1004, 0x1008, 0x100c, 0x1010]),
        &opts,
    );
    (arena, ssa)
}

fn id(ssa: &Ssa, index: u32) -> OpId {
    ssa.arena().op(index).expect("op").id
}

fn found(ssa: &Ssa, rule: Rule, index: u32) -> bool {
    let at = id(ssa, index);
    check(ssa).iter().any(|v| v.rule == rule && v.at == at)
}

const Y: Val = Val(3);

#[test]
fn checker_finds_each_rule() {
    let (_, clean) = diamond();
    assert!(check(&clean).is_empty(), "{:?}", check(&clean));
    // A value of B used in D: B does not dominate D.
    let mut ssa = clean.clone();
    ssa.arena_mut().ops_mut()[9].a[0] = Arg::V(Y);
    assert!(found(&ssa, Rule::DefDominatesUse, 9));
    // A use before its def in the same block.
    let mut ssa = clean.clone();
    ssa.arena_mut().ops_mut()[3].a[0] = Arg::V(Y);
    assert!(found(&ssa, Rule::DefDominatesUse, 3));
    // A use in the block that no edge reaches is not checked for dominance.
    let mut ssa = clean.clone();
    ssa.arena_mut().ops_mut()[12].a[0] = Arg::V(Y);
    assert!(check(&ssa).is_empty());
    // A value with no def.
    let mut ssa = clean.clone();
    ssa.arena_mut().ops_mut()[9].a[1] = Arg::V(Val(500));
    assert!(found(&ssa, Rule::RemovedValue, 9));
    // A value whose def op is gone.
    let mut ssa = clean.clone();
    ssa.arena_mut().ops_mut()[4].out = None;
    assert!(
        check(&ssa)
            .iter()
            .any(|v| v.rule == Rule::RemovedValue && v.val == Some(Y))
    );
    // Two ops give the same value.
    let mut ssa = clean.clone();
    ssa.arena_mut().ops_mut()[9].out = Some(Y);
    assert!(found(&ssa, Rule::SingleDef, 9));
    // An instruction op that reads a location.
    let mut ssa = clean.clone();
    ssa.arena_mut().ops_mut()[1].opc = Opc::Get;
    ssa.arena_mut().ops_mut()[1].a = [Arg::L(Loc::RAX), NIL, NIL];
    assert!(found(&ssa, Rule::Shape, 1));
    // A phi with an extra argument, and a phi argument that the predecessor cannot see.
    let phi = ssa_phi(&clean, Node(3));
    let mut ssa = clean.clone();
    let list = phi_list(&ssa, phi);
    ssa.arena_mut()
        .phi_args_mut(list)
        .expect("args")
        .push(Arg::k(0));
    assert!(found(&ssa, Rule::PhiArity, phi));
    let mut ssa = clean.clone();
    let own = ssa.arena().op(phi).and_then(|op| op.out).expect("value");
    ssa.arena_mut().phi_args_mut(list).expect("args")[0] = Arg::V(own);
    assert!(found(&ssa, Rule::DefDominatesUse, phi));
    // A non-phi op at the head of a block.
    let mut ssa = clean;
    ssa.arena_mut().ops_mut()[usize::try_from(phi).expect("index")].opc = Opc::Copy;
    assert!(found(&ssa, Rule::Shape, phi));
}

fn ssa_phi(ssa: &Ssa, block: Node) -> u32 {
    let phis = ssa.phis(block);
    assert_eq!(phis.len(), 1, "one phi: {phis:?}");
    phis[0]
}

fn phi_list(ssa: &Ssa, phi: u32) -> u32 {
    let op = ssa.arena().op(phi).expect("phi");
    u32::try_from(op.a[0].as_k().expect("list index")).expect("small")
}

#[test]
fn violation_text_and_rule_names() {
    let v = Violation {
        rule: Rule::PhiArity,
        at: OpId {
            addr: 0x1000,
            seq: 0xf001,
        },
        val: Some(Val(4)),
    };
    assert_eq!(v.to_string(), "phi_arity at 0x1000:61441 (v4)");
    let w = Violation { val: None, ..v };
    assert_eq!(w.to_string(), "phi_arity at 0x1000:61441");
    let names: Vec<&str> = [
        Rule::SingleDef,
        Rule::DefDominatesUse,
        Rule::PhiArity,
        Rule::RemovedValue,
        Rule::Shape,
    ]
    .iter()
    .map(|r| r.name())
    .collect();
    assert_eq!(
        names,
        [
            "single_def",
            "def_dominates_use",
            "phi_arity",
            "removed_value",
            "shape"
        ]
    );
}
