//! Raw blobs: the raw loader (AC-057), retraction, shared code, endbr heads and hostile bytes.

use ghidorah_analysis::{Rule, RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId};
use ghidorah_db::{FactKey, Program, StartReason};
use ghidorah_loader::LoadOpts;
use ghidorah_testkit::rng::{Rng, Xoshiro256ss};

use crate::blobs::{BASE, Blob};
use crate::support::{analyze, program_of};

fn func(p: &Program, off: u64) -> Option<StartReason> {
    p.func(FuncId(Address::ram(BASE + off)))
        .map(|f| f.func.start_reason)
}

fn entries(p: &Program) -> Vec<u64> {
    p.funcs().iter().map(|f| f.func.entry.off - BASE).collect()
}

#[test]
fn ac_057_raw_loader() {
    // 0x0: call 0x10; ret.  0x10: mov eax, 1; ret.
    let blob = Blob::new().call(0x10).ret().at(0x10).mov_eax(1).ret();
    let mut p = blob.load(Some(0));
    assert_eq!(
        p.mem().region_at(BASE).map(|r| r.name.as_str()),
        Some("raw")
    );
    let _ = analyze(&mut p);
    assert_eq!(
        func(&p, 0),
        Some(StartReason::Entry),
        "the function at entry"
    );
    assert_eq!(func(&p, 0x10), Some(StartReason::Call));
    let main = p
        .func(FuncId(Address::ram(BASE)))
        .expect("the entry function");
    assert_eq!(main.func.size(), 6, "call and ret");
    assert!(p.code_unit(BASE + 5).is_some(), "the ret after the call");
    assert!(
        p.check_invariants().is_empty(),
        "{:?}",
        p.check_invariants()
    );

    // With no entry, a raw load seeds nothing but endbr heads.
    let mut none = blob.load(None);
    let _ = analyze(&mut none);
    assert!(none.funcs().is_empty());
}

#[test]
fn dead_code_callees_drop() {
    // 0x0: call 0x20 (hlt only); call 0x30; ret.  The second call is dead code.
    let blob = Blob::new()
        .call(0x20)
        .call(0x30)
        .ret()
        .at(0x20)
        .hlt()
        .at(0x30)
        .ret();
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    assert_eq!(entries(&p), [0x0, 0x20], "the callee of dead code goes");
    let f = p.func(FuncId(Address::ram(BASE + 0x20))).expect("the trap");
    assert_eq!(f.noreturn.map(|n| n.value), Some(true));
    assert!(
        p.code_unit(BASE + 5).is_none(),
        "no unit after the noreturn call"
    );
    assert!(
        p.check_invariants().is_empty(),
        "{:?}",
        p.check_invariants()
    );
}

#[test]
fn lower_entry_keeps_shared_code() {
    // 0x0: call 0x10; call 0x20; ret.  0x10: jmp 0x30.  0x20: jmp 0x30.  0x30: ret.
    let blob = Blob::new()
        .call(0x10)
        .call(0x20)
        .ret()
        .at(0x10)
        .jmp(0x30)
        .at(0x20)
        .jmp(0x30)
        .at(0x30)
        .ret();
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    assert_eq!(entries(&p), [0x0, 0x10, 0x20]);
    assert_eq!(
        p.owner_of(Address::ram(BASE + 0x30)),
        Some(FuncId(Address::ram(BASE + 0x10))),
        "the lower entry keeps the shared tail"
    );
    let b = p.func(FuncId(Address::ram(BASE + 0x20))).expect("b");
    assert_eq!(b.func.size(), 5, "the higher entry keeps its jump only");
    for k in [1, 3] {
        let mut q = blob.load(Some(0));
        let mut s = Scheduler::new();
        while s
            .run(&mut q, Until::Full, &mut Fuel::new(k))
            .expect("a slice")
            .state
            != RunState::Complete
        {}
        assert_eq!(q.analysis(), p.analysis(), "slices of {k}");
    }
}

#[test]
fn endbr_heads_seed_functions() {
    // 0x0: call 0x40; endbr64 (a setjmp landing in the body); ret.
    // 0x20: endbr64; ret (a free head).  0x40: ret.
    let blob = Blob::new()
        .call(0x40)
        .endbr()
        .ret()
        .at(0x20)
        .endbr()
        .ret()
        .at(0x40)
        .ret();
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    assert_eq!(func(&p, 0x20), Some(StartReason::Endbr));
    assert_eq!(func(&p, 5), None, "a head inside a body is not a seed");
    assert_eq!(entries(&p), [0x0, 0x20, 0x40]);
}

#[test]
fn slot_jump_and_bad_code() {
    // 0x0: call 0x10; call 0x20; ret.  0x10: jmp [rip+0x80] (no import).  0x20: bad bytes.
    let blob = Blob::new()
        .call(0x10)
        .call(0x20)
        .ret()
        .at(0x10)
        .jmp_slot(0x80)
        .at(0x20)
        .raw(&[0x06])
        .at(0x80)
        .raw(&[0; 8]);
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    for off in [0x10, 0x20] {
        let f = p.func(FuncId(Address::ram(BASE + off))).expect("a callee");
        assert!(
            f.noreturn.is_none(),
            "an unknown end is not noreturn: {off:#x}"
        );
    }
    assert!(
        p.check_invariants().is_empty(),
        "{:?}",
        p.check_invariants()
    );
}

#[test]
fn regress_fallthrough_flag_is_stable() {
    // 0x0: call 0x100; call 0x110; call 0x120; ret.  Each callee calls 0x200 and then holds
    // bad bytes.  0x200: jmp rax.  The fall-through rule flags 0x200, and the cut after the
    // call of 0x100 then makes the calls of 0x110 and 0x120 dead code.
    let mut blob = Blob::new().call(0x100).call(0x110).call(0x120).ret();
    for off in [0x100, 0x110, 0x120] {
        blob = blob.at(off).call(0x200).raw(&[0x06]);
    }
    let blob = blob.at(0x200).jmp_rax();
    let mut p = blob.load(Some(0));
    let (sched, out) = analyze(&mut p);
    assert!(
        out.steps_used < 1_000,
        "the fixpoint ends early: {}",
        out.steps_used
    );
    let disasm = sched
        .rows()
        .into_iter()
        .find(|r| r.name == "Disasm")
        .expect("a row");
    assert!(
        disasm.runs < 20,
        "no flag flips back and forth: {}",
        disasm.runs
    );
    let shared = FuncId(Address::ram(BASE + 0x200));
    let why = p.why(&FactKey::Noreturn(shared)).expect("a flag");
    assert_eq!(why.rule.as_str(), Rule::NoreturnFallthrough.code());
    let first = FuncId(Address::ram(BASE + 0x100));
    assert_eq!(
        p.why(&FactKey::Noreturn(first))
            .map(|w| w.rule.as_str().to_owned()),
        Some(Rule::NoreturnBody.code().to_owned())
    );
    for k in [1, 4] {
        let mut sliced = blob.load(Some(0));
        let mut runner = Scheduler::new();
        while runner
            .run(&mut sliced, Until::Full, &mut Fuel::new(k))
            .expect("a slice")
            .state
            != RunState::Complete
        {}
        assert_eq!(sliced.analysis(), p.analysis(), "slices of {k}");
    }
}

#[test]
fn raw_random_blobs_never_panic() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x57);
    for round in 0..40 {
        let len = 64 + usize::try_from(rng.next_u64() % 512).expect("small");
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        let entry = BASE + rng.next_u64() % 32;
        let mut p = program_of(&bytes, &LoadOpts::raw(BASE, Some(entry)));
        let _ = analyze(&mut p);
        let found = p.check_invariants();
        assert!(found.is_empty(), "round {round}: {found:?}");
    }
}
