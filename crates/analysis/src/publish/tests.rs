use ghidorah_base::Limits;
use ghidorah_db::{FactKey, Program};
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::elf::{ElfBuilder, Loc, Section};

use super::kept;
use super::whys::Whys;
use crate::why::{Rule, Why};

fn program() -> Program {
    let elf = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3]))
        .entry(Loc::section(".text", 0))
        .build();
    let (binary, mem) = load(&elf, &LoadOpts::AUTO, &Limits::DEFAULT).unwrap();
    Program::from_binary(binary, mem, &Limits::DEFAULT).unwrap()
}

fn unit(at: u64) -> FactKey {
    FactKey::CodeUnit(at)
}

/// The walk visits the premises of a fact first. It cuts the premise that closes a cycle,
/// a premise of a fact on itself and a premise outside the set and the inputs.
#[test]
fn the_walk_cuts_cycles_and_unknown_premises() {
    let rule = Rule::DisasmFlow;
    let mut whys = Whys::default();
    for (key, why) in [
        (unit(1), Why::new(rule, vec![unit(2)])),
        (unit(2), Why::new(rule, vec![unit(1), unit(3)])),
        (unit(3), Why::new(rule, vec![unit(99)])),
        (unit(4), Why::new(rule, vec![unit(4)])),
    ] {
        whys.insert(key, why);
    }
    // Unit 3 has no premise left. Unit 2 loses unit 1, which closes the cycle. Unit 1 keeps
    // unit 2. Unit 4 loses itself.
    assert_eq!(kept(&program(), &whys.records()), vec![0b1, 0b10, 0, 0]);
}

/// Compact records take part in the walk as general records do. A code unit names its owner
/// function, and a reference names the code unit of its source.
#[test]
fn the_walk_takes_compact_records() {
    use ghidorah_base::{Address, FuncId};
    use ghidorah_db::{RefKey, RefType};

    let call = |from: u64| RefKey {
        from: Address::ram(from),
        op_index: -1,
        to: Address::ram(0x10),
        kind: RefType::UnconditionalCall,
    };
    let func = FactKey::Func(FuncId(Address::ram(0x10)));
    let mut whys = Whys::default();
    whys.insert(unit(0x10), Why::new(Rule::DisasmFlow, vec![func.clone()]));
    whys.insert(
        func.clone(),
        Why::new(Rule::CallTarget, vec![FactKey::Ref(call(0x10))]),
    );
    whys.insert(
        FactKey::Ref(call(0x10)),
        Why::new(Rule::FlowRef, vec![unit(0x10)]),
    );
    whys.insert(
        FactKey::Ref(call(0x99)),
        Why::new(Rule::FlowRef, vec![unit(0x99)]),
    );
    let records = whys.records();
    let keys: Vec<FactKey> = records.iter().map(super::whys::Rec::key).collect();
    assert_eq!(
        keys,
        [
            unit(0x10),
            func,
            FactKey::Ref(call(0x10)),
            FactKey::Ref(call(0x99))
        ]
    );
    // The reference from 0x10 closes the cycle unit, function, reference. The reference from
    // 0x99 names a unit outside the set.
    assert_eq!(kept(&program(), &records), vec![0b1, 0b1, 0, 0]);
}
