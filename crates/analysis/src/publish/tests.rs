use std::collections::BTreeMap;

use ghidorah_base::Limits;
use ghidorah_db::{FactKey, Program};
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::elf::{ElfBuilder, Loc, Section};

use super::order;
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
fn order_cuts_cycles_and_unknown_premises() {
    let rule = Rule::DisasmFlow;
    let whys: BTreeMap<FactKey, Why> = [
        (unit(1), Why::new(rule, vec![unit(2)])),
        (unit(2), Why::new(rule, vec![unit(1), unit(3)])),
        (unit(3), Why::new(rule, vec![unit(99)])),
        (unit(4), Why::new(rule, vec![unit(4)])),
    ]
    .into_iter()
    .collect();
    // Unit 3 has no premise left and comes first. Unit 2 loses unit 1, which closes the
    // cycle. Unit 1 keeps unit 2. Unit 4 loses itself.
    assert_eq!(
        order(&program(), &whys),
        vec![(2, 0b1), (1, 0b10), (0, 0), (3, 0)]
    );
}
