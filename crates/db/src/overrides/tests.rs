use ghidorah_base::{Address, TxId};

use super::{FlowOverride, FlowOverrides, MAX_TARGETS};
use crate::fact::{Invalid, Origin, SessionLabel, WriteError};
use crate::source::Source;

fn agent() -> Origin {
    Origin::new(
        Source::Agent,
        TxId(1),
        SessionLabel::new("cli").unwrap(),
        false,
    )
}

#[test]
fn targets_sort_and_dedup() {
    let mut o = FlowOverrides::default();
    let at = Address::ram(0x40_1000);
    let targets = vec![
        Address::ram(3),
        Address::ram(1),
        Address::external(1),
        Address::ram(3),
    ];
    assert_eq!(
        o.set(at, Some(FlowOverride::IndirectTargets(targets)), &agent())
            .unwrap(),
        None
    );
    assert_eq!(
        o.get(at).unwrap().value,
        FlowOverride::IndirectTargets(vec![Address::ram(1), Address::ram(3), Address::external(1)])
    );
    let many: Vec<Address> = (0..=MAX_TARGETS as u64).map(Address::ram).collect();
    assert_eq!(
        o.set(at, Some(FlowOverride::IndirectTargets(many)), &agent()),
        Err(WriteError::Invalid(Invalid::TooMany {
            count: MAX_TARGETS + 1,
            max: MAX_TARGETS
        }))
    );
    let dupes: Vec<Address> = (0..=MAX_TARGETS as u64)
        .map(|i| Address::ram(i % 2))
        .collect();
    o.set(at, Some(FlowOverride::IndirectTargets(dupes)), &agent())
        .unwrap();
}

#[test]
fn set_follows_the_rule_and_names() {
    let mut o = FlowOverrides::default();
    let at = Address::ram(0x10);
    o.set(at, Some(FlowOverride::CallAsJump), &agent()).unwrap();
    o.set(
        Address::ram(0x20),
        Some(FlowOverride::Fallthrough(Address::ram(0x30))),
        &agent(),
    )
    .unwrap();
    assert!(matches!(
        o.set(at, Some(FlowOverride::JumpAsCall), &Origin::analysis()),
        Err(WriteError::Blocked(_))
    ));
    assert_eq!(o.len(), 2);
    assert!(!o.is_empty());
    assert_eq!(
        o.iter().map(|(a, _)| a).collect::<Vec<_>>(),
        [at, Address::ram(0x20)]
    );
    assert_eq!(
        o.set(at, None, &agent()).unwrap().map(|f| f.value),
        Some(FlowOverride::CallAsJump)
    );
    let names: Vec<String> = [
        FlowOverride::Fallthrough(Address::ram(1)),
        FlowOverride::CallAsJump,
        FlowOverride::JumpAsCall,
        FlowOverride::IndirectTargets(Vec::new()),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        names,
        [
            "fallthrough",
            "call_as_jump",
            "jump_as_call",
            "indirect_targets"
        ]
    );
}
