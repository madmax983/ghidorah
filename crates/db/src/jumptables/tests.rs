use ghidorah_base::{Address, JumpTableId, TxId};

use super::{JtMethod, JumpTable, JumpTables, MAX_ENTRIES};
use crate::fact::{Invalid, Origin, SessionLabel, WriteError};
use crate::source::Source;

fn table(n: usize, method: JtMethod) -> JumpTable {
    let targets: Vec<Address> = (0..n).map(|i| Address::ram(0x1000 + i as u64)).collect();
    JumpTable {
        base: Some(Address::ram(0x2000)),
        entry_size: 4,
        count: u16::try_from(n).unwrap_or(u16::MAX),
        targets,
        method,
        resolved: n > 0,
    }
}

#[test]
fn set_get_and_caps() {
    let mut j = JumpTables::default();
    let id = JumpTableId(Address::ram(0x40_1200));
    let agent = Origin::new(
        Source::Agent,
        TxId(1),
        SessionLabel::new("cli").unwrap(),
        false,
    );
    assert_eq!(
        j.set(id, Some(table(3, JtMethod::A)), &Origin::analysis())
            .unwrap(),
        None
    );
    assert_eq!(j.get(id).unwrap().value.targets.len(), 3);
    let old = j
        .set(id, Some(table(2, JtMethod::Agent)), &agent)
        .unwrap()
        .unwrap();
    assert_eq!(old.value.method, JtMethod::A);
    assert!(matches!(
        j.set(id, Some(table(1, JtMethod::A)), &Origin::analysis()),
        Err(WriteError::Blocked(_))
    ));
    assert_eq!(
        j.set(id, Some(table(MAX_ENTRIES + 1, JtMethod::Agent)), &agent),
        Err(WriteError::Invalid(Invalid::TooMany {
            count: MAX_ENTRIES + 1,
            max: MAX_ENTRIES
        }))
    );
    j.set(id, Some(table(MAX_ENTRIES, JtMethod::Agent)), &agent)
        .unwrap();
    j.set(
        JumpTableId(Address::ram(0x10)),
        Some(table(0, JtMethod::A)),
        &Origin::analysis(),
    )
    .unwrap();
    assert_eq!(j.len(), 2);
    assert!(!j.is_empty());
    assert_eq!(
        j.iter().map(|(i, _)| i).collect::<Vec<_>>(),
        [JumpTableId(Address::ram(0x10)), id]
    );
    assert!(j.set(id, None, &agent).unwrap().is_some());
    assert_eq!(j.len(), 1);
    assert_eq!(JtMethod::A.to_string(), "a");
    assert_eq!(JtMethod::Agent.name(), "agent");
}
