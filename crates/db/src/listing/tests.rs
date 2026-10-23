use ghidorah_base::{Range, TxId};
use ghidorah_types::TypeId;

use super::{CodeUnit, DataDef, FlowKind, Listing};
use crate::fact::{Invalid, Origin, SessionLabel, WriteError};
use crate::source::Source;

fn insn(len: u8) -> CodeUnit {
    CodeUnit::Insn {
        len,
        flow: FlowKind::Seq,
        flags: 0,
    }
}

fn def(len: u32) -> DataDef {
    DataDef {
        ty: TypeId::from_index(1),
        len,
    }
}

#[test]
fn units_do_not_overlap() {
    let mut l = Listing::default();
    l.insert_unit(0x10, insn(4)).unwrap();
    l.insert_unit(0x14, insn(1)).unwrap();
    l.insert_unit(0x0c, insn(4)).unwrap();
    assert_eq!(l.unit_count(), 3);
    assert_eq!(
        l.insert_unit(0x12, insn(1)),
        Err(Invalid::Overlap {
            new: Range {
                first: 0x12,
                last: 0x12
            },
            existing: Range {
                first: 0x10,
                last: 0x13
            }
        })
    );
    assert!(matches!(
        l.insert_unit(0x0e, insn(1)),
        Err(Invalid::Overlap { .. })
    ));
    assert!(matches!(
        l.insert_unit(0x09, insn(4)),
        Err(Invalid::Overlap { .. })
    ));
    assert!(matches!(
        l.insert_unit(0x10, insn(4)),
        Err(Invalid::Overlap { .. })
    ));
    assert_eq!(l.insert_unit(0x40, insn(0)), Err(Invalid::BadLength(0)));
    assert_eq!(l.insert_unit(u64::MAX, insn(2)), Err(Invalid::BadLength(2)));
    l.insert_unit(u64::MAX, insn(1)).unwrap();

    assert_eq!(l.unit(0x10), Some(&insn(4)));
    assert_eq!(l.unit(0x11), None);
    assert_eq!(l.unit_containing(0x13), Some((0x10, &insn(4))));
    assert_eq!(l.unit_containing(0x14), Some((0x14, &insn(1))));
    assert_eq!(l.unit_containing(0x15), None);
    assert_eq!(l.unit_containing(0x0b), None);
    assert_eq!(l.unit_containing(u64::MAX), Some((u64::MAX, &insn(1))));
    let starts: Vec<u64> = l
        .units_in(Range {
            first: 0x0d,
            last: 0x14,
        })
        .map(|(a, _)| a)
        .collect();
    assert_eq!(starts, [0x10, 0x14]);
    assert_eq!(l.remove_unit(0x10), Some(insn(4)));
    assert_eq!(l.unit_containing(0x11), None);
    l.insert_unit(0x11, insn(3)).unwrap();
}

#[test]
fn unit_ranges_and_flow_names() {
    assert_eq!(
        insn(3).range(0x10),
        Some(Range {
            first: 0x10,
            last: 0x12
        })
    );
    assert_eq!(insn(3).range(u64::MAX - 1), None);
    assert_eq!(insn(0).range(0x10), None);
    assert_eq!(insn(3).len(), 3);
    assert!(!insn(3).is_empty());
    assert!(insn(0).is_empty());
    let names: Vec<String> = [
        FlowKind::Seq,
        FlowKind::Jmp,
        FlowKind::Jcc,
        FlowKind::Call,
        FlowKind::ICall,
        FlowKind::IJmp,
        FlowKind::Ret,
        FlowKind::Trap,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        names,
        ["seq", "jmp", "jcc", "call", "icall", "ijmp", "ret", "trap"]
    );
    assert_eq!(
        def(8).range(0x20),
        Some(Range {
            first: 0x20,
            last: 0x27
        })
    );
    assert_eq!(def(0).range(0x20), None);
    assert_eq!(def(2).range(u64::MAX), None);
}

#[test]
fn data_follows_the_write_rule_and_does_not_overlap() {
    let mut l = Listing::default();
    let agent = Origin::new(
        Source::Agent,
        TxId(9),
        SessionLabel::new("cli").unwrap(),
        false,
    );
    assert_eq!(
        l.set_data(0x100, Some(def(8)), &Origin::analysis())
            .unwrap(),
        None
    );
    let old = l.set_data(0x100, Some(def(4)), &agent).unwrap().unwrap();
    assert_eq!(old.value, def(8));
    assert_eq!(l.data(0x100).unwrap().value, def(4));
    assert!(matches!(
        l.set_data(0x100, None, &Origin::analysis()),
        Err(WriteError::Blocked(_))
    ));
    assert!(matches!(
        l.set_data(0x0fe, Some(def(4)), &agent),
        Err(WriteError::Invalid(Invalid::Overlap { .. }))
    ));
    assert!(matches!(
        l.set_data(0x102, Some(def(1)), &agent),
        Err(WriteError::Invalid(Invalid::Overlap { .. }))
    ));
    assert_eq!(
        l.set_data(0x200, Some(def(0)), &agent),
        Err(WriteError::Invalid(Invalid::BadLength(0)))
    );
    l.set_data(0x104, Some(def(4)), &agent).unwrap();
    assert_eq!(l.data_count(), 2);
    assert_eq!(l.data_containing(0x107).map(|(a, _)| a), Some(0x104));
    assert_eq!(l.data_containing(0x108).map(|(a, _)| a), None);
    assert_eq!(
        l.data_defs().map(|(a, _)| a).collect::<Vec<_>>(),
        [0x100, 0x104]
    );
    assert_eq!(
        l.set_data(0x100, None, &agent).unwrap().map(|f| f.value),
        Some(def(4))
    );
    assert_eq!(l.set_data(0x100, None, &agent).unwrap(), None);
    l.set_data(0x0fe, Some(def(4)), &agent).unwrap();
}

#[test]
fn a_bulk_build_of_units_matches_one_insert_at_a_time() {
    let one_by_one = |units: &[(u64, CodeUnit)]| {
        let mut l = Listing::default();
        let mut result = Ok(());
        for (i, (off, u)) in units.iter().enumerate() {
            result = result.and_then(|()| l.insert_unit(*off, *u).map_err(|e| (i, e)));
        }
        (l, result)
    };
    let cases: [&[(u64, CodeUnit)]; 4] = [
        &[(0x10, insn(4)), (0x14, insn(2)), (0x20, insn(15))],
        &[(0x20, insn(4)), (0x10, insn(4))],
        &[(0x10, insn(8)), (0x14, insn(2))],
        &[(0x10, insn(0))],
    ];
    for units in cases {
        let mut bulk = Listing::default();
        let result = bulk.extend_units(units.to_vec());
        let (single, expected) = one_by_one(units);
        assert_eq!(result, expected, "{units:?}");
        if result.is_ok() {
            assert_eq!(bulk, single, "{units:?}");
        }
    }
}
