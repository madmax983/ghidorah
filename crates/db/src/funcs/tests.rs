use ghidorah_base::{Address, FuncId, Range, TxId};
use ghidorah_kernel::RangeSet;
use ghidorah_types::TypeId;

use super::{Funcs, Function, StartReason};
use crate::fact::{Invalid, Origin, SessionLabel, WriteError};
use crate::source::Source;

fn body(ranges: &[(u64, u64)]) -> RangeSet {
    let mut set = RangeSet::new();
    for &(first, last) in ranges {
        set.insert(Range { first, last });
    }
    set
}

fn func(entry: u64, ranges: &[(u64, u64)]) -> Function {
    let mut f = Function::new(
        Address::ram(entry),
        StartReason::Symbol,
        100,
        Source::Analysis,
    );
    f.body = body(ranges);
    f
}

fn id(entry: u64) -> FuncId {
    FuncId(Address::ram(entry))
}

#[test]
fn ownership_at_u64_max() {
    let mut funcs = Funcs::default();
    let top = u64::MAX - 3;
    funcs.insert(func(top, &[(top, u64::MAX)])).unwrap();
    assert_eq!(funcs.owner_of(u64::MAX), Some(id(top)));
    assert_eq!(funcs.owner_of(top), Some(id(top)));
    assert_eq!(funcs.owner_of(top - 1), None);
    assert_eq!(
        funcs.owner_range(u64::MAX),
        Some((
            Range {
                first: top,
                last: u64::MAX
            },
            id(top)
        ))
    );
    assert_eq!(funcs.get(id(top)).unwrap().size(), 4);
    assert_eq!(
        funcs.owners_in(Range {
            first: 0,
            last: u64::MAX
        }),
        [id(top)]
    );

    let err = funcs
        .insert(func(u64::MAX, &[(u64::MAX, u64::MAX)]))
        .unwrap_err();
    assert_eq!(
        err,
        Invalid::Overlap {
            new: Range::single(u64::MAX),
            existing: Range {
                first: top,
                last: u64::MAX
            }
        }
    );
    assert_eq!(funcs.len(), 1);

    let mut full = func(0, &[(0, u64::MAX)]);
    full.entry = Address::ram(0);
    let mut other = Funcs::default();
    other.insert(full).unwrap();
    assert_eq!(other.get(id(0)).unwrap().size(), 1u128 << 64);
    assert_eq!(other.owner_of(u64::MAX), Some(id(0)));

    let removed = funcs.remove(id(top)).unwrap();
    assert_eq!(removed.entry, Address::ram(top));
    assert_eq!(funcs.owner_of(u64::MAX), None);
    assert!(funcs.ownership().is_empty());
    funcs
        .insert(func(u64::MAX, &[(u64::MAX, u64::MAX)]))
        .unwrap();
    assert_eq!(funcs.owner_of(u64::MAX), Some(id(u64::MAX)));
}

#[test]
fn insert_checks_entry_space_and_overlap() {
    let mut funcs = Funcs::default();
    funcs
        .insert(func(0x1000, &[(0x1000, 0x10ff), (0x2000, 0x20ff)]))
        .unwrap();
    assert_eq!(funcs.ownership().len(), 2);
    assert_eq!(funcs.owner_of(0x2080), Some(id(0x1000)));
    assert_eq!(funcs.owner_of(0x1100), None);

    assert_eq!(
        funcs.insert(func(0x1000, &[(0x1000, 0x1000)])),
        Err(Invalid::FuncExists(id(0x1000)))
    );
    assert_eq!(
        funcs.insert(func(0x3000, &[(0x3001, 0x3010)])),
        Err(Invalid::EntryOutsideBody(Address::ram(0x3000)))
    );
    let mut ext = func(5, &[(5, 5)]);
    ext.entry = Address::external(5);
    assert_eq!(
        funcs.insert(ext),
        Err(Invalid::NotRam(Address::external(5)))
    );
    let err = funcs.insert(func(0x3000, &[(0x3000, 0x3010), (0x20f0, 0x2100)]));
    assert!(matches!(err, Err(Invalid::Overlap { .. })));
    assert_eq!(funcs.len(), 1, "a failed insert changes nothing");
    assert_eq!(funcs.ownership().len(), 2);
    assert!(!funcs.is_empty());

    funcs.insert(func(0x3000, &[(0x3000, 0x3010)])).unwrap();
    assert_eq!(
        funcs.owners_in(Range {
            first: 0x1000,
            last: 0x3000
        }),
        [id(0x1000), id(0x3000)],
        "a function with two ranges comes once"
    );
    assert_eq!(
        funcs.iter().map(Function::id).collect::<Vec<_>>(),
        [id(0x1000), id(0x3000)]
    );
    assert!(funcs.remove(id(0x9999)).is_none());
}

#[test]
fn set_body_moves_ownership() {
    let mut funcs = Funcs::default();
    funcs.insert(func(0x1000, &[(0x1000, 0x1fff)])).unwrap();
    funcs.insert(func(0x3000, &[(0x3000, 0x30ff)])).unwrap();
    let old = funcs
        .set_body(id(0x1000), body(&[(0x1000, 0x100f)]))
        .unwrap();
    assert_eq!(old, body(&[(0x1000, 0x1fff)]));
    assert_eq!(funcs.owner_of(0x1800), None);
    funcs
        .set_body(id(0x1000), body(&[(0x1000, 0x2fff)]))
        .unwrap();
    assert_eq!(funcs.owner_of(0x2fff), Some(id(0x1000)));

    let err = funcs.set_body(id(0x1000), body(&[(0x1000, 0x3000)]));
    assert!(matches!(err, Err(Invalid::Overlap { .. })));
    assert_eq!(
        funcs.owner_of(0x2fff),
        Some(id(0x1000)),
        "a failed change keeps the body"
    );
    assert_eq!(
        funcs.set_body(id(0x1000), body(&[(0x1001, 0x1010)])),
        Err(Invalid::EntryOutsideBody(Address::ram(0x1000)))
    );
    assert_eq!(
        funcs.set_body(id(0x5000), body(&[(0x5000, 0x5000)])),
        Err(Invalid::NoFunc(id(0x5000)))
    );
}

#[test]
fn signature_and_noreturn_follow_the_write_rule() {
    let mut funcs = Funcs::default();
    funcs.insert(func(0x1000, &[(0x1000, 0x1000)])).unwrap();
    let agent = Origin::new(
        Source::Agent,
        TxId(4),
        SessionLabel::new("cli").unwrap(),
        false,
    );
    let sig = TypeId::from_index(3);

    assert_eq!(funcs.set_sig(id(0x1000), Some(sig), &agent).unwrap(), None);
    assert_eq!(
        funcs.get(id(0x1000)).unwrap().sig.as_ref().map(|f| f.value),
        Some(sig)
    );
    let err = funcs
        .set_sig(id(0x1000), None, &Origin::analysis())
        .unwrap_err();
    assert!(matches!(err, WriteError::Blocked(b) if b.current.value == sig));
    assert_eq!(
        funcs.set_sig(id(0x2000), Some(sig), &agent),
        Err(WriteError::Invalid(Invalid::NoFunc(id(0x2000))))
    );

    assert_eq!(
        funcs.set_noreturn(id(0x1000), Some(true), &agent).unwrap(),
        None
    );
    let old = funcs
        .set_noreturn(id(0x1000), Some(false), &agent)
        .unwrap()
        .unwrap();
    assert!(old.value);
    let flags = &funcs.get(id(0x1000)).unwrap().flags;
    assert_eq!(flags.noreturn.as_ref().map(|f| f.value), Some(false));
    assert!(matches!(
        funcs.set_noreturn(id(0x1000), Some(true), &Origin::analysis()),
        Err(WriteError::Blocked(_))
    ));
    assert!(funcs.set_noreturn(id(0x2000), None, &agent).is_err());
}

#[test]
fn new_function_holds_its_entry() {
    let f = Function::new(Address::ram(0x40), StartReason::Agent, 250, Source::Agent);
    assert_eq!(f.confidence, 100, "the confidence caps at 100");
    assert!(f.body.contains(0x40));
    assert_eq!(f.size(), 1);
    assert_eq!(f.id(), id(0x40));
}

#[test]
fn start_reason_names() {
    let names: Vec<&str> = StartReason::ALL.iter().map(|r| r.name()).collect();
    assert_eq!(
        names,
        [
            "entry",
            "symbol",
            "plt_stub",
            "main",
            "pdata",
            "fde",
            "call",
            "tail_call",
            "endbr",
            "agent"
        ]
    );
    for r in StartReason::ALL {
        assert_eq!(StartReason::parse(r.name()), Some(r));
        assert_eq!(r.to_string(), r.name());
    }
    assert_eq!(StartReason::parse("guess"), None);
}
