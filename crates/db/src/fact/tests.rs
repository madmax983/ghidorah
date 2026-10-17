use std::collections::BTreeMap;

use ghidorah_base::{Address, ErrorCode, FuncId, NoteId, Range, TxId};

use super::{
    Blocked, Fact, Invalid, Origin, SessionLabel, WriteError, check, higher, put, put_slot,
};
use crate::source::Source;

fn origin(source: Source, force: bool) -> Origin {
    Origin::new(source, TxId(7), SessionLabel::new("mcp-1").unwrap(), force)
}

#[test]
fn blocked_write_reports_current_value() {
    let mut map: BTreeMap<u64, Fact<String>> = BTreeMap::new();
    put(&mut map, 1, Some("puts@plt".to_string()), &Origin::load()).unwrap();

    let err = put(
        &mut map,
        1,
        Some("my_puts".to_string()),
        &origin(Source::Agent, false),
    )
    .unwrap_err();
    let WriteError::Blocked(blocked) = &err else {
        panic!("expected a blocked write, got {err:?}");
    };
    assert_eq!(blocked.current.value, "puts@plt");
    assert_eq!(blocked.current.source, Source::Imported);
    assert_eq!(blocked.current.session.as_str(), SessionLabel::LOAD);
    assert_eq!(blocked.attempted, Source::Agent);
    assert!(blocked.force_applies());
    assert_eq!(err.code(), ErrorCode::BlockedByHigherPrioritySource);
    assert_eq!(map[&1].value, "puts@plt", "a refused write changes nothing");
    assert!(err.to_string().contains("imported (rank 4)"));

    let old = put(
        &mut map,
        1,
        Some("my_puts".to_string()),
        &origin(Source::Agent, true),
    )
    .unwrap()
    .unwrap();
    assert_eq!(old.value, "puts@plt");
    assert_eq!(map[&1].value, "my_puts");
    assert!(
        map[&1].force,
        "the fact keeps the force flag for the journal"
    );

    put(
        &mut map,
        2,
        Some("user name".to_string()),
        &origin(Source::User, false),
    )
    .unwrap();
    let err = put(&mut map, 2, None, &origin(Source::Agent, true)).unwrap_err();
    let WriteError::Blocked(blocked) = err else {
        panic!("expected a blocked delete");
    };
    assert_eq!(blocked.current.value, "user name");
    assert_eq!(blocked.current.source, Source::User);
    assert!(!blocked.force_applies(), "force never passes a user fact");

    let analysis = Origin::analysis();
    let err = put(&mut map, 1, Some("FUN_x".to_string()), &analysis).unwrap_err();
    assert!(matches!(err, WriteError::Blocked(b) if b.current.source == Source::Agent));
}

#[test]
fn put_removes_and_reports_old_facts() {
    let mut map: BTreeMap<u64, Fact<u8>> = BTreeMap::new();
    let a = origin(Source::Agent, false);
    assert_eq!(put(&mut map, 5, Some(1), &a).unwrap(), None);
    let old = put(&mut map, 5, Some(2), &a).unwrap().unwrap();
    assert_eq!(old.value, 1);
    assert_eq!(old.tx, TxId(7));
    let old = put(&mut map, 5, None, &a).unwrap().unwrap();
    assert_eq!(old.value, 2);
    assert!(map.is_empty());
    assert_eq!(put(&mut map, 6, None, &a).unwrap(), None);

    let default = Origin::new(
        Source::Default,
        TxId(1),
        SessionLabel::new("cli").unwrap(),
        false,
    );
    let err = put(&mut map, 5, Some(1), &default).unwrap_err();
    assert_eq!(err, WriteError::Invalid(Invalid::DefaultSource));
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn put_slot_follows_the_write_rule() {
    let mut slot: Option<Fact<bool>> = None;
    let agent = origin(Source::Agent, false);
    assert_eq!(put_slot(&mut slot, Some(true), &agent).unwrap(), None);
    assert_eq!(slot.as_ref().map(|f| f.value), Some(true));
    let err = put_slot(&mut slot, Some(false), &Origin::analysis()).unwrap_err();
    assert!(matches!(err, WriteError::Blocked(_)));
    assert_eq!(slot.as_ref().map(|f| f.value), Some(true));
    let old = put_slot(&mut slot, None, &origin(Source::User, false)).unwrap();
    assert_eq!(old.map(|f| f.value), Some(true));
    assert!(slot.is_none());
    assert!(check::<bool>(None, &agent).is_ok());
}

#[test]
fn higher_picks_the_higher_rank() {
    let low = Origin::analysis().fact(1);
    let high = origin(Source::Agent, false).fact(2);
    assert_eq!(higher(Some(&low), Some(&high)).map(|f| f.value), Some(2));
    assert_eq!(higher(Some(&high), Some(&low)).map(|f| f.value), Some(2));
    assert_eq!(higher(None, Some(&low)).map(|f| f.value), Some(1));
    assert_eq!(higher(Some(&low), None).map(|f| f.value), Some(1));
    let tie = Origin::analysis().fact(3);
    assert_eq!(higher(Some(&low), Some(&tie)).map(|f| f.value), Some(1));
    assert_eq!(higher::<u8>(None, None), None);
}

#[test]
fn session_labels_obey_the_grammar() {
    for good in ["cli", "mcp-1", "a.b_c-D9", &"x".repeat(64)] {
        assert_eq!(SessionLabel::new(good).unwrap().as_str(), good);
    }
    for bad in ["", "a b", "*", "é", &"x".repeat(65)] {
        assert_eq!(SessionLabel::new(bad), Err(Invalid::BadLabel), "{bad:?}");
    }
    assert_eq!(SessionLabel::new("cli").unwrap().to_string(), "cli");
    assert_eq!(Origin::load().session.as_str(), "load");
    assert_eq!(Origin::analysis().session.as_str(), "analysis");
    assert_eq!(Origin::load().source, Source::Imported);
    let fact = origin(Source::User, true).fact("x");
    assert_eq!(fact.origin(), origin(Source::User, true));
}

#[test]
fn invalid_codes_and_texts() {
    let r = Range { first: 1, last: 2 };
    let cases: Vec<(Invalid, ErrorCode)> = vec![
        (Invalid::DefaultSource, ErrorCode::InvalidArgument),
        (Invalid::BadLabel, ErrorCode::InvalidArgument),
        (Invalid::EmptyName, ErrorCode::InvalidArgument),
        (Invalid::DuplicateName("x".to_string()), ErrorCode::Conflict),
        (
            Invalid::TooLong { len: 5, max: 4 },
            ErrorCode::LimitExceeded,
        ),
        (
            Invalid::TooMany { count: 5, max: 4 },
            ErrorCode::LimitExceeded,
        ),
        (
            Invalid::NotRam(Address::external(3)),
            ErrorCode::InvalidArgument,
        ),
        (Invalid::BadLength(0), ErrorCode::InvalidArgument),
        (
            Invalid::Overlap {
                new: r,
                existing: r,
            },
            ErrorCode::BodyOverlap,
        ),
        (
            Invalid::EntryOutsideBody(Address::ram(1)),
            ErrorCode::InvalidArgument,
        ),
        (
            Invalid::FuncExists(FuncId(Address::ram(1))),
            ErrorCode::BodyOverlap,
        ),
        (
            Invalid::NoFunc(FuncId(Address::ram(1))),
            ErrorCode::NotFound,
        ),
        (
            Invalid::SetNameTaken {
                name: "s".to_string(),
                owner: NoteId(1),
            },
            ErrorCode::Conflict,
        ),
        (Invalid::SetMismatch, ErrorCode::InvalidArgument),
        (Invalid::SetKinds, ErrorCode::InvalidArgument),
        (
            Invalid::BadEvidence("x".to_string()),
            ErrorCode::InvalidArgument,
        ),
        (
            Invalid::BadSource(Source::Analysis),
            ErrorCode::InvalidArgument,
        ),
    ];
    for (invalid, code) in cases {
        assert_eq!(invalid.code(), code, "{invalid:?}");
        let text = invalid.to_string();
        assert!(text.ends_with('.'), "{text}");
        let err: WriteError<u8> = invalid.clone().into();
        assert_eq!(err.to_string(), text);
    }
    let blocked = Blocked {
        current: Origin::load().fact(1u8),
        attempted: Source::Analysis,
        force: false,
    };
    assert_eq!(blocked.code(), ErrorCode::BlockedByHigherPrioritySource);
    assert_eq!(
        blocked.to_string(),
        "A fact with the source imported (rank 4) blocks the write with the source analysis (rank 2)."
    );
    assert!(!blocked.force_applies());
}
