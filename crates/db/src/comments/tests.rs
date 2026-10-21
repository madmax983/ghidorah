use ghidorah_base::{Address, TxId};

use super::{CommentKind, Comments, MAX_COMMENT};
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
fn set_get_and_remove() {
    let mut c = Comments::default();
    let a = Address::ram(0x40_1000);
    assert_eq!(
        c.set(a, CommentKind::Pre, Some("entry".to_string()), &agent())
            .unwrap(),
        None
    );
    c.set(a, CommentKind::Eol, Some("x".to_string()), &agent())
        .unwrap();
    c.set(
        Address::ram(0x40_1001),
        CommentKind::Eol,
        Some("y".to_string()),
        &agent(),
    )
    .unwrap();
    assert_eq!(c.len(), 3);
    assert!(!c.is_empty());
    assert_eq!(c.get(a, CommentKind::Pre).unwrap().value, "entry");
    let kinds: Vec<CommentKind> = c.at(a).map(|(k, _)| k).collect();
    assert_eq!(kinds, [CommentKind::Eol, CommentKind::Pre]);
    assert_eq!(c.iter().count(), 3);

    let old = c
        .set(a, CommentKind::Pre, Some(String::new()), &agent())
        .unwrap();
    assert_eq!(
        old.map(|f| f.value),
        Some("entry".to_string()),
        "an empty text removes"
    );
    assert!(c.get(a, CommentKind::Pre).is_none());
    assert!(
        c.set(a, CommentKind::Eol, None, &agent())
            .unwrap()
            .is_some()
    );
    assert_eq!(c.at(a).count(), 0);
}

#[test]
fn caps_and_rule() {
    let mut c = Comments::default();
    let a = Address::ram(1);
    let long = "é".repeat(MAX_COMMENT + 1);
    assert_eq!(
        c.set(a, CommentKind::Plate, Some(long), &agent()),
        Err(WriteError::Invalid(Invalid::TooLong {
            len: MAX_COMMENT + 1,
            max: MAX_COMMENT
        }))
    );
    c.set(
        a,
        CommentKind::Plate,
        Some("é".repeat(MAX_COMMENT)),
        &agent(),
    )
    .unwrap();
    let user = Origin::new(
        Source::User,
        TxId(2),
        SessionLabel::new("cli").unwrap(),
        false,
    );
    c.set(a, CommentKind::Repeatable, Some("u".to_string()), &user)
        .unwrap();
    assert!(matches!(
        c.set(a, CommentKind::Repeatable, Some("a".to_string()), &agent()),
        Err(WriteError::Blocked(_))
    ));
}

#[test]
fn kind_codes_and_names() {
    let got: Vec<(u8, &str)> = CommentKind::ALL
        .iter()
        .map(|k| (k.code(), k.name()))
        .collect();
    assert_eq!(
        got,
        [
            (0, "eol"),
            (1, "pre"),
            (2, "post"),
            (3, "plate"),
            (4, "repeatable")
        ]
    );
    for k in CommentKind::ALL {
        assert_eq!(CommentKind::parse(k.name()), Some(k));
        assert_eq!(k.to_string(), k.name());
    }
    assert_eq!(CommentKind::parse("side"), None);
}
