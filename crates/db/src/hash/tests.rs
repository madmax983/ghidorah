use ghidorah_base::FuncId;

use crate::comments::CommentKind;
use crate::edit::Edit;
use crate::fact::Origin;
use crate::progress::FuncProgress;
use crate::source::Source;
use crate::tests::{fixture, ram, seeded, session};

#[test]
fn state_hash_tracks_facts_only() {
    let mut p = seeded();
    let start = p.state_hash().unwrap();
    assert_eq!(start.to_string().len(), 64);
    assert!(start.to_string().bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(p.clone().state_hash().unwrap(), start);
    assert_ne!(fixture("hello.gcc-O2").state_hash().unwrap(), start);
    assert_ne!(
        fixture("hello.gcc-O2").state_hash().unwrap(),
        fixture("hello.gcc-O2.stripped").state_hash().unwrap()
    );
    // Progress rows are session metadata.
    p.progress_mut().set(
        FuncId(ram(0x1080)),
        FuncProgress {
            visited: true,
            ..FuncProgress::default()
        },
    );
    assert_eq!(p.state_hash().unwrap(), start);
    let mut tx = p
        .begin("comment_set", Source::Agent, session("mcp-1"))
        .unwrap();
    let c = Edit::SetComment {
        addr: ram(0x1084),
        kind: CommentKind::Pre,
        text: Some(tx.fact("x".to_string())),
    };
    tx.apply(c).unwrap();
    assert_ne!(tx.program().state_hash().unwrap(), start);
    drop(tx);
    assert_eq!(p.state_hash().unwrap(), start);
}

#[test]
fn state_hash_ignores_insertion_order() {
    let mut a = seeded();
    let mut b = seeded();
    let o = Origin::analysis();
    let comments = [(0x1084, "one"), (0x1088, "two"), (0x108c, "three")];
    for (at, text) in comments {
        a.analysis_at_mut(ghidorah_base::Address::ram(0x1000))
            .comments
            .set(ram(at), CommentKind::Eol, Some(text.to_string()), &o)
            .unwrap();
    }
    for (at, text) in comments.into_iter().rev() {
        b.analysis_at_mut(ghidorah_base::Address::ram(0x1000))
            .comments
            .set(ram(at), CommentKind::Eol, Some(text.to_string()), &o)
            .unwrap();
    }
    assert_eq!(a.state_hash().unwrap(), b.state_hash().unwrap());
    assert_ne!(a.state_hash().unwrap(), seeded().state_hash().unwrap());
}
