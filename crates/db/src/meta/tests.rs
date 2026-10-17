//! Tests of meta lines.

use ghidorah_base::{Address, FuncId, Rev};

use super::{MetaLine, apply};
use crate::progress::FuncProgress;
use crate::tests::{seeded, session};

#[test]
fn folds_are_idempotent_and_keep_the_higher_rev() {
    let mut p = seeded();
    let hash = p.state_hash().unwrap();
    let func = FuncId(Address::ram(0x1080));
    let row = FuncProgress {
        visited: true,
        named: true,
        ..FuncProgress::default()
    };
    let line = MetaLine::Progress { func, row };
    apply(&mut p, &line);
    apply(&mut p, &line);
    assert_eq!(p.progress().get(func), row);
    let label = session("mcp-1");
    apply(
        &mut p,
        &MetaLine::Brief {
            session: label.clone(),
            rev: Rev(7),
        },
    );
    apply(
        &mut p,
        &MetaLine::Brief {
            session: label.clone(),
            rev: Rev(3),
        },
    );
    assert_eq!(
        p.progress().mark(&label).map(|m| m.last_brief_rev),
        Some(Rev(7))
    );
    assert_eq!(p.state_hash().unwrap(), hash, "meta lines change no fact");
    assert_eq!(p.rev(), Rev(0), "meta lines change no rev");
}

#[test]
fn json_form_reads_back() {
    let line = MetaLine::Brief {
        session: session("mcp-1"),
        rev: Rev(57),
    };
    let mut members: Vec<(&str, ghidorah_json::Value)> =
        vec![("v", ghidorah_json::Value::from(1u64))];
    members.extend(line.members());
    let value = ghidorah_json::Value::object(members);
    assert_eq!(MetaLine::from_json(&value), Ok(line));
    let bad = ghidorah_json::Value::object([("meta", ghidorah_json::Value::from("other"))]);
    assert!(MetaLine::from_json(&bad).is_err());
}
