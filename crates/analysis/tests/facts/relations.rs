//! The relation catalog, the reference classes and the outcome rules.

use ghidorah_analysis::facts::{
    CATALOG, ColKind, Evidence, Gap, NAMES, Outcome, RefClass, Relation, Verdict,
};
use ghidorah_base::{Address, FuncId};
use ghidorah_db::{RefKey, RefType};

#[test]
fn catalog_rows_match_the_relations() {
    assert_eq!(CATALOG.len(), Relation::ALL.len());
    for (i, rel) in Relation::ALL.into_iter().enumerate() {
        let row = rel.spec();
        assert_eq!(row.relation, rel);
        assert_eq!(Some(&row.name), NAMES.get(i));
        assert_eq!(Relation::parse(row.name), Some(rel));
        assert!(
            !row.columns.is_empty() && row.columns.len() <= 3,
            "{}",
            row.name
        );
        assert!(!row.doc.is_empty() && !row.index.is_empty(), "{}", row.name);
        let first_optional = row.columns.iter().position(|c| c.optional);
        if let Some(k) = first_optional {
            assert!(
                row.columns.iter().skip(k).all(|c| c.optional),
                "only the last columns of {} are optional",
                row.name
            );
        }
        assert_eq!(row.required(), first_optional.unwrap_or(row.columns.len()));
    }
    assert_eq!(Relation::parse("returns_const"), None);
    let calls = Relation::Calls.spec();
    let g = calls.columns.get(1).expect("the column g");
    assert_eq!(g.kinds, [ColKind::Func, ColKind::Import, ColKind::Syscall]);
    let names: Vec<&str> = g.kinds.iter().map(|k| k.name()).collect();
    assert_eq!(names, ["fn", "imp", "sys"]);
    assert_eq!(Relation::Reaches.spec().required(), 2);
    assert_eq!(Relation::Xref.spec().required(), 2);
    assert_eq!(Relation::Noreturn.to_string(), "noreturn");
}

#[test]
fn ref_classes_match_types() {
    let call = RefClass::parse("call").expect("a class");
    assert!(call.matches(RefType::UnconditionalCall));
    assert!(call.matches(RefType::ComputedCall));
    assert!(!call.matches(RefType::UnconditionalJump));
    let jump = RefClass::parse("jump").expect("a class");
    assert!(jump.matches(RefType::ComputedJump));
    let read = RefClass::parse("read").expect("a class");
    assert!(read.matches(RefType::ReadWrite) && !read.matches(RefType::Write));
    let write = RefClass::parse("write").expect("a class");
    assert!(write.matches(RefType::ReadWrite) && !write.matches(RefType::Read));
    let data = RefClass::parse("data").expect("a type name");
    assert_eq!(data, RefClass::Type(RefType::Data));
    assert!(data.matches(RefType::Data) && !data.matches(RefType::Read));
    assert_eq!(RefClass::parse("nope"), None);
}

#[test]
fn outcome_sorts_and_weakens() {
    let site = Address::ram(0x20);
    let key = RefKey {
        from: Address::ram(0x10),
        op_index: 0,
        to: Address::ram(0x30),
        kind: RefType::Read,
    };
    let mut o = Outcome::new(
        Verdict::Refuted,
        vec![
            Evidence::Site(site),
            Evidence::Ref(key),
            Evidence::Site(site),
        ],
        vec![Gap::Func(FuncId(site)), Gap::Site(site)],
    );
    assert_eq!(o.evidence, [Evidence::Ref(key), Evidence::Site(site)]);
    assert_eq!(o.gaps, [Gap::Site(site), Gap::Func(FuncId(site))]);
    assert!(!o.complete());
    let texts: Vec<String> = o.evidence.iter().map(Evidence::text).collect();
    assert_eq!(texts, ["ref:0x10>0x30:read", "0x20"]);
    let gaps: Vec<String> = o.gaps.iter().map(Gap::text).collect();
    assert_eq!(gaps, ["0x20", "fn:0x20"]);
    o.weaken();
    assert_eq!(o.verdict, Verdict::Unknown);
    let mut s = Outcome::new(Verdict::Supported, Vec::new(), Vec::new());
    s.weaken();
    assert_eq!(s.verdict, Verdict::Supported);
    assert!(s.complete());
    let stopped = Outcome::out_of_fuel();
    assert!(stopped.stopped && !stopped.complete());
    assert_eq!(stopped.verdict.name(), "unknown");
}
