//! The ID forms of `key_of` and the shape of why trees.

use ghidorah_analysis::facts::{ExplainError, explain, fact_name, key_of};
use ghidorah_base::{FuncId, StringId};
use ghidorah_db::{FactKey, Source};

use crate::support::{analyzed, ram};

#[test]
fn key_of_reads_each_form() {
    let p = analyzed("crackme.gcc-O2");
    let key = |t: &str| key_of(&p, t);
    assert_eq!(key("fn:0x1080"), Ok(FactKey::Func(FuncId(ram(0x1080)))));
    assert_eq!(key("0x1091"), Ok(FactKey::CodeUnit(0x1091)));
    assert_eq!(key("str:0x2004"), Ok(FactKey::Str(StringId(ram(0x2004)))));
    let r = key("ref:0x1091>0x11e0:unconditional_call").expect("the reference");
    assert!(matches!(r, FactKey::Ref(k) if k.from == ram(0x1091)));
    let s = key("sym:main").expect("the symbol");
    assert!(matches!(s, FactKey::Symbol(a, _) if a == ram(0x1080)));
    assert!(matches!(key("imp:puts"), Ok(FactKey::Import(_))));
    assert_eq!(key("fn:0x9999"), Err(ExplainError::NotFound("function")));
    assert!(matches!(key("t:int"), Err(ExplainError::BadId(_))));
    assert!(matches!(
        key("ref:0x1091>0x1092:read"),
        Err(ExplainError::NotFound(_))
    ));
    assert!(matches!(key("no id"), Err(ExplainError::BadId(_))));
    assert_eq!(fact_name(&FactKey::Entry(0)), "entry");
    assert!(!ExplainError::NotFound("ref").to_string().is_empty());
}

#[test]
fn tree_of_a_function() {
    let p = analyzed("crackme.gcc-O2");
    let key = FactKey::Func(FuncId(ram(0x11e0)));
    let mut nodes = 100;
    let tree = explain(&p, &key, 5, &mut nodes);
    assert_eq!(tree.id, "fn:0x11e0");
    assert_eq!(
        tree.rule.as_ref().map(ghidorah_db::RuleCode::as_str),
        Some("R_SYMBOL_FUNC")
    );
    assert_eq!(tree.premises.len(), 1);
    let leaf = tree.premises.first().expect("the symbol");
    assert_eq!(leaf.id, "sym:check_password");
    assert_eq!(leaf.source, Some(Source::Imported));
    assert!(leaf.premises.is_empty() && !leaf.truncated && !leaf.cycle);
    assert_eq!(nodes, 98, "the walk takes one unit per node");
}

#[test]
fn tree_bounds() {
    let p = analyzed("crackme.gcc-O2");
    let key = key_of(&p, "ref:0x1091>0x11e0:unconditional_call").expect("the reference");
    let mut nodes = 100;
    let flat = explain(&p, &key, 0, &mut nodes);
    assert!(flat.premises.is_empty() && flat.truncated, "{flat:?}");
    let mut none = 0;
    let root = explain(&p, &key, 5, &mut none);
    assert_eq!(root.id, "ref:0x1091>0x11e0:unconditional_call");
    assert!(root.premises.is_empty() && root.truncated, "{root:?}");
    let mut two = 2;
    let cut = explain(&p, &key, 5, &mut two);
    assert_eq!(cut.premises.len(), 1);
    assert!(cut.premises.first().is_some_and(|n| n.truncated));
    assert_eq!(two, 0);
}
