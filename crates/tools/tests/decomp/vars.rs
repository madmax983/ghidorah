//! AC-105a: a variable rename or retype survives a re-decompile. AC-113b: after a signature
//! edit, each caller's decompiled call text matches its golden snippet.

use ghidorah_base::{Address, BinaryId, VarId};
use ghidorah_db::{CommentKind, Edit, VarField};
use ghidorah_json::Value;
use ghidorah_tools::Session;
use ghidorah_types::{Prim, Type, TypeId};

use crate::support::{commit, decomp, entry_of, fixture, json, program, root, text_at, text_of};

/// Gives the first type of the program store that `pick` accepts.
fn type_where(s: &Session, id: BinaryId, pick: impl Fn(&Type) -> bool) -> TypeId {
    let store = program(s, id).types().store();
    store
        .ids()
        .find(|t| store.get(*t).is_some_and(&pick))
        .expect("the store holds the type")
}

/// Gives the row of the variable `id` in a decompile section.
fn var_row(section: &Value, id: &str) -> Value {
    section
        .get("vars")
        .and_then(Value::as_array)
        .and_then(|vars| vars.iter().find(|v| text_at(v, "/id") == id).cloned())
        .unwrap_or_else(|| panic!("no variable {id}: {section}"))
}

#[test]
fn ac_105a_var_identity() {
    let (mut s, id) = fixture("loops.gcc-O0");
    let target = format!("{:#x}", entry_of(program(&s, id), "gcd"));
    let first = decomp(&mut s, &target, "{}");
    let row = first
        .get("vars")
        .and_then(Value::as_array)
        .and_then(|v| v.first().cloned())
        .expect("gcd has a variable");
    let var_text = text_at(&row, "/id");
    let old = text_at(&row, "/name");
    let var: VarId = ghidorah_base::Id::parse(&var_text)
        .ok()
        .and_then(|i| match i {
            ghidorah_base::Id::Var(v) => Some(v),
            _ => None,
        })
        .expect("a var: ID");
    commit(&mut s, id, |tx| Edit::SetVarFact {
        var: var.clone(),
        field: VarField::Name(Some(tx.fact("divisor".to_owned()))),
    });
    let renamed = decomp(&mut s, &target, "{}");
    assert_eq!(text_at(&var_row(&renamed, &var_text), "/name"), "divisor");
    assert_eq!(text_at(&var_row(&renamed, &var_text), "/source"), "agent");
    let text = text_of(&renamed);
    assert!(text.contains("divisor"), "{text}");
    assert!(
        !text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|w| w == old),
        "the old name {old} is gone:\n{text}"
    );
    let int = type_where(&s, id, |t| *t == Type::Prim(Prim::Int));
    commit(&mut s, id, |tx| Edit::SetVarFact {
        var: var.clone(),
        field: VarField::Type(Some(tx.fact(int))),
    });
    let entry = entry_of(program(&s, id), "gcd");
    commit(&mut s, id, |tx| Edit::SetComment {
        addr: Address::ram(entry),
        kind: CommentKind::Plate,
        text: Some(tx.fact("Euclid".to_owned())),
    });
    let again = decomp(&mut s, &target, "{}");
    let row = var_row(&again, &var_text);
    assert_eq!(text_at(&row, "/name"), "divisor", "{row}");
    assert_eq!(text_at(&row, "/type"), "int", "{row}");
    assert!(text_of(&again).contains("Euclid"));
}

#[test]
fn ac_113b_callers_decompile() {
    let text = std::fs::read_to_string(root().join("tests/golden/decomp/callers.json"))
        .expect("the golden file");
    let spec = json(&text);
    let s_ = |v: &Value, k: &str| text_at(v, &format!("/{k}"));
    let fixture_name: &'static str = Box::leak(s_(&spec, "fixture").into_boxed_str());
    let (mut s, id) = fixture(fixture_name);
    let callee = entry_of(program(&s, id), &s_(&spec, "callee"));
    let rows = spec
        .get("callers")
        .and_then(Value::as_array)
        .expect("callers");
    assert!(!rows.is_empty());
    for row in rows {
        let caller = format!("{:#x}", entry_of(program(&s, id), &s_(row, "caller")));
        let before = text_of(&decomp(&mut s, &caller, "{}"));
        assert!(before.contains(&s_(row, "before")), "{before}");
    }
    let sig = type_where(
        &s,
        id,
        |t| matches!(t, Type::Func(sig) if sig.params.len() == 1),
    );
    commit(&mut s, id, |tx| Edit::SetSignature {
        id: ghidorah_base::FuncId(Address::ram(callee)),
        sig: Some(tx.fact(sig)),
    });
    for row in rows {
        let caller = format!("{:#x}", entry_of(program(&s, id), &s_(row, "caller")));
        let after = text_of(&decomp(&mut s, &caller, "{}"));
        let snippet = s_(row, "snippet");
        assert!(after.contains(&snippet), "no `{snippet}` in\n{after}");
        assert!(!after.contains(&s_(row, "before")), "{after}");
    }
}
