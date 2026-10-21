//! Why trees: no cycles, rules on inner nodes, and the depth and node bounds.

use std::collections::BTreeSet;

use ghidorah_json::Value;

use crate::support::{call, call_value, data, open, program, text_at};

/// Walks a tree. Makes sure that no node repeats a fact of its path and that each inner node
/// has a rule. Gives the number of nodes.
fn walk(node: &Value, path: &mut Vec<(String, String)>, rules: &BTreeSet<String>) -> usize {
    let me = (text_at(node, "/fact"), text_at(node, "/id"));
    assert!(!me.1.is_empty(), "a node has an ID: {node}");
    assert!(
        !path.contains(&me),
        "the node {me:?} is on its own path {path:?}"
    );
    assert_ne!(node.get("cycle"), Some(&Value::Bool(true)), "{node}");
    let premises = node
        .get("premises")
        .and_then(Value::as_array)
        .expect("a node has premises");
    let rule = text_at(node, "/rule");
    if !premises.is_empty() {
        assert!(!rule.is_empty(), "an inner node has a rule: {node}");
    }
    if rule.is_empty() {
        assert!(
            !text_at(node, "/source").is_empty(),
            "a leaf has a source: {node}"
        );
    } else {
        assert!(rules.contains(&rule), "the rules list holds {rule}");
    }
    path.push(me);
    let mut count = 1;
    for p in premises {
        count += walk(p, path, rules);
    }
    path.pop();
    count
}

#[test]
fn why_tree_acyclic() {
    for fixture in ["demo", "fixtures/bin/func_ptrs.gcc-O2"] {
        let (mut s, id) = open(fixture);
        let p = program(&s, id);
        let mut ids: Vec<String> = p.funcs().iter().map(|v| v.id().to_string()).collect();
        for r in p.analysis().refs().iter().take(40) {
            if let Ok(rid) = r.value.key.id() {
                ids.push(rid.to_string());
            }
        }
        let mut trees = 0;
        for chunk in ids.chunks(10) {
            let args = Value::object([
                (
                    "explain",
                    Value::Array(chunk.iter().map(|i| Value::from(i.as_str())).collect()),
                ),
                ("depth", Value::from(10)),
                ("max_nodes", Value::from(1_000)),
            ]);
            let envelope = call_value(&mut s, "fact_check", args);
            let d = data(&envelope);
            let rules: BTreeSet<String> = d
                .get("rules")
                .and_then(Value::as_array)
                .expect("rules")
                .iter()
                .map(|r| text_at(r, "/rule"))
                .collect();
            let list = d
                .get("explanations")
                .and_then(Value::as_array)
                .expect("explanations");
            assert_eq!(list.len(), chunk.len(), "{envelope}");
            let mut nodes = 0;
            for (tree, want) in list.iter().zip(chunk) {
                assert_eq!(&text_at(tree, "/id"), want, "{tree}");
                assert!(
                    !text_at(tree, "/rule").is_empty(),
                    "{want} has a why-record"
                );
                nodes += walk(tree, &mut Vec::new(), &rules);
                trees += 1;
            }
            assert!(nodes <= 1_000, "the trees hold {nodes} nodes");
        }
        assert!(trees >= 20, "{fixture}: {trees} trees");
    }
}

#[test]
fn explain_tree_of_a_call() {
    let (mut s, _) = open("demo");
    let envelope = call(
        &mut s,
        "fact_check",
        r#"{"explain":["ref:0x10a1>0x1060:unconditional_call"],"depth":3}"#,
    );
    let tree = data(&envelope)
        .pointer("/explanations/0")
        .expect("one tree")
        .clone();
    assert_eq!(text_at(&tree, "/fact"), "ref", "{tree}");
    assert_eq!(text_at(&tree, "/rule"), "R_FLOW_REF", "{tree}");
    assert_eq!(text_at(&tree, "/premises/0/id"), "0x10a1", "{tree}");
    assert_eq!(
        text_at(&tree, "/premises/0/rule"),
        "R_DISASM_FLOW",
        "{tree}"
    );
    assert_eq!(text_at(&tree, "/premises/0/premises/0/id"), "fn:0x1080");
    let rules = data(&envelope).get("rules").expect("rules");
    assert_eq!(text_at(rules, "/0/rule"), "R_DISASM_FLOW", "{rules}");
    assert!(!text_at(rules, "/0/doc").is_empty(), "{rules}");
}

#[test]
fn explain_bounds() {
    let (mut s, _) = open("demo");
    let shallow = call(
        &mut s,
        "fact_check",
        r#"{"explain":["ref:0x10a1>0x1060:unconditional_call"],"depth":1}"#,
    );
    let tree = data(&shallow).pointer("/explanations/0").expect("a tree");
    assert_eq!(
        tree.pointer("/premises/0/truncated"),
        Some(&Value::Bool(true)),
        "the depth cuts the premises of the code unit: {tree}"
    );
    assert_eq!(
        tree.pointer("/premises/0/premises")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(0),
        "{tree}"
    );
    let one = call(
        &mut s,
        "fact_check",
        r#"{"explain":["fn:0x11e0","fn:0x1080"],"max_nodes":1}"#,
    );
    let list = data(&one)
        .get("explanations")
        .and_then(Value::as_array)
        .expect("two trees");
    let first = list.first().expect("the first tree");
    assert_eq!(first.get("truncated"), Some(&Value::Bool(true)), "{one}");
    let second = list.get(1).expect("the second tree");
    assert_eq!(text_at(second, "/id"), "fn:0x1080", "{one}");
    assert_eq!(second.get("truncated"), Some(&Value::Bool(true)), "{one}");
}
