//! `type_get`, `type_edit` and typed `mem_read` (design Sections 9.3 to 9.5).

use ghidorah_base::{Address, FuncId, Id};
use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_tools::demo as builtin;

use crate::support::{
    DEMO_ID, call, code, config_in, data, demo, items, load_demo, program, root, session_with,
    text_at, tmp,
};

/// The prototype of the signature tests.
const SIG: &str = r#"{"target":"fn:0x11e0","signature":"int check_password(const char *input)"}"#;

/// Gives the header of the type goldens on the demo binary.
fn header(generator: &str) -> Header {
    let sha = ghidorah_base::hex::encode(&ghidorah_base::sha256(builtin::BYTES));
    Header::new(generator, "1")
        .with("fixture", builtin::FIXTURE)
        .with("fixture_sha256", &sha)
}

#[test]
fn ac_113_signature_apply() {
    let mut s = demo();
    let edit = call(&mut s, "type_edit", SIG);
    let out = data(&edit);
    assert_eq!(text_at(out, "/applied/target"), "fn:0x11e0");
    assert_eq!(out.pointer("/applied/old"), Some(&Value::Null), "{edit}");
    let get = call(
        &mut s,
        "func_get",
        r#"{"target":"fn:0x11e0","include":["summary","vars"]}"#,
    );
    let signature = text_at(data(&get), "/signature");
    assert!(signature.contains("input"), "{signature}");
    let xrefs = call(
        &mut s,
        "xref_list",
        r#"{"targets":["fn:0x11e0"],"args":true}"#,
    );
    let sites = items(&xrefs);
    let args: Vec<Value> = sites
        .iter()
        .map(|i| i.get("args").cloned().unwrap_or(Value::Null))
        .collect();
    assert!(
        args.iter()
            .any(|a| a.pointer("/0/name").and_then(Value::as_str) == Some("input")),
        "the argument label comes from the signature: {xrefs}"
    );
    let doc = Value::object([
        ("type_edit", out.clone()),
        ("signature", Value::from(signature)),
        (
            "vars",
            data(&get).get("vars").cloned().unwrap_or(Value::Null),
        ),
        ("args", Value::Array(args)),
    ]);
    golden::assert_json(
        &root().join("tests/golden/types/sig_apply.json"),
        &header("sig_apply"),
        &write_pretty(&doc),
    );
}

#[test]
fn ac_114_typed_read() {
    let mut s = demo();
    let envelope = call(
        &mut s,
        "mem_read",
        r#"{"target":"0x2004","as":"type","c":"struct sockaddr_in"}"#,
    );
    let fields = data(&envelope)
        .get("fields")
        .and_then(Value::as_array)
        .expect("the field rows");
    let paths: Vec<String> = fields.iter().map(|f| text_at(f, "/path")).collect();
    assert_eq!(
        paths,
        ["sin_family", "sin_port", "sin_addr.s_addr", "sin_zero"],
        "{envelope}"
    );
    let offsets: Vec<u64> = fields
        .iter()
        .filter_map(|f| f.get("offset").and_then(Value::as_u64))
        .collect();
    assert_eq!(offsets, [0, 2, 4, 8]);
    let doc = Value::object([("fields", Value::Array(fields.to_vec()))]);
    golden::assert_json(
        &root().join("tests/golden/types/typed_read.json"),
        &header("typed_read"),
        &write_pretty(&doc),
    );
    // The applied data type and type_get give the same layout.
    let get = call(&mut s, "type_get", r#"{"target":"t:sockaddr_in"}"#);
    let names: Vec<String> = data(&get)
        .get("fields")
        .and_then(Value::as_array)
        .expect("the fields of type_get")
        .iter()
        .map(|f| text_at(f, "/name"))
        .collect();
    assert_eq!(names, ["sin_family", "sin_port", "sin_addr", "sin_zero"]);
}

#[test]
fn type_get_gives_the_layout() {
    let mut s = demo();
    let envelope = call(&mut s, "type_get", r#"{"target":"t:sockaddr_in"}"#);
    let out = data(&envelope);
    assert_eq!(text_at(out, "/id"), "t:sockaddr_in");
    assert_eq!(text_at(out, "/kind"), "struct");
    assert_eq!(out.get("size").and_then(Value::as_u64), Some(16));
    assert_eq!(out.get("align").and_then(Value::as_u64), Some(4));
    let layout = out.get("layout").and_then(Value::as_array).expect("lines");
    assert_eq!(layout.len(), 4, "{envelope}");
    assert!(
        layout
            .iter()
            .any(|l| l.as_str().is_some_and(|t| t.starts_with("+0x8 "))),
        "{envelope}"
    );
    assert!(
        text_at(out, "/c").starts_with("struct sockaddr_in {"),
        "{envelope}"
    );
    let ptr = call(
        &mut s,
        "type_get",
        r#"{"c":"struct timespec *","include":["decl"]}"#,
    );
    let out = data(&ptr);
    assert_eq!(text_at(out, "/kind"), "ptr");
    assert_eq!(out.get("size").and_then(Value::as_u64), Some(8));
    assert!(out.get("layout").is_none(), "no layout part: {ptr}");
    assert!(text_at(out, "/id").starts_with("t:#"), "{ptr}");
    let void = call(&mut s, "type_get", r#"{"target":"void"}"#);
    assert_eq!(data(&void).get("size"), Some(&Value::Null), "{void}");
    let named = call(
        &mut s,
        "type_get",
        r#"{"target":"size_t","include":["layout"]}"#,
    );
    let out = data(&named);
    assert_eq!(text_at(out, "/kind"), "typedef");
    assert_eq!(text_at(out, "/name"), "size_t");
    assert!(out.get("c").is_none(), "no decl part: {named}");
}

#[test]
fn type_get_errors() {
    let mut s = demo();
    let before = program(&s).types().store().len();
    let unknown = call(&mut s, "type_get", r#"{"target":"sockadr_in"}"#);
    assert_eq!(code(&unknown), "NOT_FOUND", "{unknown}");
    assert!(
        unknown
            .pointer("/error/candidates")
            .and_then(Value::as_array)
            .is_some_and(|c| c
                .iter()
                .any(|v| text_at(v, "/value").contains("sockaddr_in"))),
        "{unknown}"
    );
    let bad = call(&mut s, "type_get", r#"{"c":"struct {"}"#);
    assert_eq!(code(&bad), "C_PARSE_ERROR", "{bad}");
    assert!(
        bad.pointer("/error/details/errors/0/code").is_some(),
        "{bad}"
    );
    let fresh = call(&mut s, "type_get", r#"{"c":"unsigned char (*)[7]"}"#);
    data(&fresh);
    assert_eq!(
        program(&s).types().store().len(),
        before,
        "type_get changes no type"
    );
}

#[test]
fn type_edit_applies_variable_and_data_types() {
    let mut s = demo();
    let var = call(
        &mut s,
        "type_edit",
        r#"{"target":"var:0x11e0/param:0","type":"const char *"}"#,
    );
    let out = data(&var);
    assert_eq!(text_at(out, "/applied/new"), "const char *");
    assert!(
        out.get("analysis").is_none(),
        "a variable type is not analysis-affecting"
    );
    let Ok(Id::Var(v)) = Id::parse("var:0x11e0/param:0") else {
        panic!("a variable ID");
    };
    assert!(program(&s).var(&v).ty.is_some());
    let data_edit = call(
        &mut s,
        "type_edit",
        r#"{"target":"0x2004","type":"char [26]"}"#,
    );
    let out = data(&data_edit);
    assert_eq!(text_at(out, "/applied/target"), "0x2004");
    assert_eq!(text_at(out, "/analysis/state"), "complete", "{data_edit}");
    let def = program(&s).data_def(0x2004).expect("the data definition");
    assert_eq!(def.value.len, 26);
    let again = call(
        &mut s,
        "type_edit",
        r#"{"target":"0x2004","type":"char [26]"}"#,
    );
    assert_eq!(again.get("noop"), Some(&Value::Bool(true)), "{again}");
    let changed = call(
        &mut s,
        "type_edit",
        r#"{"target":"0x2004","type":"char [8]"}"#,
    );
    assert_eq!(text_at(data(&changed), "/applied/old"), "char [26]");
}

#[test]
fn type_edit_errors() {
    let mut s = demo();
    let rev = program(&s).rev();
    let types = program(&s).types().store().len();
    let bad = call(
        &mut s,
        "type_edit",
        r#"{"target":"fn:0x11e0","signature":"int check_password("}"#,
    );
    assert_eq!(code(&bad), "C_PARSE_ERROR", "{bad}");
    let on_var = call(
        &mut s,
        "type_edit",
        r#"{"target":"var:0x11e0/param:0","signature":"int f(int a)"}"#,
    );
    assert_eq!(code(&on_var), "INVALID_ARGUMENT", "{on_var}");
    let on_func = call(
        &mut s,
        "type_edit",
        r#"{"target":"fn:0x11e0","type":"int"}"#,
    );
    assert_eq!(code(&on_func), "INVALID_ARGUMENT", "{on_func}");
    let no_func = call(
        &mut s,
        "type_edit",
        r#"{"target":"fn:0x11d0","signature":"int f(int a)"}"#,
    );
    assert_eq!(code(&no_func), "NOT_FOUND", "{no_func}");
    let no_size = call(&mut s, "type_edit", r#"{"target":"0x2004","type":"void"}"#);
    assert_eq!(code(&no_size), "INVALID_ARGUMENT", "{no_size}");
    assert_eq!(program(&s).rev(), rev, "no error commits");
    assert_eq!(
        program(&s).types().store().len(),
        types,
        "no error adds a type"
    );
}

#[test]
fn type_edit_survives_reopen() {
    let dir = tmp("types");
    let want;
    {
        let mut s = session_with(config_in(&dir));
        load_demo(&mut s);
        data(&call(&mut s, "type_edit", SIG));
        data(&call(
            &mut s,
            "type_edit",
            r#"{"target":"var:0x11e0/param:0","type":"const unsigned char *"}"#,
        ));
        want = program(&s).state_hash().expect("a hash");
    }
    let mut s = session_with(config_in(&dir));
    data(&call(
        &mut s,
        "binary_load",
        &format!(r#"{{"binary_id":"{DEMO_ID}"}}"#),
    ));
    assert_eq!(program(&s).state_hash().expect("a hash"), want);
    let sig = program(&s)
        .func(FuncId(Address::ram(0x11e0)))
        .and_then(|v| v.sig)
        .map(|f| f.value)
        .expect("the signature persists");
    let text = program(&s).types().store().c_text(sig).expect("a text");
    assert!(text.contains("input"), "{text}");
}
