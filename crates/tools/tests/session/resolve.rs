//! The address resolver: the rule order, the errors and the target table (AC-138, AC-215).

use ghidorah_base::{Address, BinaryId, FuncId};
use ghidorah_db::Program;
use ghidorah_json::Value;
use ghidorah_tools::resolve::{
    Family, Named, Resolved, Rule, Site, Target, accepted, address, function, resolve, target,
    value_of,
};
use ghidorah_tools::{Call, Session};

use crate::support::{
    DEMO_ID, DEMO_MAIN, add_function, call_value, code, data, demo, fixture, json, text_at,
};

/// The names of the `adversarial_names` fixture with their symbol addresses (gcc -O2).
const ADVERSARIAL: [(&str, u64); 5] = [
    ("x@plt", 0x11b0),
    ("puts@GLIBC_2.2.5", 0x11c0),
    ("FUN_00401000", 0x11d0),
    (".fini", 0x11e0),
    ("foo.cold", 0x11f0),
];

/// The two `helper` functions of the `two_helpers` fixture (gcc -O2).
const HELPERS: [u64; 2] = [0x1190, 0x11c0];

fn program<'s>(session: &'s Session, id: &str) -> &'s Program {
    let id = BinaryId::parse(id).expect("a binary ID");
    &session.binary(id).expect("the binary is open").program
}

fn resolve_str(p: &Program, text: &str) -> Result<Resolved, ghidorah_tools::ToolError> {
    resolve(p, &Value::from(text), &Site::default())
}

fn addr_of(p: &Program, text: &str) -> u64 {
    let resolved = resolve_str(p, text).unwrap_or_else(|e| panic!("{text}: {e}"));
    value_of(p, &resolved).expect("an address").off
}

fn candidate_values(error: &ghidorah_tools::ToolError) -> Vec<String> {
    error
        .candidates
        .iter()
        .map(|c| c.value.as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn ac_138_ambiguous_names() {
    let (s, id) = fixture("two_helpers.gcc-O2");
    let p = program(&s, &id);
    let error = resolve_str(p, "helper").expect_err("two matches");
    assert_eq!(error.code, ghidorah_base::ErrorCode::AmbiguousName);
    let want: Vec<String> = HELPERS.iter().map(|a| format!("helper@{a:#x}")).collect();
    assert_eq!(candidate_values(&error), want);
    let json = error.to_json();
    assert_eq!(json.pointer("/candidates_total"), Some(&Value::from(2_u64)));
    let addrs: Vec<String> = error
        .candidates
        .iter()
        .filter_map(|c| c.addr.clone())
        .collect();
    assert_eq!(addrs, ["0x1190", "0x11c0"]);
    for (value, want) in want.iter().zip(HELPERS) {
        let resolved = resolve_str(p, value).expect("the candidate resolves");
        assert_eq!(resolved.rule, Rule::NameAt);
        assert_eq!(resolved.named, Named::Addr(Address::ram(want)));
    }
    let error = resolve_str(p, "sym:helper").expect_err("the sym: form is also ambiguous");
    assert_eq!(error.code, ghidorah_base::ErrorCode::AmbiguousName);
    assert!(
        resolve_str(p, "helper@0x1191").is_err(),
        "no helper at 0x1191"
    );

    let mut s = s;
    let envelope = call_value(
        &mut s,
        "calc",
        Value::object([("expr", Value::from("helper"))]),
    );
    assert_eq!(code(&envelope), "AMBIGUOUS_NAME", "{envelope}");
    let envelope = call_value(
        &mut s,
        "calc",
        Value::object([("expr", Value::from("helper@0x11c0 + 0x2"))]),
    );
    assert_eq!(text_at(data(&envelope), "/value"), "0x11c2");
}

#[test]
fn ac_215_adversarial_names() {
    let (s, id) = fixture("adversarial_names.gcc-O2");
    let p = program(&s, &id);
    for (name, want) in ADVERSARIAL {
        let resolved = resolve_str(p, &format!("sym:{name}")).expect("the sym: form resolves");
        assert_eq!(resolved.rule, Rule::Id, "{name}");
        assert_eq!(
            value_of(p, &resolved).ok(),
            Some(Address::ram(want)),
            "{name}"
        );
        match resolve_str(p, name) {
            Ok(bare) => {
                assert_eq!(bare.rule, Rule::Symbol, "{name} resolves by rule 4");
                assert_eq!(value_of(p, &bare).ok(), Some(Address::ram(want)), "{name}");
            }
            Err(e) => {
                assert_eq!(
                    e.code,
                    ghidorah_base::ErrorCode::AmbiguousName,
                    "{name}: {e}"
                );
                let addrs: Vec<String> =
                    e.candidates.iter().filter_map(|c| c.addr.clone()).collect();
                assert!(addrs.contains(&format!("{want:#x}")), "{name}: {addrs:?}");
                for value in candidate_values(&e) {
                    assert!(resolve_str(p, &value).is_ok(), "{value} resolves");
                }
            }
        }
    }
    // The section .fini is not the symbol .fini.
    let section = resolve_str(p, "sec:17:.fini").expect("the section ID resolves");
    assert_eq!(value_of(p, &section).ok(), Some(Address::ram(0x11f8)));
    // The real FUN_00401000 hides the default name of 0x401000.
    assert_eq!(addr_of(p, "FUN_00401000"), 0x11d0);
    assert_eq!(addr_of(p, "FUN_00001060"), 0x1060);
    assert_eq!(
        resolve_str(p, "FUN_00001060").map(|r| r.rule).ok(),
        Some(Rule::DefaultName)
    );
}

#[test]
fn resolver_rule_order() {
    let s = demo();
    let p = program(&s, DEMO_ID);
    let main = Address::ram(DEMO_MAIN);
    let cases: [(Value, Rule, Named); 9] = [
        (json("4224"), Rule::Integer, Named::Addr(main)),
        (Value::from("0x1080"), Rule::Hex, Named::Addr(main)),
        (Value::from("bb:0x1080"), Rule::Id, Named::Addr(main)),
        (Value::from("sym:main"), Rule::Id, Named::Addr(main)),
        (Value::from("main"), Rule::Symbol, Named::Addr(main)),
        (Value::from(".text"), Rule::Section, Named::Addr(main)),
        (
            Value::from("LAB_00001080"),
            Rule::DefaultName,
            Named::Addr(main),
        ),
        (Value::from("main@0x1080"), Rule::NameAt, Named::Addr(main)),
        (
            Value::from("check_password-0x160"),
            Rule::Offset,
            Named::Addr(main),
        ),
    ];
    for (input, rule, named) in cases {
        let resolved =
            resolve(p, &input, &Site::default()).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(resolved.rule, rule, "{input}");
        assert_eq!(resolved.named, named, "{input}");
        let from = resolved.resolved_from();
        assert_eq!(text_at(&from, "/rule"), rule.name(), "{input}");
        assert!(!text_at(&from, "/matched").is_empty(), "{input}");
    }
    let names: Vec<&str> = Rule::ALL.iter().map(|r| r.name()).collect();
    assert_eq!(
        names,
        [
            "integer",
            "hex",
            "id",
            "symbol",
            "section",
            "default_name",
            "name_at",
            "offset"
        ]
    );
    let imp = resolve_str(p, "imp:puts").expect("the import resolves");
    assert!(matches!(imp.named, Named::Import(_)), "{imp:?}");
    let stub = value_of(p, &imp).expect("the stub address");
    assert!((0x1020..0x1080).contains(&stub.off), "{stub}");
    let ext = resolve_str(p, "ext:0x1").expect("an EXTERNAL address");
    assert_eq!(value_of(p, &ext).ok(), Some(Address::external(1)));
    let fun = resolve_str(p, "fn:0x1080").expect_err("no function without analysis");
    assert_eq!(fun.code, ghidorah_base::ErrorCode::NotFound);
}

#[test]
fn resolver_errors() {
    let s = demo();
    let p = program(&s, DEMO_ID);
    let error = resolve_str(p, "4224").expect_err("digits only");
    assert_eq!(error.code, ghidorah_base::ErrorCode::AddressBaseAmbiguous);
    assert_eq!(candidate_values(&error), ["0x1080", "0x4224"]);
    let labels: Vec<&str> = error.candidates.iter().map(|c| c.label.as_str()).collect();
    assert!(
        labels[0].contains("mapped") && labels[1].contains("not mapped"),
        "{labels:?}"
    );
    let error = resolve_str(p, "main+16").expect_err("a digits offset");
    assert_eq!(error.code, ghidorah_base::ErrorCode::AddressBaseAmbiguous);
    assert_eq!(candidate_values(&error), ["main+0x10", "main+0x16"]);

    let error = resolve_str(p, "mian").expect_err("an unknown name");
    assert_eq!(error.code, ghidorah_base::ErrorCode::NotFound);
    assert_eq!(
        candidate_values(&error).first().map(String::as_str),
        Some("main")
    );
    let error = resolve_str(p, "0xffffffffffffffff+0x1").expect_err("the offset wraps");
    assert_eq!(error.code, ghidorah_base::ErrorCode::AddressInvalid);
    let error = resolve(p, &json("9007199254740992"), &Site::default()).expect_err("2^53");
    assert_eq!(error.code, ghidorah_base::ErrorCode::AddressInvalid);
    let error = resolve(p, &json("true"), &Site::default()).expect_err("a boolean");
    assert_eq!(error.code, ghidorah_base::ErrorCode::InvalidArgument);
    let error = resolve_str(p, "imp:no_such_import").expect_err("an unknown import");
    assert_eq!(error.code, ghidorah_base::ErrorCode::NotFound);
    let error = resolve_str(p, "sec:16:.data").expect_err("the index has another name");
    assert_eq!(error.code, ghidorah_base::ErrorCode::NotFound);
    let error = resolve_str(p, "seg:99").expect_err("no such segment");
    assert_eq!(error.code, ghidorah_base::ErrorCode::NotFound);

    let repair = |text: &str| {
        Call::new(
            "calc",
            Value::object([("expr", Value::from(text))]),
            "Send the address as a 0x hex string.",
        )
    };
    let site = Site {
        path: "/target",
        repair: Some(&repair),
    };
    let error = resolve(p, &Value::from("1080abc"), &site).expect_err("bare hex text");
    assert_eq!(error.code, ghidorah_base::ErrorCode::AddressInvalid);
    assert_eq!(error.field_path.as_deref(), Some("/target"));
    let next = error.next.first().expect("a repair call");
    assert_eq!(text_at(&next.args, "/expr"), "0x1080abc");

    let unmapped = address(p, &Value::from("0x100000"), &Site::default()).expect_err("not mapped");
    assert_eq!(unmapped.code, ghidorah_base::ErrorCode::AddressUnmapped);
    assert!(
        !unmapped.candidates.is_empty(),
        "the nearest mapped addresses"
    );
}

#[test]
fn target_table() {
    let mut s = demo();
    add_function(&mut s, DEMO_ID, DEMO_MAIN, 0x53);
    let p = program(&s, DEMO_ID);
    let main = FuncId(Address::ram(DEMO_MAIN));
    let get = |text: &str, family: Family| {
        let resolved = resolve_str(p, text).unwrap_or_else(|e| panic!("{text}: {e}"));
        target(p, &resolved, family)
    };
    assert_eq!(
        get("main+0x10", Family::Function).ok(),
        Some(Target::Func(main))
    );
    assert_eq!(
        get("fn:0x1080", Family::Address).ok(),
        Some(Target::Addr(main.0))
    );
    assert_eq!(
        get("fn:0x1080", Family::XrefFrom).ok(),
        Some(Target::RefsFromBody(main))
    );
    assert_eq!(
        get("main+0x4", Family::XrefFrom).ok(),
        Some(Target::RefsFromInsn(Address::ram(DEMO_MAIN + 4)))
    );
    assert_eq!(
        get("str:0x2004", Family::XrefTo).ok(),
        Some(Target::RefsTo(Address::ram(0x2004)))
    );
    assert!(matches!(
        get("imp:puts", Family::XrefTo),
        Ok(Target::ImportSites(_))
    ));
    assert!(matches!(
        get("sys:1", Family::XrefTo),
        Ok(Target::SyscallSites(_))
    ));
    assert!(matches!(
        get("jt:0x1090", Family::XrefFrom),
        Ok(Target::CaseEdges(_))
    ));
    assert_eq!(
        get("jt:0x1090", Family::Function).ok(),
        Some(Target::Func(main))
    );
    let not_in = get("0x11e0", Family::Function).expect_err("no function at check_password");
    assert_eq!(not_in.code, ghidorah_base::ErrorCode::NotInFunction);
    for (text, family) in [
        ("sys:1", Family::Address),
        ("note:1", Family::Address),
        ("str:0x2004", Family::Function),
        ("sec:16:.text", Family::Function),
        ("imp:puts", Family::XrefFrom),
        ("t:int", Family::XrefTo),
    ] {
        let error = get(text, family).expect_err("an invalid kind");
        assert_eq!(
            error.code,
            ghidorah_base::ErrorCode::InvalidArgument,
            "{text}"
        );
        let listed = error
            .details
            .as_ref()
            .and_then(|d| d.get("accepted"))
            .and_then(Value::as_array)
            .map(<[Value]>::len);
        assert_eq!(listed, Some(accepted(family).len()), "{text}");
    }
    for family in [
        Family::Address,
        Family::Function,
        Family::XrefTo,
        Family::XrefFrom,
    ] {
        assert!(!accepted(family).is_empty());
    }
    let (f, _) = function(p, &Value::from("main+0x8"), &Site::default()).expect("a function");
    assert_eq!(f, main);
    let (a, _) = address(p, &Value::from("main"), &Site::default()).expect("an address");
    assert_eq!(a, main.0);
}
