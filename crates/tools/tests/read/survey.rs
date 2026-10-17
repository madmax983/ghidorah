//! `binary_survey`: other machines, language hints, the survey floor and cut sections
//! (AC-056b, AC-115b, AC-153a).

use ghidorah_json::Value;
use ghidorah_testkit::elf::{ElfBuilder, ImportKind, Loc, Section, Symbol};
use ghidorah_tools::hints::{Call, check};

use crate::support::{
    call, call_value, chars, code, data, fixture, load_bytes, registry, session_with, str_of,
    text_at, truth, truth_fixtures, warnings,
};

/// `EM_AARCH64`.
const EM_AARCH64: u16 = 183;

#[test]
fn ac_056b_other_arch_survey() {
    let code_bytes = [0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
    let b = ElfBuilder::exec()
        .machine(EM_AARCH64)
        .section(Section::code(".text", &code_bytes))
        .section(Section::rodata(".rodata", b"aarch64 text\0"))
        .symbol(Symbol::func("main", Loc::section(".text", 0), 8))
        .entry(Loc::symbol("main"));
    let (mut session, load) = load_bytes("ac_056b", &b.build(), "full");
    assert_eq!(text_at(&load, "/data/arch"), "other:183", "{load}");
    assert_eq!(warnings(&load, "W_ARCH_UNSUPPORTED"), 1, "{load}");
    let survey = call(&mut session, "binary_survey", "{}");
    let d = data(&survey);
    assert_eq!(warnings(&survey, "W_ARCH_UNSUPPORTED"), 1, "{survey}");
    assert_eq!(text_at(d, "/identity/arch"), "other:183");
    let sections = d
        .pointer("/sections/items")
        .and_then(Value::as_array)
        .expect("the sections list");
    assert!(
        sections.iter().any(|s| str_of(s, "name") == ".text"),
        "{survey}"
    );
    assert_eq!(
        d.pointer("/functions/total").and_then(Value::as_u64),
        Some(0)
    );
    let func = call(&mut session, "func_get", r#"{"target":"main"}"#);
    assert_eq!(code(&func), "UNSUPPORTED_ARCH", "{func}");
    let sweep = call(
        &mut session,
        "mem_read",
        r#"{"target":"main","as":"insn","count":2}"#,
    );
    assert_eq!(code(&sweep), "UNSUPPORTED_ARCH", "{sweep}");
    let hex = call(&mut session, "mem_read", r#"{"target":"main","len":8}"#);
    assert_eq!(text_at(data(&hex), "/hex"), "1f2003d5c0035fd6");
}

/// Gives the language hints of a survey: `(lang, count)` pairs in output order.
fn languages(envelope: &Value) -> Vec<(String, u64)> {
    data(envelope)
        .pointer("/languages/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|h| {
            (
                str_of(h, "lang"),
                h.get("count").and_then(Value::as_u64).unwrap_or(0),
            )
        })
        .collect()
}

#[test]
fn ac_115b_language_hints() {
    let code_bytes = [0xc3; 8];
    let at = |off| Loc::section(".text", off);
    let cpp = ElfBuilder::exec()
        .section(Section::code(".text", &code_bytes))
        .symbol(Symbol::func("_ZN3foo3barEv", at(0), 1))
        .symbol(Symbol::func("_ZN3foo3bazEv", at(1), 1))
        .import("__cxa_atexit", ImportKind::Plt);
    let rust = ElfBuilder::exec()
        .section(Section::code(".text", &code_bytes))
        .symbol(Symbol::func("_RNvCs1234_7mycrate3foo", at(0), 1))
        .symbol(Symbol::func("rust_begin_unwind", at(1), 1));
    let go = ElfBuilder::exec()
        .section(Section::code(".text", &code_bytes))
        .section(Section::rodata(".gopclntab", &[0xfb, 0xff, 0xff, 0xff]))
        .symbol(Symbol::func("runtime.main", at(0), 1));
    let cases = [
        ("cpp", cpp, "c++", 3),
        ("rust", rust, "rust", 2),
        ("go", go, "go", 2),
    ];
    for (name, builder, lang, count) in cases {
        let (mut session, _) = load_bytes(&format!("ac_115b_{name}"), &builder.build(), "none");
        let survey = call(
            &mut session,
            "binary_survey",
            r#"{"include":["languages"]}"#,
        );
        let found = languages(&survey);
        assert_eq!(found, vec![(lang.to_owned(), count)], "{survey}");
        let hint = text_at(data(&survey), "/languages/items/0/hint");
        assert_eq!(hint, "Names are not demangled in this version.");
    }
    // T3: the test binary itself holds Rust symbols.
    let exe = std::env::current_exe().expect("the test binary has a path");
    let dir = exe.parent().expect("the test binary has a directory");
    let mut session = session_with(crate::support::config_at(dir));
    let file = exe.file_name().and_then(|n| n.to_str()).expect("a name");
    let args = Value::object([
        ("path", Value::from(file)),
        ("analysis", Value::from("none")),
    ]);
    let load = call_value(&mut session, "binary_load", args);
    assert!(load.get("ok") == Some(&Value::Bool(true)), "{load}");
    let survey = call(
        &mut session,
        "binary_survey",
        r#"{"include":["languages"]}"#,
    );
    let found = languages(&survey);
    assert!(
        found.iter().any(|(l, c)| l == "rust" && *c > 0),
        "{found:?}"
    );
}

/// Tells if the survey `d` holds the survey fact `fact` of a truth file.
fn holds(d: &Value, fact: &Value) -> bool {
    let value = str_of(fact, "value");
    match str_of(fact, "kind").as_str() {
        "protection" => d
            .pointer(&format!("/protections/{value}"))
            .is_some_and(|v| v == &Value::Bool(true)),
        "string" => {
            let mut found = false;
            crate::support::walk(d.get("strings").unwrap_or(&Value::Null), &mut |v| {
                found |= v.get("text").and_then(Value::as_str) == Some(value.as_str());
            });
            found
        }
        kind => {
            let section = match kind {
                "function" => "functions",
                "import" | "library" => "imports",
                "syscall" => "syscalls",
                _ => return false,
            };
            let mut found = false;
            crate::support::walk(d.get(section).unwrap_or(&Value::Null), &mut |v| {
                found |= v.as_str() == Some(value.as_str());
            });
            found
        }
    }
}

#[test]
fn ac_153a_survey_floor() {
    let mut checked = 0;
    for name in truth_fixtures() {
        let facts = truth(name)
            .get("survey_facts")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        let (mut session, _) = fixture(name);
        let survey = call(&mut session, "binary_survey", "{}");
        let size = chars(&survey);
        assert!(size <= 12_000, "{name}: {size} characters");
        let d = data(&survey);
        let held = facts.iter().filter(|f| holds(d, f)).count();
        let missing: Vec<&Value> = facts.iter().filter(|f| !holds(d, f)).collect();
        assert!(
            held * 10 >= facts.len() * 6,
            "{name}: {held} of {} facts, missing {missing:?}",
            facts.len()
        );
        checked += 1;
    }
    assert!(checked >= 60, "{checked} fixtures");
}

#[test]
fn survey_cut_sections_name_the_rest() {
    let (mut session, _) = fixture("socket_client.gcc-O2");
    let survey = call(&mut session, "binary_survey", r#"{"max_chars":2500}"#);
    assert!(chars(&survey) <= 2500, "{survey}");
    let d = data(&survey);
    let registry = registry();
    let mut cut = 0;
    for (name, section) in d.as_object().expect("an object").iter() {
        let Some(omitted) = section.get("omitted") else {
            continue;
        };
        cut += 1;
        assert!(
            omitted.get("count").and_then(Value::as_u64).unwrap_or(0) > 0,
            "{name}: {omitted}"
        );
        if let Some(next) = omitted.get("next") {
            let call = Call::new(
                &str_of(next, "tool"),
                next.get("args").cloned().unwrap_or_default(),
                "",
            );
            assert!(check(&registry, &|_| true, &call).is_ok(), "{name}: {next}");
            assert_eq!(call.tool, "search");
        }
    }
    assert!(cut > 0, "the small budget cuts a section: {survey}");
}

#[test]
fn survey_hints_name_priority_and_main() {
    let (mut session, _) = fixture("hello.gcc-O2");
    let survey = call(&mut session, "binary_survey", "{}");
    let next = survey
        .get("next")
        .and_then(Value::as_array)
        .expect("the survey has hints");
    let tools: Vec<String> = next.iter().map(|n| str_of(n, "tool")).collect();
    assert_eq!(tools, ["func_list", "func_get"], "{survey}");
    assert_eq!(
        next[1].pointer("/args/target").and_then(Value::as_str),
        Some("fn:0x1080")
    );
    let d = data(&survey);
    assert_eq!(text_at(d, "/identity/format"), "elf64-le");
    assert_eq!(
        d.pointer("/protections/pie"),
        Some(&Value::Bool(true)),
        "{survey}"
    );
    let strings = d
        .pointer("/strings/items")
        .and_then(Value::as_array)
        .expect("the strings list");
    assert!(
        strings
            .iter()
            .all(|s| s.pointer("/text/src").and_then(Value::as_str) == Some("binary"))
    );
}
