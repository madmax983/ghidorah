//! Rules over every read tool: partial results, hostile text, mangled names, default loads
//! and output budgets (AC-115a, AC-133, AC-145, AC-146a to AC-146d, AC-209).

use ghidorah_json::Value;
use ghidorah_testkit::elf::{ElfBuilder, ImportKind, Loc, Section, Symbol};

use crate::support::{
    WP17B, call, call_value, chars, code, fixture, is_bin_text, items, json, load_bytes, session,
    str_of, t1_fixtures, t2_fixtures, text_at, truth, walk, warnings,
};

/// One call of every read tool that works on any loaded ELF file.
const READS: [(&str, &str); 8] = [
    ("binary_survey", "{}"),
    ("func_list", "{}"),
    (
        "func_get",
        r#"{"target":"main","include":["summary","disasm"]}"#,
    ),
    ("xref_list", r#"{"targets":["main"]}"#),
    ("search", r#"{"kind":"string","include_unreferenced":true}"#),
    ("mem_read", r#"{"target":"main","as":"insn","count":4}"#),
    ("addr_info", r#"{"target":"main"}"#),
    ("search", r#"{"kind":"name","query":"main"}"#),
];

#[test]
fn ac_145_partial_flag() {
    let mut session = session();
    let load = call(
        &mut session,
        "binary_load",
        r#"{"path":"fixtures/bin/socket_client.gcc-O2","max_steps":40}"#,
    );
    assert_eq!(
        text_at(&load, "/data/analysis/state"),
        "budget_stopped",
        "{load}"
    );
    for (tool, args) in READS {
        let envelope = call(&mut session, tool, args);
        if envelope.get("ok") != Some(&Value::Bool(true)) {
            continue;
        }
        assert_eq!(
            envelope.get("partial"),
            Some(&Value::Bool(true)),
            "{tool}: {envelope}"
        );
        assert_eq!(
            text_at(&envelope, "/analysis/state"),
            "budget_stopped",
            "{tool}"
        );
        let next = envelope
            .get("next")
            .and_then(Value::as_array)
            .expect("next");
        assert!(
            next.iter().any(|n| str_of(n, "tool") == "analysis_run"),
            "{tool}"
        );
    }
    let main = call(&mut session, "func_get", r#"{"target":"_start"}"#);
    assert_eq!(text_at(&main, "/data/name"), "_start", "{main}");
    let survey = call(&mut session, "binary_survey", r#"{"include":["identity"]}"#);
    assert_eq!(
        text_at(&survey, "/data/identity/format"),
        "elf64-le",
        "{survey}"
    );
    let done = call(&mut session, "analysis_run", "{}");
    assert_eq!(text_at(&done, "/data/state"), "complete", "{done}");
    let after = call(&mut session, "func_list", "{}");
    assert_eq!(after.get("partial"), Some(&Value::Bool(false)));
}

/// The hostile fixtures.
const HOSTILE: [&str; 3] = [
    "hostile_strings.gcc-O2",
    "hostile_strings.gcc-O0",
    "hostile_strings.clang-O2",
];

/// Gives the envelopes of a battery of read calls on a hostile fixture.
fn hostile_outputs(name: &'static str) -> Vec<Value> {
    let (mut session, _) = fixture(name);
    let mut out = Vec::new();
    for (tool, args) in READS {
        out.push(call(&mut session, tool, args));
    }
    let strings = items(&call(
        &mut session,
        "search",
        r#"{"kind":"string","include_unreferenced":true,"limit":100}"#,
    ));
    let mut targets = Vec::new();
    for s in &strings {
        let id = str_of(s, "id");
        let addr = str_of(s, "addr");
        targets.push(Value::from(id.as_str()));
        for form in ["cstr", "hex"] {
            let args = Value::object([
                ("target", Value::from(addr.as_str())),
                ("as", Value::from(form)),
            ]);
            out.push(call_value(&mut session, "mem_read", args));
        }
        let args = Value::object([("target", Value::from(addr.as_str()))]);
        out.push(call_value(&mut session, "addr_info", args));
    }
    let args = Value::object([
        ("targets", Value::Array(targets)),
        ("args", Value::Bool(true)),
    ]);
    out.push(call_value(&mut session, "xref_list", args));
    for f in items(&call(&mut session, "func_list", "{}")) {
        let args = Value::object([
            ("target", Value::from(str_of(&f, "id"))),
            ("include", json(r#"["strings","disasm","xrefs"]"#)),
        ]);
        out.push(call_value(&mut session, "func_get", args));
    }
    let args = json(r#"{"targets":["imp:puts"],"args":true,"context":2}"#);
    out.push(call_value(&mut session, "xref_list", args));
    out
}

/// Tells if `c` is a character that output text must escape.
fn raw_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}' | '\u{61c}'
        | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[test]
fn ac_146a_controls_escaped() {
    for name in HOSTILE {
        let mut texts = 0;
        for envelope in hostile_outputs(name) {
            walk(&envelope, &mut |v| {
                texts += usize::from(is_bin_text(v));
                if let Value::String(text) = v {
                    assert!(!text.chars().any(raw_control), "{name}: {text:?}");
                }
                if let Value::Object(o) = v {
                    for (key, _) in o.iter() {
                        assert!(!key.chars().any(raw_control), "{name}: key {key:?}");
                    }
                }
            });
        }
        assert!(texts >= 50, "{name}: {texts} binary texts");
    }
}

#[test]
fn ac_146b_capped() {
    for name in HOSTILE {
        let mut long_cut = false;
        for envelope in hostile_outputs(name) {
            walk(&envelope, &mut |v| {
                if !is_bin_text(v) {
                    return;
                }
                let text = str_of(v, "text");
                let len = v.get("len").and_then(Value::as_u64).unwrap_or(0);
                let truncated = v.get("truncated") == Some(&Value::Bool(true));
                assert!(text.chars().count() <= 256 || truncated, "{name}: {v}");
                assert!(text.chars().count() <= 4096, "{name}: {v}");
                if len > 256 {
                    assert!(truncated, "{name}: a long text is cut: {v}");
                    long_cut |= text.starts_with("long:");
                }
            });
        }
        assert!(long_cut, "{name}: the long string comes back cut");
    }
}

#[test]
fn ac_146c_exact_hex() {
    for name in HOSTILE {
        let want: Vec<(String, String)> = truth(name)
            .get("strings")
            .and_then(Value::as_array)
            .expect("truth strings")
            .iter()
            .map(|s| (str_of(s, "addr"), str_of(s, "hex")))
            .collect();
        let mut seen = vec![false; want.len()];
        for envelope in hostile_outputs(name) {
            walk(&envelope, &mut |v| {
                if let Some(text) = v.get("text").filter(|t| is_bin_text(t)) {
                    let hex = str_of(text, "hex");
                    assert!(
                        ghidorah_base::hex::decode(&hex).is_ok(),
                        "{name}: the hex decodes: {text}"
                    );
                    let addr = str_of(v, "addr");
                    for (i, (a, h)) in want.iter().enumerate() {
                        if *a == addr && str_of(v, "id").starts_with("str:") {
                            assert!(h.starts_with(&hex), "{name} {a}: {hex} against {h}");
                            seen[i] = true;
                        }
                    }
                }
            });
        }
        assert!(
            seen.iter().all(|s| *s),
            "{name}: every truth string shows its hex"
        );
    }
}

/// The fragments of the hostile texts that must never reach a hint.
const FRAGMENTS: [&str; 7] = [
    "ALERT",
    "compromised",
    "invoice",
    "Ignore previous",
    "secret key",
    "owned title",
    "AAAAAAAAAA",
];

#[test]
fn ac_146d_no_binary_text_in_hints() {
    for name in HOSTILE {
        let mut hints = 0;
        for envelope in hostile_outputs(name) {
            let mut places = Vec::new();
            if let Some(next) = envelope.get("next") {
                places.push(ghidorah_json::write(next));
            }
            if let Some(hint) = envelope.pointer("/page/hint") {
                places.push(ghidorah_json::write(hint));
            }
            if let Some(hint) = envelope.pointer("/error/hint") {
                places.push(ghidorah_json::write(hint));
            }
            for w in envelope
                .get("warnings")
                .and_then(Value::as_array)
                .unwrap_or_default()
            {
                if let Some(remedy) = w.get("remedy") {
                    places.push(ghidorah_json::write(remedy));
                }
            }
            walk(&envelope, &mut |v| {
                if let Some(next) = v.get("next").filter(|n| n.get("tool").is_some()) {
                    places.push(ghidorah_json::write(next));
                }
                if let Some(next) = v.pointer("/omitted/next") {
                    places.push(ghidorah_json::write(next));
                }
            });
            hints += places.len();
            for place in &places {
                for fragment in FRAGMENTS {
                    assert!(!place.contains(fragment), "{name}: {fragment} in {place}");
                }
            }
        }
        assert!(hints >= 10, "{name}: {hints} hints");
    }
}

#[test]
fn ac_115a_not_demangled() {
    let text = [0xc3; 4];
    let at = |off| Loc::section(".text", off);
    let b = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .symbol(Symbol::func("_ZN3foo3barEv", at(0), 1))
        .symbol(Symbol::func("_ZN3foo3bazEv", at(1), 1))
        .symbol(Symbol::func("main", at(2), 1))
        .import("__cxa_atexit", ImportKind::Plt)
        .entry(Loc::symbol("main"));
    let (mut session, load) = load_bytes("ac_115a", &b.build(), "full");
    assert_eq!(text_at(&load, "/data/analysis/state"), "complete", "{load}");
    let mangled = [
        ("func_list", "{}"),
        ("func_get", r#"{"target":"sym:_ZN3foo3barEv"}"#),
        ("search", r#"{"kind":"name","query":"_ZN"}"#),
        ("search", r#"{"kind":"symbol"}"#),
        ("binary_survey", "{}"),
        ("addr_info", r#"{"target":"_ZN3foo3bazEv"}"#),
    ];
    for (tool, args) in mangled {
        let envelope = call(&mut session, tool, args);
        assert_eq!(
            warnings(&envelope, "W_NOT_DEMANGLED"),
            1,
            "{tool}: {envelope}"
        );
        let raw = ghidorah_json::write(&envelope).contains("_ZN3foo3");
        assert!(raw, "{tool} shows the raw name");
    }
    let plain = call(&mut session, "func_list", r#"{"filter":{"name":"main"}}"#);
    assert_eq!(warnings(&plain, "W_NOT_DEMANGLED"), 0, "{plain}");
}

/// Loads each fixture of `names` with default arguments and gives `(name, "<state> <has
/// functions>")` pairs.
fn load_states(names: &[&'static str]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in names {
        let mut s = session();
        let args = Value::object([("path", Value::from(format!("fixtures/bin/{name}")))]);
        let load = call_value(&mut s, "binary_load", args);
        let count = call(&mut s, "func_list", r#"{"count_only":true}"#);
        let functions = count
            .pointer("/data/count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let state = text_at(&load, "/data/analysis/state");
        out.push(((*name).to_owned(), format!("{state} {}", functions > 0)));
    }
    out
}

/// Loads each fixture of `names` with default arguments on 4 threads and gives the states.
fn default_states(names: &[&'static str]) -> Vec<(String, String)> {
    let size = names.len().div_ceil(4).max(1);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in names.chunks(size) {
            handles.push(scope.spawn(move || load_states(chunk)));
        }
        let mut out = Vec::new();
        for handle in handles {
            out.extend(handle.join().expect("the load thread ends"));
        }
        out
    })
}

#[test]
fn ac_209_default_load_completes() {
    let names = t1_fixtures();
    assert!(names.len() >= 100, "{} fixtures", names.len());
    for (name, state) in default_states(&names) {
        assert_eq!(state, "complete true", "{name}");
    }
}

#[test]
#[ignore = "tier2"]
fn ac_209_t2() {
    let names = t2_fixtures();
    assert!(!names.is_empty());
    for (name, state) in default_states(&names) {
        assert_eq!(state, "complete true", "{name}");
    }
}

/// Makes a synthetic ELF file with `count` functions of one `ret` each.
fn synthetic(count: u32) -> Vec<u8> {
    let text = vec![0xc3; usize::try_from(count).expect("a size")];
    let mut b = ElfBuilder::exec().section(Section::code(".text", &text));
    for i in 0..count {
        let name = format!("func_{i:05}");
        b = b.symbol(Symbol::func(&name, Loc::section(".text", u64::from(i)), 1));
    }
    b.entry(Loc::symbol("func_00000")).build()
}

/// Runs every example of the read tools with `limit` at its cap on a synthetic file.
fn budget_check(count: u32) {
    let (mut session, load) = load_bytes(&format!("ac_133_{count}"), &synthetic(count), "triage");
    assert_eq!(load.get("ok"), Some(&Value::Bool(true)), "{load}");
    let mut runs = 0;
    for tool in WP17B {
        for example in tool.examples {
            let mut args = json(example.args).as_object().cloned().unwrap_or_default();
            if tool.list.is_some() {
                let _ = args.remove("limit");
                args.push("limit", Value::from(1000));
            }
            let envelope = call_value(&mut session, tool.name, Value::Object(args));
            let size = chars(&envelope);
            assert!(
                size <= 60_000,
                "{} {}: {size} characters",
                tool.name,
                example.args
            );
            assert_ne!(code(&envelope), "OUTPUT_BUDGET_EXCEEDED", "{}", tool.name);
            runs += 1;
        }
    }
    assert!(runs >= 38);
    let big = call(
        &mut session,
        "func_list",
        r#"{"limit":1000,"max_chars":60000}"#,
    );
    assert!(chars(&big) <= 60_000);
    assert_eq!(big.pointer("/page/truncated"), Some(&Value::Bool(true)));
}

#[test]
fn ac_133_output_budget() {
    budget_check(5_000);
}

#[test]
#[ignore = "tier2"]
fn ac_133_output_budget_large() {
    budget_check(50_000);
}
