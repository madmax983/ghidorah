//! Schema-driven fuzzing of every tool (design Section 13.5, AC-191a to AC-191c).
//!
//! The generator reads the `ArgSpec` list of each tool and its global arguments. Each case
//! starts from an example of the tool or from no arguments. Then it sets, removes or adds up to
//! three arguments with valid values, boundary values, values of the wrong type and unknown
//! keys. Two sessions on the demo binary get the same calls in the same order.
//!
//! The run happens once per test binary. Each test checks one property of the results.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;

use ghidorah_base::{ErrorCode, FixedClock, WarningCode};
use ghidorah_json::{Limits, Object, Value};
use ghidorah_testkit::fixture::cached;
use ghidorah_testkit::fuzz::{install_panic_counter, panic_count};
use ghidorah_testkit::rng::{Xoshiro256ss, below, fnv1a64};
use ghidorah_tools::args::globals_of;
use ghidorah_tools::budget::PROTOCOL_RESERVE;
use ghidorah_tools::content::chars;
use ghidorah_tools::registry::shipped;
use ghidorah_tools::{
    ArgKind, ArgSpec, Request, Roots, Session, SessionConfig, ToolSpec, dispatch_with, handlers,
};

/// The number of calls of each tool.
const CASES_PER_TOOL: u64 = 40;

/// The deepest nesting of a generated value.
const MAX_DEPTH: u32 = 3;

/// The largest number of items of a generated list.
const MAX_ITEMS: u64 = 3;

/// Address inputs of the demo binary, good and bad.
const ADDRS: [&str; 14] = [
    "main",
    "0x1080",
    "fn:0x1080",
    "check_password",
    "imp:puts",
    "sec:.text",
    "file:0x1080",
    "main+0x4",
    "0x0",
    "0xffffffffffffffff",
    "FUN_00001090",
    "zz",
    "",
    "str:0x2004",
];

/// String inputs, good and bad.
const TEXTS: [&str; 9] = [
    "",
    "a",
    "main",
    "fixtures/bin/hello.gcc-O2",
    "../outside",
    "/etc/passwd",
    "int *",
    "struct timespec",
    "é\u{1}\"\\",
];

/// The result of one call of the run.
struct Call {
    /// The tool name.
    tool: &'static str,
    /// The arguments.
    args: Value,
    /// The envelope of session A as compact JSON.
    first: String,
    /// The envelope of session B as compact JSON.
    second: String,
    /// The state hashes of session A before and after the call.
    hashes: (String, String),
    /// `true` when the tool writes no fact.
    read_only: bool,
    /// The character cap of the call.
    cap: u64,
}

/// The results of the run.
struct Run {
    calls: Vec<Call>,
    panics: u64,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Makes a session of the shipped registry with the analysis engine and the demo binary.
fn demo_session() -> Session {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root");
    let mut session = Session::new(SessionConfig::new(roots), Box::new(FixedClock::new(0)));
    handlers::analysis_run::install(&mut session);
    let args = ghidorah_json::parse(r#"{"builtin":"demo"}"#, &Limits::DEFAULT).expect("args");
    let registry = session.active_registry();
    let envelope = dispatch_with(&registry, &mut session, &Request::new("binary_load", args));
    assert!(envelope.ok(), "the demo loads");
    session
}

/// Gives the state hashes of every open binary of `session`, in ID order.
fn state(session: &Session) -> String {
    session
        .binaries()
        .map(|b| {
            b.program
                .state_hash()
                .map_or_else(|e| format!("error {e}"), |h| h.to_string())
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn pick<'a, T>(rng: &mut Xoshiro256ss, items: &'a [T]) -> &'a T {
    let i = usize::try_from(below(rng, items.len() as u64)).unwrap_or(0);
    &items[i]
}

/// Gives a value of the wrong JSON type for `kind`.
fn wrong(kind: &ArgKind) -> Value {
    match kind {
        ArgKind::Bool | ArgKind::Enum(_) | ArgKind::Str(_) | ArgKind::Id(_) => {
            Value::Array(Vec::new())
        }
        ArgKind::Int { .. } | ArgKind::Addr => Value::from(true),
        ArgKind::AddrList(_) | ArgKind::List(..) | ArgKind::Obj(_) => Value::from(7u64),
        ArgKind::Json => Value::Null,
    }
}

/// Gives an integer of the range `min..=max`, a bound or a value just outside.
fn int(rng: &mut Xoshiro256ss, min: i64, max: i64) -> Value {
    let choices = [
        min,
        max,
        min.saturating_sub(1),
        max.saturating_add(1),
        0,
        min / 2 + max / 2,
        -1,
        1 << 53,
    ];
    Value::from(*pick(rng, &choices))
}

/// Gives a list of `max` or fewer generated items, or one item more than `max`.
fn list(
    rng: &mut Xoshiro256ss,
    max: usize,
    depth: u32,
    item: &dyn Fn(&mut Xoshiro256ss, u32) -> Value,
) -> Value {
    let len = if below(rng, 8) == 0 {
        max.saturating_add(1).min(1_100)
    } else {
        usize::try_from(below(rng, MAX_ITEMS + 1))
            .unwrap_or(0)
            .min(max)
    };
    Value::Array((0..len).map(|_| item(rng, depth + 1)).collect())
}

/// Gives a generated value for an argument of `kind`.
fn value(rng: &mut Xoshiro256ss, kind: &ArgKind, depth: u32) -> Value {
    if below(rng, 7) == 0 || depth > MAX_DEPTH {
        return wrong(kind);
    }
    match kind {
        ArgKind::Addr => {
            if below(rng, 4) == 0 {
                Value::from(0x1080u64 + below(rng, 64))
            } else {
                Value::from(*pick(rng, &ADDRS))
            }
        }
        ArgKind::AddrList(max) => list(rng, *max, depth, &|r, _| Value::from(*pick(r, &ADDRS))),
        ArgKind::Id(kinds) => {
            let prefix = if kinds.is_empty() {
                "fn:"
            } else {
                pick(rng, kinds).prefix()
            };
            let tail = *pick(rng, &["0x1080", "1", "main", "x", "", "0x2004:0x1090"]);
            Value::from(format!("{prefix}{tail}"))
        }
        ArgKind::Int { min, max } => int(rng, *min, *max),
        ArgKind::Str(max) => match below(rng, 4) {
            0 => Value::from("x".repeat(*max)),
            1 => Value::from("y".repeat(max.saturating_add(1))),
            _ => Value::from(*pick(rng, &TEXTS)),
        },
        ArgKind::Enum(values) => {
            if values.is_empty() || below(rng, 6) == 0 {
                Value::from("zz_not_a_value")
            } else {
                Value::from(*pick(rng, values))
            }
        }
        ArgKind::Bool => Value::Bool(below(rng, 2) == 0),
        ArgKind::Obj(specs) => {
            let mut out = Object::new();
            for spec in specs.iter() {
                if below(rng, 2) == 0 {
                    out.insert(spec.name, value(rng, &spec.kind, depth + 1));
                }
            }
            Value::Object(out)
        }
        ArgKind::List(item, max) => {
            let item = **item;
            list(rng, *max, depth, &move |r, d| value(r, &item.kind, d))
        }
        ArgKind::Json => {
            let text = *pick(rng, &["null", "1", "\"x\"", "[]", "{}", "{\"a\":[1,{}]}"]);
            ghidorah_json::parse(text, &Limits::DEFAULT).expect("a JSON literal")
        }
    }
}

/// Gives the arguments of one case of `tool`.
fn case(rng: &mut Xoshiro256ss, tool: &ToolSpec<Session>, specs: &[ArgSpec]) -> Value {
    let start = if tool.examples.is_empty() || below(rng, 4) == 0 {
        "{}"
    } else {
        pick(rng, tool.examples).args
    };
    let Value::Object(mut args) =
        ghidorah_json::parse(start, &Limits::DEFAULT).expect("an example parses")
    else {
        panic!("an example of {} is no object", tool.name);
    };
    for _ in 0..=below(rng, 3) {
        match below(rng, 8) {
            0 => {
                args.insert("zz_unknown", Value::from(1u64));
            }
            1 => {
                let keys: Vec<String> = args.iter().map(|(k, _)| k.to_owned()).collect();
                if !keys.is_empty() {
                    let key = pick(rng, &keys).clone();
                    args.remove(&key);
                }
            }
            _ => {
                if !specs.is_empty() {
                    let spec = pick(rng, specs);
                    let v = value(rng, &spec.kind, 0);
                    args.insert(spec.name, v);
                }
            }
        }
    }
    Value::Object(args)
}

/// Gives the character cap of a call: a valid `max_chars`, else the default of the tool.
fn cap_of(tool: &ToolSpec<Session>, args: &Value) -> u64 {
    args.get("max_chars")
        .and_then(Value::as_u64)
        .filter(|n| (1_000..=60_000).contains(n))
        .unwrap_or_else(|| u64::from(tool.max_chars))
}

fn call(session: &mut Session, tool: &str, args: &Value) -> String {
    let registry = session.active_registry();
    let envelope = dispatch_with(&registry, session, &Request::new(tool, args.clone()));
    ghidorah_json::write(&envelope.to_json())
}

/// Runs every case of every tool on two sessions.
fn run_all() -> Run {
    install_panic_counter();
    let before = panic_count();
    let registry = shipped();
    let mut a = demo_session();
    let mut b = demo_session();
    let mut calls = Vec::new();
    for tool in registry.tools() {
        let mut specs: Vec<ArgSpec> = tool.args.to_vec();
        specs.extend(globals_of(tool));
        let mut rng = Xoshiro256ss::seed_from_u64(fnv1a64(tool.name.as_bytes()));
        for _ in 0..CASES_PER_TOOL {
            let args = case(&mut rng, tool, &specs);
            let start = state(&a);
            let first = call(&mut a, tool.name, &args);
            let end = state(&a);
            let second = call(&mut b, tool.name, &args);
            calls.push(Call {
                tool: tool.name,
                cap: cap_of(tool, &args),
                args,
                first,
                second,
                hashes: (start, end),
                read_only: !tool.mutating,
            });
        }
    }
    Run {
        calls,
        panics: panic_count().saturating_sub(before),
    }
}

fn results() -> &'static Run {
    cached("schema_fuzz", run_all)
}

fn label(c: &Call) -> String {
    format!("{} {}", c.tool, ghidorah_json::write(&c.args))
}

fn envelope(c: &Call) -> Value {
    ghidorah_json::parse(&c.first, &Limits::DEFAULT).expect("the envelope parses")
}

#[test]
fn ac_191a_no_internal_error() {
    let run = results();
    assert!(
        run.calls.len() as u64 >= CASES_PER_TOOL * 23,
        "every tool runs"
    );
    let internal: Vec<String> = run
        .calls
        .iter()
        .filter(|c| {
            c.first.contains("\"INTERNAL_ERROR\"") || c.second.contains("\"INTERNAL_ERROR\"")
        })
        .map(label)
        .collect();
    assert!(internal.is_empty(), "INTERNAL_ERROR: {internal:#?}");
    assert_eq!(run.panics, 0, "no handler panics");
}

/// Gives the problems of one envelope: its shape, its codes and its size.
fn problems(c: &Call) -> Vec<String> {
    let e = envelope(c);
    let mut out = Vec::new();
    match e.get("ok") {
        Some(Value::Bool(true)) => {
            if e.get("data").is_none() {
                out.push("ok with no data".to_owned());
            }
        }
        Some(Value::Bool(false)) => {
            let code = e.pointer("/error/code").and_then(Value::as_str);
            if code.and_then(ErrorCode::from_name).is_none() {
                out.push(format!("error code {code:?} is not in the registry"));
            }
            let message = e.pointer("/error/message").and_then(Value::as_str);
            if message.is_none_or(str::is_empty) {
                out.push("error with no message".to_owned());
            }
        }
        _ => out.push("no ok member".to_owned()),
    }
    let warnings = e
        .get("warnings")
        .and_then(Value::as_array)
        .unwrap_or_default();
    for w in warnings {
        let code = w.get("code").and_then(Value::as_str);
        if code.and_then(WarningCode::from_name).is_none() {
            out.push(format!("warning code {code:?} is not in the registry"));
        }
    }
    let size = chars(&c.first);
    let limit = c.cap.saturating_sub(PROTOCOL_RESERVE);
    if size > limit {
        out.push(format!("{size} characters above the cap {limit}"));
    }
    out
}

#[test]
fn ac_191b_valid_envelopes() {
    let bad: Vec<String> = results()
        .calls
        .iter()
        .filter_map(|c| {
            let p = problems(c);
            (!p.is_empty()).then(|| format!("{}: {p:?}", label(c)))
        })
        .collect();
    assert!(bad.is_empty(), "{} bad envelopes: {bad:#?}", bad.len());
}

#[test]
fn ac_191c_repeats_equal() {
    let run = results();
    let differ: Vec<String> = run
        .calls
        .iter()
        .filter(|c| c.first != c.second)
        .map(|c| format!("{}\n  {}\n  {}", label(c), c.first, c.second))
        .collect();
    assert!(
        differ.is_empty(),
        "{} calls differ: {differ:#?}",
        differ.len()
    );
    let changed: Vec<String> = run
        .calls
        .iter()
        .filter(|c| c.read_only && c.hashes.0 != c.hashes.1)
        .map(label)
        .collect();
    assert!(
        changed.is_empty(),
        "read-only calls change the state: {changed:#?}"
    );
    let read_only = run.calls.iter().filter(|c| c.read_only).count();
    assert!(read_only > 0, "the run has read-only calls");
}
