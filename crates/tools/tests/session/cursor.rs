//! Keyset cursors: round trips, tampering, stale analysis keys and long keys.

use ghidorah_base::ErrorCode;
use ghidorah_json::Value;
use ghidorah_testkit::rng::{Rng, SplitMix64};
use ghidorah_tools::args::parse;
use ghidorah_tools::cursor::{
    Cursor, MAX_CURSOR_CHARS, Spill, analysis_derived, args_hash, decode, encode,
};
use ghidorah_tools::dispatch::CursorCall;
use ghidorah_tools::{
    AnalysisInfo, AnalysisState, ArgKind, ArgSpec, Args, Frame, KeyPart, ListSpec, Role, Session,
    SortKey, ToolSpec, handlers,
};

use crate::support::{call, code, json, registry, session, text_at};

const SORT_ARGS: &[ArgSpec] = &[ArgSpec::new(
    "sort",
    Role::Param,
    ArgKind::Enum(&["addr", "name", "size", "priority", "in_degree"]),
    "The sort order.",
)
.default_json("\"addr\"")];

/// A list tool with a sort argument.
const SORTED: ToolSpec<Session> = ToolSpec {
    title: "Sorted",
    summary: "List sorted items.",
    description: "List sorted items.",
    args: SORT_ARGS,
    list: Some(ListSpec { default_limit: 10 }),
    ..ToolSpec::base("sorted_list", empty_list)
};

fn empty_list(
    _s: &mut Session,
    _args: &Args,
    _ctx: &mut ghidorah_tools::Ctx,
) -> Result<ghidorah_tools::Payload, ghidorah_tools::ToolError> {
    Ok(ghidorah_tools::Payload::List(
        ghidorah_tools::ListPayload::new(Vec::new()),
    ))
}

fn args_of(tool: &ToolSpec<Session>, text: &str) -> Args {
    parse(tool, &json(text), None)
        .expect("the test args parse")
        .args
}

fn frame(binary: &str, analysis_rev: u64) -> Frame {
    Frame {
        binary_id: Some(binary.to_owned()),
        rev: 3,
        session: "test".to_owned(),
        analysis: Some(AnalysisInfo {
            state: AnalysisState::Complete,
            rev: analysis_rev,
        }),
    }
}

fn call_of<'a>(index: usize, args: &'a Args, frame: &'a Frame) -> CursorCall<'a> {
    CursorCall {
        tool_index: index,
        tool: "sorted_list",
        args,
        frame,
    }
}

fn random_key(rng: &mut SplitMix64) -> SortKey {
    let parts = usize::try_from(rng.next_u64() % 5).unwrap_or(0);
    let mut key = Vec::new();
    for _ in 0..parts {
        if rng.next_u64().is_multiple_of(2) {
            key.push(KeyPart::Int(rng.next_u64()));
        } else {
            let len = usize::try_from(rng.next_u64() % 20).unwrap_or(0);
            let text: String = (0..len)
                .map(|_| {
                    char::from_u32(u32::try_from(rng.next_u64() % 0x3000).unwrap_or(0x41))
                        .unwrap_or('x')
                })
                .collect();
            key.push(KeyPart::Text(text));
        }
    }
    SortKey(key)
}

#[test]
fn cursor_keyset_roundtrip() {
    let args = args_of(&SORTED, r#"{"sort":"name"}"#);
    let f = frame("467a43b75d95c826", 1);
    let call = call_of(4, &args, &f);
    let mut spill = Spill::new();
    let mut rng = SplitMix64::new(0x5eed);
    for _ in 0..500 {
        let key = random_key(&mut rng);
        for section in [0, 3] {
            let text = encode(&call, &key, section, &mut spill);
            assert!(text.len() <= MAX_CURSOR_CHARS, "{} chars", text.len());
            assert!(
                text.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert_eq!(
                decode(&call, &text, section, &spill).ok(),
                Some(key.clone())
            );
        }
    }
    assert!(spill.is_empty(), "short keys stay in the cursor");
    // A long key goes into the spill store. Another store does not know it.
    let long = SortKey(vec![KeyPart::Text("n".repeat(3_000)), KeyPart::Int(7)]);
    let text = encode(&call, &long, 0, &mut spill);
    assert!(text.len() <= MAX_CURSOR_CHARS);
    assert_eq!(spill.len(), 1);
    assert_eq!(decode(&call, &text, 0, &spill).ok(), Some(long.clone()));
    let other = decode(&call, &text, 0, &Spill::new()).expect_err("another store");
    assert_eq!(other.code, ErrorCode::CursorInvalid);
    for i in 0..ghidorah_tools::cursor::SPILL_CAP + 5 {
        let key = SortKey(vec![KeyPart::Text(format!("{i}{}", "m".repeat(2_000)))]);
        let _ = encode(&call, &key, 0, &mut spill);
    }
    assert_eq!(spill.len(), ghidorah_tools::cursor::SPILL_CAP);
    // The cursor fields survive the byte form.
    let cursor = Cursor::of_call(&call, &SortKey(vec![KeyPart::Int(9)]), 2);
    let mut store = Spill::new();
    let back = Cursor::from_bytes(&cursor.to_bytes(&mut store), &store).expect("the bytes read");
    assert_eq!(back, cursor);
    assert_eq!(back.tool_index, 4);
    assert_eq!(back.args_hash, args_hash(&args, &f));
}

#[test]
fn cursor_pages_through_the_dispatcher() {
    let mut s = session();
    let names: Vec<&str> = registry().tools().iter().map(|t| t.name).collect();
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..=names.len() {
        let args = match &cursor {
            Some(c) => format!(r#"{{"level":"names","limit":1,"cursor":"{c}"}}"#),
            None => r#"{"level":"names","limit":1}"#.to_owned(),
        };
        let envelope = call(&mut s, "tool_search", &args);
        seen.push(text_at(&envelope, "/data/items/0/name"));
        match envelope
            .pointer("/page/next_cursor")
            .and_then(Value::as_str)
        {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen, names);
    let envelope = call(&mut s, "tool_search", r#"{"cursor":"abc"}"#);
    assert_eq!(code(&envelope), "CURSOR_INVALID", "{envelope}");
    assert_eq!(text_at(&envelope, "/next/0/tool"), "tool_search");
    assert!(
        envelope.pointer("/next/0/args/cursor").is_none(),
        "{envelope}"
    );
}

#[test]
fn cursor_rejects_tampering() {
    let args = args_of(&SORTED, r#"{"sort":"name"}"#);
    let f = frame("467a43b75d95c826", 1);
    let call = call_of(4, &args, &f);
    let mut spill = Spill::new();
    let key = SortKey(vec![KeyPart::Text("main".to_owned()), KeyPart::Int(0x1080)]);
    let text = encode(&call, &key, 0, &mut spill);
    for i in 0..text.len() {
        let mut bytes = text.clone().into_bytes();
        bytes[i] = if bytes[i] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(bytes).expect("hex text");
        let error = decode(&call, &tampered, 0, &spill).expect_err("a tampered cursor");
        assert_eq!(error.code, ErrorCode::CursorInvalid, "byte {i}");
    }
    for bad in [
        "",
        "0",
        "zz",
        "0x10",
        &text[..text.len() - 2],
        &format!("{text}00"),
    ] {
        let error = decode(&call, bad, 0, &spill).expect_err("a bad cursor");
        assert_eq!(error.code, ErrorCode::CursorInvalid, "{bad}");
    }
    // Another query, tool, section or binary.
    let other_args = args_of(&SORTED, r#"{"sort":"addr"}"#);
    let other = call_of(4, &other_args, &f);
    assert_eq!(
        decode(&other, &text, 0, &spill).err().map(|e| e.code),
        Some(ErrorCode::CursorInvalid)
    );
    let other = call_of(5, &args, &f);
    assert_eq!(
        decode(&other, &text, 0, &spill).err().map(|e| e.code),
        Some(ErrorCode::CursorInvalid)
    );
    assert_eq!(
        decode(&call, &text, 1, &spill).err().map(|e| e.code),
        Some(ErrorCode::CursorInvalid)
    );
    let g = frame("0000000000000001", 1);
    let other = call_of(4, &args, &g);
    assert_eq!(
        decode(&other, &text, 0, &spill).err().map(|e| e.code),
        Some(ErrorCode::CursorInvalid)
    );
}

#[test]
fn cursor_stale_analysis_rev() {
    let f = frame("467a43b75d95c826", 5);
    let newer = frame("467a43b75d95c826", 6);
    let key = SortKey(vec![KeyPart::Int(10), KeyPart::Int(0x1080)]);
    let mut spill = Spill::new();
    for (sort, derived) in [
        ("addr", false),
        ("name", false),
        ("size", true),
        ("priority", true),
        ("in_degree", true),
    ] {
        let args = args_of(&SORTED, &format!(r#"{{"sort":"{sort}"}}"#));
        assert_eq!(analysis_derived(&args), derived, "{sort}");
        let text = encode(&call_of(0, &args, &f), &key, 0, &mut spill);
        assert_eq!(
            decode(&call_of(0, &args, &f), &text, 0, &spill).ok(),
            Some(key.clone())
        );
        let later = decode(&call_of(0, &args, &newer), &text, 0, &spill);
        if derived {
            assert_eq!(
                later.err().map(|e| e.code),
                Some(ErrorCode::CursorStale),
                "{sort}"
            );
        } else {
            assert_eq!(later.ok(), Some(key.clone()), "{sort}");
        }
    }
    // Paging and budget arguments leave the args hash alone. Other arguments change it.
    let first = args_of(
        &handlers::tool_search::SPEC,
        r#"{"query":"load","limit":5}"#,
    );
    let paged = args_of(
        &handlers::tool_search::SPEC,
        r#"{"query":"load","limit":9,"max_chars":2000,"format":"detailed","cursor":"00","shape":"table","fields":["/items"],"count_only":true,"session":"x"}"#,
    );
    let other = args_of(&handlers::tool_search::SPEC, r#"{"query":"calc"}"#);
    let given = args_of(
        &handlers::tool_search::SPEC,
        r#"{"query":"load","level":"summaries"}"#,
    );
    assert_eq!(args_hash(&first, &f), args_hash(&paged, &f));
    assert_ne!(args_hash(&first, &f), args_hash(&other, &f));
    assert_eq!(
        args_hash(&first, &f),
        args_hash(&given, &f),
        "a default equals the given value"
    );
    assert_ne!(
        args_hash(&first, &f),
        args_hash(&first, &frame("0000000000000001", 5))
    );
}
