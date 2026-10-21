use ghidorah_json::{Limits, Value, parse};

use super::{Source, apply, check, extract, operands, parse_int, parse_source, select};

fn json(text: &str) -> Value {
    parse(text, &Limits::DEFAULT).expect("the test JSON parses")
}

fn run(value: &str, steps: &str) -> Result<Value, String> {
    let mut v = json(value);
    for step in json(steps).as_array().unwrap_or_default() {
        v = apply(v, step, &[])?;
    }
    Ok(v)
}

#[test]
fn list_steps_filter_pick_and_sort() {
    let items = r#"[{"name":"socket","category":"network"},{"name":"puts","category":"io"},{"name":"connect","category":"network"}]"#;
    let out = run(
        items,
        r#"[{"op":"where","ptr":"/category","eq":"network"},{"op":"pick","ptr":"/name"},{"op":"sort"}]"#,
    );
    assert_eq!(out, Ok(json(r#"["connect","socket"]"#)));
    let out = run(
        items,
        r#"[{"op":"where","ptr":"/name","iglob":"*CONN*"},{"op":"count"}]"#,
    );
    assert_eq!(out, Ok(json("1")));
    let out = run(
        r#"[{"a":1,"b":1},{"a":1,"b":2}]"#,
        r#"[{"op":"same","a":"/a","b":"/b"},{"op":"count"}]"#,
    );
    assert_eq!(out, Ok(json("1")));
    let out = run(
        r#"[{"f":["noreturn"]},{"f":[]}]"#,
        r#"[{"op":"where","ptr":"/f","has":"noreturn"},{"op":"count"}]"#,
    );
    assert_eq!(out, Ok(json("1")));
    let out = run(
        r#"["b","a","b"]"#,
        r#"[{"op":"unique"},{"op":"take","count":1}]"#,
    );
    assert_eq!(out, Ok(json(r#"["b"]"#)));
    assert!(run(r#"{"a":1}"#, r#"[{"op":"count"}]"#).is_err());
    assert!(run("[]", r#"[{"op":"first"}]"#).is_err());
}

#[test]
fn text_steps_read_pseudo_c() {
    let text = r#""v2 = param_1 + 0x10;\n    case 0:\n        return 1;\n    case 7:\n        break;\n    case 8:\n        return 2;""#;
    let off = run(
        text,
        r#"[{"op":"lines"},{"op":"grep","glob":"*param_1 + 0x*"},{"op":"first"},{"op":"after","text":"param_1 + "},{"op":"token"},{"op":"int"}]"#,
    );
    assert_eq!(off, Ok(json("16")));
    let cases = run(
        text,
        r#"[{"op":"split","on":"case "},{"op":"drop","count":1},{"op":"grep","glob":"*:*break;*","not":true},{"op":"count"}]"#,
    );
    assert_eq!(cases, Ok(json("2")));
    let trimmed = run(
        r##"["#5","fn:0x10"]"##,
        r##"[{"op":"trim_prefix","text":"#"},{"op":"trim_prefix","text":"fn:"}]"##,
    );
    assert_eq!(trimmed, Ok(json(r#"["5","0x10"]"#)));
    assert_eq!(
        run(
            r#"" a;""#,
            r#"[{"op":"trim"},{"op":"trim_suffix","text":";"},{"op":"before","text":"z"}]"#
        )
        .ok(),
        None
    );
    assert_eq!(parse_int("0x5a"), Some(0x5a));
    assert_eq!(parse_int("12"), Some(12));
    assert_eq!(parse_int("x"), None);
}

#[test]
fn xor_decodes_with_a_key_expression() {
    // "hi" XOR (0x10 + i).
    let responses = vec![json(r#"{"hex":"7878","key":"0x10 + i"}"#)];
    let src = parse_source(&json(
        r#"{"turn":0,"ptr":"/hex","steps":[{"op":"xor","key":{"turn":0,"ptr":"/key"}}]}"#,
    ))
    .expect("the source parses");
    assert_eq!(extract(&responses, &src), Ok(json(r#""hi""#)));
    let bad = json(r#"{"op":"xor","key":{"turn":0,"ptr":"/key"}}"#);
    assert!(apply(json(r#""787""#), &bad, &responses).is_err());
}

#[test]
fn sources_check_their_members() {
    assert!(parse_source(&json(r#"{"ptr":"/a"}"#)).is_err());
    assert!(parse_source(&json(r#"{"turn":0}"#)).is_err());
    assert!(parse_source(&json(r#"{"turn":0,"ptr":"/a","steps":[{"op":"nope"}]}"#)).is_err());
    let src = Source {
        turn: 3,
        ptr: "/a".to_owned(),
        steps: Vec::new(),
    };
    assert!(extract(&[], &src).is_err());
    assert_eq!(
        select(&json(r#"{"a":[{"b":1},{"b":2}]}"#), "/a/*/b"),
        Ok(json("[1,2]"))
    );
    assert!(select(&json(r#"{"a":[{"b":1},{"c":2}]}"#), "/a/*/b").is_err());
    let steps = json(
        r#"[{"op":"where","ptr":"/x","eq":"net"},{"op":"xor","key":{"turn":0,"ptr":"/k","steps":[{"op":"after","text":"^ "}]}}]"#,
    );
    let ops = operands(steps.as_array().unwrap_or_default());
    assert_eq!(ops, ["net", "^ "]);
}

#[test]
fn checks_follow_the_frozen_answer_kinds() {
    assert!(check("equals", &json("16"), &json("16")));
    assert!(!check("equals", &json("16"), &json(r#""16""#)));
    assert!(check(
        "glob",
        &json(r#""mov*0x1337""#),
        &json(r#""mov eax, 0x1337""#)
    ));
    assert!(check("contains", &json(r#""b""#), &json(r#"["a","b"]"#)));
    let claim = json(r#"{"args":["f","g"],"rel":"calls"}"#);
    assert!(check(
        "claim",
        &claim,
        &json(r#"{"claim":{"rel":"calls","args":["f","g"]},"verdict":"supported"}"#)
    ));
    assert!(!check(
        "claim",
        &claim,
        &json(r#"{"claim":{"rel":"calls","args":["f","g"]},"verdict":"unknown"}"#)
    ));
    assert!(check(
        "abstain",
        &json(r#""unknown""#),
        &json(r#"{"verdict":"unknown","basis":{"gaps":["0x10"]}}"#)
    ));
    assert!(!check(
        "abstain",
        &json(r#""unknown""#),
        &json(r#"{"verdict":"unknown","basis":{"gaps":[]}}"#)
    ));
    assert!(!check("nope", &json("1"), &json("1")));
}
