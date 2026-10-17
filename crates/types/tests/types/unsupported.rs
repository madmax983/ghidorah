//! AC-110: features outside the MVP give `E_UNSUPPORTED` with a place and a hint.

use ghidorah_base::{DiagCode, ErrorCode};
use ghidorah_types::{parse_sig, parse_type};

use crate::support::{assert_diag, first, offset, store};

/// The mode (`true` for `sig`), the text, the text at the error place and a hint word.
const CASES: &[(bool, &str, &str, &str)] = &[
    (false, "struct { int a : 3; }", ":", "bit-field"),
    (
        false,
        "struct {\n  char a;\n  unsigned b : 1;\n}",
        ": 1",
        "bit-field",
    ),
    (
        true,
        "void f(void) __attribute__((noreturn));",
        "__attribute__",
        "__attribute__",
    ),
    (
        false,
        "__attribute__((packed)) struct { char a; }",
        "__attribute__",
        "__attribute__",
    ),
    (
        false,
        "struct { char a; } __attribute__((packed))",
        "__attribute__",
        "__attribute__",
    ),
    (
        true,
        "int __attribute((cold)) f(int x);",
        "__attribute",
        "__attribute__",
    ),
    (
        false,
        "#pragma pack(1)\nstruct { char a; int b; }",
        "#",
        "#pragma",
    ),
    (
        false,
        "struct {\n#pragma pack(push, 1)\n  char a;\n}",
        "#",
        "#pragma",
    ),
    (
        false,
        "__declspec(align(16)) int",
        "__declspec",
        "__declspec",
    ),
    (false, "_Alignas(16) int", "_Alignas", "_Alignas"),
    (false, "_Atomic int", "_Atomic", "_Atomic"),
    (false, "_Complex double", "_Complex", "_Complex"),
    (false, "typedef int myint;", "typedef", "typedef"),
    (true, "int f(void) asm(\"g\");", "asm", "asm"),
];

#[test]
fn ac_110_c_unsupported() {
    for (sig, text, needle, hint) in CASES {
        let mut s = store();
        let before = s.clone();
        let err = if *sig {
            parse_sig(&mut s, text).map(|p| p.ty)
        } else {
            parse_type(&mut s, text)
        }
        .expect_err(text);
        assert_eq!(s, before, "the store does not change on `{text}`");
        assert_eq!(err.code(), ErrorCode::CParseError);
        assert_diag(text, &err, DiagCode::Unsupported, offset(text, needle));
        let d = first(&err);
        assert!(d.hint.contains(hint), "hint of `{text}`: {:?}", d.hint);
        assert!(d.snippet.contains(needle), "snippet of `{text}`: {d:?}");
        assert!(d.at.len > 0, "length of `{text}`");
    }
}

#[test]
fn unsupported_names_the_feature_in_the_error_text() {
    let mut s = store();
    let err = parse_type(&mut s, "struct { int a : 3; }").expect_err("bit-field");
    let text = err.to_string();
    assert!(text.contains("E_UNSUPPORTED"), "{text}");
    assert!(text.contains("1:16"), "{text}");
}
