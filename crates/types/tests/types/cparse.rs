//! C parser spec tables (design Section 9.2).

use ghidorah_base::{DiagCode, ErrorCode};
use ghidorah_types::{DataModel, LayoutError, Prim, Type, layout, parse_sig, parse_type};

use crate::support::{assert_diag, first, offset, store, ty};

/// `type` mode inputs and their canonical C text.
const TYPE_CASES: &[(&str, &str)] = &[
    ("int", "int"),
    ("unsigned", "unsigned int"),
    ("signed", "int"),
    ("signed int", "int"),
    ("char", "char"),
    ("signed char", "signed char"),
    ("unsigned char", "unsigned char"),
    ("short int", "short"),
    ("unsigned short int", "unsigned short"),
    ("long int", "long"),
    ("long unsigned int", "unsigned long"),
    ("long long", "long long"),
    ("unsigned long long int", "unsigned long long"),
    ("float", "float"),
    ("double", "double"),
    ("long double", "long double"),
    ("_Bool", "_Bool"),
    ("bool", "_Bool"),
    ("__int128", "__int128"),
    ("signed __int128", "__int128"),
    ("unsigned __int128", "unsigned __int128"),
    ("wchar_t", "wchar_t"),
    ("void", "void"),
    ("void *", "void *"),
    ("char**", "char **"),
    ("const char *", "const char *"),
    ("char const *", "const char *"),
    ("char *const", "char *const"),
    ("const char *const *", "const char *const *"),
    ("volatile int", "volatile int"),
    ("const volatile unsigned", "const volatile unsigned int"),
    ("int *restrict", "int *restrict"),
    ("int *__restrict", "int *restrict"),
    ("int [4]", "int [4]"),
    ("int[2][3]", "int [2][3]"),
    ("int (*)[4]", "int (*)[4]"),
    ("int *[4]", "int *[4]"),
    ("void (*)(int)", "void (*)(int)"),
    ("void (*)(void)", "void (*)(void)"),
    ("void (*)()", "void (*)(void)"),
    ("int (*)(const char *, ...)", "int (*)(const char *, ...)"),
    ("void (*[3])(int)", "void (*[3])(int)"),
    ("int (*(*)(int))[2]", "int (*(*)(int))[2]"),
    (
        "char *(*)(char *dst, const char *src)",
        "char *(*)(char *dst, const char *src)",
    ),
    ("void (*)(int[3])", "void (*)(int *)"),
    ("void (*)(void (int))", "void (*)(void (*)(int))"),
    ("struct sockaddr_in *", "struct sockaddr_in *"),
    ("uint8_t[16]", "uint8_t [16]"),
    ("size_t", "size_t"),
    ("FILE *", "FILE *"),
    ("va_list", "va_list"),
    ("struct { int a; char *b; }", "struct { int a; char *b; }"),
    ("union { int i; float f; } *", "union { int i; float f; } *"),
    ("enum { A, B = 5, C }", "enum { A = 0, B = 5, C = 6 }"),
    ("int[1 + 2 * 3]", "int [7]"),
    ("int[(1 << 4) - 1]", "int [15]"),
    ("int[0x10]", "int [16]"),
    ("int[010]", "int [8]"),
    ("int[0b101]", "int [5]"),
    ("int[10u]", "int [10]"),
    ("int[10UL]", "int [10]"),
    ("int[3 > 2 ? 4 : 5]", "int [4]"),
    ("int[!0 + ~0 + 2]", "int [2]"),
    ("int[7 % 4 * (8 / 2)]", "int [12]"),
    (
        "int[(1 || 0) + (1 && 0) + (6 & 3) + (6 | 1) + (6 ^ 3)]",
        "int [15]",
    ),
    (
        "int[(3 == 3) + (3 != 3) + (2 <= 3) + (2 >= 3) + (2 < 3)]",
        "int [3]",
    ),
    ("int[-(-4) + +1 - (16 >> 2)]", "int [1]"),
    ("int[]", "int []"),
    ("char[0]", "char [0]"),
    ("int /* comment */ *", "int *"),
    ("int // line comment\n *", "int *"),
    ("int *;", "int *"),
    ("const int", "const int"),
    ("int const volatile", "const volatile int"),
];

#[test]
fn type_mode_canonical_text() {
    for (text, want) in TYPE_CASES {
        let mut s = store();
        let id = ty(&mut s, text);
        let got = s
            .c_text(id)
            .unwrap_or_else(|e| panic!("`{text}` gives no text: {e}"));
        assert_eq!(got, *want, "canonical text of `{text}`");
        let again = ty(&mut s, &got);
        assert_eq!(again, id, "`{got}` parses back to the type of `{text}`");
    }
}

#[test]
fn type_mode_gives_primitive_ids() {
    let mut s = store();
    for prim in Prim::ALL {
        let id = ty(&mut s, prim.c_name());
        assert_eq!(id, s.prim(prim), "{}", prim.c_name());
        assert_eq!(s.get(id), Some(&Type::Prim(prim)));
    }
}

#[test]
fn inline_definitions_go_into_the_store() {
    let mut s = store();
    let id = ty(&mut s, "struct pt { int x, y; }");
    assert_eq!(s.lookup_tag("pt"), Some(id));
    assert_eq!(s.c_text(id).expect("text"), "struct pt");
    assert_eq!(
        s.c_definition(id).expect("definition"),
        "struct pt { int x; int y; };"
    );
    let p = ty(&mut s, "struct pt *");
    assert_eq!(s.get(p), Some(&Type::Ptr(id)));

    let e = ty(&mut s, "enum color { RED = 1 << 2, GREEN = RED | 1 }");
    assert_eq!(s.c_text(e).expect("text"), "enum color");
    assert_eq!(
        s.c_definition(e).expect("definition"),
        "enum color { RED = 4, GREEN = 5 };"
    );
    let node = ty(&mut s, "struct node { struct node *next; int v; }");
    assert_eq!(s.lookup_tag("node"), Some(node));
}

#[test]
fn same_definition_again_gives_the_same_id() {
    let mut s = store();
    let before = s.lookup_tag("sockaddr_in").expect("prelude tag");
    let again = ty(
        &mut s,
        "struct sockaddr_in { sa_family_t sin_family; in_port_t sin_port; \
         struct in_addr sin_addr; unsigned char sin_zero[8]; }",
    );
    assert_eq!(again, before);
}

/// `sig` mode inputs: the text, the name, the canonical type text, `noreturn`, `variadic`.
const SIG_CASES: &[(&str, &str, &str, bool, bool)] = &[
    (
        "int puts(const char *s);",
        "puts",
        "int (const char *s)",
        false,
        false,
    ),
    (
        "int printf(const char *format, ...)",
        "printf",
        "int (const char *format, ...)",
        false,
        true,
    ),
    (
        "_Noreturn void exit(int status);",
        "exit",
        "_Noreturn void (int status)",
        true,
        false,
    ),
    ("extern int x(void);", "x", "int (void)", false, false),
    (
        "static inline char *f(char *p)",
        "f",
        "char *(char *p)",
        false,
        false,
    ),
    (
        "void (*signal(int signum, void (*handler)(int)))(int);",
        "signal",
        "void (*(int signum, void (*handler)(int)))(int)",
        false,
        false,
    ),
    (
        "int main(int argc, char *argv[])",
        "main",
        "int (int argc, char **argv)",
        false,
        false,
    ),
    ("int (f)(int)", "f", "int (int)", false, false),
    ("int g(...)", "g", "int (...)", false, true),
    (
        "size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);",
        "fread",
        "size_t (void *ptr, size_t size, size_t nmemb, FILE *stream)",
        false,
        false,
    ),
];

#[test]
fn sig_mode_cases() {
    for (text, name, want, noreturn, variadic) in SIG_CASES {
        let mut s = store();
        let got = parse_sig(&mut s, text).unwrap_or_else(|e| panic!("`{text}`: {e}"));
        assert_eq!(got.name, *name, "name of `{text}`");
        assert_eq!(s.c_text(got.ty).expect("text"), *want, "type of `{text}`");
        assert_eq!(got.sig.noreturn, *noreturn, "noreturn of `{text}`");
        assert_eq!(got.sig.variadic, *variadic, "variadic of `{text}`");
        assert_eq!(s.get(got.ty), Some(&Type::Func(got.sig.clone())));
    }
}

#[test]
fn sig_mode_params_keep_names_and_adjust_types() {
    let mut s = store();
    let got = parse_sig(&mut s, "int pipe(int pipefd[2]);").expect("parse");
    assert_eq!(got.sig.params.len(), 1);
    let p = &got.sig.params[0];
    assert_eq!(p.name.as_deref(), Some("pipefd"));
    assert_eq!(s.c_text(p.ty).expect("text"), "int *");
    let unnamed = parse_sig(&mut s, "int f(int, char *)").expect("parse");
    assert!(unnamed.sig.params.iter().all(|p| p.name.is_none()));
}

/// Inputs that fail: the mode (`true` for `sig`), the text, the code, and the text from
/// the error place to the end. An empty tail puts the error at the end of the text.
const ERROR_CASES: &[(bool, &str, DiagCode, &str)] = &[
    (false, "", DiagCode::Syntax, ""),
    (false, "int x", DiagCode::Syntax, "x"),
    (false, "uint8 *", DiagCode::UnknownType, "uint8 *"),
    (
        false,
        "struct sockadr_in *",
        DiagCode::UnknownType,
        "sockadr_in *",
    ),
    (false, "union sockaddr", DiagCode::UnknownType, "sockaddr"),
    (false, "long long long", DiagCode::Syntax, "long"),
    (false, "unsigned float", DiagCode::Syntax, "float"),
    (false, "int int", DiagCode::Syntax, "int"),
    (false, "size_t int", DiagCode::Syntax, "int"),
    (false, "int[-1]", DiagCode::ConstExpr, "-1]"),
    (false, "int[1/0]", DiagCode::ConstExpr, "/0]"),
    (false, "int[5 % 0]", DiagCode::ConstExpr, "% 0]"),
    (false, "int[1 << 200]", DiagCode::ConstExpr, "<< 200]"),
    (
        false,
        "int[sizeof(int)]",
        DiagCode::ConstExpr,
        "sizeof(int)]",
    ),
    (false, "int[X]", DiagCode::ConstExpr, "X]"),
    (
        false,
        "int[170141183460469231731687303715884105727 + 1]",
        DiagCode::Overflow,
        "+ 1]",
    ),
    (
        false,
        "int[999999999999999999999999999999999999999999]",
        DiagCode::Overflow,
        "999999999999999999999999999999999999999999]",
    ),
    (
        false,
        "int[18446744073709551616]",
        DiagCode::Overflow,
        "18446744073709551616]",
    ),
    (false, "void[3]", DiagCode::IncompleteByValue, "[3]"),
    (false, "int[3][]", DiagCode::IncompleteByValue, "[3][]"),
    (false, "struct stat[2]", DiagCode::IncompleteByValue, "[2]"),
    (false, "int ()[3]", DiagCode::Syntax, "()[3]"),
    (false, "int[3](void)", DiagCode::Syntax, "[3](void)"),
    (false, "struct { int a; int a; }", DiagCode::Syntax, "a; }"),
    (
        false,
        "struct { void v; }",
        DiagCode::IncompleteByValue,
        "v; }",
    ),
    (
        false,
        "struct { struct stat s; }",
        DiagCode::IncompleteByValue,
        "s; }",
    ),
    (false, "struct { int; }", DiagCode::Unsupported, "; }"),
    (false, "enum { A, A }", DiagCode::Syntax, "A }"),
    (false, "int @", DiagCode::Syntax, "@"),
    (false, "int * )", DiagCode::Syntax, ")"),
    (false, "const", DiagCode::Syntax, ""),
    (false, "struct", DiagCode::Syntax, ""),
    (false, "int[3", DiagCode::Syntax, ""),
    (false, "'a'", DiagCode::Syntax, "'a'"),
    (false, "static int", DiagCode::Syntax, "static int"),
    (
        false,
        "struct sockaddr_in { int x; }",
        DiagCode::Syntax,
        "sockaddr_in { int x; }",
    ),
    (false, "int *\n  @", DiagCode::Syntax, "@"),
    (true, "int x;", DiagCode::Syntax, "x;"),
    (true, "int (*fp)(int);", DiagCode::Syntax, "fp)(int);"),
    (true, "int f(void, int)", DiagCode::Syntax, "void, int)"),
    (true, "int f(int a, int a)", DiagCode::Syntax, "a)"),
    (true, "int (int)", DiagCode::Syntax, "(int)"),
    (true, "int f(..., int)", DiagCode::Syntax, ", int)"),
    (true, "int f(int) g", DiagCode::Syntax, "g"),
    (true, "int f(void) int", DiagCode::Syntax, "int"),
    (true, "int f()[2]", DiagCode::Syntax, "()[2]"),
];

#[test]
fn error_cases() {
    for (sig, text, code, tail) in ERROR_CASES {
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
        assert_diag(text, &err, *code, text.len() - tail.len());
        let d = first(&err);
        assert!(!d.hint.is_empty(), "hint of `{text}`");
        assert!(d.snippet.len() <= ghidorah_types::cparse::MAX_SNIPPET);
    }
}

#[test]
fn unknown_names_give_candidates() {
    let mut s = store();
    let err = parse_type(&mut s, "uint8 *").expect_err("unknown");
    assert!(
        first(&err).candidates.iter().any(|c| c == "uint8_t"),
        "{err:?}"
    );
    let err = parse_type(&mut s, "struct sockadr_in").expect_err("unknown tag");
    assert!(
        first(&err)
            .candidates
            .iter()
            .any(|c| c == "struct sockaddr_in"),
        "{err:?}"
    );
    let err = parse_type(&mut s, "union sockaddr").expect_err("wrong kind");
    assert_eq!(first(&err).candidates, vec!["struct sockaddr".to_string()]);
    let err = parse_type(&mut s, "").expect_err("empty");
    assert!(!first(&err).expected.is_empty(), "{err:?}");
}

#[test]
fn error_text_names_code_and_place() {
    let mut s = store();
    let err = parse_type(&mut s, "int x").expect_err("name in type mode");
    let text = err.to_string();
    assert!(text.starts_with("C_PARSE_ERROR: E_SYNTAX at 1:5"), "{text}");
    assert!(!text.contains("CDiag"), "{text}");
    let err = parse_type(&mut s, "int é").expect_err("bad char");
    let d = first(&err);
    assert_eq!((d.at.line, d.at.col, d.at.byte, d.at.len), (1, 5, 4, 2));
}

#[test]
fn long_lines_give_short_snippets() {
    let mut s = store();
    let text = format!("int{} @", " ".repeat(500));
    let err = parse_type(&mut s, &text).expect_err("bad char");
    let d = first(&err);
    assert!(d.snippet.len() <= ghidorah_types::cparse::MAX_SNIPPET);
    assert!(d.snippet.contains('@'), "{d:?}");
}

#[test]
fn enum_tags_and_values() {
    let mut s = store();
    let color = ty(&mut s, "enum color { RED, GREEN }");
    assert_eq!(ty(&mut s, "enum color"), color);
    let err = parse_type(&mut s, "enum colour").expect_err("unknown enum tag");
    assert_eq!(first(&err).candidates, vec!["enum color".to_string()]);
    let err = parse_type(&mut s, "struct color").expect_err("an enum tag as a struct");
    assert_eq!(first(&err).candidates, vec!["enum color".to_string()]);
    let err = parse_type(&mut s, "union sockaddr { int x; }").expect_err("a struct tag");
    assert_eq!(first(&err).code, DiagCode::UnknownType);
    let text = "enum { A = 170141183460469231731687303715884105727, B }";
    let err = parse_type(&mut s, text).expect_err("enum overflow");
    assert_diag(text, &err, DiagCode::Overflow, offset(text, "B }"));
    let m = DataModel::X86_64_SYSV;
    let huge = ty(&mut s, "enum huge { H = 1 << 100 }");
    assert_eq!(layout::sysv(&s, huge, &m), Err(LayoutError::Overflow(huge)));
    let neg = ty(&mut s, "enum neg { N = -1 }");
    assert_eq!(layout::sysv(&s, neg, &m).map(|l| l.size), Ok(4));
    let wide = ty(&mut s, "enum wide { W = -0x80000001 }");
    assert_eq!(layout::sysv(&s, wide, &m).map(|l| l.size), Ok(8));
    let unsigned = ty(&mut s, "enum u32max { U = 0xffffffff }");
    assert_eq!(layout::sysv(&s, unsigned, &m).map(|l| l.size), Ok(4));
    let empty = ty(&mut s, "enum { }");
    assert_eq!(layout::sysv(&s, empty, &m).map(|l| l.size), Ok(4));
    let fwd = s
        .declare(ghidorah_types::TagKind::Enum, "later")
        .expect("declare");
    assert_eq!(layout::sysv(&s, fwd, &m), Err(LayoutError::Incomplete(fwd)));
    let done = ty(&mut s, "enum later { L = 2 }");
    assert_eq!(done, fwd, "the body completes the declared enum");
}

/// More failing inputs of the `type` mode: the text, the code and the text from the error place.
const EDGE_CASES: &[(&str, DiagCode, &str)] = &[
    (
        "int * __attribute__((aligned(8)))",
        DiagCode::Unsupported,
        "__attribute__((aligned(8)))",
    ),
    ("struct { int a;", DiagCode::Syntax, ""),
    ("int[(1]", DiagCode::Syntax, "]"),
    ("int[1 ? 2]", DiagCode::Syntax, "]"),
    ("int[]]", DiagCode::Syntax, "]"),
    ("int /* no end", DiagCode::Syntax, "/* no end"),
    ("int[1.5]", DiagCode::Syntax, ".5]"),
    ("int[0x]", DiagCode::Syntax, "0x]"),
    ("int[1q]", DiagCode::Syntax, "1q]"),
    (
        "int [[deprecated]]",
        DiagCode::Unsupported,
        "[[deprecated]]",
    ),
    ("enum { A = B }", DiagCode::ConstExpr, "B }"),
    ("enum { int }", DiagCode::Syntax, "int }"),
    ("enum { A B }", DiagCode::Syntax, "B }"),
    ("int[*]", DiagCode::Syntax, "*]"),
    ("int[", DiagCode::Syntax, ""),
];

#[test]
fn edge_error_cases() {
    for (text, code, tail) in EDGE_CASES {
        let mut s = store();
        let err = parse_type(&mut s, text).expect_err(text);
        assert_diag(text, &err, *code, text.len() - tail.len());
    }
    let mut s = store();
    let got = parse_sig(&mut s, "int f(register int x);").expect("register parameter");
    assert_eq!(got.sig.params.len(), 1);
    let err = parse_sig(&mut s, "int f(").expect_err("cut prototype");
    assert_eq!(first(&err).at.byte as usize, "int f(".len());
    let err = parse_sig(&mut s, "int f(auto int x)").expect_err("auto parameter");
    assert_eq!(first(&err).code, DiagCode::Syntax);
    let err = parse_type(&mut s, "int int2").expect_err("name in type mode");
    assert!(
        err.to_string().contains("Expected: the end of the text."),
        "{err}"
    );
}
