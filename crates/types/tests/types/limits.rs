//! AC-111: parser bombs stay within the limits in a 256 KiB stack and give errors with candidates.

use std::time::{Duration, Instant};

use ghidorah_base::DiagCode;
use ghidorah_types::cparse::{
    MAX_DEPTH, MAX_IDENT, MAX_INPUT, MAX_NESTING, MAX_PARAMS, MAX_SNIPPET, MAX_TOKENS,
};
use ghidorah_types::{CParseError, TypeStore, parse_sig, parse_type};

use crate::support::{first, in_small_stack, store};

/// The nesting depth of the bombs.
const DEEP: usize = 10_000;

/// One bomb: a name, the mode (`true` for `sig`), the text and the detail code.
struct Bomb {
    name: &'static str,
    sig: bool,
    text: String,
    code: DiagCode,
}

/// The bombs of the input, the tokens and the declarators.
fn declarator_bombs() -> Vec<Bomb> {
    let deep = DEEP;
    vec![
        Bomb {
            name: "input above 1 MiB",
            sig: false,
            text: format!("int{}", " ".repeat(MAX_INPUT)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "tokens above 200,000",
            sig: false,
            text: format!("int{}", "*".repeat(MAX_TOKENS + 1)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "identifier above 1,024 bytes",
            sig: true,
            text: format!("int {}(void)", "a".repeat(MAX_IDENT + 1)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "parenthesized declarator",
            sig: true,
            text: format!("int {}f{}(void)", "(".repeat(deep), ")".repeat(deep)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "abstract declarator",
            sig: false,
            text: format!("int {}*{}", "(".repeat(deep), ")".repeat(deep)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "pointer chain",
            sig: false,
            text: format!("int {}", "*".repeat(MAX_NESTING + 1)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "array chain",
            sig: false,
            text: format!("int {}", "[1]".repeat(MAX_NESTING + 1)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "parameters above 4,096",
            sig: true,
            text: format!("void f({}int)", "int,".repeat(MAX_PARAMS)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "fields above 4,096",
            sig: false,
            text: format!(
                "struct {{ {} }}",
                (0..=MAX_PARAMS)
                    .map(|i| format!("int f{i};"))
                    .collect::<Vec<_>>()
                    .concat()
            ),
            code: DiagCode::Limit,
        },
    ]
}

/// The bombs of the records and the constant expressions.
fn nested_bombs() -> Vec<Bomb> {
    let deep = DEEP;
    vec![
        Bomb {
            name: "nested function pointer parameters",
            sig: true,
            text: format!("void f({}){}", "void (*)(".repeat(deep), ")".repeat(deep)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "nested records",
            sig: false,
            text: format!("{}int x;{}", "struct { ".repeat(deep), " } s;".repeat(deep)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "parenthesized constant",
            sig: false,
            text: format!("int[{}1{}]", "(".repeat(deep), ")".repeat(deep)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "unary chain",
            sig: false,
            text: format!("int[{}1]", "-".repeat(deep)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "conditional chain",
            sig: false,
            text: format!("int[{}1{}]", "1 ? ".repeat(deep), " : 1".repeat(deep)),
            code: DiagCode::Limit,
        },
        Bomb {
            name: "constant overflow",
            sig: false,
            text: "int[0x7fffffffffffffffffffffffffffffff * 2]".to_string(),
            code: DiagCode::Overflow,
        },
        Bomb {
            name: "literal above 128 bits",
            sig: false,
            text: format!("int[{}]", "9".repeat(60)),
            code: DiagCode::Overflow,
        },
    ]
}

fn run(store: &mut TypeStore, bomb: &Bomb) -> Result<(), CParseError> {
    if bomb.sig {
        parse_sig(store, &bomb.text).map(|_| ())
    } else {
        parse_type(store, &bomb.text).map(|_| ())
    }
}

#[test]
fn ac_111_c_parser_limits() {
    assert_eq!(MAX_DEPTH, 64);
    for bomb in declarator_bombs().into_iter().chain(nested_bombs()) {
        let started = Instant::now();
        let (result, before, after) = in_small_stack(|| {
            let mut s = store();
            let before = s.clone();
            let result = run(&mut s, &bomb);
            (result, before, s)
        });
        let err = result.expect_err(bomb.name);
        assert_eq!(before, after, "{}: the store does not change", bomb.name);
        let d = first(&err);
        assert_eq!(d.code, bomb.code, "{}: {:?}", bomb.name, d.code);
        assert!(d.at.line >= 1 && d.at.col >= 1, "{}: {:?}", bomb.name, d.at);
        assert!(
            d.at.byte as usize <= bomb.text.len(),
            "{}: {:?}",
            bomb.name,
            d.at
        );
        assert!(d.snippet.len() <= MAX_SNIPPET, "{}", bomb.name);
        assert!(!d.hint.is_empty(), "{}", bomb.name);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{} takes {:?}",
            bomb.name,
            started.elapsed()
        );
    }
    check_bomb_candidates();
    check_largest_inputs();
}

/// Checks that inputs at each limit parse in the small stack.
fn check_largest_inputs() {
    in_small_stack(|| {
        let mut s = store();
        let text = format!("void f({}int)", "int,".repeat(MAX_PARAMS - 1));
        let got = parse_sig(&mut s, &text).expect("4,096 parameters parse");
        assert_eq!(got.sig.params.len(), MAX_PARAMS);
        let text = format!("int {}", "*".repeat(MAX_NESTING));
        parse_type(&mut s, &text).expect("64 pointers parse");
        let text = format!("int {}(void)", "a".repeat(MAX_IDENT));
        parse_sig(&mut s, &text).expect("a 1,024 byte identifier parses");
        let text = format!("int[{}1{}]", "(".repeat(40), ")".repeat(40));
        parse_type(&mut s, &text).expect("40 parentheses parse");
    });
}

/// Checks that a bomb of 1,000 `const` words before an unknown type gives candidates.
fn check_bomb_candidates() {
    in_small_stack(|| {
        let mut s = store();
        let text = format!("{} uint8", "const ".repeat(1000));
        let err = parse_type(&mut s, &text).expect_err("unknown type");
        let d = first(&err);
        assert_eq!(d.code, DiagCode::UnknownType);
        assert!(d.candidates.iter().any(|c| c == "uint8_t"), "{d:?}");
        assert!(d.snippet.contains("uint8"), "{d:?}");
    });
}
