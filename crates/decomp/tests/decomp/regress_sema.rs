//! Regression tests of the meaning of the decompiled text. Each test compares the C text or
//! the IR value with the meaning of the machine code.

use ghidorah_base::Fuel;
use ghidorah_decomp::{Cond, Exit, Opts, Stmt, Tree};
use ghidorah_ir::{Loc, NoNames, Opc};

use crate::fixtures::{entry_of, fid, program};
use crate::out_print::{Spec, bin, decomp, k, op, param, text_of, un, v};
use crate::shapes::node;

/// Gives the decompiled text of the function `name` of the fixture `fixture`.
pub fn text(fixture: &str, name: &str) -> String {
    let p = program(fixture);
    let entry = entry_of(p, name);
    ghidorah_decomp::render(
        p,
        fid(entry),
        &Opts::default(),
        &NoNames,
        &mut Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{fixture} {name}: {e}"))
    .text()
}

/// Gives the lines of the text of `fixture` and `name`, without the indentation.
fn lines(fixture: &str, name: &str) -> Vec<String> {
    text(fixture, name)
        .lines()
        .map(|l| l.trim().to_owned())
        .collect()
}

/// Gives the text of `if (!c) return 1; return 0;` for the compare `opc` of `param_1`.
fn negated_test(opc: Opc) -> Vec<String> {
    let test = bin(opc, 64, v(0, 64), v(0, 64), op(0, 0, 0));
    let ret = |value: u64, i: usize| Stmt::Return {
        uses: vec![(Loc::RAX, k(value, 64))],
        at: op(i, 0, 0),
    };
    let d = decomp(
        vec![
            Spec::branch(2, 1, test, op(0, 1, 0)),
            Spec::new(Exit::Stop, vec![ret(1, 1)]),
            Spec::new(Exit::Stop, vec![ret(0, 2)]),
        ],
        vec![param(0, 64)],
        Tree::Seq(vec![
            Tree::Block(node(0)),
            Tree::If {
                cond: Cond::leaf(node(0)).negate(),
                then: Box::new(Tree::Block(node(1))),
                els: None,
            },
            Tree::Block(node(2)),
        ]),
    );
    text_of(&d)
}

/// A negated `TestZ` leaf is `x != 0`, and a negated `TestNZ` leaf is `x == 0`. The printer
/// gave each negated test the text of the plain test (decomp-01).
#[test]
fn regress_negated_test_polarity() {
    let z = negated_test(Opc::TestZ);
    assert_eq!(z[2], "    if (param_1 != 0) {", "{z:?}");
    let nz = negated_test(Opc::TestNZ);
    assert_eq!(nz[2], "    if (param_1 == 0) {", "{nz:?}");
}

/// `xor eax, eax` reads `eax` through two `Trunc` ops with two op IDs. Its value is 0, so the
/// text is `0`. The zero rule of the printer compared the op IDs too (decomp-07).
#[test]
fn regress_zero_rule_ignores_op_ids() {
    let trunc = |seq| un(Opc::Trunc, 32, 0, v(0, 64), op(0, 0, seq));
    let xor = bin(Opc::Xor, 32, trunc(1), trunc(3), op(0, 0, 4));
    let d = decomp(
        vec![Spec::new(
            Exit::Stop,
            vec![Stmt::Return {
                uses: vec![(Loc::RAX, xor)],
                at: op(0, 1, 0),
            }],
        )],
        vec![param(0, 64)],
        Tree::Block(node(0)),
    );
    let t = text_of(&d);
    assert_eq!(t[2], "    return 0;", "{t:?}");
}

/// `sum_squares` reads only `edi` (`and edi, 0x3f`). Its `xor eax, eax` and `xor edx, edx`
/// give 0, so the text has no `^`, and the function line has one parameter. The text read
/// `v1 ^ v1` of a variable with no def, and the function line had 3 parameters (decomp-07).
#[test]
fn regress_zero_idiom_params() {
    let sum = text("loops.gcc-O2", "sum_squares");
    assert!(
        sum.starts_with("uint64_t sum_squares(uint64_t param_1)\n"),
        "{sum}"
    );
    assert!(sum.contains("return 0;"), "{sum}");
    assert!(!sum.contains(" ^ "), "{sum}");
    let count = text("loops.gcc-O2", "count_bits");
    assert!(
        count.starts_with("uint64_t count_bits(uint64_t param_1)\n"),
        "{count}"
    );
    let grid = text("loops.gcc-O2", "grid_walk");
    assert!(
        grid.starts_with("uint64_t grid_walk(uint64_t param_1, uint64_t param_2)\n"),
        "{grid}"
    );
    assert!(grid.contains("return 0;"), "{grid}");
}

/// Gives the text between `start` and the next `)` after each place of `start` in `text`.
fn args_after<'t>(text: &'t str, start: &str) -> Vec<&'t str> {
    text.match_indices(start)
        .filter_map(|(i, _)| {
            let rest = text.get(i + start.len()..)?;
            rest.split([')', ',']).next()
        })
        .collect()
}

/// `main` of xor_decode.clang-O2 passes `lea rdi,[rsp+0x9]` to `decode`, `puts` and
/// `strlen`, and no instruction between the calls changes `rsp`. So the three arguments are
/// one expression. L1 kept the stack pointer 8 bytes low after each call, so each later call
/// got another pointer (decomp-04).
#[test]
fn regress_stack_pointer_after_call() {
    let t = text("xor_decode.clang-O2", "main");
    let mut seen: Vec<&str> = Vec::new();
    for call in ["decode(", "puts(", "strlen("] {
        let got = args_after(&t, call);
        assert_eq!(got.len(), 1, "{call}: {t}");
        seen.extend(got);
    }
    assert!(seen[0].ends_with(" + 9"), "{t}");
    assert!(seen.iter().all(|a| *a == seen[0]), "{seen:?}\n{t}");
    // gcc reloads the canary with `mov rax,[rsp+0x18]` after 4 calls. The buffer is at
    // `rsp + 9`, so the reload base is the base of the buffer.
    let g = text("xor_decode.gcc-O2", "main");
    let buffer = args_after(&g, "decode(")[0];
    let line = g
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(&format!("{buffer} = ")) && l.ends_with(" + 9;"))
        .unwrap_or_else(|| panic!("no def of {buffer}: {g}"));
    let base = line
        .trim_start_matches(&format!("{buffer} = "))
        .trim_end_matches(" + 9;");
    assert!(
        g.contains(&format!("*(uint64_t *)({base} + 0x18)")),
        "the canary reload reads {base} + 0x18: {g}"
    );
}

/// `test rdx,rdx; je 12fc` at 0x12d2 of `decode` skips the loop when `n == 0`. So the loop
/// runs under `param_3 != 0`. `test rdx,rdx; jne 1260` at 0x126b of `gcd` loops while the
/// remainder is not 0, so the loop breaks on `== 0` (decomp-01).
#[test]
fn regress_negated_test_polarity_fixtures() {
    let decode = lines("xor_decode.gcc-O2", "decode");
    assert!(
        decode.iter().any(|l| l == "if (param_3 != 0) {"),
        "{decode:#?}"
    );
    let gcd = text("loops.gcc-O2", "gcd");
    let zero_tests = gcd
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("if (") && l.contains("== 0"))
        .count();
    assert_eq!(zero_tests, 2, "{gcd}");
    assert!(!gcd.contains("!= 0"), "{gcd}");
}
