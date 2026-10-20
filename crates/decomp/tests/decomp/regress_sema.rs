//! Regression tests of the meaning of the decompiled text. Each test compares the C text or
//! the IR value with the meaning of the machine code.

use ghidorah_base::Fuel;
use ghidorah_decomp::{Cond, Exit, Opts, Stmt, Tree};
use ghidorah_ir::{Loc, NoNames, Opc};

use crate::fixtures::{entry_of, fid, program};
use crate::out_print::{Spec, bin, decomp, k, op, param, text_of, v};
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
