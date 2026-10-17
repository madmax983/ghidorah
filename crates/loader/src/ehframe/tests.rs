use ghidorah_base::DiagCode;

use super::cfa::{Factors, Rule, run};
use crate::binary::CfaRow;

const GCC: Factors = Factors { code: 1, data: -8 };

const RSP8: Rule = Rule {
    reg: Some(7),
    offset: 8,
};

fn rows(program: &[u8]) -> Vec<CfaRow> {
    run(program, GCC, 0x100, Some(0x200), RSP8, 64)
        .map(|r| r.rows)
        .unwrap_or_default()
}

fn stop(program: &[u8]) -> (DiagCode, usize, u8) {
    let s = run(program, GCC, 0x100, Some(0x200), RSP8, 64).expect_err("a stop");
    (s.code, s.at, s.opcode)
}

#[test]
fn cfa_run_stops() {
    // A register number above u16::MAX.
    assert_eq!(
        stop(&[0x0d, 0x80, 0x80, 0x04]),
        (DiagCode::Overflow, 0, 0x0d)
    );
    // A def_cfa offset above i64::MAX.
    let mut big = vec![0x0c, 0x07];
    big.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    assert_eq!(stop(&big), (DiagCode::Overflow, 0, 0x0c));
    // A factored offset that overflows.
    let mut sf = vec![0x41, 0x13];
    sf.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f]);
    assert_eq!(stop(&sf), (DiagCode::Overflow, 1, 0x13));
    // An operand past the end of the program.
    assert_eq!(stop(&[0x41, 0x04, 0x01]), (DiagCode::Oob, 1, 0x04));
    assert_eq!(stop(&[0x10, 0x03, 0x05, 0x01]), (DiagCode::Oob, 0, 0x10));
    // A bad LEB128 value.
    let mut leb = vec![0x0e];
    leb.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]);
    assert_eq!(stop(&leb), (DiagCode::Overflow, 0, 0x0e));
    // The instruction cap.
    assert_eq!(stop(&[0; 65]), (DiagCode::Limit, 64, 0));
    // A location past u64::MAX.
    let s = run(
        &[0x04, 0xff, 0xff, 0xff, 0xff],
        GCC,
        u64::MAX - 5,
        None,
        RSP8,
        64,
    )
    .expect_err("overflow");
    assert_eq!((s.code, s.at), (DiagCode::Overflow, 0));
}

#[test]
fn cfa_run_rows_and_rule() {
    assert_eq!(
        rows(&[0x41, 0x0e, 0x10]),
        vec![
            CfaRow {
                pc: 0x100,
                reg: 7,
                offset: 8
            },
            CfaRow {
                pc: 0x101,
                reg: 7,
                offset: 16
            }
        ]
    );
    // A CIE program has no end, and the rule after it is the start rule of each FDE.
    let cie = run(
        &[0x0c, 0x07, 0x08, 0x90, 0x01],
        GCC,
        0,
        None,
        Rule::default(),
        64,
    )
    .expect("CIE program");
    assert_eq!(cie.rule, RSP8);
    // No register gives no row.
    let none = run(&[0x0e, 0x10], GCC, 0x100, Some(0x200), Rule::default(), 64).expect("run");
    assert!(none.rows.is_empty());
    assert_eq!(none.rule.offset, 16);
    // A code factor scales the advance.
    let wide = run(
        &[0x42, 0x0e, 0x10],
        Factors { code: 4, data: -8 },
        0x100,
        Some(0x200),
        RSP8,
        64,
    )
    .expect("run");
    assert_eq!(wide.rows.last().map(|r| r.pc), Some(0x108));
}
