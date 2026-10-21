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

/// Writes one record: the length field and `body`, which starts with the 4-byte ID. With
/// `ext`, the length uses the `0xffffffff` escape and 8 bytes.
fn record(out: &mut Vec<u8>, body: &[u8], ext: bool) {
    let len = u32::try_from(body.len()).expect("a short body");
    if ext {
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&u64::from(len).to_le_bytes());
    } else {
        out.extend_from_slice(&len.to_le_bytes());
    }
    out.extend_from_slice(body);
}

/// A CIE with `zR` and `udata4` pointers, an FDE for 0x401000..0x40101f, and the end mark.
fn cie_fde(ext: bool) -> Vec<u8> {
    let mut cie = 0u32.to_le_bytes().to_vec();
    cie.extend_from_slice(&[1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x03]);
    cie.extend_from_slice(&[0x0c, 0x07, 0x08, 0x90, 0x01, 0, 0]);
    let mut out = Vec::new();
    record(&mut out, &cie, ext);
    let header = if ext { 12 } else { 4 };
    let back = u32::try_from(out.len().saturating_add(header)).expect("a small offset");
    let mut fde = back.to_le_bytes().to_vec();
    fde.extend_from_slice(&0x0040_1000u32.to_le_bytes());
    fde.extend_from_slice(&0x1fu32.to_le_bytes());
    fde.extend_from_slice(&[0, 0x41, 0x0e, 0x10]);
    record(&mut out, &fde, ext);
    out.extend_from_slice(&[0; 4]);
    out
}

#[test]
fn regress_eh_frame_extended_length_id_is_4_bytes() {
    let place = super::Place {
        va: 0x50_0000,
        file_off: 0,
    };
    let limits = ghidorah_base::Limits::DEFAULT;
    let short = super::parse_bytes(&cie_fde(false), place, &limits);
    assert!(short.diagnostics.is_empty(), "{:?}", short.diagnostics);
    assert_eq!(short.fdes.len(), 1);
    assert_eq!(short.fdes[0].cfa_rows.len(), 2, "{:?}", short.fdes);
    let long = super::parse_bytes(&cie_fde(true), place, &limits);
    assert!(
        long.diagnostics.iter().all(|d| d.code != DiagCode::Oob),
        "{:?}",
        long.diagnostics
    );
    assert!(long.diagnostics.is_empty(), "{:?}", long.diagnostics);
    assert_eq!(long.fdes, short.fdes);
}

/// The PLT expression of GNU ld: `breg7 8; breg16 0; lit15; and; lit<k>; ge; lit3; shl; plus`.
fn plt_expr(k: u8) -> Vec<u8> {
    let block = [
        0x77,
        0x08,
        0x80,
        0x00,
        0x3f,
        0x1a,
        0x30 | k,
        0x2a,
        0x33,
        0x24,
        0x22,
    ];
    let mut out = vec![0x0f, 11];
    out.extend_from_slice(&block);
    out
}

fn row(pc: u64, offset: i64) -> CfaRow {
    CfaRow { pc, reg: 7, offset }
}

#[test]
fn regress_cfa_plt_expression_rows() {
    // The PLT FDE of GNU ld: PLT0 pushes and jumps, each entry pushes at offset k.
    let mut program = vec![0x0e, 0x10, 0x46, 0x0e, 0x18, 0x4a];
    program.extend(plt_expr(11));
    program.extend_from_slice(&[0, 0, 0]);
    let run = run(&program, GCC, 0x1020, Some(0x1050), RSP8, 64).expect("the PLT rule");
    assert_eq!(
        run.rows,
        vec![
            row(0x1020, 16),
            row(0x1026, 24),
            row(0x1030, 8),
            row(0x103b, 16),
            row(0x1040, 8),
            row(0x104b, 16),
        ]
    );
    // The IBT PLT pushes at offset 9. A start inside an entry takes the rule of its offset.
    let mut ibt = vec![0x4c];
    ibt.extend(plt_expr(9));
    let run = super::cfa::run(&ibt, GCC, 0x1020, Some(0x1040), RSP8, 64).expect("the IBT rule");
    assert_eq!(
        run.rows,
        vec![
            row(0x1020, 8),
            row(0x102c, 16),
            row(0x1030, 8),
            row(0x1039, 16)
        ]
    );
}

#[test]
fn regress_cfa_plt_expression_limits() {
    // Each row counts as one instruction of the cap.
    let program = plt_expr(11);
    let s = run(&program, GCC, 0x1000, Some(0x1000 + 16 * 64), RSP8, 64).expect_err("the cap");
    assert_eq!((s.code, s.opcode), (DiagCode::Limit, 0x0f));
    // A CIE program has no end, so the PLT rule stops it.
    let s = run(&program, GCC, 0, None, RSP8, 64).expect_err("no end");
    assert_eq!(s.code, DiagCode::CfaOpcode);
    // An instruction after the PLT rule stops the FDE.
    let mut more = plt_expr(11);
    more.extend_from_slice(&[0x41, 0x0e, 0x10]);
    assert_eq!(stop(&more), (DiagCode::CfaOpcode, 0, 0x0f));
    // Another expression still stops the FDE.
    let mut other = plt_expr(11);
    other[4] = 0x31;
    assert_eq!(stop(&other), (DiagCode::CfaOpcode, 0, 0x0f));
    assert_eq!(
        stop(&[0x0f, 0x02, 0x77, 0x08]),
        (DiagCode::CfaOpcode, 0, 0x0f)
    );
    // A block that runs past the program.
    assert_eq!(stop(&[0x0f, 0x20, 0x77]), (DiagCode::Oob, 0, 0x0f));
}
