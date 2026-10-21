//! Fuzz target `addr_expr` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race.
//! The seeds hold every syntactic form of Section 10.5. Each case runs in a 256 KiB stack.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::path::PathBuf;

use ghidorah_base::addr_expr::{self, OffsetExpr};
use ghidorah_base::{AddrExpr, Address, BinaryId, DefaultName, Glob, Id};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. Stage 1: the input is UTF-8. Stage 2: the text parses.
/// Stage 3: the text parses as an ID or as an offset expression.
const STAGES: [&str; 4] = ["input", "utf8", "parsed", "id_or_offset"];

/// The seed inputs: one per syntactic form.
const SEEDS: [&str; 40] = [
    "0x401000",
    "0xffffffffffffffff",
    "401000",
    "18446744073709551616",
    "fn:0x401130",
    "fn:ext:0x3",
    "bb:0x401145",
    "op:0x401a2c:3",
    "imp:puts",
    "imp:kernel32.dll!ExitProcess",
    "imp:alpha.dll!#7",
    "imp:!a!b",
    "exp:main",
    "exp:#7",
    "sys:openat",
    "sys:257",
    "sec:14:.text",
    "seg:2",
    "str:0x402010",
    "jt:0x401200",
    "ext:0x3",
    "file:0x1040",
    "sym:puts@GLIBC_2.2.5",
    "var:0x401130/stack:-0x14",
    "var:0x401130/reg:rax@0x401136",
    "var:0x401130/param:2",
    "note:7",
    "set:parsers",
    "t:sockaddr_in",
    "t:#00000000deadbeef",
    "tx:42",
    "ref:0x401136>0x402010:read",
    "main+0x10",
    "main+16",
    "helper@0x401000",
    "FUN_00401000",
    "x@plt",
    "foo.cold",
    "0x401000-0x4",
    "fn:0x401000+0x8",
];

/// The regression directory of the target: `tests/regress/addr_expr/`.
fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/addr_expr")
}

/// Checks that an ID round-trips through its text.
fn check_id(id: &Id) -> Result<(), String> {
    let text = id.to_string();
    match Id::parse(&text) {
        Ok(back) if back == *id => Ok(()),
        other => Err(format!("{text:?} gives {other:?}")),
    }
}

/// Checks the parts of an offset expression.
fn check_offset(expr: &OffsetExpr) -> Result<(), String> {
    if matches!(*expr.term, AddrExpr::Offset(_)) {
        return Err("an offset term holds a second offset".to_string());
    }
    if let AddrExpr::Name(name) = &*expr.term
        && name.split.is_some()
    {
        return Err("a name term holds a second offset".to_string());
    }
    check_expr(&expr.term)
}

fn check_expr(expr: &AddrExpr) -> Result<(), String> {
    match expr {
        AddrExpr::Id(id) => check_id(id),
        AddrExpr::Offset(offset) => check_offset(offset),
        AddrExpr::Name(name) => {
            if let Some(default) = name.default {
                let text = default.to_string();
                if DefaultName::parse(&text) != Some(default) {
                    return Err(format!("default name {text} does not round-trip"));
                }
            }
            name.split.as_ref().map_or(Ok(()), check_offset)
        }
        AddrExpr::Hex(v) | AddrExpr::Integer(v) => {
            let text = Address::ram(*v).to_string();
            if Address::parse(&text) == Ok(Address::ram(*v)) {
                Ok(())
            } else {
                Err(format!("address {text} does not round-trip"))
            }
        }
        AddrExpr::Digits(_) => Ok(()),
    }
}

fn target(input: &[u8]) -> Outcome {
    let text = String::from_utf8_lossy(input);
    // Other parsers of the crate read the same hostile text.
    let _ = Id::parse(&text);
    let _ = BinaryId::parse(&text);
    let _ = DefaultName::parse(&text);
    if let Ok(glob) = Glob::new(&text) {
        let _ = glob.matches(&text);
    }
    let stage_utf8 = usize::from(std::str::from_utf8(input).is_ok());
    match addr_expr::parse(&text) {
        Err(_) => Outcome::reached(stage_utf8),
        Ok(expr) => {
            let stage = if matches!(expr, AddrExpr::Id(_) | AddrExpr::Offset(_)) {
                3
            } else {
                2
            };
            match check_expr(&expr) {
                Ok(()) => Outcome::reached(stage),
                Err(message) => Outcome::violation(stage, message),
            }
        }
    }
}

#[test]
fn fuzz_addr_expr() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let corpus: Vec<Vec<u8>> = SEEDS.iter().map(|s| s.as_bytes().to_vec()).collect();
    let mut config = Config::new("addr_expr", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 256;
    let report = fuzz::run(&config, &corpus, target)
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(
        report.reached_percent(2) >= 10,
        "parsed share: {:?}",
        report.reached
    );
    assert!(report.reached[3] > 0, "ID share: {:?}", report.reached);
}
