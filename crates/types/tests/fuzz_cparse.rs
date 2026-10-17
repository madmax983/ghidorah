//! Fuzz target `cparse` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. The seeds are the
//! Tier-0 prototypes and type texts. Each case runs in a 256 KiB stack. It parses the input
//! in both modes and checks the error places, the store and the canonical text.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "the seed helper uses expect")]

use std::path::PathBuf;
use std::sync::OnceLock;

use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_types::data::TIER0_H;
use ghidorah_types::{CParseError, DataModel, TypeStore, layout, parse_sig, parse_type};

/// Stage 0: any input. 1: the diagnostics are good. 2: one mode parses.
/// 3: the canonical text parses back to the same type.
const STAGES: [&str; 4] = ["input", "checked", "parsed", "round_trip"];

/// Type texts for the seed corpus.
const TYPE_SEEDS: &[&str] = &[
    "struct sockaddr_in *",
    "uint8_t[16]",
    "void (*[3])(int)",
    "int (*(*)(int))[2]",
    "struct { int a; char *b; double c[4]; }",
    "union { int i; float f; } *",
    "enum { A, B = 1 << 3, C = B | 1 }",
    "const char *const *",
    "int[(1 + 2) * 3 ? 4 : 5]",
    "struct pt { int x, y; struct pt *next; char tail[]; }",
];

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/cparse")
}

fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = TIER0_H
        .lines()
        .filter(|l| l.contains(';') && !l.trim_start().starts_with('*'))
        .take(60)
        .map(|l| l.as_bytes().to_vec())
        .collect();
    out.extend(TYPE_SEEDS.iter().map(|s| s.as_bytes().to_vec()));
    out
}

/// Checks the diagnostics of an error against the input.
fn check_error(text: &str, err: &CParseError) -> Result<(), String> {
    let Some(d) = err.first() else {
        return Err("an error without a diagnostic".to_string());
    };
    let byte = d.at.byte as usize;
    if byte > text.len() || !text.is_char_boundary(byte) {
        return Err(format!("bad error place {:?}", d.at));
    }
    if d.at.line == 0 || d.at.col == 0 {
        return Err(format!("line and column start at 1: {:?}", d.at));
    }
    if d.snippet.len() > ghidorah_types::cparse::MAX_SNIPPET || d.hint.is_empty() {
        return Err(format!("bad snippet or hint: {d:?}"));
    }
    Ok(())
}

/// Gives the prelude store of all cases.
fn base() -> &'static TypeStore {
    static BASE: OnceLock<TypeStore> = OnceLock::new();
    BASE.get_or_init(|| TypeStore::with_prelude().expect("the prelude installs"))
}

fn target(input: &[u8]) -> Outcome {
    let text = String::from_utf8_lossy(input);
    let text = text.as_ref();
    let base = base();
    let mut store = base.clone();
    let parsed = match parse_type(&mut store, text) {
        Ok(id) => Some(id),
        Err(e) => {
            if let Err(m) = check_error(text, &e) {
                return Outcome::violation(1, m);
            }
            if store != *base {
                return Outcome::violation(1, "a failed parse changes the store".to_string());
            }
            None
        }
    };
    let id = match parsed {
        Some(id) => id,
        None => match parse_sig(&mut store, text) {
            Ok(p) => p.ty,
            Err(e) => {
                if let Err(m) = check_error(text, &e) {
                    return Outcome::violation(1, m);
                }
                if store != *base {
                    return Outcome::violation(1, "a failed parse changes the store".to_string());
                }
                return Outcome::reached(1);
            }
        },
    };
    let _ = layout::sysv(&store, id, &DataModel::X86_64_SYSV);
    let Ok(canonical) = store.c_text(id) else {
        return Outcome::reached(2);
    };
    let mut again = store.clone();
    match parse_type(&mut again, &canonical) {
        Ok(back) if back == id => Outcome::reached(3),
        Ok(_) if canonical.starts_with("_Noreturn") => Outcome::reached(2),
        Ok(back) => Outcome::violation(2, format!("`{canonical}` parses to {back:?}, not {id:?}")),
        Err(e) if canonical.starts_with("_Noreturn") => {
            let _ = e;
            Outcome::reached(2)
        }
        Err(e) => Outcome::violation(2, format!("`{canonical}` does not parse: {e}")),
    }
}

#[test]
fn fuzz_cparse() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("cparse", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 4096;
    let report = fuzz::run(&config, &seeds(), target)
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report
            .crashes
            .iter()
            .map(|c| (&c.message, String::from_utf8_lossy(&c.input)))
            .collect::<Vec<_>>()
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(
        report.reached_percent(1) >= 99,
        "checked stage: {:?}",
        report.reached
    );
    assert!(
        report.reached_percent(2) >= 1,
        "parsed stage: {:?}",
        report.reached
    );
}
