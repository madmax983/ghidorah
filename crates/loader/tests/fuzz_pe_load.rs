//! Fuzz target `pe_load` (design Sections 4.15 and 13.5, AC-251).
//!
//! This binary has one test, so the global panic hook has no race. The seeds are the PE
//! fixtures and every `PeBuilder` variant: `BlockSize` 0, a huge `NumberOfNames`, cyclic
//! forwarders and sections past EOF among them. Each case loads twice and checks the
//! invariants of the model and the map.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::path::PathBuf;

use ghidorah_base::Limits;
use ghidorah_loader::{Binary, LoadOpts, MemoryMap, load};
use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_testkit::pe::variants;

/// Stage 0: any input. 1: the headers parse. 2: a mapped section. 3: imports. 4: relocations
/// or exports. 5: `.pdata` entries or TLS callbacks.
const STAGES: [&str; 6] = ["input", "headers", "sections", "imports", "relocs", "pdata"];

/// The variants that AC-251 names. Each one must be a seed.
const NAMED: [&str; 4] = ["block_size_0", "huge_names", "forwarder_cycle", "past_eof"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn regress_dir() -> PathBuf {
    root().join("tests/regress/pe_load")
}

fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = ["pe_main.exe", "pe_cc.exe", "pe_dll.dll", "pe_flags.exe"]
        .iter()
        .map(|n| {
            let path = root().join("fixtures/bin/pe").join(n);
            std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        })
        .collect();
    let all = variants();
    for name in NAMED {
        assert!(all.iter().any(|v| v.name == name), "the seed {name} exists");
    }
    out.extend(all.into_iter().map(|v| v.bytes));
    out
}

/// Checks the invariants of one load.
fn check(binary: &Binary, map: &MemoryMap, len: usize) -> Result<(), String> {
    let mut last: Option<u64> = None;
    for r in map.regions() {
        if last.is_some_and(|l| l >= r.va.first) {
            return Err(format!("regions overlap at {:#x}", r.va.first));
        }
        last = Some(r.va.last);
        let end = r.file_off.checked_add(r.file_size);
        if end.is_none_or(|e| e > len as u64) {
            return Err(format!("region file part past the file: {r:?}"));
        }
    }
    if binary.diagnostics.len() > ghidorah_loader::diag::MAX_DIAGNOSTICS {
        return Err("too many diagnostics".to_owned());
    }
    if binary.data_dirs.len() > 16 {
        return Err("more than 16 data directories".to_owned());
    }
    if binary.pdata.iter().any(|p| p.end <= p.begin) {
        return Err("a .pdata entry with no bytes".to_owned());
    }
    Ok(())
}

fn target(input: &[u8]) -> Outcome {
    let first = load(input, &LoadOpts::AUTO, &Limits::DEFAULT);
    let Ok((binary, map)) = first else {
        return Outcome::reached(0);
    };
    let again = load(input, &LoadOpts::AUTO, &Limits::DEFAULT);
    if again.as_ref().ok() != Some(&(binary.clone(), map.clone())) {
        return Outcome::violation(1, "two loads differ".to_owned());
    }
    if let Err(message) = check(&binary, &map, input.len()) {
        return Outcome::violation(1, message);
    }
    let stage = if !binary.pdata.is_empty()
        || binary
            .entry_points
            .iter()
            .any(|e| e.kind == ghidorah_loader::EntryKind::TlsCallback)
    {
        5
    } else if !binary.relocs.is_empty() || !binary.exports.is_empty() {
        4
    } else if !binary.imports.is_empty() {
        3
    } else if map.len() > 1 {
        2
    } else {
        1
    };
    Outcome::reached(stage)
}

#[test]
fn ac_251_fuzz_pe_load() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);
    let mut config = Config::new("pe_load", 10_000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 64 << 10;
    let report = fuzz::run(&config, &seeds(), target)
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 10_000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report
            .crashes
            .iter()
            .map(|c| &c.message)
            .collect::<Vec<_>>()
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    for (stage, name) in STAGES.iter().enumerate().skip(1) {
        assert!(
            report.reached_percent(stage) >= 5,
            "stage {name}: {:?}",
            report.reached
        );
    }
}
