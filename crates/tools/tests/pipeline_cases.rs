//! Fixed cases of the pipeline fuzz targets (design Section 13.5, AC-190c and AC-190d).
//!
//! The fuzz binaries `fuzz_pipeline_raw` and `fuzz_pipeline_elf` hold the random cases. This
//! binary runs the pipeline on fixed hostile inputs and checks the stage classifier of the ELF
//! target on known files.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

#[path = "pipeline/mod.rs"]
mod pipeline;

use std::collections::BTreeSet;

use ghidorah_testkit::elf::{Class, Endian, header_only, malformed_variants};

use crate::pipeline::{
    ELF_STAGES, Load, RAW_BASE, elf_seeds, elf_stage, fixture, raw_entry, raw_seeds, run, work_dir,
};

/// Gives fixed hostile raw blobs: empty, one byte, zeros, ones, traps and loops.
fn hostile_raw() -> Vec<Vec<u8>> {
    let mut out = vec![
        Vec::new(),
        vec![0xc3],
        vec![0; 4096],
        vec![0xff; 4096],
        vec![0xcc; 512],
        vec![0xeb, 0xfe],
        // call $+0 forever: a call to the next byte.
        [0xe8, 0, 0, 0, 0].repeat(200),
        // jmp to the blob start from the last byte.
        vec![0x90, 0x90, 0xeb, 0xfc],
    ];
    out.extend(raw_seeds());
    out
}

#[test]
fn ac_190c_pipeline_no_internal_error() {
    let dir = work_dir("cases_raw");
    let mut deepest = 0;
    for (i, bytes) in hostile_raw().iter().enumerate() {
        for entry in [RAW_BASE, raw_entry(bytes)] {
            let got = run(
                &dir,
                bytes,
                Load::Raw {
                    base: RAW_BASE,
                    entry,
                },
            )
            .unwrap_or_else(|e| panic!("raw case {i} at {entry:#x}: {e}"));
            deepest = deepest.max(got.raw_stage());
        }
    }
    assert_eq!(deepest, 3, "a raw case reaches func_get");
    let dir = work_dir("cases_elf");
    let hello = fixture("hello.gcc-O2");
    let mut inputs = elf_seeds();
    for cut in [0, 16, 64, 1_024, 4_096, 8_192] {
        inputs.push(hello.get(..cut).unwrap_or_default().to_vec());
    }
    for (i, bytes) in inputs.iter().enumerate() {
        run(&dir, bytes, Load::Auto).unwrap_or_else(|e| panic!("ELF case {i}: {e}"));
    }
}

#[test]
fn ac_190d_stage_reach() {
    assert_eq!(elf_stage(&[]), 0);
    assert_eq!(elf_stage(b"\x7fELF"), 0);
    assert_eq!(elf_stage(&fixture("hello.gcc-O2")), ELF_STAGES.len() - 1);
    let header = header_only(Class::Elf64, Endian::Little, 3, 62);
    assert!(elf_stage(&header) <= 1, "a header with no segment");
    let mut seen = BTreeSet::new();
    let mut inputs = elf_seeds();
    inputs.push(header);
    inputs.extend(malformed_variants().into_iter().map(|v| v.bytes));
    for bytes in &inputs {
        seen.insert(elf_stage(bytes));
    }
    for stage in [0, 1, ELF_STAGES.len() - 1] {
        assert!(seen.contains(&stage), "stage {stage} of {seen:?}");
    }
}
