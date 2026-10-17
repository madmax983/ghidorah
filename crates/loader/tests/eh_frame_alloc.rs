//! The heap of the `.eh_frame` walk on hostile bytes stays inside the bound of AC-055.
//!
//! This binary installs the counting allocator of `ghidorah-oracle`. Each walk runs in
//! [`CountingAlloc::measure`], which counts only the heap of the calling thread.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]

use ghidorah_base::Limits;
use ghidorah_loader::ehframe::{Place, parse_bytes};
use ghidorah_oracle::alloc::CountingAlloc;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

const MIB: usize = 1 << 20;

/// The heap bound of AC-055 for `len` bytes.
fn bound(len: usize) -> usize {
    len.saturating_mul(32).saturating_add(16 << 20)
}

/// A CIE with `zR` and `uleb128` FDE pointers, CFA `rsp + 8`.
fn cie() -> Vec<u8> {
    let mut out = 16u32.to_le_bytes().to_vec();
    out.extend_from_slice(&[
        0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x01, 0x0c, 0x07, 0x08,
    ]);
    out
}

/// Appends one FDE of the CIE at offset 0 with a 1-byte begin, a 1-byte range and `program`.
fn fde(out: &mut Vec<u8>, program: &[u8]) {
    let at = out.len();
    let mut body = u32::try_from(at + 4)
        .expect("pointer")
        .to_le_bytes()
        .to_vec();
    body.extend_from_slice(&[0x10, 0x7f, 0]);
    body.extend_from_slice(program);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    out.extend_from_slice(&u32::try_from(body.len()).expect("len").to_le_bytes());
    out.extend_from_slice(&body);
}

/// 1 MiB of the smallest FDEs.
fn tiny_fdes() -> Vec<u8> {
    let mut out = cie();
    while out.len() < MIB {
        fde(&mut out, &[]);
    }
    out
}

/// 1 MiB of FDEs whose programs change the CFA at each address.
fn busy_rows() -> Vec<u8> {
    let program: Vec<u8> = (0..200)
        .flat_map(|i| [0x41, 0x0e, if i % 2 == 0 { 0x10 } else { 0x08 }])
        .collect();
    let mut out = cie();
    while out.len() < MIB {
        fde(&mut out, &program);
    }
    out
}

/// 1 MiB of `remember_state` in one FDE: the state stack grows to the instruction cap.
fn deep_state() -> Vec<u8> {
    let mut out = cie();
    fde(&mut out, &vec![0x0a; MIB]);
    out
}

#[test]
fn eh_frame_bounded_allocation() {
    let place = Place {
        va: 0x1000,
        file_off: 0,
    };
    let mut problems = Vec::new();
    for (name, bytes) in [
        ("tiny_fdes", tiny_fdes()),
        ("busy_rows", busy_rows()),
        ("deep_state", deep_state()),
    ] {
        let (eh, stats) = ALLOC.measure(|| parse_bytes(&bytes, place, &Limits::DEFAULT));
        if eh.fdes.is_empty() {
            problems.push(format!("{name}: no FDE"));
        }
        let limit = bound(bytes.len());
        if stats.peak_bytes > limit {
            problems.push(format!(
                "{name}: peak {} above {limit} for {} bytes",
                stats.peak_bytes,
                bytes.len()
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
