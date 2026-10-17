//! Property tests: no panic, prefix equality, determinism and layer agreement.
//!
//! Each property also counts its decoded cases, so a decoder that rejects all input
//! fails the test.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU32, Ordering};

use ghidorah_testkit::pbt::{self, Gen};
use ghidorah_x86::{DecodeError, NoSymbols, Opts, decode, length_with, print};

use crate::common::{dec, listings, spec_lines};

/// Bytes that start with a prefix or an escape more often than uniform bytes do.
fn insn_bytes(g: &mut Gen) -> Vec<u8> {
    const HEADS: &[&[u8]] = &[
        &[0x0f],
        &[0x0f, 0x38],
        &[0x0f, 0x3a],
        &[0x66],
        &[0xf3, 0x0f],
        &[0xf2, 0x0f],
        &[0x48],
        &[0x41],
        &[0xc5],
        &[0xc4],
        &[0x62],
        &[0xd5],
        &[0x8f],
        &[0x67],
        &[0xf0],
        &[0x64],
        &[],
    ];
    let mut out = g.pick(HEADS).map(|h| h.to_vec()).unwrap_or_default();
    out.extend(g.bytes(16));
    out
}

fn options(g: &mut Gen) -> Opts {
    Opts {
        amd_branch_osz: g.bool(),
        strict_vex_legacy_prefix: g.bool(),
    }
}

/// Asserts that at least `min` of `cases` cases decoded.
fn assert_share(name: &str, decoded: &AtomicU32, cases: u32, min_percent: u32) {
    let n = decoded.load(Ordering::Relaxed);
    assert!(
        n * 100 >= cases * min_percent,
        "{name}: only {n} of {cases} cases decode"
    );
}

#[test]
fn ac_062a_no_panic() {
    let decoded = AtomicU32::new(0);
    pbt::check("ac_062a_no_panic", 30_000, |g| {
        let bytes = insn_bytes(g);
        let opts = options(g);
        let addr = g.u64();
        let run = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(insn) = decode(&bytes, addr, &opts) {
                let _ = print(&insn, &NoSymbols);
                let _ = (insn.regs_read(), insn.regs_written(), insn.flags_written());
                let _ = insn.ops().count();
                decoded.fetch_add(1, Ordering::Relaxed);
            }
            let _ = length_with(&bytes, &opts);
        }));
        run.map_err(|_| format!("panic on {bytes:02x?}"))
    });
    assert_share("ac_062a_no_panic", &decoded, 30_000, 40);
}

#[test]
fn ac_062c_prefix_equal() {
    let decoded = AtomicU32::new(0);
    pbt::check("ac_062c_prefix_equal", 30_000, |g| {
        let bytes = insn_bytes(g);
        let opts = options(g);
        match decode(&bytes, 0x40_1000, &opts) {
            Ok(insn) => {
                decoded.fetch_add(1, Ordering::Relaxed);
                let n = usize::from(insn.len());
                let cut = decode(&bytes[..n], 0x40_1000, &opts);
                if cut == Ok(insn) {
                    Ok(())
                } else {
                    Err(format!("{bytes:02x?}: the first {n} bytes give {cut:?}"))
                }
            }
            Err(_) => Ok(()),
        }
    });
    assert_share("ac_062c_prefix_equal", &decoded, 30_000, 40);
    for l in listings() {
        for i in &l.insns {
            let insn = dec(&i.bytes, i.addr).unwrap_or_else(|e| panic!("{:x}: {e}", i.addr));
            let mut longer = i.bytes.clone();
            longer.extend_from_slice(&[0x0f, 0x0f, 0x0f]);
            assert_eq!(
                dec(&longer, i.addr),
                Ok(insn),
                "{} at {:x}",
                l.fixture,
                i.addr
            );
        }
    }
}

#[test]
fn ac_062e_deterministic() {
    let decoded = AtomicU32::new(0);
    pbt::check("ac_062e_deterministic", 20_000, |g| {
        let bytes = insn_bytes(g);
        let opts = options(g);
        let a = decode(&bytes, 0x1000, &opts);
        let b = decode(&bytes, 0x1000, &opts);
        if a != b {
            return Err(format!("{bytes:02x?}: {a:?} then {b:?}"));
        }
        if let Ok(insn) = a {
            decoded.fetch_add(1, Ordering::Relaxed);
            if print(&insn, &NoSymbols) != print(&insn, &NoSymbols) {
                return Err(format!("{bytes:02x?}: two texts"));
            }
        }
        Ok(())
    });
    assert_share("ac_062e_deterministic", &decoded, 20_000, 40);
    for v in spec_lines().iter().filter(|v| !v.is_error()) {
        let a = dec(&v.bytes, 0x1000).unwrap_or_else(|e| panic!("line {}: {e}", v.line));
        assert_eq!(dec(&v.bytes, 0x1000), Ok(a), "line {}", v.line);
        let text = print(&a, &NoSymbols);
        assert!(!text.is_empty(), "line {}", v.line);
        assert_eq!(print(&a, &NoSymbols), text, "line {}", v.line);
    }
}

#[test]
fn length_agrees_with_decode() {
    let decoded = AtomicU32::new(0);
    pbt::check("length_agrees_with_decode", 30_000, |g| {
        let bytes = insn_bytes(g);
        let opts = options(g);
        let len = length_with(&bytes, &opts);
        let insn = decode(&bytes, 0, &opts);
        match (len, insn) {
            (Ok(n), Ok(i)) if n == i.len() => {
                decoded.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            (Err(a), Err(b)) if a == b => Ok(()),
            (
                Ok(n),
                Err(
                    DecodeError::Invalid {
                        len_consumed: m, ..
                    }
                    | DecodeError::Unsupported { len: m, .. },
                ),
            ) if n == m => Ok(()),
            (len, insn) => Err(format!("{bytes:02x?}: length {len:?}, decode {insn:?}")),
        }
    });
    assert_share("length_agrees_with_decode", &decoded, 30_000, 40);
}

#[test]
fn error_fields_stay_in_range() {
    let errors = AtomicU32::new(0);
    pbt::check("error_fields_stay_in_range", 20_000, |g| {
        let bytes = insn_bytes(g);
        let Err(e) = decode(&bytes, 0, &Opts::DEFAULT) else {
            return Ok(());
        };
        errors.fetch_add(1, Ordering::Relaxed);
        match e {
            DecodeError::Truncated {
                have,
                need_at_least,
            } if usize::from(have) != bytes.len().min(15)
                || need_at_least <= have
                || need_at_least > 15 =>
            {
                Err(format!("{bytes:02x?}: have {have}, need {need_at_least}"))
            }
            DecodeError::Invalid {
                len_consumed: 0, ..
            } => Err(format!("{bytes:02x?}: zero bytes consumed")),
            e if e.skip() == 0 || e.skip() > 15 => Err(format!("{bytes:02x?}: {e:?}")),
            e if e.to_string().is_empty() => Err("empty text".to_owned()),
            _ => Ok(()),
        }
    });
    assert!(
        errors.load(Ordering::Relaxed) > 100,
        "the generator makes errors"
    );
}
