//! Tier-2 differential test: random instruction bytes against `llvm-objdump`.

use std::process::Command;

use ghidorah_testkit::rng::Xoshiro256ss;
use ghidorah_x86::{DecodeError, Encoding, Insn, InvalidReason};

use crate::common::dec;
use crate::oracle::{lengths, lines, llvm_objdump, object, scratch};

/// The number of random candidates.
const CASES: usize = 60_000;

/// The prefixes and escapes that start a candidate.
const HEADS: &[&[u8]] = &[
    &[],
    &[0x0f],
    &[0x66],
    &[0xf3],
    &[0xf2],
    &[0x48],
    &[0x41],
    &[0x66, 0x0f],
    &[0xf3, 0x0f],
    &[0xf2, 0x0f],
    &[0x48, 0x0f],
    &[0x67],
    &[0x64],
    &[0xf0],
    &[0xc5],
    &[0xc4, 0xe1],
    &[0xc4, 0xe2],
    &[0xc4, 0xe3],
    &[0x62, 0xf1],
    &[0x62, 0xf2],
    &[0x62, 0xf3],
    &[0x62, 0xf4],
    &[0xd5, 0x00],
    &[0xd5, 0x80],
];

fn candidates() -> Vec<Vec<u8>> {
    let mut rng = Xoshiro256ss::seed_from_u64(0x5eed_0086);
    (0..CASES)
        .map(|_| {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            let head = HEADS[usize::from(buf[15]) % HEADS.len()];
            let mut c = head.to_vec();
            c.extend_from_slice(&buf[..15 - head.len()]);
            c
        })
        .collect()
}

/// Tells if llvm-objdump 22 misreads the SIB base of an instruction.
///
/// With REX2.B4, `mod` 00 and SIB base 101 it reads base r21 or r29 and no displacement.
/// GNU objdump 2.42 and the APX rules read a 32-bit displacement and no base.
fn llvm_sib_quirk(insn: &Insn) -> bool {
    let raw = insn.raw();
    raw.encoding == Encoding::Rex2
        && raw.rex.is_some_and(|p| p & 0x10 != 0)
        && raw.modrm.is_some_and(|m| m >> 6 == 0)
        && raw.sib.is_some_and(|b| b & 7 == 5)
}

#[test]
#[ignore = "tier2"]
fn tier2_random_lengths_match_llvm() {
    let cands = candidates();
    let obj = object(&scratch(), "random", &cands);
    let out = Command::new(llvm_objdump())
        .args(["-d", "-z", "--x86-asm-syntax=intel"])
        .arg(&obj)
        .output()
        .expect("run llvm-objdump");
    let got = lengths(&lines(&out.stdout), cands.len());
    let mut checked = 0;
    let mut differ = Vec::new();
    let mut rejected = Vec::new();
    for (c, g) in cands.iter().zip(&got) {
        let Some((n, text)) = g else {
            continue;
        };
        // llvm-objdump prints a prefix that it cannot attach as a one-word line.
        let bare = matches!(
            text.as_str(),
            "lock"
                | "xacquire"
                | "xrelease"
                | "rep"
                | "repne"
                | "data16"
                | "rex64"
                | "cs"
                | "ds"
                | "es"
                | "fs"
                | "gs"
                | "ss"
        );
        if text.contains("<unknown>") || bare {
            continue;
        }
        let mine = match dec(c, 0) {
            Ok(insn) if llvm_sib_quirk(&insn) => continue,
            Ok(insn) => Ok(insn.len()),
            Err(DecodeError::Unsupported { len, .. }) => Ok(len),
            // The APX rules make `0F` after REX2 undefined. llvm-objdump decodes the legacy form.
            Err(DecodeError::Invalid {
                len_consumed,
                reason: InvalidReason::BadRex2,
            }) if usize::from(len_consumed)
                .checked_sub(1)
                .and_then(|i| c.get(i))
                == Some(&0x0f) =>
            {
                continue;
            }
            // llvm-objdump does not check `lock` or a prefix after REX2. Only the length counts.
            Err(DecodeError::Invalid {
                len_consumed,
                reason: InvalidReason::BadLock | InvalidReason::BadRex2,
            }) => Ok(len_consumed),
            Err(e) => Err(e),
        };
        match mine {
            Ok(len) if u64::from(len) == *n => checked += 1,
            Ok(len) => differ.push(format!("{c:02x?}: {len} <> llvm {n} {text}")),
            Err(e) => rejected.push(format!("{c:02x?}: {e:?} <> llvm {n} {text}")),
        }
    }
    assert!(checked > CASES / 4, "only {checked} checked");
    assert!(
        differ.is_empty() && rejected.is_empty(),
        "{checked} agree, {} differ, {} rejected:\n{}\n{}",
        differ.len(),
        rejected.len(),
        differ
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
        rejected
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
