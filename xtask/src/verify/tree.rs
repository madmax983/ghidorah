//! The tree hash of the proof inputs (design Section 13.3, AC-034).
//!
//! The hash covers the files under [`SOURCE_DIRS`] and the Verus argument list [`ARGV`].
//! A change to a kernel file, to the stub crate or to the flags makes the record stale.
//!
//! Encoding: for each file in path order, the hash takes `file <path>\n<byte count>\n<bytes>`.
//! Then it takes `argv <ARGV joined with spaces>\n`.
//!
//! This file uses only `std`. The kernel test `ac_034_proof_freshness` includes it with `#[path]`.
//! So the record and the test use one hash definition.

use std::fmt::Write as _;
use std::io;
use std::path::Path;

/// The Verus argument list of the record. The program name is `verus` on every host.
pub const ARGV: &[&str] = &[
    "verus",
    "--cfg",
    "verus_only",
    "--no-cheating",
    "--crate-type=lib",
    "--output-json",
    "crates/kernel/src/lib.rs",
];

/// The proof record, relative to the workspace root.
pub const RESULTS_PATH: &str = "verify/results.json";

/// The source directories that the tree hash covers, relative to the workspace root.
pub const SOURCE_DIRS: &[&str] = &["crates/kernel/src", "crates/spec/src"];

/// The maximum depth of the directory walk.
const MAX_DEPTH: usize = 16;

/// The round constants of SHA-256 (FIPS 180-4, Section 4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial hash value of SHA-256 (FIPS 180-4, Section 5.3.3).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Applies the compression function to one 64-byte block.
#[expect(clippy::many_single_char_names, reason = "the names follow FIPS 180-4")]
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, w) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(w);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// Gives the SHA-256 digest of `bytes` (FIPS 180-4).
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let mut blocks = bytes.chunks_exact(64);
    for block in &mut blocks {
        compress(&mut state, block);
    }
    let rest = blocks.remainder();
    // The padding: one 0x80 byte, zero bytes, then the bit length as a big-endian u64.
    let mut last = [0u8; 128];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] = 0x80;
    let size = if rest.len() < 56 { 64 } else { 128 };
    let bits = (bytes.len() as u64).wrapping_mul(8);
    last[size - 8..size].copy_from_slice(&bits.to_be_bytes());
    for block in last[..size].chunks_exact(64) {
        compress(&mut state, block);
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Gives the lowercase hex text of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Gives the tree hash of `files` and `argv` as lowercase hex.
///
/// Each file is a pair of a relative path with `/` separators and its bytes.
/// The order of `files` has no effect.
#[must_use]
pub fn hash_files(files: &[(String, Vec<u8>)], argv: &[&str]) -> String {
    let mut sorted: Vec<&(String, Vec<u8>)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut input = Vec::new();
    for (path, bytes) in sorted {
        input.extend_from_slice(format!("file {path}\n{}\n", bytes.len()).as_bytes());
        input.extend_from_slice(bytes);
    }
    input.extend_from_slice(format!("argv {}\n", argv.join(" ")).as_bytes());
    hex(&sha256(&input))
}

/// Adds each file under `dir` to `out`, with its path relative to `root`.
fn walk(root: &Path, dir: &Path, depth: usize, out: &mut Vec<(String, Vec<u8>)>) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            walk(root, &path, depth + 1, out)?;
        } else if kind.is_file() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            let name = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            out.push((name, std::fs::read(&path)?));
        }
    }
    Ok(())
}

/// Gives each file under [`SOURCE_DIRS`] as a pair of a relative path and its bytes.
///
/// The pairs come in path order.
///
/// # Errors
///
/// Gives the I/O error of a failed directory read or file read.
pub fn tree_files(root: &Path) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for dir in SOURCE_DIRS {
        walk(root, &root.join(dir), 0, &mut files)?;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// Gives the tree hash of the proof inputs under `root` with [`ARGV`].
///
/// # Errors
///
/// Gives the I/O error of a failed directory read or file read.
pub fn tree_sha256(root: &Path) -> io::Result<String> {
    Ok(hash_files(&tree_files(root)?, ARGV))
}
