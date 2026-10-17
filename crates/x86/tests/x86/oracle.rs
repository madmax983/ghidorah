//! Tier-2 oracle checks. They need GNU `as`, GNU `objdump` and `llvm-objdump` of the
//! toolchain `llvm-tools` component.

use std::path::{Path, PathBuf};
use std::process::Command;

use ghidorah_x86::{NoSymbols, print};

use crate::common::{dec, hex, normalize_objdump, normalize_printer, root, spec_lines};

/// The distance between two candidates in the probe file.
const STRIDE: usize = 32;

/// Finds `llvm-objdump` in the active toolchain.
fn llvm_objdump() -> PathBuf {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("run rustc");
    let host = Command::new("rustc").arg("-vV").output().expect("run rustc");
    let host = String::from_utf8_lossy(&host.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
        .expect("host triple");
    PathBuf::from(String::from_utf8_lossy(&sysroot.stdout).trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin/llvm-objdump")
}

/// Assembles the candidates at a fixed stride into an object file and gives its path.
fn object(dir: &Path, name: &str, cands: &[Vec<u8>]) -> PathBuf {
    let src = dir.join(format!("{name}.s"));
    let obj = dir.join(format!("{name}.o"));
    let mut text = String::new();
    for c in cands {
        let mut b = c.clone();
        b.resize(STRIDE, 0xcc);
        let bytes: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
        text.push_str(&format!(".byte {}\n", bytes.join(",")));
    }
    std::fs::write(&src, text).expect("write the probe source");
    let ok = Command::new("as")
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("run as");
    assert!(ok.success(), "as fails");
    obj
}

/// Parses a disassembly into `(address, text)` lines.
fn lines(out: &[u8]) -> Vec<(u64, String)> {
    String::from_utf8_lossy(out)
        .lines()
        .filter_map(|l| {
            let (addr, rest) = l.split_once(':')?;
            let addr = u64::from_str_radix(addr.trim(), 16).ok()?;
            let text = rest.rsplit('\t').next().unwrap_or_default().trim().to_owned();
            Some((addr, text))
        })
        .collect()
}

fn scratch() -> PathBuf {
    let dir = root().join("target/x86-oracle");
    std::fs::create_dir_all(&dir).expect("make the scratch directory");
    dir
}

/// Gives the length of each candidate: the distance to the next decoded address.
fn lengths(listing: &[(u64, String)], count: usize) -> Vec<Option<(u64, String)>> {
    let mut out = vec![None; count];
    for (i, (addr, text)) in listing.iter().enumerate() {
        let a = usize::try_from(*addr).expect("address");
        if a % STRIDE == 0 && a / STRIDE < count {
            let next = listing.get(i + 1).map_or(*addr + 1, |n| n.0);
            out[a / STRIDE] = Some((next - addr, text.clone()));
        }
    }
    out
}

#[test]
#[ignore = "tier2"]
fn tier2_length_goldens_match_llvm() {
    for name in ["vector.txt", "legacy.txt"] {
        let text = std::fs::read_to_string(root().join("tests/golden/x86_len").join(name))
            .expect("read the golden");
        let rows: Vec<(Vec<u8>, u64)> = text
            .lines()
            .skip(1)
            .map(|l| {
                let f: Vec<&str> = l.split('|').collect();
                (hex(f[0]), f[1].parse().expect("length"))
            })
            .collect();
        let cands: Vec<Vec<u8>> = rows.iter().map(|r| r.0.clone()).collect();
        let obj = object(&scratch(), "len", &cands);
        let out = Command::new(llvm_objdump())
            .args(["-d", "-z", "--x86-asm-syntax=intel"])
            .arg(&obj)
            .output()
            .expect("run llvm-objdump");
        let got = lengths(&lines(&out.stdout), rows.len());
        for (i, (bytes, n)) in rows.iter().enumerate() {
            let len = got[i].as_ref().map(|g| g.0);
            assert_eq!(len, Some(*n), "{name}: {bytes:02x?}");
        }
    }
}

#[test]
#[ignore = "tier2"]
fn tier2_spec_matches_gnu_objdump() {
    let vectors: Vec<_> = spec_lines()
        .into_iter()
        .filter(|v| !v.is_error() && v.mnem != "(vector)")
        .collect();
    let cands: Vec<Vec<u8>> = vectors.iter().map(|v| v.bytes.clone()).collect();
    let obj = object(&scratch(), "spec", &cands);
    let out = Command::new("objdump")
        .args(["-d", "-w", "-z", "-M", "intel"])
        .arg(&obj)
        .output()
        .expect("run objdump");
    let got = lengths(&lines(&out.stdout), vectors.len());
    let mut failures = Vec::new();
    for (i, v) in vectors.iter().enumerate() {
        let addr = u64::try_from(i * STRIDE).expect("address");
        let insn = dec(&v.bytes, addr).unwrap_or_else(|e| panic!("line {}: {e}", v.line));
        let mine = normalize_printer(&print(&insn, &NoSymbols));
        match &got[i] {
            Some((n, text)) if *n == u64::from(v.len) && normalize_objdump(text) == mine => {}
            other => failures.push(format!("line {}: {mine} <> {other:?}", v.line)),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
