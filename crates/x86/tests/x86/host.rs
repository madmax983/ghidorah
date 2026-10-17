//! Tier-2 boundary agreement on host bash and libc (AC-066).
//!
//! The test disassembles the `.text` section of each host binary with GNU objdump and
//! decodes each listed instruction. A `(bad)` line agrees with a decode error. Each other
//! line agrees when the decoded length equals the listed byte count. The test prints one
//! line `oracle-result {..}`, and `xtask oracle bash` writes it to
//! `verify/oracle-results.json`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use ghidorah_base::sha256::sha256_hex;
use ghidorah_x86::length;

use crate::common::{parse_listing, sections};

/// The result of one host binary.
struct Agreement {
    path: PathBuf,
    sha256: String,
    insns: usize,
    agree: usize,
    first: Vec<String>,
}

fn bash_path() -> PathBuf {
    let path = ["/bin/bash", "/usr/bin/bash"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("host bash");
    std::fs::canonicalize(path).expect("the bash path")
}

fn libc_path(bash: &Path) -> PathBuf {
    let out = Command::new("ldd").arg(bash).output().expect("run ldd");
    let text = String::from_utf8_lossy(&out.stdout);
    let path = text
        .lines()
        .find(|l| l.contains("libc.so"))
        .and_then(|l| l.split("=>").nth(1))
        .and_then(|r| r.split_whitespace().next())
        .expect("libc in the ldd output");
    std::fs::canonicalize(path).expect("the libc path")
}

fn agreement(path: &Path) -> Agreement {
    let file = std::fs::read(path).expect("read a host binary");
    let text = sections(&file)
        .into_iter()
        .find(|s| s.name == ".text")
        .expect("a .text section");
    let out = Command::new("objdump")
        .args(["-d", "-w", "-z", "-M", "intel", "-j", ".text"])
        .arg(path)
        .output()
        .expect("run objdump");
    let listing = parse_listing(&format!(
        "# header\n{}",
        String::from_utf8_lossy(&out.stdout)
    ));
    let start = usize::try_from(text.offset).expect("offset");
    let end = start + usize::try_from(text.size).expect("size");
    let code = &file[start..end];
    let (mut insns, mut agree, mut first) = (0, 0, Vec::new());
    for i in &listing.insns {
        insns += 1;
        let off = usize::try_from(i.addr - text.addr).expect("offset");
        let decoded = length(&code[off..]);
        let ok = if i.text.starts_with("(bad)") {
            decoded.is_err()
        } else {
            decoded.ok().map(usize::from) == Some(i.bytes.len())
        };
        if ok {
            agree += 1;
        } else if first.len() < 5 {
            first.push(format!("{:#x} {}: {decoded:?}", i.addr, i.text));
        }
    }
    Agreement {
        path: path.to_owned(),
        sha256: sha256_hex(&file),
        insns,
        agree,
        first,
    }
}

fn json_of(a: &Agreement) -> String {
    let first: Vec<String> = a
        .first
        .iter()
        .map(|m| format!("\"{}\"", m.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"path\":\"{}\",\"sha256\":\"{}\",\"insns\":{},\"agree\":{},\"mismatches\":{},\"first\":[{}]}}",
        a.path.display(),
        a.sha256,
        a.insns,
        a.agree,
        a.insns - a.agree,
        first.join(",")
    );
    out
}

#[test]
#[ignore = "tier2"]
#[allow(
    clippy::print_stdout,
    reason = "xtask oracle bash reads the result line"
)]
fn tier2_host_boundaries() {
    let bash = bash_path();
    let results = [
        ("bash", agreement(&bash)),
        ("libc", agreement(&libc_path(&bash))),
    ];
    let version = Command::new("objdump")
        .arg("--version")
        .output()
        .expect("objdump");
    let version = String::from_utf8_lossy(&version.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let body: Vec<String> = results
        .iter()
        .map(|(k, a)| format!("\"{k}\":{}", json_of(a)))
        .collect();
    println!(
        "oracle-result {{\"objdump\":\"{}\",{}}}",
        version.replace('"', "'"),
        body.join(",")
    );
    for (name, a) in &results {
        assert!(a.insns > 10_000, "{name}: only {} instructions", a.insns);
        assert_eq!(a.agree, a.insns, "{name}: {:?}", a.first);
    }
}
