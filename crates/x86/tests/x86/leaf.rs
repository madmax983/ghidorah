//! The leaf-function vectors of the T1 `O0` and `O2nv` builds (AC-072).
//!
//! Each leaf function of a truth file lifts over its body. Each vector of its leaf-driver
//! file sets the arguments, runs the L0 interpreter from the entry and compares the return
//! value in `rax` with the native result.

use std::path::PathBuf;

use ghidorah_base::Fuel;
use ghidorah_ir::{Arena, Builder, Config, Image, Interp, Loc, StopReason};
use ghidorah_x86::lift as lift_insn;

use crate::common::{dec, fixture_bytes, root};
use crate::json::{self, Json};

/// The lowest address of the stack region.
const STACK_LO: u64 = 0x7fff_0000;

/// The size of the stack region.
const STACK_SIZE: u64 = 0x1_0000;

/// The fuel of one run.
const FUEL: u64 = 200_000;

/// The loadable segments of an ELF file and a writable stack.
pub struct ElfImage {
    segments: Vec<(u64, Vec<u8>)>,
}

fn u16_at(b: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes(
        b[at..at + 2].try_into().expect("2 bytes"),
    ))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn to_usize(v: u64) -> usize {
    usize::try_from(v).expect("fits usize")
}

impl ElfImage {
    /// Reads the `PT_LOAD` segments of a checked-in ELF64 file.
    pub fn new(file: &[u8]) -> Self {
        let phoff = to_usize(u64_at(file, 0x20));
        let entsize = u16_at(file, 0x36);
        let count = u16_at(file, 0x38);
        let segments = (0..count)
            .filter_map(|i| {
                let h = phoff + i * entsize;
                let kind = u32::from_le_bytes(file[h..h + 4].try_into().expect("4 bytes"));
                (kind == 1).then(|| {
                    let off = to_usize(u64_at(file, h + 8));
                    let vaddr = u64_at(file, h + 16);
                    let filesz = to_usize(u64_at(file, h + 32));
                    let memsz = to_usize(u64_at(file, h + 40));
                    let mut bytes = file[off..off + filesz].to_vec();
                    bytes.resize(memsz, 0);
                    (vaddr, bytes)
                })
            })
            .collect();
        Self { segments }
    }
}

impl Image for ElfImage {
    fn read(&self, addr: u64) -> Option<u8> {
        if (STACK_LO..STACK_LO + STACK_SIZE).contains(&addr) {
            return Some(0);
        }
        self.segments.iter().find_map(|(base, bytes)| {
            let off = usize::try_from(addr.checked_sub(*base)?).ok()?;
            bytes.get(off).copied()
        })
    }

    fn writable(&self, addr: u64) -> bool {
        (STACK_LO..STACK_LO + STACK_SIZE).contains(&addr)
    }
}

/// One leaf function of a truth file.
struct Leaf {
    name: String,
    addr: u64,
    size: u64,
    ret_bits: u32,
}

fn bits_of(sig: &str) -> u32 {
    let ret = sig.split('(').next().expect("a return type");
    ret.trim_start_matches(['u', 'i']).parse().expect("a width")
}

/// Gives the truth files with leaf functions.
fn truth_files() -> Vec<(String, Vec<Leaf>)> {
    let dir = root().join("fixtures/truth");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("the truth directory")
        .map(|e| e.expect("entry").path())
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for p in paths {
        let t = json::parse(&std::fs::read_to_string(&p).expect("a truth file"));
        let leaves = t.get("leaf_functions").arr();
        if leaves.is_empty() {
            continue;
        }
        let funcs = t.get("functions").arr();
        let find = |name: &str| -> &Json {
            funcs
                .iter()
                .find(|f| f.get("name").str() == name)
                .unwrap_or_else(|| panic!("function {name}"))
        };
        let list = leaves
            .iter()
            .map(|l| {
                let name = l.get("name").str();
                let f = find(name);
                Leaf {
                    name: name.to_owned(),
                    addr: u64::try_from(f.get("addr").hex()).expect("address"),
                    size: f.get("size").u64(),
                    ret_bits: bits_of(l.get("sig").str()),
                }
            })
            .collect();
        out.push((t.get("fixture").str().to_owned(), list));
    }
    out
}

/// Lifts the body of a function with a linear sweep.
fn lift_body(image: &ElfImage, leaf: &Leaf) -> Arena {
    let mut b = Builder::new();
    let mut at = leaf.addr;
    while at < leaf.addr + leaf.size {
        let bytes: Vec<u8> = (0..15).filter_map(|i| image.read(at + i)).collect();
        let insn = dec(&bytes, at).unwrap_or_else(|e| panic!("{} {at:#x}: {e}", leaf.name));
        lift_insn(&insn, &mut b).unwrap_or_else(|e| panic!("{} {at:#x}: {e}", leaf.name));
        at = insn.next_addr();
    }
    b.finish()
}

/// Reads the leaf-driver vectors of one function: `(arguments, result)`.
fn vectors(fixture: &str, name: &str) -> Vec<(Vec<u64>, u64)> {
    let path = root().join(format!("tests/golden/semantics/leaf/{fixture}.jsonl"));
    let text = std::fs::read_to_string(&path).expect("a leaf vector file");
    text.lines()
        .skip(1)
        .map(json::parse)
        .filter(|v| v.get("fn").str() == name)
        .map(|v| {
            let args = v
                .get("args")
                .arr()
                .iter()
                .map(|a| u64::try_from(a.hex()).expect("arg"))
                .collect();
            (args, u64::try_from(v.get("ret").hex()).expect("ret"))
        })
        .collect()
}

/// Runs every vector of one fixture. Gives the count of runs and the failures.
fn run_fixture(fixture: &str, leaves: &[Leaf]) -> (usize, Vec<String>) {
    let file = fixture_bytes(fixture);
    let image = ElfImage::new(&file);
    let mut runs = 0;
    let mut failures = Vec::new();
    for leaf in leaves {
        let arena = lift_body(&image, leaf);
        let cases = vectors(fixture, &leaf.name);
        assert_eq!(
            cases.len(),
            1000,
            "{fixture} {}: the vector count",
            leaf.name
        );
        let mask = if leaf.ret_bits >= 64 {
            u64::MAX
        } else {
            (1 << leaf.ret_bits) - 1
        };
        for (args, ret) in cases {
            let mut interp = Interp::new(&arena, &image, Config::default());
            let sp = STACK_LO + STACK_SIZE - 0x100;
            for (loc, v) in [Loc::RDI, Loc::RSI, Loc::RDX].into_iter().zip(&args) {
                interp.set_loc(loc, u128::from(*v));
            }
            interp.set_loc(Loc::RSP, u128::from(sp));
            let stop = interp.run(leaf.addr, &mut Fuel::new(FUEL));
            let got =
                u64::try_from(interp.loc(Loc::RAX) & u128::from(u64::MAX)).expect("rax") & mask;
            runs += 1;
            if stop.reason != StopReason::Returned || got != ret {
                failures.push(format!(
                    "{fixture} {}({args:x?}): {:?} at {}, rax {got:#x}, want {ret:#x}",
                    leaf.name, stop.reason, stop.at
                ));
            }
        }
    }
    (runs, failures)
}

#[test]
fn ac_072_leaf_function_vectors() {
    let files = truth_files();
    assert_eq!(
        files.len(),
        9,
        "the O0 and O2nv builds of loops, switch and xor_decode"
    );
    let results: Vec<(usize, Vec<String>)> = std::thread::scope(|s| {
        #[expect(
            clippy::needless_collect,
            reason = "every thread starts before the first join"
        )]
        let handles: Vec<_> = files
            .iter()
            .map(|(fixture, leaves)| s.spawn(move || run_fixture(fixture, leaves)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a worker thread"))
            .collect()
    });
    let runs: usize = results.iter().map(|r| r.0).sum();
    let failures: Vec<&String> = results.iter().flat_map(|r| &r.1).collect();
    assert!(runs >= 25_000, "only {runs} runs");
    let shown: Vec<&String> = failures.iter().take(10).copied().collect();
    assert!(
        failures.is_empty(),
        "{} failures:\n{shown:#?}",
        failures.len()
    );
}
